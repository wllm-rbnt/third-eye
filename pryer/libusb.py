"""
A small ctypes binding for libusb-1.0.

The rest of the project has no third-party dependencies (the Android path talks
to /dev/raw-gadget through ctypes as well), so rather than pull in PyUSB we
bind the handful of libusb entry points the iOS path needs.

Reading: queued single-URB transfers
------------------------------------
A tunnel reader must never have a URB cancelled while data can still arrive
in it. On a Raspberry Pi 4B that rules out long synchronous reads. dwc2 cannot
do scatter-gather, so libusb's Linux backend splits any transfer larger than
MAX_URB_SIZE into 16 kiB URBs chained with USBFS_URB_BULK_CONTINUATION, all
but the last marked SHORT_NOT_OK. Every DJI tunnel packet ends in a short
packet, so such a read is complete after its first URB, and usbfs then cancels
the others. dwc2 does not wait for that: it starts the next queued URB as soon
as one completes, typically 20-150 us after the short packet. Data that
arrives in it is lost, because the URB is dequeued and handed back empty, and
its DATA toggle is not carried over, so the host later ACKs a good packet and
drops it as a duplicate. The wire then carries a complete stream while the
application misses goggles requests and pieces of video (PROTOCOL.md section
9.3; `pryer.linkaudit` detects it in a capture).

`BulkReader` keeps `count` independent transfers of at most MAX_URB_SIZE
queued, with no timeout, and resubmits each one from its completion callback.
So no URB is ever cancelled while data can still arrive in it, and the
endpoint always has a request queued, as with an iPhone. One thread per
context runs libusb's event loop (`Context.start_events`). Synchronous
`bulk_read` stays available as the fallback. It is capped at one URB for the
same reason.

Writes and control transfers stay synchronous.
"""

from __future__ import annotations

import collections
import ctypes
import ctypes.util
import logging
import struct
import sys
import threading
import time

log = logging.getLogger("pryer.libusb")

# --------------------------------------------------------------------------- #
# Error codes
# --------------------------------------------------------------------------- #

SUCCESS = 0
ERROR_IO = -1
ERROR_INVALID_PARAM = -2
ERROR_ACCESS = -3
ERROR_NO_DEVICE = -4
ERROR_NOT_FOUND = -5
ERROR_BUSY = -6
ERROR_TIMEOUT = -7
ERROR_OVERFLOW = -8
ERROR_PIPE = -9
ERROR_INTERRUPTED = -10
ERROR_NO_MEM = -11
ERROR_NOT_SUPPORTED = -12
ERROR_OTHER = -99

ERROR_NAMES = {
    ERROR_IO: "LIBUSB_ERROR_IO",
    ERROR_INVALID_PARAM: "LIBUSB_ERROR_INVALID_PARAM",
    ERROR_ACCESS: "LIBUSB_ERROR_ACCESS (need root or a udev rule)",
    ERROR_NO_DEVICE: "LIBUSB_ERROR_NO_DEVICE (device went away)",
    ERROR_NOT_FOUND: "LIBUSB_ERROR_NOT_FOUND",
    ERROR_BUSY: "LIBUSB_ERROR_BUSY (a kernel driver holds the interface)",
    ERROR_TIMEOUT: "LIBUSB_ERROR_TIMEOUT",
    ERROR_OVERFLOW: "LIBUSB_ERROR_OVERFLOW",
    ERROR_PIPE: "LIBUSB_ERROR_PIPE (endpoint stalled)",
    ERROR_INTERRUPTED: "LIBUSB_ERROR_INTERRUPTED",
    ERROR_NO_MEM: "LIBUSB_ERROR_NO_MEM",
    ERROR_NOT_SUPPORTED: "LIBUSB_ERROR_NOT_SUPPORTED",
    ERROR_OTHER: "LIBUSB_ERROR_OTHER",
}


class UsbError(OSError):
    def __init__(self, code: int, what: str):
        self.code = code
        super().__init__("%s: %s (%d)"
                         % (what, ERROR_NAMES.get(code, "unknown"), code))


class UsbTimeout(UsbError):
    pass


def _check(code: int, what: str) -> int:
    if code >= 0:
        return code
    if code == ERROR_TIMEOUT:
        raise UsbTimeout(code, what)
    raise UsbError(code, what)


# --------------------------------------------------------------------------- #
# Structures
# --------------------------------------------------------------------------- #

class DeviceDescriptor(ctypes.Structure):
    _fields_ = [
        ("bLength", ctypes.c_uint8),
        ("bDescriptorType", ctypes.c_uint8),
        ("bcdUSB", ctypes.c_uint16),
        ("bDeviceClass", ctypes.c_uint8),
        ("bDeviceSubClass", ctypes.c_uint8),
        ("bDeviceProtocol", ctypes.c_uint8),
        ("bMaxPacketSize0", ctypes.c_uint8),
        ("idVendor", ctypes.c_uint16),
        ("idProduct", ctypes.c_uint16),
        ("bcdDevice", ctypes.c_uint16),
        ("iManufacturer", ctypes.c_uint8),
        ("iProduct", ctypes.c_uint8),
        ("iSerialNumber", ctypes.c_uint8),
        ("bNumConfigurations", ctypes.c_uint8),
    ]


# --------------------------------------------------------------------------- #
# Asynchronous transfers
# --------------------------------------------------------------------------- #

# The most libusb's Linux backend puts into one URB when the host controller
# cannot do scatter-gather (MAX_BULK_BUFFER_LENGTH in libusb/os/linux_usbfs.c).
# dwc2 cannot. A larger transfer becomes a chain of URBs of this size, and on
# an IN endpoint a short packet makes usbfs cancel the rest of the chain,
# losing data (module docstring). Transfers up to this size are one URB,
# with neither BULK_CONTINUATION nor SHORT_NOT_OK.
MAX_URB_SIZE = 16 * 1024

TRANSFER_COMPLETED = 0
TRANSFER_ERROR = 1
TRANSFER_TIMED_OUT = 2
TRANSFER_CANCELLED = 3
TRANSFER_STALL = 4
TRANSFER_NO_DEVICE = 5
TRANSFER_OVERFLOW = 6

TRANSFER_STATUS_NAMES = {
    TRANSFER_COMPLETED: "COMPLETED",
    TRANSFER_ERROR: "ERROR",
    TRANSFER_TIMED_OUT: "TIMED_OUT",
    TRANSFER_CANCELLED: "CANCELLED",
    TRANSFER_STALL: "STALL",
    TRANSFER_NO_DEVICE: "NO_DEVICE",
    TRANSFER_OVERFLOW: "OVERFLOW",
}

# The error code the synchronous API reports for each status (libusb sync.c).
STATUS_ERRORS = {
    TRANSFER_ERROR: ERROR_IO,
    TRANSFER_TIMED_OUT: ERROR_TIMEOUT,
    TRANSFER_STALL: ERROR_PIPE,
    TRANSFER_NO_DEVICE: ERROR_NO_DEVICE,
    TRANSFER_OVERFLOW: ERROR_OVERFLOW,
}

TRANSFER_TYPE_BULK = 2


class Transfer(ctypes.Structure):
    """`struct libusb_transfer`, minus the trailing isochronous descriptors.

    Transfers are always allocated by `libusb_alloc_transfer(0)`, so the
    flexible array at the end is never touched and need not be declared.
    """


TransferCallback = ctypes.CFUNCTYPE(None, ctypes.POINTER(Transfer))

Transfer._fields_ = [
    ("dev_handle", ctypes.c_void_p),
    ("flags", ctypes.c_uint8),
    ("endpoint", ctypes.c_ubyte),
    ("type", ctypes.c_ubyte),
    ("timeout", ctypes.c_uint),
    ("status", ctypes.c_int),
    ("length", ctypes.c_int),
    ("actual_length", ctypes.c_int),
    ("callback", TransferCallback),
    ("user_data", ctypes.c_void_p),
    ("buffer", ctypes.POINTER(ctypes.c_ubyte)),
    ("num_iso_packets", ctypes.c_int),
]

ASYNC_FUNCTIONS = ("libusb_alloc_transfer", "libusb_free_transfer",
                   "libusb_submit_transfer", "libusb_cancel_transfer",
                   "libusb_handle_events_timeout_completed")

# How often the event thread wakes up on its own to check for a stop request.
# Stopping normally interrupts it at once (libusb_interrupt_event_handler, in
# libusb since 1.0.21), and cancelled transfers wake it too.
EVENT_WAKEUP_S = 1


def _timeval(seconds: int):
    """
    A `struct timeval` of whole seconds, whatever size this libc's time_t is.

    32-bit Raspberry Pi OS images before Debian trixie have a 32-bit time_t
    (an 8-byte timeval). trixie's armhf and every 64-bit image have a 64-bit
    one (16 bytes). Sixteen zero bytes with the seconds written as a
    little-endian 64-bit integer read as (seconds, 0 us) in both layouts.
    """
    buf = (ctypes.c_uint8 * 16)()
    if sys.byteorder == "little":
        struct.pack_into("<q", buf, 0, seconds)
    else:                                   # not a Pi; plain C longs
        struct.pack_into("=ll", buf, 0, seconds, 0)
    return buf


_lib = None


def library():
    """Load libusb-1.0 lazily so importing pryer never fails without it."""
    global _lib
    if _lib is not None:
        return _lib
    for name in ("libusb-1.0.so.0", "libusb-1.0.so",
                 ctypes.util.find_library("usb-1.0")):
        if not name:
            continue
        try:
            lib = ctypes.CDLL(name)
        except OSError:
            continue
        _configure(lib)
        _lib = lib
        return lib
    raise UsbError(ERROR_NOT_SUPPORTED,
                   "libusb-1.0 not found -- install libusb-1.0-0")


def available() -> bool:
    try:
        library()
        return True
    except OSError:
        return False


def async_available(lib=None) -> bool:
    """True if this libusb has the asynchronous transfer API (all 1.0.x do)."""
    try:
        lib = lib or library()
    except OSError:
        return False
    return all(hasattr(lib, fn) for fn in ASYNC_FUNCTIONS)


def _configure(lib) -> None:
    p = ctypes.c_void_p
    lib.libusb_init.argtypes = [ctypes.POINTER(p)]
    lib.libusb_init.restype = ctypes.c_int
    lib.libusb_exit.argtypes = [p]
    lib.libusb_exit.restype = None
    lib.libusb_open_device_with_vid_pid.argtypes = [
        p, ctypes.c_uint16, ctypes.c_uint16]
    lib.libusb_open_device_with_vid_pid.restype = p
    lib.libusb_close.argtypes = [p]
    lib.libusb_close.restype = None
    for fn in ("libusb_claim_interface", "libusb_release_interface",
               "libusb_detach_kernel_driver", "libusb_attach_kernel_driver",
               "libusb_kernel_driver_active", "libusb_set_configuration"):
        f = getattr(lib, fn)
        f.argtypes = [p, ctypes.c_int]
        f.restype = ctypes.c_int
    lib.libusb_set_auto_detach_kernel_driver.argtypes = [p, ctypes.c_int]
    lib.libusb_set_auto_detach_kernel_driver.restype = ctypes.c_int
    lib.libusb_set_interface_alt_setting.argtypes = [
        p, ctypes.c_int, ctypes.c_int]
    lib.libusb_set_interface_alt_setting.restype = ctypes.c_int
    lib.libusb_bulk_transfer.argtypes = [
        p, ctypes.c_uint8, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int,
        ctypes.POINTER(ctypes.c_int), ctypes.c_uint]
    lib.libusb_bulk_transfer.restype = ctypes.c_int
    lib.libusb_control_transfer.argtypes = [
        p, ctypes.c_uint8, ctypes.c_uint8, ctypes.c_uint16, ctypes.c_uint16,
        ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint16, ctypes.c_uint]
    lib.libusb_control_transfer.restype = ctypes.c_int
    lib.libusb_clear_halt.argtypes = [p, ctypes.c_uint8]
    lib.libusb_clear_halt.restype = ctypes.c_int
    lib.libusb_reset_device.argtypes = [p]
    lib.libusb_reset_device.restype = ctypes.c_int
    lib.libusb_get_device_list.argtypes = [p, ctypes.POINTER(
        ctypes.POINTER(p))]
    lib.libusb_get_device_list.restype = ctypes.c_ssize_t
    lib.libusb_free_device_list.argtypes = [ctypes.POINTER(p), ctypes.c_int]
    lib.libusb_free_device_list.restype = None
    lib.libusb_get_device_descriptor.argtypes = [
        p, ctypes.POINTER(DeviceDescriptor)]
    lib.libusb_get_device_descriptor.restype = ctypes.c_int
    lib.libusb_get_string_descriptor_ascii.argtypes = [
        p, ctypes.c_uint8, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int]
    lib.libusb_get_string_descriptor_ascii.restype = ctypes.c_int
    if not all(hasattr(lib, fn) for fn in ASYNC_FUNCTIONS):
        return
    tp = ctypes.POINTER(Transfer)
    lib.libusb_alloc_transfer.argtypes = [ctypes.c_int]
    lib.libusb_alloc_transfer.restype = tp
    lib.libusb_free_transfer.argtypes = [tp]
    lib.libusb_free_transfer.restype = None
    lib.libusb_submit_transfer.argtypes = [tp]
    lib.libusb_submit_transfer.restype = ctypes.c_int
    lib.libusb_cancel_transfer.argtypes = [tp]
    lib.libusb_cancel_transfer.restype = ctypes.c_int
    lib.libusb_handle_events_timeout_completed.argtypes = [
        p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]
    lib.libusb_handle_events_timeout_completed.restype = ctypes.c_int
    if hasattr(lib, "libusb_interrupt_event_handler"):
        lib.libusb_interrupt_event_handler.argtypes = [p]
        lib.libusb_interrupt_event_handler.restype = None


# --------------------------------------------------------------------------- #
# Context / device
# --------------------------------------------------------------------------- #

class Context:
    def __init__(self) -> None:
        self.lib = library()
        ctx = ctypes.c_void_p()
        _check(self.lib.libusb_init(ctypes.byref(ctx)), "libusb_init")
        self.ctx = ctx
        self._events_lock = threading.Lock()
        self._events_thread: threading.Thread | None = None
        self._events_stop = threading.Event()

    def close(self) -> None:
        self.stop_events()
        if self.ctx:
            self.lib.libusb_exit(self.ctx)
            self.ctx = None

    # ------------------------------------------------------------------ #
    def start_events(self) -> None:
        """
        Run libusb's event loop on a thread of its own, once per context.

        Asynchronous transfers only complete while some thread handles
        events. Synchronous calls on other threads keep working alongside it:
        libusb lets one thread at a time handle events and wakes the others
        when their transfer is done. A completion callback can run on any
        thread that is handling events, this one or a synchronous caller.
        """
        with self._events_lock:
            if self._events_thread is not None:
                return
            self._events_stop.clear()
            thread = threading.Thread(target=self._event_loop,
                                      name="libusb-events", daemon=True)
            self._events_thread = thread
            thread.start()

    def _event_loop(self) -> None:
        tv = _timeval(EVENT_WAKEUP_S)
        failures = 0
        while not self._events_stop.is_set():
            rc = self.lib.libusb_handle_events_timeout_completed(
                self.ctx, ctypes.cast(tv, ctypes.c_void_p), None)
            if rc < 0 and rc != ERROR_INTERRUPTED:
                failures += 1
                if failures in (1, 1000):
                    log.warning("libusb event handling failed: %s (%d)",
                                ERROR_NAMES.get(rc, "unknown"), rc)
                time.sleep(0.001)          # never spin on a persistent error
            else:
                failures = 0

    def stop_events(self) -> None:
        with self._events_lock:
            thread, self._events_thread = self._events_thread, None
        if thread is None:
            return
        self._events_stop.set()
        interrupt = getattr(self.lib, "libusb_interrupt_event_handler", None)
        if interrupt is not None and self.ctx:
            interrupt(self.ctx)
        if thread is not threading.current_thread():
            thread.join(timeout=EVENT_WAKEUP_S + 1.0)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # ------------------------------------------------------------------ #
    def list_devices(self) -> list[tuple[int, int]]:
        """Return (vid, pid) for every device currently on the buses."""
        arr = ctypes.POINTER(ctypes.c_void_p)()
        n = self.lib.libusb_get_device_list(self.ctx, ctypes.byref(arr))
        _check(int(n), "libusb_get_device_list")
        out = []
        try:
            for i in range(int(n)):
                desc = DeviceDescriptor()
                if self.lib.libusb_get_device_descriptor(
                        arr[i], ctypes.byref(desc)) == 0:
                    out.append((desc.idVendor, desc.idProduct))
        finally:
            self.lib.libusb_free_device_list(arr, 1)
        return out

    def open(self, vid: int, pid: int) -> "Device":
        handle = self.lib.libusb_open_device_with_vid_pid(self.ctx, vid, pid)
        if not handle:
            raise UsbError(ERROR_NO_DEVICE,
                           "cannot open %04x:%04x" % (vid, pid))
        return Device(self, ctypes.c_void_p(handle), vid, pid)


class Device:
    def __init__(self, ctx: Context, handle, vid: int, pid: int):
        self.ctx = ctx
        self.lib = ctx.lib
        self.handle = handle
        self.vid = vid
        self.pid = pid
        self._claimed: list[int] = []
        self._readers: list[BulkReader] = []
        # Best effort: kick usbfs/other drivers off interfaces we claim.
        self.lib.libusb_set_auto_detach_kernel_driver(self.handle, 1)

    # ------------------------------------------------------------------ #
    def string(self, index: int) -> str:
        if not index:
            return ""
        buf = (ctypes.c_ubyte * 256)()
        n = self.lib.libusb_get_string_descriptor_ascii(
            self.handle, index, buf, len(buf))
        if n < 0:
            return ""
        return bytes(buf[:n]).decode("ascii", "replace")

    def claim(self, interface: int) -> None:
        _check(self.lib.libusb_claim_interface(self.handle, interface),
               "claim interface %d" % interface)
        self._claimed.append(interface)
        log.debug("claimed interface %d", interface)

    def set_alt(self, interface: int, alt: int) -> None:
        _check(self.lib.libusb_set_interface_alt_setting(
            self.handle, interface, alt),
            "set interface %d alt %d" % (interface, alt))
        log.debug("interface %d -> alternate setting %d", interface, alt)

    def control(self, request_type: int, request: int, value: int, index: int,
                data: bytes | int = b"", timeout: int = 1000) -> bytes:
        if isinstance(data, int):  # IN transfer: `data` is a length
            buf = (ctypes.c_ubyte * data)()
            n = _check(self.lib.libusb_control_transfer(
                self.handle, request_type, request, value, index, buf, data,
                timeout), "control IN 0x%02x" % request)
            return bytes(buf[:n])
        buf = (ctypes.c_ubyte * max(1, len(data)))(*data)
        _check(self.lib.libusb_control_transfer(
            self.handle, request_type, request, value, index, buf, len(data),
            timeout), "control OUT 0x%02x" % request)
        return b""

    def bulk_read(self, ep: int, length: int, timeout: int = 1000) -> bytes:
        """
        One synchronous bulk IN transfer, at most MAX_URB_SIZE bytes.

        Longer requests are cut to MAX_URB_SIZE. A bulk read may always
        return less than asked for, and a longer one would be split into
        chained URBs that the first short packet cancels, which loses data
        (module docstring). A timeout is a cancellation too; prefer
        `bulk_reader()` for an endpoint that streams.
        """
        length = min(length, MAX_URB_SIZE)
        buf = (ctypes.c_ubyte * length)()
        got = ctypes.c_int(0)
        rc = self.lib.libusb_bulk_transfer(
            self.handle, ep, buf, length, ctypes.byref(got), timeout)
        if rc == ERROR_TIMEOUT:
            # A timeout can still have moved data; hand over what arrived.
            return bytes(buf[:got.value])
        _check(rc, "bulk read 0x%02x" % ep)
        return bytes(buf[:got.value])

    def bulk_write(self, ep: int, data: bytes, timeout: int = 1000) -> int:
        if not data:
            return 0
        buf = (ctypes.c_ubyte * len(data))(*data)
        got = ctypes.c_int(0)
        _check(self.lib.libusb_bulk_transfer(
            self.handle, ep, buf, len(data), ctypes.byref(got), timeout),
            "bulk write 0x%02x" % ep)
        return got.value

    def bulk_reader(self, ep: int, size: int = MAX_URB_SIZE,
                    count: int = 8) -> "BulkReader":
        """Start a BulkReader on *ep*; closed with the device if not before."""
        reader = BulkReader(self, ep, size=size, count=count)
        reader.start()
        self._readers.append(reader)
        return reader

    def clear_halt(self, ep: int) -> None:
        self.lib.libusb_clear_halt(self.handle, ep)

    def reset(self) -> None:
        self.lib.libusb_reset_device(self.handle)

    def close(self) -> None:
        if not self.handle:
            return
        for reader in self._readers:       # no URB in flight past this point
            reader.close()
        self._readers.clear()
        for iface in reversed(self._claimed):
            self.lib.libusb_release_interface(self.handle, iface)
        self._claimed.clear()
        self.lib.libusb_close(self.handle)
        self.handle = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


# --------------------------------------------------------------------------- #
# Streaming reads
# --------------------------------------------------------------------------- #

# Readers whose transfers libusb never handed back after cancelling them
# (BulkReader.close). Never released, so a late completion still finds its
# callback and buffers.
_LEAKED: list = []


class BulkReader:
    """
    Keep *count* bulk IN transfers queued on one endpoint and hand back what
    they deliver, in order.

    Each transfer is one URB (*size* <= MAX_URB_SIZE), has no timeout and is
    not SHORT_NOT_OK, so a short packet simply completes it. The callback
    queues the data and resubmits the transfer at once, which keeps the
    endpoint polled without a gap whatever the reading thread is doing. Nothing
    is cancelled until `close()`. The kernel completes one endpoint's URBs in
    submission order, and libusb runs one completion callback at a time, so
    the chunks come out in wire order.

    If the reader falls behind by *max_backlog* chunks, completed transfers
    are parked instead of resubmitted. The endpoint is then NAKed and the
    device holds its data, rather than this process growing without bound.
    `read()` resubmits them once the backlog has halved.

    An error completion (stall, device gone, I/O error, babble) stops the
    reader. `read()` returns the data that arrived before it, then raises it
    as UsbError, which is what the synchronous call would have raised.
    """

    def __init__(self, dev, ep: int, size: int = MAX_URB_SIZE, count: int = 8,
                 *, max_backlog: int = 4096):
        if not 0 < size <= MAX_URB_SIZE:
            raise ValueError("transfer size must be 1..%d, got %d"
                             % (MAX_URB_SIZE, size))
        if count < 1:
            raise ValueError("need at least one transfer")
        self.lib = dev.lib
        self._dev = dev
        self.ep = ep
        self.size = size
        self.count = count
        self.max_backlog = max(2, max_backlog)
        self._callback = TransferCallback(self._on_complete)  # keep alive
        self._slots: list = []                # (POINTER(Transfer), buffer)
        self._index: dict[int, int] = {}      # transfer address -> slot
        self._cond = threading.Condition()
        self._chunks: collections.deque[bytes] = collections.deque()
        self._in_flight = 0
        self._parked: list[int] = []
        self._error: UsbError | None = None
        self._closing = False
        self._closed = False
        self._leaked: list = []
        # statistics, for the log at close
        self.completions = 0
        self.bytes = 0
        self.most_queued = 0
        self.parks = 0

    # ------------------------------------------------------------------ #
    def start(self) -> None:
        self._dev.ctx.start_events()          # completions need a handler
        handle = self._dev.handle
        if isinstance(handle, ctypes.c_void_p):
            handle = handle.value
        try:
            for i in range(self.count):
                ptr = self.lib.libusb_alloc_transfer(0)
                if not ptr:
                    raise UsbError(ERROR_NO_MEM, "libusb_alloc_transfer")
                buf = (ctypes.c_ubyte * self.size)()
                tr = ptr.contents
                tr.dev_handle = handle
                tr.flags = 0          # no SHORT_NOT_OK: a short packet ends it
                tr.endpoint = self.ep
                tr.type = TRANSFER_TYPE_BULK
                tr.timeout = 0        # never: a timeout is a cancellation
                tr.length = self.size
                tr.buffer = ctypes.cast(buf, ctypes.POINTER(ctypes.c_ubyte))
                tr.callback = self._callback
                tr.user_data = None
                tr.num_iso_packets = 0
                self._slots.append((ptr, buf))
                self._index[ctypes.addressof(tr)] = i
            for i in range(self.count):
                with self._cond:
                    self._in_flight += 1
                rc = self.lib.libusb_submit_transfer(self._slots[i][0])
                if rc < 0:
                    with self._cond:
                        self._in_flight -= 1
                    raise UsbError(rc, "submit bulk read 0x%02x" % self.ep)
        except BaseException:
            self.close()
            raise
        log.debug("EP 0x%02x: %d x %d-byte transfers queued",
                  self.ep, self.count, self.size)

    # ------------------------------------------------------------------ #
    def _on_complete(self, ptr) -> None:
        # Runs on whichever thread is handling libusb events. An exception
        # must not escape into C, so anything unexpected becomes the error.
        try:
            self._complete(ptr)
        except BaseException as exc:  # noqa: BLE001
            with self._cond:
                if self._error is None:
                    self._error = UsbError(ERROR_OTHER, "bulk read 0x%02x "
                                           "callback: %r" % (self.ep, exc))
                self._cond.notify_all()

    def _complete(self, ptr) -> None:
        tr = ptr.contents
        status = tr.status
        n = tr.actual_length
        data = ctypes.string_at(tr.buffer, n) if n > 0 else b""
        resubmit = cancel_rest = False
        with self._cond:
            self.completions += 1
            if data:
                self._chunks.append(data)
                self.bytes += n
                if len(self._chunks) > self.most_queued:
                    self.most_queued = len(self._chunks)
            if status == TRANSFER_COMPLETED:
                if self._closing or self._error is not None:
                    self._in_flight -= 1
                elif len(self._chunks) >= self.max_backlog:
                    self._in_flight -= 1
                    self._parked.append(self._index[ctypes.addressof(tr)])
                    self.parks += 1
                else:
                    resubmit = True
            else:
                self._in_flight -= 1
                if (status != TRANSFER_CANCELLED and self._error is None
                        and not self._closing):
                    self._error = UsbError(
                        STATUS_ERRORS.get(status, ERROR_OTHER),
                        "bulk read 0x%02x (transfer %s)" % (
                            self.ep, TRANSFER_STATUS_NAMES.get(status,
                                                               status)))
                    cancel_rest = True
            self._cond.notify_all()
        if resubmit:
            rc = self.lib.libusb_submit_transfer(ptr)
            if rc < 0:
                with self._cond:
                    self._in_flight -= 1
                    if self._error is None and not self._closing:
                        self._error = UsbError(rc, "resubmit bulk read 0x%02x"
                                               % self.ep)
                    self._cond.notify_all()
        if cancel_rest:
            self._cancel_all()

    def _cancel_all(self) -> None:
        for ptr, _buf in self._slots:
            self.lib.libusb_cancel_transfer(ptr)   # NOT_FOUND if not queued

    # ------------------------------------------------------------------ #
    def read(self, timeout: float | None = None,
             max_bytes: int = 256 * 1024) -> bytes:
        """
        The next data, joining whatever has queued up, to about *max_bytes*.

        Blocks for up to *timeout* seconds (None: forever) and returns b"" if
        nothing arrived, or once the reader is closing. Chunks are never
        split, so one read can exceed *max_bytes* by less than one transfer.
        """
        deadline = None if timeout is None else time.monotonic() + timeout
        with self._cond:
            while not self._chunks:
                if self._error is not None:
                    raise self._error
                if self._closing:
                    return b""
                if deadline is None:
                    self._cond.wait()
                    continue
                left = deadline - time.monotonic()
                if left <= 0:
                    return b""
                self._cond.wait(left)
            out = [self._chunks.popleft()]
            size = len(out[0])
            while self._chunks and size + len(self._chunks[0]) <= max_bytes:
                chunk = self._chunks.popleft()
                out.append(chunk)
                size += len(chunk)
            revive: list[int] = []
            if (self._parked and not self._closing and self._error is None
                    and len(self._chunks) <= self.max_backlog // 2):
                revive, self._parked = self._parked, []
                self._in_flight += len(revive)
        for i in revive:
            rc = self.lib.libusb_submit_transfer(self._slots[i][0])
            if rc < 0:
                with self._cond:
                    self._in_flight -= 1
                    if self._error is None:
                        self._error = UsbError(rc, "resubmit bulk read 0x%02x"
                                               % self.ep)
                    self._cond.notify_all()
        return out[0] if len(out) == 1 else b"".join(out)

    @property
    def in_flight(self) -> int:
        with self._cond:
            return self._in_flight

    def describe(self) -> str:
        return ("EP 0x%02x: %d transfers completed, %d bytes, at most %d "
                "waiting to be read, reads paused %d time(s)"
                % (self.ep, self.completions, self.bytes, self.most_queued,
                   self.parks))

    # ------------------------------------------------------------------ #
    def close(self, timeout: float = 2.0) -> None:
        """Cancel every transfer, wait for libusb to hand them back, free."""
        with self._cond:
            if self._closed:
                return
            self._closing = True
            self._cond.notify_all()
        deadline = time.monotonic() + timeout
        while True:
            with self._cond:
                if self._in_flight <= 0:
                    break
            if time.monotonic() >= deadline:
                break
            # Repeated, because a callback may have resubmitted a transfer
            # just before it saw _closing.
            self._cancel_all()
            with self._cond:
                if self._in_flight > 0:
                    self._cond.wait(0.05)
        with self._cond:
            leaked = self._in_flight
            self._closed = True
            self._cond.notify_all()
        if leaked > 0:
            # Freeing a transfer libusb still owns would be a use-after-free,
            # and so would letting this object (its callback and buffers) be
            # collected. Both stay allocated for the life of the process.
            log.warning("EP 0x%02x: %d transfer(s) still in flight after "
                        "cancelling; leaving them allocated", self.ep, leaked)
            self._leaked = list(self._slots)
            _LEAKED.append(self)
        else:
            for ptr, _buf in self._slots:
                self.lib.libusb_free_transfer(ptr)
        self._slots = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
