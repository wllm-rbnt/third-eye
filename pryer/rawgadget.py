"""
Thin ctypes binding for the Linux USB Raw Gadget driver (/dev/raw-gadget).

Raw Gadget has been in mainline since Linux 5.7 (CONFIG_USB_RAW_GADGET=y/m,
module name `raw_gadget`). It lets a userspace process implement an arbitrary
USB *device*: we get every control request delivered to us and we answer the
descriptors ourselves, which is exactly what is needed to impersonate an
Android phone in Open Accessory mode.

This binding mirrors include/uapi/linux/usb/raw_gadget.h.

Requirements
------------
* A board with a USB Device Controller (UDC) wired to a peripheral-capable
  port. The reference target for this project is a **Raspberry Pi 4 Model B**,
  whose USB-C socket is wired to the SoC's `dwc2` controller. Pi Zero /
  Zero 2 W and most Allwinner/Rockchip SBCs (`musb-hdrc`, `dwc3`) work too.
  A desktop PC cannot do this.
* `modprobe raw_gadget`, plus `dwc2` in peripheral mode
  (`dtoverlay=dwc2,dr_mode=peripheral` in `/boot/firmware/config.txt`).
* Root.

The Raspberry Pi 4B naming trap
-------------------------------
``USB_RAW_IOCTL_INIT`` takes *two* names and they are not interchangeable:

* ``device_name`` is matched against the UDC's **device** name, i.e. the
  directory name in ``/sys/class/udc`` -- ``fe980000.usb`` on a Pi 4B
  (``20980000.usb`` on a Pi Zero/3, ``dummy_udc.0`` under Dummy HCD).
* ``driver_name`` is matched against ``gadget->name`` inside
  ``raw_gadget``'s ``gadget_bind``, and ``dwc2`` sets
  ``hsotg->gadget.name = dev_name(dev)`` -- so it is **also** ``fe980000.usb``,
  *not* the string ``"dwc2"``.

Passing ``"dwc2"`` as the driver name therefore makes every bind fail with
``ENODEV`` on a Pi 4B, which surfaces much later as "the goggles never sent
START_ACCESSORY". Both names are therefore derived from the kernel instead of
being hard-coded: udc-core exports the right driver name as ``USB_UDC_NAME`` in
``/sys/class/udc/<udc>/uevent``, so :func:`udc_driver_name` reads it there.

Other dwc2 behaviour this module has to account for
---------------------------------------------------
* **No ``vbus_draw``.** ``dwc2_hsotg_vbus_draw`` returns ``-ENOTSUPP`` unless a
  ``usb_phy`` is bound, and none is on a Pi. The ioctl must therefore be
  treated as advisory (see :meth:`RawGadget.vbus_draw`).
* **Bus resets arrive as ``DISCONNECT``.** dwc2 does not report
  ``USB_RAW_EVENT_RESET``; it reports ``USB_RAW_EVENT_DISCONNECT`` instead
  (documented in the Raw Gadget hardware notes). Callers must treat both as
  "the link restarted": disable every endpoint, keep fetching events, and
  re-enable on the next ``SET_CONFIGURATION``. :data:`RESET_EVENTS` and
  :func:`is_link_gone` exist for that.

The ep0 direction rule
----------------------
Raw Gadget decides the direction of every control request's *next* ep0
operation when the SETUP arrives (``gadget_setup`` in
``drivers/usb/gadget/legacy/raw_gadget.c``)::

    if ((ctrl->bRequestType & USB_DIR_IN) && ctrl->wLength)
            dev->ep0_in_pending = true;
    else
            dev->ep0_out_pending = true;

So a request is answered with ``EP0_WRITE`` **only** if it is device-to-host
*and* has a data stage. Everything else -- every host-to-device request, and in
particular every request with ``wLength == 0`` (SET_CONFIGURATION,
SET_INTERFACE, CLEAR/SET_FEATURE, AOA START_ACCESSORY, Apple's 0x51 role
swap) -- is acknowledged with ``EP0_READ`` of length 0. For ``wLength == 0``
the kernel also returns ``USB_GADGET_DELAYED_STATUS``, so the UDC holds the
status stage (NAKs it) until that read is queued.

A call in the wrong direction is rejected by ``raw_process_ep0_io`` as "wrong
direction" with **-EBUSY**, and nothing is queued on ep0. The host then polls
the status stage and is NAKed for as long as it keeps trying: on the goggles
that is a SET_CONFIGURATION that never completes, and the AOA probe never
comes. EBUSY is also what endpoint I/O returns while an endpoint is being
disabled, so on ep0 it must not be mistaken for a bus reset.
:meth:`RawGadget.ep0_ack` and the direction-aware :meth:`RawGadget.ep0_reply`
encode the rule, and :func:`is_link_gone` does not count EBUSY as a reset for
ep0 operations.

Releasing the UDC between sessions
----------------------------------
A raw-gadget instance stays bound to the UDC until ``raw_release`` runs, and
that happens only when the *last* reference to the file goes away. A thread
blocked in ``USB_RAW_IOCTL_EVENT_FETCH`` holds such a reference for as long as
it is blocked, so ``os.close(fd)`` from another thread does **not** unbind the
gadget: the fd number disappears but the kernel file, the bound driver and the
D+ pull-up all stay. The event fetch sleeps in ``down_interruptible`` and wakes
only for a new event or a signal, and a goggles that has just been sent
START_ACCESSORY sends neither.

The next session's ``USB_RAW_IOCTL_RUN`` then finds the UDC still bound and
fails with EBUSY. On kernels >= 6.0 this is the "couldn't find an available
UDC or it's busy" path of ``usb_gadget_register_driver_owner``, because
raw-gadget sets ``match_existing_only``.

:func:`stop_ep0_thread` therefore wakes the thread before the fd is closed. It
first calls :meth:`RawGadget.soft_disconnect`, which writes ``disconnect`` to
the UDC's ``soft_connect`` attribute. That drops the pull-up, so the goggles
sees the unplug a real phone does, and makes udc-core call raw-gadget's
``disconnect`` callback. The callback queues a DISCONNECT event and the fetch
returns. If the thread is still blocked after that, it is sent
:data:`INTERRUPT_SIGNAL`, and the fetch returns EINTR (raw-gadget handles that
explicitly). :func:`wait_udc_released` then confirms, via the UDC's
``function`` attribute, that the driver really has let go.

All ioctls go through ctypes (the GIL)
--------------------------------------
``fcntl.ioctl`` copies a mutable buffer of up to 1024 bytes and releases the
GIL around the call. A *larger* buffer is passed to the kernel in place, and
then CPython keeps the GIL for the whole call (``Modules/fcntlmodule.c`` in
3.11 to 3.13, "think array.resize()"). A bulk read is such a buffer, so while
the stream thread is blocked waiting for video, no other Python thread would
run. That includes the ep0 thread, which then could not answer a control
request or handle a reset. :func:`_ioctl` calls libc's ``ioctl`` through ctypes, which
always releases the GIL and never retries on EINTR.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import errno
import os
import re
import signal
import struct
import threading
import time

DEVICE = "/dev/raw-gadget"
SYS_UDC = "/sys/class/udc"

# Where Raspberry Pi OS keeps config.txt. The first path is correct on
# Bookworm and later, the second on older images.
CONFIG_TXT_PATHS = ("/boot/firmware/config.txt", "/boot/config.txt")

# The kernel caps one EP_READ / EP_WRITE at KMALLOC_MAX_SIZE, which is far
# above anything we ask for. dwc2 then splits the request internally at
# ~1023 * wMaxPacketSize (523776 bytes for a 512-byte bulk endpoint), so the
# 256 KiB default read of pryer.tunnel is a single request as far as we are
# concerned and needs no chunking here.
DWC2_MAX_TRANSFER = 1023 * 512

UDC_NAME_LENGTH_MAX = 128
USB_RAW_EP_NAME_MAX = 16
USB_RAW_MAX_ENDPOINTS = 32

# ---- ioctl encoding ------------------------------------------------------- #
_IOC_NRBITS, _IOC_TYPEBITS, _IOC_SIZEBITS = 8, 8, 14
_IOC_NRSHIFT = 0
_IOC_TYPESHIFT = _IOC_NRSHIFT + _IOC_NRBITS
_IOC_SIZESHIFT = _IOC_TYPESHIFT + _IOC_TYPEBITS
_IOC_DIRSHIFT = _IOC_SIZESHIFT + _IOC_SIZEBITS
_IOC_NONE, _IOC_WRITE, _IOC_READ = 0, 1, 2


def _ioc(direction: int, typ: int, nr: int, size: int) -> int:
    return ((direction << _IOC_DIRSHIFT) | (typ << _IOC_TYPESHIFT)
            | (nr << _IOC_NRSHIFT) | (size << _IOC_SIZESHIFT))


_U = ord("U")

# sizeof() of the structs the header uses in its ioctl definitions
_SZ_INIT = UDC_NAME_LENGTH_MAX * 2 + 1        # struct usb_raw_init
_SZ_EVENT = 8                                 # struct usb_raw_event
_SZ_EP_IO = 8                                 # struct usb_raw_ep_io
_SZ_EP_DESC = 9                               # struct usb_endpoint_descriptor
_SZ_U32 = 4
_SZ_EPS_INFO = USB_RAW_MAX_ENDPOINTS * 32     # struct usb_raw_eps_info

IOCTL_INIT = _ioc(_IOC_WRITE, _U, 0, _SZ_INIT)
IOCTL_RUN = _ioc(_IOC_NONE, _U, 1, 0)
IOCTL_EVENT_FETCH = _ioc(_IOC_READ, _U, 2, _SZ_EVENT)
IOCTL_EP0_WRITE = _ioc(_IOC_WRITE, _U, 3, _SZ_EP_IO)
IOCTL_EP0_READ = _ioc(_IOC_WRITE | _IOC_READ, _U, 4, _SZ_EP_IO)
IOCTL_EP_ENABLE = _ioc(_IOC_WRITE, _U, 5, _SZ_EP_DESC)
IOCTL_EP_DISABLE = _ioc(_IOC_WRITE, _U, 6, _SZ_U32)
IOCTL_EP_WRITE = _ioc(_IOC_WRITE, _U, 7, _SZ_EP_IO)
IOCTL_EP_READ = _ioc(_IOC_WRITE | _IOC_READ, _U, 8, _SZ_EP_IO)
IOCTL_CONFIGURE = _ioc(_IOC_NONE, _U, 9, 0)
IOCTL_VBUS_DRAW = _ioc(_IOC_WRITE, _U, 10, _SZ_U32)
IOCTL_EPS_INFO = _ioc(_IOC_READ, _U, 11, _SZ_EPS_INFO)
IOCTL_EP0_STALL = _ioc(_IOC_NONE, _U, 12, 0)
IOCTL_EP_SET_HALT = _ioc(_IOC_WRITE, _U, 13, _SZ_U32)
IOCTL_EP_CLEAR_HALT = _ioc(_IOC_WRITE, _U, 14, _SZ_U32)
IOCTL_EP_SET_WEDGE = _ioc(_IOC_WRITE, _U, 15, _SZ_U32)

# ---- the ioctl call itself ------------------------------------------------ #
def _load_libc():
    try:
        lib = ctypes.CDLL(ctypes.util.find_library("c") or None, use_errno=True)
        fn = lib.ioctl
    except (OSError, AttributeError):
        return None
    fn.restype = ctypes.c_int
    return lib


_libc = _load_libc()


def _ioctl(fd: int, request: int, arg=None) -> int:
    """
    ``ioctl(fd, request, arg)`` through ctypes, with the GIL released.

    Do not use ``fcntl.ioctl`` here. It keeps the GIL for the whole call when
    the buffer is larger than 1024 bytes, which is true of every bulk read (see
    the module notes). *arg* is None or a ctypes object, which is passed by
    pointer. Raises OSError with the kernel's errno. EINTR is not retried,
    because :func:`stop_ep0_thread` relies on seeing it.
    """
    if _libc is None:
        raise OSError(errno.ENOSYS, "libc ioctl() is not available")
    c_arg = ctypes.c_void_p(0) if arg is None else ctypes.byref(arg)
    ret = _libc.ioctl(ctypes.c_int(fd), ctypes.c_ulong(request), c_arg)
    if ret < 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    return ret


# ---- enums ---------------------------------------------------------------- #
EVENT_INVALID = 0
EVENT_CONNECT = 1
EVENT_CONTROL = 2
EVENT_SUSPEND = 3
EVENT_RESUME = 4
EVENT_RESET = 5
EVENT_DISCONNECT = 6

EVENT_NAMES = {
    EVENT_INVALID: "INVALID", EVENT_CONNECT: "CONNECT",
    EVENT_CONTROL: "CONTROL", EVENT_SUSPEND: "SUSPEND",
    EVENT_RESUME: "RESUME", EVENT_RESET: "RESET",
    EVENT_DISCONNECT: "DISCONNECT",
}

SPEED_UNKNOWN, SPEED_LOW, SPEED_FULL, SPEED_HIGH = 0, 1, 2, 3
SPEED_WIRELESS, SPEED_SUPER, SPEED_SUPER_PLUS = 4, 5, 6

# dwc2 reports a bus reset as DISCONNECT rather than RESET, so both have to be
# handled by the same "tear the endpoints down and wait for the next
# SET_CONFIGURATION" path.
RESET_EVENTS = (EVENT_RESET, EVENT_DISCONNECT)

# Errnos that mean "this endpoint or this gadget went away underneath us",
# rather than "the call was wrong". ESHUTDOWN is what raw-gadget returns for
# I/O on an endpoint the UDC has just disabled, which on dwc2 happens on every
# bus reset; EBUSY is returned while an endpoint is being disabled or is not
# enabled yet.
LINK_GONE_ERRNOS = frozenset((errno.ESHUTDOWN, errno.EBUSY, errno.ENODEV,
                              errno.ECONNRESET, errno.EPIPE))


def is_link_gone(exc: BaseException, *, ep0: bool = False) -> bool:
    """
    True if *exc* means the USB link restarted rather than a real fault.

    Pass ``ep0=True`` when *exc* came from answering a control request
    (``EP0_READ`` / ``EP0_WRITE`` / ``EP0_STALL``). On ep0, raw-gadget uses
    EBUSY for caller errors -- wrong direction for the pending request, a
    transfer already queued, no request pending -- not for a reset (a reset
    mid-transfer completes the request with ESHUTDOWN/ECONNRESET instead).
    Treating that EBUSY as a reset would hide a status-stage bug behind a
    debug-level "link reset" line, so it is a hard error here.
    """
    if not isinstance(exc, OSError):
        return False
    if ep0 and exc.errno == errno.EBUSY:
        return False
    return exc.errno in LINK_GONE_ERRNOS


def ep0_is_in(req: "CtrlRequest") -> bool:
    """
    True if raw-gadget expects EP0_WRITE for *req*, False if it expects
    EP0_READ.

    This is the kernel's rule verbatim: IN direction *and* a data stage. An IN
    request with ``wLength == 0`` is acknowledged with a zero-length read, like
    every OUT request.
    """
    return bool(req.bRequestType & 0x80) and req.wLength > 0


class CtrlRequest(ctypes.LittleEndianStructure):
    """struct usb_ctrlrequest (8 bytes, packed)"""
    # _layout_ only states explicitly what _pack_ implies; it silences the
    # DeprecationWarning of Python >= 3.14 and is ignored by older versions.
    _layout_ = "ms"
    _pack_ = 1
    _fields_ = [
        ("bRequestType", ctypes.c_uint8),
        ("bRequest", ctypes.c_uint8),
        ("wValue", ctypes.c_uint16),
        ("wIndex", ctypes.c_uint16),
        ("wLength", ctypes.c_uint16),
    ]

    @property
    def is_in(self) -> bool:
        return bool(self.bRequestType & 0x80)

    @property
    def req_type(self) -> int:
        """0 = standard, 1 = class, 2 = vendor."""
        return (self.bRequestType >> 5) & 3

    def __repr__(self) -> str:
        return ("ctrl(bmRequestType=0x%02x bRequest=%d wValue=0x%04x "
                "wIndex=0x%04x wLength=%d)" % (
                    self.bRequestType, self.bRequest, self.wValue,
                    self.wIndex, self.wLength))


class RawGadgetError(OSError):
    pass


class RawGadget:
    """One open handle on /dev/raw-gadget = one virtual USB device session."""

    def __init__(self, driver: str | None = None, device: str | None = None,
                 speed: int = SPEED_HIGH, path: str = DEVICE):
        """
        *device* is the UDC device name (a directory in /sys/class/udc) and
        *driver* is the UDC driver name (``gadget->name``). Leave either as
        None to have it discovered from sysfs, which is the only way to get
        both right across boards: on a Pi 4B they are *both* ``fe980000.usb``,
        on a Pi Zero both ``20980000.usb``, under Dummy HCD ``dummy_udc.0``
        and ``dummy_udc``. Passing the literal ``"dwc2"`` never works.
        """
        self.device = device or pick_udc()
        self.driver = driver or udc_driver_name(self.device)
        self.speed = speed
        self.fd = os.open(path, os.O_RDWR)
        try:
            self._init()
        except OSError as exc:
            os.close(self.fd)
            self.fd = -1
            raise _explain_init_failure(exc, self.driver, self.device) from exc

    # -- lifecycle -------------------------------------------------------- #
    def _init(self) -> None:
        buf = ctypes.create_string_buffer(_SZ_INIT)
        d = self.driver.encode()
        n = self.device.encode()
        if len(d) >= UDC_NAME_LENGTH_MAX or len(n) >= UDC_NAME_LENGTH_MAX:
            raise ValueError("UDC name too long")
        ctypes.memmove(buf, d, len(d))
        ctypes.memmove(ctypes.byref(buf, UDC_NAME_LENGTH_MAX), n, len(n))
        buf[UDC_NAME_LENGTH_MAX * 2] = bytes((self.speed,))
        _ioctl(self.fd, IOCTL_INIT, buf)

    def run(self) -> None:
        """Attach to the bus; the host will now see us and start enumeration."""
        try:
            _ioctl(self.fd, IOCTL_RUN)
        except OSError as exc:
            raise _explain_run_failure(exc, self.driver, self.device) from exc

    def close(self) -> None:
        """
        Close the fd.

        This unbinds the gadget from the UDC only if no other thread is still
        inside an ioctl on the fd. Stop the ep0 thread with
        :func:`stop_ep0_thread` first, then call this, then
        :func:`wait_udc_released`.
        """
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def soft_disconnect(self) -> bool:
        """
        Drop the D+ pull-up and wake a blocked EVENT_FETCH.

        This writes ``disconnect`` to ``/sys/class/udc/<udc>/soft_connect``.
        udc-core then turns the pull-up off, so the host sees the device
        unplugged, and calls the bound driver's ``disconnect`` callback.
        raw-gadget's callback queues ``USB_RAW_EVENT_DISCONNECT``, and that
        returns any EVENT_FETCH sleeping on this fd. The gadget stays
        registered until the fd is released. Returns True if the kernel
        accepted the write.
        """
        return udc_soft_disconnect(self.device)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # -- events ----------------------------------------------------------- #
    def event_fetch(self, max_data: int = 64) -> tuple[int, bytes]:
        """Block until the next gadget event. Returns (type, data)."""
        buf = ctypes.create_string_buffer(_SZ_EVENT + max_data)
        ctypes.memmove(ctypes.byref(buf, 4), (max_data).to_bytes(4, "little"), 4)
        _ioctl(self.fd, IOCTL_EVENT_FETCH, buf)
        etype = int.from_bytes(buf.raw[0:4], "little")
        length = int.from_bytes(buf.raw[4:8], "little")
        return etype, buf.raw[8:8 + length]

    def control_event(self) -> tuple[int, CtrlRequest | None, bytes]:
        etype, data = self.event_fetch(ctypes.sizeof(CtrlRequest))
        if etype != EVENT_CONTROL:
            return etype, None, data
        req = CtrlRequest.from_buffer_copy(data.ljust(8, b"\x00"))
        return etype, req, data

    # -- endpoint 0 ------------------------------------------------------- #
    def _ep_io(self, ioctl: int, ep: int, data: bytes | None,
               length: int) -> bytes:
        # Reads reuse one buffer per (ioctl, endpoint) and copy out only the
        # n bytes received. Allocating, zero-filling and copying a fresh
        # buffer of the full request size on every read costs far more than
        # the read itself on a Pi 4 (see pryer.tunnel.ACCESSORY_READ_SIZE). An endpoint is only ever read by
        # one thread at a time (raw-gadget refuses a second queued request
        # with EBUSY), so sharing the buffer per endpoint is safe.
        size = length if data is None else len(data)
        need = _SZ_EP_IO + max(size, 1)
        if data is None:
            cache = self.__dict__.setdefault("_read_bufs", {})
            buf = cache.get((ioctl, ep))
            if buf is None or ctypes.sizeof(buf) < need:
                buf = ctypes.create_string_buffer(need)
                cache[(ioctl, ep)] = buf
        else:
            buf = ctypes.create_string_buffer(need)
        struct.pack_into("<HHI", buf, 0, ep, 0, size)     # ep, flags, length
        if data:
            ctypes.memmove(ctypes.byref(buf, 8), data, len(data))
        n = _ioctl(self.fd, ioctl, buf)
        if ioctl in (IOCTL_EP0_READ, IOCTL_EP_READ):
            return ctypes.string_at(ctypes.addressof(buf) + 8, max(n, 0))
        return b""

    def ep0_write(self, data: bytes = b"") -> None:
        """
        Data stage of a device-to-host request that has ``wLength > 0``.

        Never use this to acknowledge a request without a data stage: raw-gadget
        rejects that with EBUSY ("wrong direction") and the host is left NAKed
        in the status stage. Use :meth:`ep0_ack` or :meth:`ep0_reply`.
        """
        self._ep_io(IOCTL_EP0_WRITE, 0, data, len(data))

    def ep0_read(self, length: int) -> bytes:
        """
        Data stage of a host-to-device request, or -- with ``length=0`` -- the
        status-stage acknowledgement of any request that has no data stage.
        """
        return self._ep_io(IOCTL_EP0_READ, 0, None, length)

    def ep0_ack(self) -> None:
        """
        Complete a control request that has no data stage.

        Raw Gadget marks every such request ``ep0_out_pending`` and returns
        ``USB_GADGET_DELAYED_STATUS`` to the UDC, which then NAKs the status
        stage until this zero-length ``EP0_READ`` is queued. This is the call
        SET_CONFIGURATION, SET_INTERFACE, CLEAR/SET_FEATURE, AOA
        START_ACCESSORY and Apple's role swap all need.
        """
        self._ep_io(IOCTL_EP0_READ, 0, None, 0)

    def ep0_stall(self) -> None:
        _ioctl(self.fd, IOCTL_EP0_STALL)

    def ep0_reply(self, req: CtrlRequest, data: bytes) -> None:
        """
        Answer a device-to-host request, truncating to wLength.

        An IN request with ``wLength == 0`` has no data stage, so raw-gadget
        expects a zero-length read for it rather than a write; that case is
        routed to :meth:`ep0_ack`.
        """
        if ep0_is_in(req):
            self.ep0_write(data[:req.wLength])
        else:
            self.ep0_ack()

    # -- non-zero endpoints ----------------------------------------------- #
    def ep_enable(self, descriptor: bytes) -> int:
        """Enable an endpoint from its 7-byte descriptor. Returns raw ep handle."""
        buf = ctypes.create_string_buffer(_SZ_EP_DESC)
        ctypes.memmove(buf, descriptor[:7], 7)
        return _ioctl(self.fd, IOCTL_EP_ENABLE, buf)

    def ep_disable(self, handle: int) -> None:
        _ioctl(self.fd, IOCTL_EP_DISABLE, ctypes.c_uint32(int(handle)))

    def ep_read(self, handle: int, length: int) -> bytes:
        return self._ep_io(IOCTL_EP_READ, handle, None, length)

    def ep_write(self, handle: int, data: bytes) -> None:
        self._ep_io(IOCTL_EP_WRITE, handle, data, len(data))

    def configure(self) -> None:
        _ioctl(self.fd, IOCTL_CONFIGURE)

    def vbus_draw(self, milliamps: int) -> bool:
        """
        Advisory: tell the UDC how much bus current we intend to draw.

        This is deliberately non-fatal. ``dwc2_hsotg_vbus_draw`` returns
        ``-ENOTSUPP`` whenever no ``usb_phy`` is bound to the controller, and
        none is on any Raspberry Pi, so on a Pi 4B this ioctl *always* fails.
        Called unguarded from the SET_CONFIGURATION handler, the resulting
        OSError would kill the endpoint-0 thread and the accessory handshake
        would time out with a misleading message. Nothing about
        the link depends on it -- the host reads bMaxPower out of our
        configuration descriptor -- so a failure is logged at debug level and
        ignored. Returns True if the UDC accepted it.
        """
        try:
            _ioctl(self.fd, IOCTL_VBUS_DRAW, ctypes.c_uint32(int(milliamps)))
        except OSError:
            return False
        return True

    def eps_info(self) -> list[dict]:
        buf = ctypes.create_string_buffer(_SZ_EPS_INFO)
        n = _ioctl(self.fd, IOCTL_EPS_INFO, buf)
        out = []
        for i in range(max(n, 0)):
            raw = buf.raw[i * 32:(i + 1) * 32]
            caps = int.from_bytes(raw[20:24], "little")
            out.append({
                "name": raw[:USB_RAW_EP_NAME_MAX].split(b"\x00")[0].decode(
                    errors="replace"),
                "addr": int.from_bytes(raw[16:20], "little"),
                "caps": caps,
                # struct usb_raw_ep_caps, in declaration order
                "control": bool(caps & 1),
                "iso": bool(caps & 2),
                "bulk": bool(caps & 4),
                "interrupt": bool(caps & 8),
                "dir_in": bool(caps & 16),
                "dir_out": bool(caps & 32),
                "maxpacket_limit": int.from_bytes(raw[24:26], "little"),
            })
        return out

    def bulk_endpoints_available(self) -> tuple[int, int]:
        """(IN, OUT) count of UDC endpoints that can carry a bulk pipe."""
        try:
            eps = self.eps_info()
        except OSError:
            return (0, 0)
        ins = sum(1 for e in eps if e["bulk"] and e["dir_in"])
        outs = sum(1 for e in eps if e["bulk"] and e["dir_out"])
        return (ins, outs)


# --------------------------------------------------------------------------- #
# UDC discovery
# --------------------------------------------------------------------------- #
def available() -> bool:
    return os.path.exists(DEVICE)


def list_udcs() -> list[str]:
    try:
        return sorted(os.listdir(SYS_UDC))
    except OSError:
        return []


def _sysfs(udc: str, attr: str) -> str:
    try:
        with open(os.path.join(SYS_UDC, udc, attr)) as fh:
            return fh.read().strip()
    except OSError:
        return ""


def udc_driver_name(udc: str) -> str:
    """
    The UDC *driver* name raw-gadget's INIT ioctl wants for this UDC.

    udc-core publishes it in the UDC's uevent as ``USB_UDC_NAME``, taken
    straight from ``gadget->name`` -- the very string ``gadget_bind`` compares
    against. Reading it here is exact, so nothing has to know that a Pi 4B
    calls its controller ``fe980000.usb`` while Dummy HCD calls its
    ``dummy_udc``. If the uevent is unreadable, fall back to the device name,
    which is what dwc2 (and dwc3, and most platform UDCs) use anyway.
    """
    for line in _sysfs(udc, "uevent").splitlines():
        if line.startswith("USB_UDC_NAME="):
            return line.split("=", 1)[1].strip()
    return udc


def udc_state(udc: str) -> str:
    """'not attached', 'addressed', 'configured', ... as the UDC sees it."""
    return _sysfs(udc, "state") or "unknown"


def udc_soft_disconnect(udc: str) -> bool:
    """Write ``disconnect`` to the UDC's ``soft_connect`` attribute."""
    path = os.path.join(SYS_UDC, udc, "soft_connect")
    try:
        with open(path, "w") as fh:
            fh.write("disconnect")
    except OSError:
        return False
    return True


# How long to wait for the kernel to unbind a closed raw-gadget session from
# the UDC before reporting it. raw_release unbinds synchronously once the last
# file reference is gone, so in practice this takes well under 10 ms.
UDC_RELEASE_TIMEOUT = 2.0


def wait_udc_released(udc: str, timeout: float = UDC_RELEASE_TIMEOUT,
                      poll: float = 0.01) -> bool:
    """
    Wait until no gadget driver is bound to *udc*.

    ``/sys/class/udc/<udc>/function`` holds the bound driver's function
    string, ``USB Raw Gadget`` for raw-gadget, and is empty once the UDC is
    free. Returns True if it became empty within *timeout*. If the attribute
    cannot be read (no such UDC, or the tests' fake names), the result is True,
    because there is nothing to wait for.
    """
    deadline = time.monotonic() + timeout
    while udc_function(udc):
        if time.monotonic() >= deadline:
            return False
        time.sleep(poll)
    return True


def udc_function(udc: str) -> str:
    """
    Name of the gadget driver currently bound to this UDC, if any.

    A non-empty value other than ours means something else owns the
    controller -- typically ``g_ether``/``g_serial`` left over from an old
    ``modules-load.d`` entry, or a ``libcomposite`` gadget assembled in
    configfs, or ``USB Raw Gadget`` when another raw-gadget session (possibly
    our own previous one) still holds it. raw-gadget's RUN then fails with
    EBUSY, so it is worth reporting by name rather than as an errno.
    """
    return _sysfs(udc, "function")


def pick_udc(preferred: str | None = None) -> str:
    """Choose a UDC device name, preferring a dwc2 one if several exist."""
    udcs = list_udcs()
    if preferred:
        if preferred not in udcs:
            raise RuntimeError(
                "UDC %r is not in %s (found: %s)"
                % (preferred, SYS_UDC, ", ".join(udcs) or "none"))
        return preferred
    if not udcs:
        raise RuntimeError("no UDC found; " + " ".join(diagnose()))
    # A Pi 4B has exactly one, but a board with both dwc2 and dwc3 would list
    # two; the dwc2 one is the port the goggles plugs into.
    for udc in udcs:
        if _sysfs(udc, "uevent").find("dwc2") >= 0 or "980000.usb" in udc:
            return udc
    return udcs[0]


# --------------------------------------------------------------------------- #
# Board / boot-configuration inspection (Raspberry Pi)
# --------------------------------------------------------------------------- #
def board_model() -> str:
    """The device-tree model string, e.g. 'Raspberry Pi 4 Model B Rev 1.4'."""
    for path in ("/proc/device-tree/model", "/sys/firmware/devicetree/base/model"):
        try:
            with open(path, "rb") as fh:
                return fh.read().rstrip(b"\x00").decode(errors="replace")
        except OSError:
            continue
    return ""


def is_pi4() -> bool:
    model = board_model()
    return "Raspberry Pi 4" in model or "Compute Module 4" in model


def config_txt_path() -> str | None:
    for path in CONFIG_TXT_PATHS:
        if os.path.isfile(path):
            return path
    return None


def _config_txt_lines() -> list[str]:
    path = config_txt_path()
    if path is None:
        return []
    try:
        with open(path, errors="replace") as fh:
            return [ln.strip() for ln in fh
                    if ln.strip() and not ln.strip().startswith("#")]
    except OSError:
        return []


# `dtoverlay=dwc2[,params]`
_DWC2_OVERLAY = re.compile(r"^dtoverlay\s*=\s*(dwc2)(?=[,\s]|$)(.*)$")
_OTG_MODE = re.compile(r"^otg_mode\s*=\s*(\S+)")


def boot_config() -> dict:
    """
    What config.txt says about the dwc2 controller.

    Returns ``{"path", "dwc2": bool, "dr_mode": str|None,
    "otg_mode": str|None, "params": dict}``. ``dr_mode`` is None when the
    overlay is present without the parameter, which the overlay resolves to
    ``otg``.
    """
    out: dict = {"path": config_txt_path(), "dwc2": False, "dr_mode": None,
                 "otg_mode": None, "params": {}}
    for line in _config_txt_lines():
        m = _OTG_MODE.match(line)
        if m:
            out["otg_mode"] = m.group(1)
            continue
        m = _DWC2_OVERLAY.match(line)
        if m:
            out["dwc2"] = True
            for part in m.group(2).split(","):
                part = part.strip()
                if not part:
                    continue
                key, _, value = part.partition("=")
                out["params"][key.strip()] = value.strip()
            out["dr_mode"] = out["params"].get("dr_mode") or out["dr_mode"]
    return out


def boot_config_problems() -> list[str]:
    """
    Pi-specific config.txt mistakes that stop the USB-C port being a gadget.

    All three of these produce the same symptom -- an empty
    ``/sys/class/udc`` -- so they are worth separating out by name.
    """
    cfg = boot_config()
    if cfg["path"] is None:
        return []
    problems = []
    if cfg["otg_mode"] not in (None, "0"):
        problems.append(
            "%s sets `otg_mode=%s`. On a Pi 4B that routes the USB-C port to "
            "the host-only XHCI controller and it wins over "
            "`dtoverlay=dwc2`, so no UDC is created. Comment it out."
            % (cfg["path"], cfg["otg_mode"]))
    if not cfg["dwc2"]:
        problems.append(
            "%s has no `dtoverlay=dwc2` line. Add "
            "`dtoverlay=dwc2,dr_mode=peripheral` under `[all]` and reboot."
            % cfg["path"])
    elif cfg["dr_mode"] == "host":
        problems.append(
            "%s sets `dtoverlay=dwc2,dr_mode=host`, which makes the USB-C "
            "port a host port and creates no UDC. Use `dr_mode=peripheral` "
            "for the AOA transport or `dr_mode=otg` for the iOS transport."
            % cfg["path"])
    return problems


def diagnose() -> list[str]:
    """Human-readable list of reasons raw-gadget will not work here."""
    problems = []
    if not os.path.exists(DEVICE):
        problems.append(
            "%s is missing -- run `sudo modprobe raw_gadget` (needs "
            "CONFIG_USB_RAW_GADGET, Linux >= 5.7)." % DEVICE)
    elif not os.access(DEVICE, os.R_OK | os.W_OK):
        problems.append("%s is not readable/writable -- run as root." % DEVICE)

    udcs = list_udcs()
    if not udcs:
        detail = boot_config_problems()
        problems.append(
            "No USB Device Controller in %s, so this machine cannot act as a "
            "USB gadget yet.%s" % (SYS_UDC,
                                   "" if detail else
                                   " On a Raspberry Pi 4B add "
                                   "`dtoverlay=dwc2,dr_mode=peripheral` to "
                                   "/boot/firmware/config.txt, make sure "
                                   "`otg_mode=1` is not set, and reboot."))
        problems += detail
    else:
        for udc in udcs:
            fn = udc_function(udc)
            if fn == RAW_GADGET_FUNCTION:
                problems.append(
                    "UDC %s is already held by another raw-gadget session. "
                    "Another process (possibly an earlier run of this program "
                    "that is still exiting) has /dev/raw-gadget open; find it "
                    "with `sudo fuser -v /dev/raw-gadget`." % udc)
            elif fn:
                problems.append(
                    "UDC %s is already claimed by the gadget driver %r; "
                    "raw-gadget cannot bind to it. Unload that driver "
                    "(`sudo modprobe -r %s`) or remove the configfs gadget "
                    "first." % (udc, fn, fn.split(".")[0]))
    return problems


# --------------------------------------------------------------------------- #
# Error translation
# --------------------------------------------------------------------------- #
def _explain_init_failure(exc: OSError, driver: str, device: str) -> OSError:
    """Turn an INIT errno into something a user can act on."""
    if exc.errno == errno.EBUSY:
        fn = udc_function(device) or "another gadget driver"
        return RawGadgetError(
            exc.errno,
            "USB_RAW_IOCTL_INIT: UDC %s is busy -- %s already owns it. "
            "Unload it, or remove the configfs gadget, and try again."
            % (device, fn))
    if exc.errno == errno.EINVAL:
        return RawGadgetError(
            exc.errno,
            "USB_RAW_IOCTL_INIT rejected driver=%r device=%r. Check the UDC "
            "exists in %s; on a Raspberry Pi 4B both names are "
            "'fe980000.usb'." % (driver, device, SYS_UDC))
    return exc


RAW_GADGET_FUNCTION = "USB Raw Gadget"     # DRIVER_DESC in raw_gadget.c


def _explain_run_failure(exc: OSError, driver: str, device: str) -> OSError:
    """
    Turn a RUN errno into something a user can act on.

    Since Linux 6.0 RUN reports two different failures as EBUSY: the UDC is
    already bound to another gadget driver, *or* no UDC accepted the bind (for
    example a wrong driver name). Blaming the name is wrong when the names are
    right and the UDC is still held by this program's own phase-1 session. The
    UDC's ``function`` attribute tells the two apart.
    """
    owner = udc_function(device) if exc.errno == errno.EBUSY else ""
    if owner:
        if owner == RAW_GADGET_FUNCTION:
            detail = (
                "a previous raw-gadget session still holds it. The usual cause "
                "is a raw-gadget fd that was closed while another thread was "
                "blocked in an ioctl on it (the kernel only releases the UDC "
                "when that ioctl returns). Otherwise another process has "
                "/dev/raw-gadget "
                "open: check `sudo fuser -v /dev/raw-gadget`")
        else:
            detail = ("it is claimed by the gadget driver %r. Unload it "
                      "(`sudo modprobe -r %s`) or remove the configfs gadget"
                      % (owner, owner.split(".")[0].split()[0]))
        return RawGadgetError(
            exc.errno,
            "USB_RAW_IOCTL_RUN: UDC %s is still bound to %r, so %s."
            % (device, owner, detail))
    if exc.errno in (errno.ENODEV, errno.EBUSY):
        return RawGadgetError(
            exc.errno,
            "USB_RAW_IOCTL_RUN could not bind to UDC %s with driver name %r. "
            "That name must equal the kernel's gadget->name, which is what "
            "%s/%s/uevent reports as USB_UDC_NAME (%r on this machine). "
            "Passing a literal 'dwc2' here is the classic Raspberry Pi 4B "
            "mistake. (The UDC reported no bound driver when this was checked; "
            "if a previous session was still letting go, simply retry.)"
            % (device, driver, SYS_UDC, device, udc_driver_name(device)))
    return exc


# --------------------------------------------------------------------------- #
# Stopping an ep0 thread so that the UDC is actually released
# --------------------------------------------------------------------------- #
# Sent to an ep0 thread that is still blocked in an ioctl after the soft
# disconnect. A Python-level handler must be installed or the default action
# would terminate the process; install_interrupt_handler() does that, and it
# can only run in the main thread.
INTERRUPT_SIGNAL = signal.SIGUSR1
_interrupt_ready = False


def _on_interrupt_signal(signum, frame) -> None:
    """No-op: the signal exists only to make a blocked ioctl return EINTR."""


def install_interrupt_handler() -> bool:
    """
    Make :data:`INTERRUPT_SIGNAL` safe to send to our own threads.

    Call from the main thread before starting a session. CPython installs its
    handlers without ``SA_RESTART``, so the signal makes a blocked
    EVENT_FETCH / EP0_* / EP_* ioctl return EINTR. An existing handler is kept
    as long as it is a real handler. Returns True if the signal can be used.
    """
    global _interrupt_ready
    if _interrupt_ready:
        return True
    try:
        current = signal.getsignal(INTERRUPT_SIGNAL)
    except (ValueError, OSError):
        return False
    if callable(current):
        _interrupt_ready = True
        return True
    if threading.current_thread() is not threading.main_thread():
        return False
    try:
        signal.signal(INTERRUPT_SIGNAL, _on_interrupt_signal)
    except (ValueError, OSError):
        return False
    _interrupt_ready = True
    return True


# How long stop_ep0_thread waits in total. With the soft disconnect the thread
# normally leaves EVENT_FETCH within a millisecond or two.
EP0_STOP_TIMEOUT = 1.0


def stop_ep0_thread(gadget, thread: threading.Thread | None,
                    timeout: float = EP0_STOP_TIMEOUT,
                    log=None) -> bool:
    """
    Wake an ep0 thread blocked in raw-gadget and wait for it to exit.

    The caller must already have set the thread's stop flag, and must close
    the fd only *after* this returns (see the module notes: closing first does
    not release the UDC). Steps, each only if the thread is still alive:

    1. ``gadget.soft_disconnect()``: pull-up off, DISCONNECT event queued.
    2. :data:`INTERRUPT_SIGNAL` to the thread every 50 ms: the ioctl returns
       EINTR.

    Returns True if the thread has exited (or there was none).
    """
    if thread is None or thread is threading.current_thread():
        return True
    if not thread.is_alive():
        return True
    deadline = time.monotonic() + timeout
    soft = getattr(gadget, "soft_disconnect", None)
    if soft is not None:
        ok = soft()
        if log is not None:
            log.debug("soft disconnect %s", "requested" if ok else
                      "not available; falling back to a signal")
        thread.join(min(0.2, timeout))
    while thread.is_alive() and time.monotonic() < deadline:
        if _interrupt_ready and thread.ident is not None:
            try:
                signal.pthread_kill(thread.ident, INTERRUPT_SIGNAL)
            except (OSError, ProcessLookupError):
                pass
        thread.join(0.05)
    return not thread.is_alive()
