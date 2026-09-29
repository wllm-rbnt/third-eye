"""
The iOS / MFi transport: talk to the DJI Goggles 3 the way an iPhone does.

Why this path looks nothing like the Android one
------------------------------------------------

On the Android path the goggles stays the USB **host** for the whole session
and we have to be a USB gadget.  On the iOS path the goggles does that only
long enough to recognise an Apple device, and then hands the bus over::

    goggles (host) enumerates 05ac:12a8 "Apple Inc." / "iPhone"
    goggles selects configuration 1 (the PTP one)
    goggles -> phone   bmRequestType 0x40, bRequest 0x51, no data
        ... USB roles swap ...
    phone (host) enumerates 2ca3:1002 "Dajiang Innovation" / "DJI_GOGGLES"
        interface 0        ff/f0/00  "iAP Interface"   EP 0x81 IN, 0x01 OUT
        interface 1 alt 0  ff/f0/01  "com.dji.logiclink"  (no endpoints)
        interface 1 alt 1  ff/f0/01  EP 0x82 IN, 0x02 OUT
    phone runs iAP2 on interface 0, authenticates the goggles, identifies it
    phone SET_INTERFACE(interface 1, alt 1)
    the DJI tunnel starts flowing on EP 0x82 / 0x02

So for most of the session Linux wants to be the **host**, which is the easy
role -- plain libusb, no raw-gadget, no kernel patches.  Two facts make that
work in our favour:

1. We are the *verifier* in the MFi exchange.  The goggles owns the
   authentication coprocessor; it sends us a certificate and signs our
   challenge.  We only have to send 32 random bytes and say "yes".  No Apple
   secrets are needed anywhere on the Linux side.
2. The External Accessory protocol is declared with a
   ``NativeTransportComponentIdentifier`` parameter, which means
   ``com.dji.logiclink`` is *not* multiplexed into an iAP2 session -- it gets
   its own bulk pipe.  Nothing on the wire ever opens an
   ExternalAccessoryProtocolSession.  The tunnel bytes on EP 0x82 are the same
   ``55 CC`` framing as the Android path, so the existing demuxer, DUML codec
   and H.264 assembler are reused unchanged.

The one genuinely awkward step is getting the goggles *into* MFi mode at all.
It only presents 2ca3:1002 after it has enumerated an Apple device and issued
request 0x51; plugged into an ordinary PC it comes up in "PC mode" with a
different product id and eight interfaces instead of two.  So the full Linux
recipe needs a dual-role port: impersonate an iPhone as a gadget, accept
request 0x51, then flip our own port to host and pick the goggles up as a
device.  :func:`trigger_mfi_mode` does the first half and
:class:`IapHost` the second.
"""

from __future__ import annotations

import errno
import glob
import logging
import os
import re
import shutil
import subprocess
import threading
import time

from . import iap2, libusb, rawgadget, tunnel, usbdesc
from .rawgadget import CtrlRequest, RawGadget

log = logging.getLogger("pryer.mfi")

# --------------------------------------------------------------------------- #
# Identities and endpoints (PROTOCOL.md sections 3.2 and 3.5)
# --------------------------------------------------------------------------- #

DJI_VID = 0x2CA3
MFI_PID = 0x1002          # "MFI mode": 2 interfaces, iAP2 + com.dji.logiclink
PC_MODE_PID = 0x0020      # what you get when you plug into a plain PC

IAP_INTERFACE = 0
IAP_CLASS = (0xFF, 0xF0, 0x00)
EP_IAP_IN = 0x81
EP_IAP_OUT = 0x01

EA_INTERFACE = 1
EA_CLASS = (0xFF, 0xF0, 0x01)
EA_ALT_SETTING = 1
EP_EA_IN = 0x82
EP_EA_OUT = 0x02

BULK_MPS = 512
EA_PROTOCOL_NAME = "com.dji.logiclink"

# Size of one bulk IN transfer on the External Accessory pipe: one URB. See
# pryer.tunnel.DEFAULT_READ_SIZE and the pryer.libusb docstring for why reads
# must not be longer (PROTOCOL.md section 9.3).
DEFAULT_READ_SIZE = tunnel.DEFAULT_READ_SIZE

# Bulk IN transfers kept queued on EP 0x82 (`--transfers`). Every tunnel
# packet is a USB transfer of its own, and video comes in bursts of one
# access unit: 4,104-byte packets a median 0.19 ms apart,
# up to 45 of them for an IDR. A completed transfer is resubmitted by its
# callback, which needs the interpreter lock, and a busy main thread can hold
# that for up to Python's 5 ms switch interval. 32 transfers cover 6 ms of a
# burst, and they take 512 kiB. If they do run out, the endpoint is NAKed and
# the goggles holds its data until the next one is queued; nothing is lost.
# 0 means synchronous reads, one single-URB transfer at a time.
DEFAULT_TRANSFERS = 32

# The iAP2 link on EP 0x81 is serviced the same way, with fewer and smaller
# transfers: its packets are at most a few hundred bytes (1,067 bytes in 12
# packets in a typical session), and all of them come before the tunnel
# opens.
IAP_READ_SIZE = BULK_MPS * 8
IAP_TRANSFERS = 2

# Timeout for one synchronous bulk transfer, milliseconds.
#
# Do not lower this below roughly 250 ms. Video is bursty, so an idle gap of a
# full frame period is normal (measured p99 inter-packet gap 33-35 ms, maximum
# 73 ms), and the control channel can be quieter still. A
# short timeout turns ordinary idleness into a stream of spurious timeout
# errors. 1000 ms leaves ample headroom while still letting a genuinely dead
# link be noticed within a second.
DEFAULT_TIMEOUT_MS = 1000

# The Apple device identity the goggles expects to find.
IPHONE_VID = 0x05AC
IPHONE_PID = 0x12A8
APPLE_ROLE_SWAP = 0x51    # bmRequestType 0x40, wValue 0, wIndex 0, wLength 0

# The iPhone's USB identity, assembled from named fields. The result is
# byte-identical to what the iPhone presents (test_iap2.py checks it against
# the reference captures, when they are available). The goggles walks all
# four configurations before choosing configuration value 1, so all four are
# served.
#
# Configuration layout (bmAttributes 0xc0 self-powered, bMaxPower 250 = 500 mA
# in every one; iConfiguration 5..8):
#   value 1  PTP                          -- the one the goggles selects
#   value 2  USB audio (UAC 1.0) + HID
#   value 3  PTP + Apple vendor bulk pair ff/fe/02
#   value 4  PTP + ff/fe/02 + ff/fd/01 with three alternate settings
# The string indices (iConfiguration, iInterface) are the iOS build's own
# numbering and differ between sessions (see
# test_iphone_descriptors_vary_only_in_string_indices); the structure does not.
IPHONE_DEVICE_DESC = usbdesc.device_descriptor(
    IPHONE_VID, IPHONE_PID, bcd_device=0x1404, i_manufacturer=1, i_product=2,
    i_serial=3, num_configs=4)

_IPHONE_CFG_ATTRIBUTES = 0xC0
_IPHONE_CFG_MAX_POWER = 250          # 2 mA units: 500 mA
PTP_CLASS = (usbdesc.CLASS_STILL_IMAGE, 0x01, 0x01)
APPLE_VENDOR_CLASS = (usbdesc.CLASS_VENDOR, 0xFE, 0x02)
APPLE_VENDOR2_CLASS = (usbdesc.CLASS_VENDOR, 0xFD, 0x01)
AUDIO_SAMPLE_RATES = (8000, 11025, 12000, 16000, 22050, 24000, 32000, 44100,
                      48000)
HID_REPORT_LENGTH = 0xD0             # the report descriptor itself is never read


def _iphone_config(value: int, body: bytes, num_interfaces: int) -> bytes:
    return usbdesc.config_descriptor(body, num_interfaces, value=value,
                                     i_config=4 + value,
                                     attributes=_IPHONE_CFG_ATTRIBUTES,
                                     max_power=_IPHONE_CFG_MAX_POWER)


def _ptp_interface() -> bytes:
    """Still Image (PTP): bulk OUT 0x02, bulk IN 0x81, interrupt IN 0x83."""
    cls, sub, proto = PTP_CLASS
    return (usbdesc.interface_descriptor(0, 3, cls=cls, subcls=sub,
                                         proto=proto, i_interface=0x1B)
            + usbdesc.bulk_pair(0x02, 0x81)
            + usbdesc.endpoint_descriptor(0x83, 64, usbdesc.XFER_INTERRUPT,
                                          interval=10))


def _apple_vendor_interface() -> bytes:
    cls, sub, proto = APPLE_VENDOR_CLASS
    return (usbdesc.interface_descriptor(1, 2, cls=cls, subcls=sub,
                                         proto=proto, i_interface=0x14)
            + usbdesc.bulk_pair(0x04, 0x85))


def _apple_vendor2_interface() -> bytes:
    """ff/fd/01: alt 0 without endpoints, alts 1 and 2 with a bulk pair."""
    cls, sub, proto = APPLE_VENDOR2_CLASS
    out = usbdesc.interface_descriptor(2, 0, cls=cls, subcls=sub, proto=proto,
                                       i_interface=0x11)
    for alt in (1, 2):
        out += (usbdesc.interface_descriptor(2, 2, alt=alt, cls=cls,
                                             subcls=sub, proto=proto,
                                             i_interface=0x11)
                + usbdesc.bulk_pair(0x86, 0x05))
    return out


def _audio_hid_body() -> bytes:
    """UAC 1.0 microphone-style input (terminal 1 -> USB streaming 2) + HID."""
    terminals = (
        usbdesc.uac_input_terminal(1, usbdesc.UAC_TERMINAL_MICROPHONE,
                                   assoc_terminal=2, channels=2,
                                   channel_config=0x0003)
        + usbdesc.uac_output_terminal(2, usbdesc.UAC_TERMINAL_USB_STREAMING,
                                      assoc_terminal=1, source_id=1))
    header_len = 9                   # uac_header with one streaming interface
    control = (
        usbdesc.interface_descriptor(0, 0, cls=usbdesc.CLASS_AUDIO,
                                     subcls=usbdesc.AUDIO_SUBCLASS_CONTROL,
                                     proto=0)
        + usbdesc.uac_header([1], header_len + len(terminals))
        + terminals)
    streaming = (
        usbdesc.interface_descriptor(1, 0, cls=usbdesc.CLASS_AUDIO,
                                     subcls=usbdesc.AUDIO_SUBCLASS_STREAMING,
                                     proto=0)
        + usbdesc.interface_descriptor(1, 1, alt=1, cls=usbdesc.CLASS_AUDIO,
                                       subcls=usbdesc.AUDIO_SUBCLASS_STREAMING,
                                       proto=0)
        + usbdesc.uac_as_general(terminal_link=2, delay=1)
        + usbdesc.uac_format_type_i(channels=2, subframe_size=2,
                                    bit_resolution=16,
                                    sample_rates=AUDIO_SAMPLE_RATES)
        + usbdesc.uac_endpoint(0x81, 0x00C0, interval=4)
        + usbdesc.uac_cs_endpoint(attributes=0x01))
    hid = (usbdesc.interface_descriptor(2, 1, cls=usbdesc.CLASS_HID, subcls=0,
                                        proto=0)
           + usbdesc.hid_descriptor(HID_REPORT_LENGTH, bcd_hid=0x0111)
           + usbdesc.endpoint_descriptor(0x83, 64, usbdesc.XFER_INTERRUPT,
                                         interval=1))
    return control + streaming + hid


IPHONE_CONFIGS = [
    _iphone_config(1, _ptp_interface(), 1),
    _iphone_config(2, _audio_hid_body(), 3),
    _iphone_config(3, _ptp_interface() + _apple_vendor_interface(), 2),
    _iphone_config(4, _ptp_interface() + _apple_vendor_interface()
                   + _apple_vendor2_interface(), 3),
]
# Strings 1..3.  The manufacturer and product strings are exactly what the
# iPhone presents; the serial number is synthetic -- same shape, but there is no
# reason to bake a real handset's serial into this repository, and the goggles
# never checks it.
IPHONE_STRINGS = ["Apple Inc.", "iPhone", "424242424242424242424242"]
# The real iPhone stalled these two requests, so we do the same.
IPHONE_STALLED_STRINGS = (5, 27)


# --------------------------------------------------------------------------- #
# Phase 1 (optional): impersonate an iPhone so the goggles enters MFi mode
# --------------------------------------------------------------------------- #

class _IphoneSession:
    """
    A raw-gadget session that answers enumeration as an iPhone and waits for
    the Apple role-swap request.

    This is deliberately minimal: the goggles only reads descriptors, sets a
    configuration and then issues request 0x51.  It never moves bulk data
    before the swap, so no endpoint has to work.
    """

    def __init__(self, driver: str | None = None, udc: str | None = None,
                 gadget=None):
        # Both names default to None so RawGadget resolves them from sysfs; on
        # a Raspberry Pi 4B they are both 'fe980000.usb', never 'dwc2'.
        self.gadget = gadget if gadget is not None else RawGadget(
            driver, udc, rawgadget.SPEED_HIGH)
        self.stop = threading.Event()
        self.configured = threading.Event()
        self.role_swap_requested = threading.Event()
        self.role_swap_at: float | None = None      # time.monotonic()
        self.error: BaseException | None = None
        self.requests: list[CtrlRequest] = []
        self._thread: threading.Thread | None = None

    # ------------------------------------------------------------------ #
    def start(self) -> None:
        self.gadget.run()
        self._thread = threading.Thread(target=self._loop, name="ep0-iphone",
                                        daemon=True)
        self._thread.start()

    def close(self) -> bool:
        """
        End the session and release the UDC. Returns True once it is free.

        This follows the same order as ``accessory._Session.close`` and for the
        same reason. Closing the fd while the ep0 thread
        is blocked in EVENT_FETCH leaves the gadget bound to the UDC. Here that
        would also leave the port in device mode when
        :func:`switch_to_host_role` tries to flip it.
        """
        self.stop.set()
        exited = rawgadget.stop_ep0_thread(self.gadget, self._thread, log=log)
        self.gadget.close()
        if not exited:
            log.error("iPhone ep0 thread still blocked in raw-gadget after "
                      "%.1f s; the UDC stays bound until that call returns",
                      rawgadget.EP0_STOP_TIMEOUT)
            return False
        udc = getattr(self.gadget, "device", None)
        if udc and not rawgadget.wait_udc_released(udc):
            log.warning("UDC %s still reports the gadget driver %r after the "
                        "iPhone session was closed", udc,
                        rawgadget.udc_function(udc))
            return False
        return True

    def handle_one(self, req: CtrlRequest) -> None:
        self._handle(req)

    def wait_for_role_swap(self, timeout: float) -> bool:
        return self.role_swap_requested.wait(timeout)

    # ------------------------------------------------------------------ #
    def _loop(self) -> None:
        """
        Service ep0 until the role swap arrives.

        Resets are survivable and expected: dwc2 reports them as DISCONNECT,
        and the goggles resets the bus a few times while enumerating us. The
        loop therefore logs them and keeps fetching events instead of ending
        the session; ending it would make the trigger phase report "no
        role-swap request" after the very first reset.
        """
        while not self.stop.is_set():
            try:
                etype, req, _ = self.gadget.control_event()
                if etype == rawgadget.EVENT_CONTROL and req is not None:
                    self._handle(req)
                elif etype in rawgadget.RESET_EVENTS:
                    self.configured.clear()
                    log.debug("bus %s -- waiting for re-enumeration",
                              rawgadget.EVENT_NAMES.get(etype, etype))
            except OSError as exc:
                if self.stop.is_set():
                    return
                if exc.errno == errno.EINTR:
                    continue
                # ep0=True: an EBUSY from answering a request is raw-gadget
                # rejecting the call (wrong direction), not a reset.
                if rawgadget.is_link_gone(exc, ep0=True):
                    self.configured.clear()
                    log.debug("iPhone ep0 interrupted by a link reset: %s", exc)
                    continue
                self.error = exc
                log.error("iPhone ep0 loop ended: %s", exc)
                return

    def _handle(self, req: CtrlRequest) -> None:
        g = self.gadget
        self.requests.append(req)

        if req.req_type == 2:  # vendor
            if req.bRequest == APPLE_ROLE_SWAP:
                log.info("goggles asked for the Apple role swap (0x51) -- "
                         "acknowledging; it will now become a USB device")
                # bmRequestType 0x40, wLength 0: no data stage, so raw-gadget
                # expects a zero-length EP0_READ; a write would be refused
                # and the swap never acknowledged on the wire.
                g.ep0_ack()
                self.role_swap_at = time.monotonic()
                self.role_swap_requested.set()
            else:
                log.debug("unexpected vendor request %s", req)
                g.ep0_stall()
            return

        if req.req_type != 0:
            g.ep0_stall()
            return

        if req.bRequest == 0x06:  # GET_DESCRIPTOR
            dtype, index = req.wValue >> 8, req.wValue & 0xFF
            if dtype == 1:
                g.ep0_reply(req, IPHONE_DEVICE_DESC)
            elif dtype == 2:
                if index < len(IPHONE_CONFIGS):
                    g.ep0_reply(req, IPHONE_CONFIGS[index])
                else:
                    g.ep0_stall()
            elif dtype == 3:
                self._string(req, index)
            else:
                # device qualifier / BOS / debug: the handset answers none of
                # these on the path the goggles takes
                g.ep0_stall()
            return

        if req.bRequest == 0x09:  # SET_CONFIGURATION
            log.info("goggles selected configuration %d", req.wValue)
            # No endpoint is ever used before the role swap, so there is
            # nothing to enable; the zero-length read completes the status
            # stage (see rawgadget.ep0_is_in).
            g.ep0_ack()
            if req.wValue:
                self.configured.set()
            else:
                self.configured.clear()
            return

        # Requests without a data stage are acknowledged with ep0_ack(), never
        # with ep0_write(); requests with one go through ep0_reply().
        if req.bRequest == 0x0B:  # SET_INTERFACE
            g.ep0_ack()
            return
        if req.bRequest == 0x08:  # GET_CONFIGURATION
            g.ep0_reply(req, b"\x01" if self.configured.is_set() else b"\x00")
            return
        if req.bRequest == 0x0A:  # GET_INTERFACE
            g.ep0_reply(req, b"\x00")
            return
        if req.bRequest == 0x00:  # GET_STATUS
            g.ep0_reply(req, b"\x00\x00")
            return
        if req.bRequest in (0x01, 0x03):  # CLEAR_FEATURE / SET_FEATURE
            g.ep0_ack()
            return

        log.debug("unhandled standard request %s", req)
        g.ep0_stall()

    def _string(self, req: CtrlRequest, index: int) -> None:
        g = self.gadget
        if index == 0:
            g.ep0_reply(req, usbdesc.lang_descriptor())
        elif index in IPHONE_STALLED_STRINGS:
            g.ep0_stall()
        elif 1 <= index <= len(IPHONE_STRINGS):
            g.ep0_reply(req, usbdesc.string_descriptor(
                IPHONE_STRINGS[index - 1]))
        else:
            g.ep0_stall()


# --------------------------------------------------------------------------- #
# USB role switching
# --------------------------------------------------------------------------- #

class RoleSwitchError(RuntimeError):
    """The port could not be moved to the role the next phase needs."""


# The Raspberry Pi 4B has no Type-C port controller: the USB-C connector's CC
# lines go to resistors, not to a PD/CC chip, so nothing registers a usb_role
# switch for the port. The dwc2 core is still dual-role capable, and its role
# is changed at runtime by setting the ``dr_mode`` property with a runtime
# overlay and re-probing the controller: unbind the platform device, apply
# ``dtoverlay dwc2 dr_mode=host``, bind it again.
#
# This never unloads or reloads the dwc2 *module*. A reload can fail with
# "Exec format error" -- the kernel refusing a dwc2.ko on disk that was built
# for a newer, not yet booted kernel -- and that leaves the Pi with no dwc2
# driver at all while the goggles sits on the bus as a USB device waiting for
# a host. A rebind needs no module load, so it cannot fail that way.

DWC2_DRIVER_DIR = "/sys/bus/platform/drivers/dwc2"
PLATFORM_DEVICES_DIR = "/sys/bus/platform/devices"
# Platform device names of the dwc2 controller on the Pi boards: 4B / CM4,
# Zero / Zero W / 1, and Zero 2 W / 3.
KNOWN_DWC2_DEVICES = ("fe980000.usb", "20980000.usb", "3f980000.usb")
DWC2_COMPATIBLE = "brcm,bcm2835-usb"

# How long to wait for the re-probed controller to show up in its new role.
ROLE_SETTLE_TIMEOUT = 3.0


def dtoverlay_available() -> bool:
    """True if the `dtoverlay` helper is installed (raspi-utils / libraspberrypi-bin)."""
    return shutil.which("dtoverlay") is not None


def _run(cmd: list[str]) -> tuple[int, str]:
    """Run a helper; (returncode, stderr-or-stdout). Missing tool -> 127."""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)
    except OSError as exc:
        return 127, str(exc)
    return proc.returncode, (proc.stderr or proc.stdout or "").strip()


def _write(path: str, value: str) -> None:
    with open(path, "w") as fh:
        fh.write(value)


def dwc2_device(udc: str | None = None) -> str | None:
    """
    The dwc2 controller's platform device name, e.g. ``fe980000.usb``.

    Looked up, in order: devices bound to the dwc2 driver, the device behind
    the UDC, platform devices whose DT node is ``brcm,bcm2835-usb``, and the
    known Raspberry Pi names. Works in either role and with the driver
    unbound.
    """
    try:
        bound = [n for n in sorted(os.listdir(DWC2_DRIVER_DIR))
                 if n not in ("module", "bind", "unbind", "uevent")
                 and os.path.islink(os.path.join(DWC2_DRIVER_DIR, n))]
    except OSError:
        bound = []
    if bound:
        return bound[0]
    for name in ([udc] if udc else []) + rawgadget.list_udcs():
        dev = os.path.realpath(os.path.join(rawgadget.SYS_UDC, name, "device"))
        if os.path.basename(dev) and os.path.exists(dev):
            return os.path.basename(dev)
    try:
        names = sorted(os.listdir(PLATFORM_DEVICES_DIR))
    except OSError:
        names = []
    for name in names:
        try:
            with open(os.path.join(PLATFORM_DEVICES_DIR, name, "of_node",
                                   "compatible"), "rb") as fh:
                if DWC2_COMPATIBLE.encode() in fh.read():
                    return name
        except OSError:
            continue
    for name in KNOWN_DWC2_DEVICES:
        if name in names:
            return name
    return None


def dwc2_driver_loaded() -> bool:
    """True if the dwc2 platform driver is registered (module loaded or built in)."""
    return os.path.isdir(DWC2_DRIVER_DIR)


def dwc2_bound(device: str) -> bool:
    return os.path.exists(os.path.join(DWC2_DRIVER_DIR, device))


def dwc2_host_buses(device: str) -> list[str]:
    """USB buses (``usbN``) the controller has registered, i.e. it is a host."""
    return sorted(os.path.basename(p) for p in glob.glob(
        os.path.join(PLATFORM_DEVICES_DIR, device, "usb[0-9]*")))


def dwc2_current_role(device: str | None = None) -> str:
    """'host', 'gadget', 'unbound', 'no driver' or 'unknown'."""
    device = device or dwc2_device()
    if not dwc2_driver_loaded():
        return "no driver"
    if device is None:
        return "unknown"
    if not dwc2_bound(device):
        return "unbound"
    if dwc2_host_buses(device):
        return "host"
    if rawgadget.list_udcs():
        return "gadget"
    return "unknown"


_OVERLAY_LINE = re.compile(r"^\s*\d+:\s+(\S+)\s*(.*)$")


def runtime_overlays() -> list[tuple[str, str]]:
    """Overlays applied at runtime, as ``(name, params)`` from ``dtoverlay -l``."""
    if not dtoverlay_available():
        return []
    rc, out = _run(["dtoverlay", "-l"])
    if rc != 0:
        return []
    found = []
    for line in out.splitlines():
        m = _OVERLAY_LINE.match(line)
        if m:
            found.append((m.group(1), m.group(2).strip()))
    return found


def runtime_dwc2_overlay() -> str | None:
    """Params of a runtime ``dwc2`` overlay (``""`` if none given), else None."""
    for name, params in runtime_overlays():
        if name == "dwc2":
            return params
    return None


def _module_file(name: str) -> str | None:
    rc, out = _run(["modinfo", "-n", name])
    if rc != 0 or not out or out.startswith("("):     # "(builtin)"
        return None
    return out.splitlines()[0].strip()


def _boot_time() -> float | None:
    try:
        with open("/proc/uptime") as fh:
            return time.time() - float(fh.read().split()[0])
    except (OSError, ValueError, IndexError):
        return None


def dwc2_module_mismatch() -> str | None:
    """
    Why loading dwc2.ko from disk would fail, if we can tell. None if fine.

    "Exec format error" (ENOEXEC) from ``modprobe`` is the kernel rejecting
    the module file -- almost always because a kernel package was upgraded
    since boot. Raspberry Pi OS rebuilds keep the same ``uname -r``, so the
    new modules land in the running kernel's own directory and nothing else
    looks wrong. Two checks catch it: the loaded module's ``srcversion``
    against the file's, and the file's mtime against the boot time.
    """
    path = _module_file("dwc2")
    if path is None:
        return None
    try:
        with open("/sys/module/dwc2/srcversion") as fh:
            loaded = fh.read().strip()
    except OSError:
        loaded = ""
    if loaded:
        rc, on_disk = _run(["modinfo", "-F", "srcversion", "dwc2"])
        if rc == 0 and on_disk and on_disk != loaded:
            return ("the dwc2 module on disk (%s, srcversion %s) is not the "
                    "one running (srcversion %s): the kernel was upgraded "
                    "since boot. Reboot." % (path, on_disk, loaded))
    boot = _boot_time()
    try:
        mtime = os.stat(path).st_mtime
    except OSError:
        return None
    if boot is not None and mtime > boot + 60:
        return ("%s was installed after this boot (%s), so it probably does "
                "not match the running kernel %s: a kernel upgrade without a "
                "reboot. Reboot." % (path, time.strftime(
                    "%Y-%m-%d %H:%M", time.localtime(mtime)),
                    os.uname().release))
    return None


def explain_module_load_failure(detail: str) -> str:
    """Turn a failed ``modprobe dwc2`` into advice."""
    if "Exec format error" in detail:
        return ("the kernel refused dwc2.ko (ENOEXEC, 'Exec format error'): "
                "the module on disk was not built for the running kernel %s. "
                "That almost always means a kernel upgrade has been installed "
                "since the last boot. Reboot, then run again; the role switch "
                "itself never unloads dwc2, so this only matters once."
                % os.uname().release)
    if "not found" in detail:
        return ("dwc2 is not installed for kernel %s" % os.uname().release)
    return detail


def _load_dwc2() -> bool:
    """modprobe dwc2 -- only used when the driver is not loaded at all."""
    mismatch = dwc2_module_mismatch()
    if mismatch:
        log.warning("%s", mismatch)
    rc, detail = _run(["modprobe", "dwc2"])
    if rc != 0:
        log.error("`modprobe dwc2` failed (%d): %s -- %s", rc, detail,
                  explain_module_load_failure(detail))
        return False
    return True


def _wait_for(pred, timeout: float, poll: float = 0.05) -> bool:
    deadline = time.monotonic() + timeout
    while True:
        if pred():
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(poll)


def switch_dwc2_role(role: str | None, *, dwc2_params: str = "",
                     device: str | None = None,
                     settle: float = ROLE_SETTLE_TIMEOUT) -> bool:
    """
    Re-probe dwc2 in a different role on a Raspberry Pi, without a module load.

    *role* is a ``dr_mode`` (``host``, ``peripheral``, ``otg``), or None to
    drop our runtime overlay and go back to whatever config.txt says. All of
    it needs root:

    1. unbind the controller from the dwc2 driver
       (``/sys/bus/platform/drivers/dwc2/unbind``);
    2. ``dtoverlay -r dwc2`` if a runtime dwc2 overlay is loaded;
    3. ``dtoverlay dwc2 dr_mode=<role>`` -- a runtime overlay that updates the
       live ``dr_mode`` property of the same DT node (skipped for None);
    4. bind it again (``.../bind``), and dwc2 probes in the new role.

    Only if the dwc2 driver is not registered at all -- e.g. something else
    unloaded it -- is ``modprobe dwc2`` tried.

    Returns True once the controller is in the new role: a ``usbN`` bus under
    the platform device for host, a UDC in ``/sys/class/udc`` otherwise.
    """
    if role not in (None, "host", "peripheral", "otg"):
        raise ValueError("dr_mode must be host, peripheral or otg")
    if not dtoverlay_available():
        log.error("the `dtoverlay` tool is not installed -- "
                  "`sudo apt install raspi-utils` (or libraspberrypi-bin)")
        return False
    if os.geteuid() != 0:
        log.error("switching the dwc2 role needs root")
        return False
    device = device or dwc2_device()
    if device is None:
        log.error("cannot find the dwc2 controller's platform device "
                  "(looked in %s and %s)", DWC2_DRIVER_DIR,
                  PLATFORM_DEVICES_DIR)
        return False

    log.info("re-probing dwc2 (%s) with %s", device,
             "dr_mode=%s" % role if role else "the dr_mode from config.txt")
    loaded = dwc2_driver_loaded()
    if loaded and dwc2_bound(device):
        try:
            _write(os.path.join(DWC2_DRIVER_DIR, "unbind"), device)
        except OSError as exc:
            log.error("unbinding %s from dwc2 failed: %s", device, exc)
            return False
        log.debug("ok: unbound %s", device)

    if runtime_dwc2_overlay() is not None:
        rc, detail = _run(["dtoverlay", "-r", "dwc2"])
        if rc != 0:
            log.error("`dtoverlay -r dwc2` failed (%d): %s", rc, detail)
            return False
        log.debug("ok: dtoverlay -r dwc2")
    if role is not None:
        spec = ["dr_mode=%s" % role] + dwc2_params.split()
        rc, detail = _run(["dtoverlay", "dwc2"] + spec)
        if rc != 0:
            log.error("`dtoverlay dwc2 %s` failed (%d): %s", " ".join(spec),
                      rc, detail)
            # leave the controller usable in its old role rather than unbound
            if loaded:
                _bind_quietly(device)
            return False
        log.debug("ok: dtoverlay dwc2 %s", " ".join(spec))

    if loaded:
        try:
            _write(os.path.join(DWC2_DRIVER_DIR, "bind"), device)
        except OSError as exc:
            log.error("binding %s to dwc2 failed: %s (see dmesg)", device, exc)
            return False
        log.debug("ok: bound %s", device)
    elif not _load_dwc2():
        return False

    if role == "host":
        ok = _wait_for(lambda: bool(dwc2_host_buses(device)), settle)
        log.info("dwc2 %s in host mode%s", "now" if ok else "NOT",
                 " (%s)" % ", ".join(dwc2_host_buses(device)) if ok else
                 " -- no USB bus appeared under %s" % device)
    else:
        ok = _wait_for(lambda: bool(rawgadget.list_udcs()), settle)
        log.info("dwc2 %s a gadget again; /sys/class/udc: %s",
                 "is" if ok else "is NOT",
                 ", ".join(rawgadget.list_udcs()) or "empty")
    return ok


def _bind_quietly(device: str) -> None:
    try:
        _write(os.path.join(DWC2_DRIVER_DIR, "bind"), device)
    except OSError:
        pass


def role_switching_available() -> bool:
    """True if this machine can re-probe dwc2 in another role (a Pi 4B, or
    anything with the `dtoverlay` tool)."""
    return rawgadget.is_pi4() or dtoverlay_available()


def switch_to_host_role() -> bool:
    """
    Flip the port from gadget to host by re-probing dwc2 with
    ``dr_mode=host`` (:func:`switch_dwc2_role`).
    """
    if not role_switching_available():
        log.info("this machine cannot re-probe dwc2 -- flip the port to host "
                 "yourself before the iAP2 host phase")
        return False
    return switch_dwc2_role("host")


def switch_to_gadget_role() -> bool:
    """
    Undo :func:`switch_to_host_role`: make the port a gadget port again.

    This drops our runtime overlay, so the controller goes back to the
    ``dr_mode`` in config.txt. A no-op (True) if it already is a gadget.
    """
    if not role_switching_available():
        return bool(rawgadget.list_udcs())
    if rawgadget.list_udcs() and runtime_dwc2_overlay() is None:
        return True
    return switch_dwc2_role(None)


def ensure_gadget_role() -> None:
    """
    Before phase 1: make sure there is a UDC, repairing what a previous run
    may have left behind (port still in host mode, or dwc2 not loaded at
    all). Raises RoleSwitchError if there is
    still no UDC afterwards.
    """
    if rawgadget.list_udcs():
        return
    if role_switching_available():
        why = ("dwc2 is not loaded" if not dwc2_driver_loaded() else
               "the port is still in host mode (dwc2 role: %s)"
               % dwc2_current_role())
        log.warning("no UDC: %s -- switching the port back to gadget mode",
                    why)
        if switch_to_gadget_role():
            return
    raise RoleSwitchError(
        "no UDC in /sys/class/udc, so the iPhone impersonation cannot start. "
        "Run `sudo ./third-eye doctor`; `sudo ./third-eye role "
        "gadget` puts the port back, and a reboot always does.")


# Delay between acknowledging request 0x51 and releasing the bus.
#
# With a real iPhone (PROTOCOL.md section 3.4): the iPhone ACKs the status
# stage 54 us after the SETUP, the goggles stops sending SOFs 37 ms later,
# the iPhone drops its pull-up at +75 ms, the goggles attaches as a
# full-speed device at +205..218 ms and the iPhone resets it as the new host
# at about +370 ms. A gadget still pulling D+ up when the goggles attaches
# would collide with it, so 50 ms releases the bus inside the iPhone's
# window. The goggles itself is not in a hurry -- it waits at least 12 s for
# a host -- so this is about matching the handset, not about a deadline.
POST_SWAP_DELAY = 0.05


def trigger_mfi_mode(driver: str | None = None, udc: str | None = None,
                     timeout: float = 60.0,
                     switch_to_host: bool = True) -> bool:
    """
    Phase 1: pretend to be an iPhone until the goggles asks for the role swap.

    Returns True if request 0x51 arrived. When *switch_to_host* is set the port
    is flipped to host afterwards so that :class:`IapHost` can enumerate the
    goggles (see :func:`switch_to_host_role`). If that switch fails, :class:`RoleSwitchError` is raised at once rather than
    waiting out the phase-2 timeout on a port that could never see the
    goggles.

    *driver* and *udc* default to None, meaning "discover them from sysfs" --
    the only thing that works unchanged on a Pi 4B, where both names are
    ``fe980000.usb``.
    """
    udc = rawgadget.pick_udc(udc)
    driver = driver or rawgadget.udc_driver_name(udc)

    rawgadget.install_interrupt_handler()   # teardown fallback, see close()
    session = _IphoneSession(driver, udc)
    try:
        session.start()
        log.info("presenting as %04x:%04x (Apple Inc. / iPhone) on %s/%s",
                 IPHONE_VID, IPHONE_PID, driver, udc)
        deadline = time.monotonic() + timeout
        ok = False
        while time.monotonic() < deadline:
            if session.wait_for_role_swap(0.05):
                ok = True
                break
            if session.error is not None:
                # already logged at ERROR by the ep0 thread
                raise session.error
        if not ok:
            log.error("no role-swap request after %.0fs (%d control requests "
                      "seen)", timeout, len(session.requests))
            return False
        # Let the status stage settle, then get off the bus the way the
        # iPhone does (see POST_SWAP_DELAY).
        time.sleep(POST_SWAP_DELAY)
    finally:
        session.close()

    if switch_to_host:
        if not switch_to_host_role():
            if role_switching_available():
                raise RoleSwitchError(
                    "the goggles has handed over the host role, but this port "
                    "could not be switched to host mode (see the error above)."
                    " The goggles is now waiting on the bus as a USB device.")
        elif session.role_swap_at is not None:
            # A real iPhone resets the goggles as its new host about 370 ms
            # after the request.
            log.info("port is host %.0f ms after the role-swap request",
                     (time.monotonic() - session.role_swap_at) * 1000)
    return True


# --------------------------------------------------------------------------- #
# Phase 2: be the Apple device (USB host) and run iAP2
# --------------------------------------------------------------------------- #

class IapHost:
    """
    The Apple-device half of the link, over libusb.

    Exposes the same ``read()`` / ``write()`` surface as
    :class:`pryer.accessory.AoaAccessory`, so :class:`pryer.pipeline.
    StreamPipeline` works with either transport unchanged.  ``read()`` returns
    DJI tunnel bytes from the External Accessory pipe; the iAP2 control link
    is serviced on its own thread in the background.
    """

    def __init__(self, vid: int = DJI_VID, pid: int = MFI_PID,
                 read_size: int = DEFAULT_READ_SIZE,
                 timeout_ms: int = DEFAULT_TIMEOUT_MS,
                 send_detect: bool = True, initial_seq: int | None = None,
                 transfers: int = DEFAULT_TRANSFERS):
        self.vid = vid
        self.pid = pid
        if read_size > libusb.MAX_URB_SIZE:
            log.warning("read size %d is more than one URB; using %d. A "
                        "longer read is split into chained URBs that the "
                        "first short packet cancels, which loses data on a "
                        "Pi's dwc2 (PROTOCOL.md 9.3)", read_size,
                        libusb.MAX_URB_SIZE)
            read_size = libusb.MAX_URB_SIZE
        self.read_size = read_size
        self.transfers = max(0, transfers)
        self.timeout_ms = timeout_ms
        self.send_detect = send_detect
        self.session = iap2.DeviceSession(initial_seq=initial_seq)
        self.ctx: libusb.Context | None = None
        self.dev: libusb.Device | None = None
        self._stop = threading.Event()
        self._iap_thread: threading.Thread | None = None
        self._ea_open = False
        self._ea_reader: libusb.BulkReader | None = None
        self._iap_reader: libusb.BulkReader | None = None
        self.error: BaseException | None = None

    # ------------------------------------------------------------------ #
    def wait_for_device(self, timeout: float = 30.0) -> None:
        """Poll the buses until the goggles shows up in MFi mode."""
        self.ctx = libusb.Context()
        deadline = time.time() + timeout
        warned = False
        while time.time() < deadline:
            present = self.ctx.list_devices()
            if (self.vid, self.pid) in present:
                return
            if (DJI_VID, PC_MODE_PID) in present and not warned:
                warned = True
                log.warning(
                    "found %04x:%04x -- that is the goggles in PC mode, not "
                    "MFi mode. It only exposes iAP2 after it has enumerated "
                    "an Apple device; run the trigger phase first.",
                    DJI_VID, PC_MODE_PID)
            time.sleep(0.25)
        raise TimeoutError(
            "goggles did not appear as %04x:%04x within %.0fs"
            % (self.vid, self.pid, timeout))

    def open(self, timeout: float = 30.0, iap_timeout: float = 15.0) -> None:
        self.wait_for_device(timeout)
        assert self.ctx is not None
        self.dev = self.ctx.open(self.vid, self.pid)
        log.info("opened %04x:%04x  %s / %s  serial %s",
                 self.vid, self.pid, self.dev.string(1), self.dev.string(2),
                 self.dev.string(3))

        self.dev.claim(IAP_INTERFACE)
        self._stop.clear()
        self._iap_reader = self._start_reader(EP_IAP_IN, IAP_READ_SIZE,
                                              IAP_TRANSFERS)
        self._iap_thread = threading.Thread(target=self._iap_loop,
                                            name="iap2", daemon=True)
        self._iap_thread.start()

        if self.send_detect:
            # Harmless if the accessory does not need it: unknown preambles are
            # skipped by the link-layer parser on both sides.
            self._write_iap(iap2.DETECT)

        if not self._wait_ready(iap_timeout):
            state = ("linked=%s authenticated=%s identified=%s"
                     % (self.session.linked, self.session.authenticated,
                        self.session.identified))
            raise TimeoutError("iAP2 link did not come up in %.0fs (%s)"
                               % (iap_timeout, state))

        ident = self.session.identification
        if ident is not None:
            log.info("accessory identified:\n%s", ident.describe())
            if ident.ea_protocol_id(EA_PROTOCOL_NAME) is None:
                log.warning("accessory did not advertise %s -- the External "
                            "Accessory pipe may not carry the tunnel",
                            EA_PROTOCOL_NAME)

        self._open_ea()

    def _wait_ready(self, timeout: float) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.session.ready:
                return True
            if self.error:
                raise self.error
            time.sleep(0.02)
        return False

    def _open_ea(self) -> None:
        """Claim interface 1 and switch it to the alternate setting with EPs."""
        assert self.dev is not None
        self.dev.claim(EA_INTERFACE)
        self.dev.set_alt(EA_INTERFACE, EA_ALT_SETTING)
        # Poll the tunnel from the moment it exists, as the iPhone does; the
        # data waits in the reader until read() collects it.
        self._ea_reader = self._start_reader(EP_EA_IN, self.read_size,
                                             self.transfers)
        self._ea_open = True
        log.info("External Accessory pipe up: EP 0x%02x IN / 0x%02x OUT "
                 "(%s alternate setting %d); %s", EP_EA_IN, EP_EA_OUT,
                 EA_PROTOCOL_NAME, EA_ALT_SETTING,
                 "reading with %d queued %d-byte transfers"
                 % (self.transfers, self.read_size) if self._ea_reader
                 else "synchronous %d-byte reads" % self.read_size)

    def _start_reader(self, ep: int, size: int,
                      count: int) -> libusb.BulkReader | None:
        """Queue *count* transfers on *ep*, or None for synchronous reads."""
        if self.transfers == 0 or count == 0:
            return None
        assert self.dev is not None
        if not libusb.async_available(self.dev.lib):
            log.warning("this libusb has no asynchronous API; reading EP "
                        "0x%02x synchronously", ep)
            return None
        try:
            return self.dev.bulk_reader(ep, size=size, count=count)
        except libusb.UsbError as exc:
            log.warning("could not queue transfers on EP 0x%02x (%s); "
                        "reading it synchronously", ep, exc)
            return None

    # ------------------------------------------------------------------ #
    def _write_iap(self, data: bytes) -> None:
        if not data or self.dev is None:
            return
        self.dev.bulk_write(EP_IAP_OUT, data, self.timeout_ms)

    def _iap_loop(self) -> None:
        """Service the iAP2 control link for as long as the session lives."""
        try:
            while not self._stop.is_set():
                chunk = self._read_iap()
                if not chunk:
                    continue
                reply = self.session.feed(chunk)
                if reply:
                    self._write_iap(reply)
        except BaseException as exc:  # noqa: BLE001 -- surfaced to the caller
            if not self._stop.is_set():
                self.error = exc
                log.error("iAP2 link failed: %s", exc)

    def _read_iap(self) -> bytes:
        if self._iap_reader is not None:
            return self._iap_reader.read(self.timeout_ms / 1000.0)
        assert self.dev is not None
        try:
            return self.dev.bulk_read(EP_IAP_IN, IAP_READ_SIZE,
                                      self.timeout_ms)
        except libusb.UsbTimeout:
            return b""

    # ------------------------------------------------------------------ #
    def read(self, size: int | None = None) -> bytes:
        """
        Read DJI tunnel bytes from the External Accessory pipe.

        With queued transfers (the default) this returns everything
        that has arrived since the last call, joined, up to about 256 kiB or
        *size*, and b"" after `timeout_ms` of silence. With `transfers=0` it
        is one synchronous transfer of at most `read_size` (<= 16 kiB, one
        URB). Either way, no read is ever split into chained URBs, which
        loses data on a Pi's dwc2 (PROTOCOL.md 9.3).
        """
        if not self._ea_open or self.dev is None:
            raise RuntimeError("External Accessory pipe is not open")
        if self.error:
            raise self.error
        if self._ea_reader is not None:
            return self._ea_reader.read(self.timeout_ms / 1000.0,
                                        max_bytes=size or 256 * 1024)
        return self.dev.bulk_read(EP_EA_IN, size or self.read_size,
                                  self.timeout_ms)

    def write(self, data: bytes) -> int:
        """Send app -> goggles tunnel bytes."""
        if not self._ea_open or self.dev is None:
            raise RuntimeError("External Accessory pipe is not open")
        return self.dev.bulk_write(EP_EA_OUT, data, self.timeout_ms)

    def close(self) -> None:
        self._stop.set()
        # Readers first: cancelling their transfers also wakes the iAP2
        # thread, and nothing may be in flight once the interfaces go.
        for reader in (self._ea_reader, self._iap_reader):
            if reader is not None:
                reader.close()
                log.info("%s", reader.describe())
        self._ea_reader = self._iap_reader = None
        if self._iap_thread and self._iap_thread is not threading.current_thread():
            self._iap_thread.join(timeout=1.5)
        self._ea_open = False
        if self.dev:
            self.dev.close()
            self.dev = None
        if self.ctx:
            self.ctx.close()
            self.ctx = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


# --------------------------------------------------------------------------- #
# Diagnostics
# --------------------------------------------------------------------------- #

def _goggles_on_the_bus() -> list[tuple[bool, str]]:
    """
    What libusb sees of the goggles before a run, as a `doctor` check.

    Not seeing it is the normal case. On this transport the goggles is the
    USB *host* until the role swap, as on the Android one, so there is nothing
    for our side to enumerate. It shows up as 2ca3:1002 only during phase 2 of
    `stream -t ios`, after the Pi has switched to host, so its absence is not
    reported as a failure.
    """
    try:
        with libusb.Context() as ctx:
            devs = ctx.list_devices()
    except OSError as exc:
        return [(False, "libusb could not list USB devices: %s" % exc)]
    if (DJI_VID, MFI_PID) in devs:
        return [(True, "goggles already on a host port in MFi mode "
                       "(%04x:%04x), e.g. left over from a run with "
                       "--keep-host-role; `stream -t ios --no-trigger` can "
                       "use it as it is" % (DJI_VID, MFI_PID))]
    if (DJI_VID, PC_MODE_PID) in devs:
        return [(False, "goggles enumerated in PC mode (%04x:%04x), so it "
                        "is on a USB host port: a Pi 4B USB-A port, or the "
                        "USB-C port left in host mode. Both transports need "
                        "it on the dwc2 port in gadget mode, with the goggles "
                        "as the host. Move the cable, or run `sudo "
                        "./third-eye role gadget` if the USB-C port was "
                        "left in host mode" % (DJI_VID, PC_MODE_PID))]
    return [(True, "goggles not visible to libusb, as expected: it is the USB "
                   "host until the role swap and appears as %04x:%04x only in "
                   "phase 2 of a run" % (DJI_VID, MFI_PID))]


def diagnose() -> list[tuple[bool, str]]:
    """Checks for the `doctor` subcommand, iOS path only."""
    out: list[tuple[bool, str]] = []

    ok = libusb.available()
    out.append((ok, "libusb-1.0 present"
                if ok else "libusb-1.0 missing (apt install libusb-1.0-0)"))

    out.append((os.geteuid() == 0,
                "running as root (needed for raw bulk access)"
                if os.geteuid() == 0
                else "not root -- use sudo or install a udev rule for 2ca3:1002"))

    if ok:
        out.extend(_goggles_on_the_bus())

    model = rawgadget.board_model()
    if model:
        out.append((True, "board: %s" % model))

    if role_switching_available():
        if dtoverlay_available():
            out.append((True, "role switching by dwc2 re-probe is available "
                              "(unbind, runtime overlay dr_mode=host, bind; "
                              "no module reload)"))
        else:
            out.append((False, "the `dtoverlay` tool is missing, so the port "
                               "cannot be flipped to host at runtime -- "
                               "`sudo apt install raspi-utils`"))
    else:
        out.append((False, "no `dtoverlay` tool and not a Raspberry Pi 4B -- "
                           "this machine cannot flip between gadget and host "
                           "on one port"))

    if rawgadget.board_model():
        device = dwc2_device()
        role = dwc2_current_role(device)
        if role == "no driver":
            out.append((False, "the dwc2 driver is not loaded, so there is "
                               "neither a UDC nor a host port. A failed "
                               "`modprobe dwc2` leaves it like this; reboot, "
                               "or `sudo ./third-eye role gadget`"))
        elif device:
            out.append((role in ("gadget", "host"),
                        "dwc2 controller %s: %s" % (device, role)))
        overlay = runtime_dwc2_overlay()
        if overlay is not None:
            out.append((False, "a runtime `dtoverlay dwc2 %s` is still loaded "
                               "from an earlier run; `sudo ./third-eye "
                               "role gadget` removes it" % overlay))
        mismatch = dwc2_module_mismatch()
        if mismatch:
            out.append((False, mismatch))
    return out
