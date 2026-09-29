"""
Tearing down the phase-1 gadget so that phase 2 can bind the UDC
(PROTOCOL.md section 8.4).

A raw-gadget instance is released, and the UDC unbound, only once every ioctl
on its file has returned. After START_ACCESSORY the goggles sends nothing
more, so an ep0 thread blocked in EVENT_FETCH never returns on its own:
closing the fd under it leaves phase 1 bound, the gadget stays attached to the
bus, and phase 2's USB_RAW_IOCTL_RUN fails with EBUSY.

Four groups of tests:

* unit tests with a fake that models the kernel's file lifetime
  (`tests/fakegadget.KernelLifetimeFake`): closing the fd first leaves the UDC
  bound; `_Session.close()` wakes the thread (soft disconnect, else a signal),
  joins it, and only then closes the fd;
* phase 2's RUN retry and the error message that names what holds the UDC;
* every raw-gadget ioctl goes through ctypes, so a blocking bulk read does not
  hold the GIL;
* `decode`'s diagnosis on a reference capture of a session where phase 1
  kept the UDC (skipped when the captures are not available): the whole AOA
  handshake is on the wire, the device never re-enumerates in accessory mode,
  and the Pi stays attached, idle, for about 1.5 s after START_ACCESSORY.

Run with:  python -m pytest tests/test_gadget_teardown.py
       or:  python tests/test_gadget_teardown.py
"""

from __future__ import annotations

import ctypes
import errno
import logging
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pryer import aoa, accessory, pcapng, rawgadget  # noqa: E402
from pryer.accessory import AoaAccessory, _Session  # noqa: E402
from pryer.cli import _explain_empty_capture  # noqa: E402
from fakegadget import KernelLifetimeFake, StrictFakeGadget  # noqa: E402
import support  # noqa: E402
from support import Skip  # noqa: E402

# A Pi 4B session whose phase 1 did not release the UDC.
UDC_KEPT_AFTER_PHASE_1 = "E_rpi"


def _udc_kept_capture() -> str:
    return support.capture_path(UDC_KEPT_AFTER_PHASE_1, pcapng_only=True)


# --------------------------------------------------------------------------- #
# The teardown, against a fake with the kernel's file lifetime
# --------------------------------------------------------------------------- #
def _running_session(fake) -> _Session:
    s = _Session(aoa.phone_descriptors(), "f", "f", gadget=fake,
                 enable_endpoints=False)
    s.start()
    deadline = time.monotonic() + 1.0
    while fake._in_ioctl == 0 and time.monotonic() < deadline:
        time.sleep(0.005)
    assert fake._in_ioctl == 1, "ep0 thread never entered EVENT_FETCH"
    return s


def test_closing_the_fd_first_leaves_the_udc_bound():
    """
    The wrong order: close the fd, then join. The fake, like the kernel, does
    not release while the fetch is blocked. This pins down the failure mode.
    """
    fake = KernelLifetimeFake()
    s = _running_session(fake)
    s.stop.set()
    fake.close()                       # the fd first...
    s._thread.join(0.2)                # ...then a join, which times out
    assert s._thread.is_alive()
    assert fake.fd_closed and not fake.released
    fake.queue(rawgadget.EVENT_DISCONNECT)    # clean up the thread
    s._thread.join(1.0)
    assert fake.released


def test_close_wakes_the_ep0_thread_and_releases_the_udc():
    fake = KernelLifetimeFake()
    s = _running_session(fake)
    t0 = time.monotonic()
    assert s.close() is True
    assert time.monotonic() - t0 < 0.5
    assert fake.soft_disconnects == 1
    assert not s._thread.is_alive()
    assert fake.released


def test_close_falls_back_to_a_signal_without_soft_connect():
    """
    No soft_connect attribute, so the thread has to be interrupted. This uses
    a real signal on a real blocking syscall (libc read on a pipe via ctypes,
    which, like our ioctl, is not retried on EINTR).
    """
    if threading.current_thread() is not threading.main_thread():
        raise Skip("needs the main thread to install the handler")
    assert rawgadget.install_interrupt_handler()
    libc = ctypes.CDLL(None, use_errno=True)
    r, w = os.pipe()

    class BlockingRead(StrictFakeGadget):
        device = "fake-udc"
        soft_disconnect = staticmethod(lambda: False)
        entered = threading.Event()

        def control_event(self):
            buf = ctypes.create_string_buffer(1)
            self.entered.set()
            n = libc.read(r, buf, 1)
            if n < 0:
                e = ctypes.get_errno()
                raise OSError(e, os.strerror(e))
            return rawgadget.EVENT_INVALID, None, b""

    fake = BlockingRead()
    s = _Session(aoa.phone_descriptors(), "f", "f", gadget=fake,
                 enable_endpoints=False)
    try:
        s.start()
        assert fake.entered.wait(1.0)
        time.sleep(0.05)
        t0 = time.monotonic()
        assert s.close() is True
        assert time.monotonic() - t0 < 0.8
        assert not s._thread.is_alive()
    finally:
        os.close(r)
        os.close(w)


def test_close_reports_a_thread_that_cannot_be_woken():
    fake = KernelLifetimeFake(soft_connect=False)
    s = _running_session(fake)
    saved = rawgadget._interrupt_ready, rawgadget.EP0_STOP_TIMEOUT
    rawgadget._interrupt_ready = False          # no signal fallback either
    records = []
    handler = logging.Handler()
    handler.emit = records.append
    logging.getLogger("pryer.accessory").addHandler(handler)
    try:
        s.stop.set()
        ok = rawgadget.stop_ep0_thread(fake, s._thread, timeout=0.2)
        assert ok is False
        fake.close()
        assert not fake.released
    finally:
        logging.getLogger("pryer.accessory").removeHandler(handler)
        rawgadget._interrupt_ready, rawgadget.EP0_STOP_TIMEOUT = saved
        fake.queue(rawgadget.EVENT_DISCONNECT)
        s._thread.join(1.0)


def test_ep0_loop_ignores_a_stray_eintr():
    """Ctrl-C can land on the ep0 thread; that is not a session error."""
    calls = []

    class Interrupted(StrictFakeGadget):
        def control_event(self):
            calls.append(1)
            if len(calls) == 1:
                raise OSError(errno.EINTR, "Interrupted system call")
            s.stop.set()
            return rawgadget.EVENT_SUSPEND, None, b""

    s = _Session(aoa.phone_descriptors(), "f", "f", gadget=Interrupted(),
                 enable_endpoints=False)
    s._loop()
    assert s.error is None and len(calls) == 2


# --------------------------------------------------------------------------- #
# Phase 2 RUN: retry while bound, explain what holds the UDC
# --------------------------------------------------------------------------- #
class _RunFake(StrictFakeGadget):
    def __init__(self, fail: bool):
        super().__init__()
        self.fail = fail

    def run(self):
        if self.fail:
            raise OSError(errno.EBUSY, "Device or resource busy")

    def control_event(self):
        time.sleep(0.01)
        return rawgadget.EVENT_INVALID, None, b""


def _accessory_with(fails: int, owner: str):
    acc = object.__new__(AoaAccessory)
    acc.driver = acc.udc = "fake-udc"
    made = []

    def new_session(desc, enable_endpoints=True):
        fake = _RunFake(fail=len(made) < fails)
        made.append(fake)
        return _Session(desc, "f", "fake-udc", gadget=fake,
                        enable_endpoints=enable_endpoints)

    acc._new_session = new_session
    state = {"owner": owner}
    return acc, made, state


def _patched_function(state):
    return lambda udc: state["owner"]


def test_phase_2_run_is_retried_while_the_udc_is_still_bound():
    acc, made, state = _accessory_with(fails=2, owner="USB Raw Gadget")
    saved = rawgadget.udc_function, accessory.RUN_RETRY_DELAY
    rawgadget.udc_function = _patched_function(state)
    accessory.RUN_RETRY_DELAY = 0.01
    try:
        s = acc._start_session(aoa.accessory_descriptors())
        assert len(made) == 3
        assert made[0].closed and made[1].closed and not made[2].closed
        s.stop.set()
        s.close(wait_release=False)
    finally:
        rawgadget.udc_function, accessory.RUN_RETRY_DELAY = saved


def test_phase_2_ebusy_with_a_free_udc_is_raised_at_once():
    acc, made, state = _accessory_with(fails=5, owner="")
    saved = rawgadget.udc_function
    rawgadget.udc_function = _patched_function(state)
    try:
        try:
            acc._start_session(aoa.accessory_descriptors())
        except OSError as exc:
            assert exc.errno == errno.EBUSY
        else:
            raise AssertionError("expected EBUSY")
        assert len(made) == 1
    finally:
        rawgadget.udc_function = saved


def test_run_failure_message_names_what_holds_the_udc():
    saved = rawgadget.udc_function
    try:
        rawgadget.udc_function = lambda udc: "USB Raw Gadget"
        msg = str(rawgadget._explain_run_failure(
            OSError(errno.EBUSY, "busy"), "fe980000.usb", "fe980000.usb"))
        assert "still bound" in msg and "raw-gadget session" in msg, msg
        assert "classic Raspberry Pi 4B" not in msg, msg
        rawgadget.udc_function = lambda udc: "g_ether"
        msg = str(rawgadget._explain_run_failure(
            OSError(errno.EBUSY, "busy"), "fe980000.usb", "fe980000.usb"))
        assert "g_ether" in msg and "modprobe -r g_ether" in msg, msg
        rawgadget.udc_function = lambda udc: ""
        msg = str(rawgadget._explain_run_failure(
            OSError(errno.EBUSY, "busy"), "dwc2", "fe980000.usb"))
        assert "USB_UDC_NAME" in msg, msg
    finally:
        rawgadget.udc_function = saved


# --------------------------------------------------------------------------- #
# ioctl through ctypes (no GIL held across a blocking bulk read)
# --------------------------------------------------------------------------- #
def test_rawgadget_does_not_use_fcntl_ioctl():
    """
    fcntl.ioctl keeps the GIL for buffers > 1024 bytes (CPython
    Modules/fcntlmodule.c), which a bulk read buffer always is. Every
    raw-gadget ioctl must go through rawgadget._ioctl instead.
    """
    import inspect
    src = inspect.getsource(rawgadget.RawGadget)
    assert "fcntl.ioctl(" not in src
    assert not hasattr(rawgadget, "fcntl")


def test_bulk_read_goes_through_ctypes_ioctl():
    seen = []

    class FakeLibc:
        @staticmethod
        def ioctl(fd, request, arg):
            seen.append((fd.value, request.value))
            return 5

    rg = object.__new__(rawgadget.RawGadget)
    rg.fd = 42
    saved = rawgadget._libc
    rawgadget._libc = FakeLibc()
    try:
        data = rg.ep_read(3, 256 * 1024)
    finally:
        rawgadget._libc = saved
    assert seen == [(42, rawgadget.IOCTL_EP_READ)]
    assert len(data) == 5


def test_ctypes_ioctl_reports_the_kernel_errno():
    fd = os.open(os.devnull, os.O_RDWR)
    try:
        buf = ctypes.create_string_buffer(8 + 256 * 1024)
        try:
            rawgadget._ioctl(fd, rawgadget.IOCTL_EP_READ, buf)
        except OSError as exc:
            assert exc.errno == errno.ENOTTY, exc
        else:
            raise AssertionError("ioctl on /dev/null should fail")
    finally:
        os.close(fd)


# --------------------------------------------------------------------------- #
# A session whose phase 1 kept the UDC (reference capture)
# --------------------------------------------------------------------------- #
def test_udc_kept_session_completes_the_whole_aoa_handshake():
    """Every AOA step is on the wire, up to and including START_ACCESSORY."""
    path = _udc_kept_capture()
    reqs = [(c.bm_request_type, c.b_request, c.w_index)
            for c in pcapng.control_transfers(path)]
    assert (0x00, 9, 0) in reqs                       # SET_CONFIGURATION
    assert (0xC0, 51, 0) in reqs                      # GET_PROTOCOL
    assert sorted(i for t, r, i in reqs if (t, r) == (0x40, 52)) == \
        [0, 1, 2, 3, 4, 5]                            # six SEND_STRINGs
    assert (0x40, 53, 0) in reqs                      # START_ACCESSORY


def test_udc_kept_session_never_reenumerates_as_the_accessory():
    path = _udc_kept_capture()
    transfers = list(pcapng.control_transfers(path))
    start = next(c.ts for c in transfers
                 if c.bm_request_type == 0x40 and c.b_request == 53)
    devs = [c.data for c in transfers
            if c.ts > start and c.b_request == 6 and c.setup[3] == 1]
    assert not devs, devs


def test_udc_kept_session_stays_attached_after_start_accessory():
    """
    The signature of a phase 1 that kept the UDC: nothing but SOFs for ~1.5 s
    after the last control transfer, then the detach when the process exits
    (0.15 s grace + a 1.0 s thread join that timed out + 0.3 s).
    """
    path = _udc_kept_capture()
    transfers = list(pcapng.control_transfers(path))
    start = next(c.ts for c in transfers
                 if c.bm_request_type == 0x40 and c.b_request == 53)
    last_token = max(t.ts for t in pcapng.transactions(path))
    assert (last_token - start) / 1e9 < 0.02          # 2 string reads, 6 ms
    resets = [ts for ts, text in pcapng.log_messages(path)
              if ts > start and "Bus Reset" in text]
    assert resets, "expected the detach to show as a bus reset"
    idle = (resets[0] - start) / 1e9
    assert 1.4 < idle < 1.7, idle


def test_decode_names_the_missing_phase_2_instead_of_nothing_wrong():
    path = _udc_kept_capture()
    text = "\n".join(_explain_empty_capture(path, False))
    assert "never came back in accessory mode" in text, text
    assert "nothing wrong here" not in text, text
    assert "PROTOCOL.md 8.4" in text


# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    sys.exit(support.main(globals()))
