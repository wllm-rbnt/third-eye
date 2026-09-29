"""
A fake /dev/raw-gadget that enforces the kernel's ep0 direction rule.

A fake that accepted any ep0 call for any request would let a gadget that
acknowledges SET_CONFIGURATION with EP0_WRITE pass every test and then fail on
real hardware. This one behaves like
``drivers/usb/gadget/legacy/raw_gadget.c``:

* ``gadget_setup`` marks a request *IN-pending* only if it is device-to-host
  **and** has ``wLength > 0``; everything else is *OUT-pending*.
* ``raw_process_ep0_io`` refuses an EP0_WRITE on an OUT-pending request (and an
  EP0_READ on an IN-pending one) with **EBUSY** ("fail, wrong direction").
  EBUSY matters here because it is also an errno that endpoint I/O returns
  across a reset, and must not be mistaken for one on ep0.
* A request that is neither answered nor stalled leaves the host NAKing its
  status stage forever. The kernel cannot tell us that, but a test can, so
  :func:`strict` makes it an assertion failure.
"""

from __future__ import annotations

import errno
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pryer.rawgadget import ep0_is_in  # noqa: E402


class StrictFakeGadget:
    """Records what the device side does; rejects wrong-direction ep0 I/O."""

    def __init__(self, ep0_out: list[bytes] | None = None):
        self.writes: list[bytes] = []          # EP0_WRITE data stages
        self.reads = list(ep0_out or [])       # queued host-to-device data
        self.acks = 0                          # zero-length EP0_READs
        self.enabled: list[bytes] = []
        self.stalls = 0
        self.configured = False
        self.vbus = None
        self.closed = False
        self.pending: str | None = None        # "in", "out" or None
        self.ep_enable_errors: list[int] = []  # errnos to raise, in order
        self._next_handle = 10

    # -- what the kernel does when a SETUP arrives ------------------------- #
    def begin(self, req) -> None:
        assert self.pending is None, (
            "previous control request was never answered -- the host would "
            "be NAKing its status stage")
        self.pending = "in" if ep0_is_in(req) else "out"

    def _take(self, direction: str) -> None:
        if self.pending != direction:
            raise OSError(errno.EBUSY,
                          "raw-gadget: fail, wrong direction (EP0_%s on a "
                          "request that is %s-pending)"
                          % ("WRITE" if direction == "in" else "READ",
                             self.pending or "not"))
        self.pending = None

    # -- raw-gadget surface ------------------------------------------------ #
    def run(self) -> None:
        pass

    def ep0_write(self, data: bytes = b"") -> None:
        self._take("in")
        self.writes.append(bytes(data))

    def ep0_read(self, length: int) -> bytes:
        self._take("out")
        if length == 0:
            self.acks += 1
            return b""
        return self.reads.pop(0) if self.reads else bytes(length)

    def ep0_ack(self) -> None:
        self.ep0_read(0)

    def ep0_reply(self, req, data: bytes) -> None:
        # same routing as RawGadget.ep0_reply
        if ep0_is_in(req):
            self.ep0_write(data[:req.wLength])
        else:
            self.ep0_ack()

    def ep0_stall(self) -> None:
        assert self.pending is not None, "stall with no request pending"
        self.pending = None
        self.stalls += 1

    def ep_enable(self, descriptor: bytes) -> int:
        if self.ep_enable_errors:
            code = self.ep_enable_errors.pop(0)
            raise OSError(code, os.strerror(code))
        self.enabled.append(bytes(descriptor))
        self._next_handle += 1
        return self._next_handle

    def ep_disable(self, handle: int) -> None:
        pass

    def configure(self) -> None:
        self.configured = True

    def vbus_draw(self, ma: int) -> bool:
        self.vbus = ma
        return True

    def close(self) -> None:
        self.closed = True


def strict(session, fake: StrictFakeGadget):
    """
    Wrap ``session.handle_one`` so every request goes through ``fake.begin``
    and must be answered (data stage, zero-length ack or stall) before the
    handler returns -- exactly the obligation raw-gadget puts on us.
    """
    inner = session.handle_one

    def handle_one(req):
        fake.begin(req)
        inner(req)
        assert fake.pending is None, (
            "%r left unanswered -- the host would NAK its status stage "
            "forever (PROTOCOL.md section 8.2)" % (req,))

    session.handle_one = handle_one
    return session


class KernelLifetimeFake(StrictFakeGadget):
    """
    Models how long a raw-gadget instance stays bound to the UDC.

    This is the kernel behaviour behind PROTOCOL.md section 8.4. The
    gadget is unbound (``released``) only when the fd has been closed *and*
    no thread is inside an ioctl on it, because an in-flight ioctl holds a
    reference to the file and ``raw_release`` runs on the last ``fput``.
    ``control_event`` blocks like EVENT_FETCH until an event is queued.
    ``soft_disconnect`` queues DISCONNECT, as udc-core does when
    ``disconnect`` is written to ``soft_connect``.
    """

    def __init__(self, soft_connect: bool = True):
        super().__init__()
        import threading
        self._cv = threading.Condition()
        self._events: list = []
        self._in_ioctl = 0
        self.fd_closed = False
        self.released = False
        self.soft_disconnects = 0
        if not soft_connect:
            # an old kernel / UDC without the soft_connect attribute
            self.soft_disconnect = lambda: False

    device = "fake-udc"

    def control_event(self):
        with self._cv:
            if self.fd_closed:
                raise OSError(errno.EBADF, "Bad file descriptor")
            self._in_ioctl += 1
            try:
                while not self._events:
                    self._cv.wait()
                etype = self._events.pop(0)
            finally:
                self._in_ioctl -= 1
                self._maybe_release()
        return etype, None, b""

    def queue(self, etype: int) -> None:
        with self._cv:
            self._events.append(etype)
            self._cv.notify_all()

    def soft_disconnect(self) -> bool:
        from pryer import rawgadget
        self.soft_disconnects += 1
        self.queue(rawgadget.EVENT_DISCONNECT)
        return True

    def close(self) -> None:
        with self._cv:
            self.closed = self.fd_closed = True
            self._maybe_release()

    def _maybe_release(self) -> None:
        if self.fd_closed and self._in_ioctl == 0:
            self.released = True
