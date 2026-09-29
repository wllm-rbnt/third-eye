"""
Link writes on a thread of their own.

Why
---
On the gadget side (AOA transport) a bulk IN write completes only when the
goggles polls the IN endpoint, and the goggles does not always poll promptly:
it can leave a pending IN write uncollected for well over 100 ms. If the same
thread that reads the OUT endpoint also performs the writes, no read is queued
while it waits, and the goggles is NAKed on OUT for that whole time. Even when
the goggles collects promptly, a read followed by a write re-arms the OUT
endpoint measurably later than a read alone (about 1.9 ms against 1.6 ms on a
Raspberry Pi 4B), and that delay is paid on every transfer that carries a
request. Video leaves little slack for it (see
`pryer.tunnel.ACCESSORY_READ_SIZE`).

`AsyncWriter` puts writes on a queue that one thread drains. The read loop
never blocks on the IN endpoint, and the order of the writes is kept. Both
transports use it.

Shutdown
--------
A raw-gadget fd must not be closed while an ioctl on it is in flight (see
`pryer.rawgadget`, "Releasing the UDC between sessions"). `close()` therefore
stops the writer and waits for it to exit *before* the caller closes the link.
If the thread is stuck in a write the goggles never collects, it is sent
`rawgadget.INTERRUPT_SIGNAL`, and the ioctl returns EINTR. That is the same
fallback the ep0 thread uses.
"""

from __future__ import annotations

import errno
import logging
import queue
import signal
import threading
import time

log = logging.getLogger("pryer.linkio")

# Several seconds of the goggles' request rate. A write queue that deep means
# the goggles has stopped reading, so dropping is the right response.
DEFAULT_QUEUE = 1024
STOP_TIMEOUT = 1.0

_STOP = object()


class AsyncWriter:
    """
    ``writer(data)`` queues *data* for ``write(data)`` on a worker thread.

    Calling the instance never blocks. Writes happen in call order. If the
    queue is full, the data is dropped and counted in ``.dropped``. An OSError
    from *write* is logged and counted in ``.errors``; it does not stop the
    thread, because a bus reset can make one write fail and later ones succeed
    (the transports already wait for the relink internally).
    """

    def __init__(self, write, *, max_queue: int = DEFAULT_QUEUE,
                 name: str = "pryer-writer"):
        self._write = write
        self._q: queue.Queue = queue.Queue(max_queue)
        self._stopping = threading.Event()
        self.written = 0
        self.dropped = 0
        self.errors = 0
        self._thread = threading.Thread(target=self._run, name=name,
                                        daemon=True)
        self._thread.start()

    # ------------------------------------------------------------------ #
    def __call__(self, data: bytes) -> None:
        if self._stopping.is_set():
            return
        try:
            self._q.put_nowait(data)
        except queue.Full:
            self.dropped += 1
            if self.dropped == 1 or self.dropped % 100 == 0:
                log.warning("write queue full (%d queued): the goggles is not "
                            "reading; %d write(s) dropped so far",
                            self._q.qsize(), self.dropped)

    @property
    def pending(self) -> int:
        return self._q.qsize()

    def _run(self) -> None:
        while True:
            item = self._q.get()
            if item is _STOP or self._stopping.is_set():
                return
            try:
                self._write(item)
                self.written += 1
            except OSError as exc:
                if self._stopping.is_set():
                    return
                if exc.errno == errno.EINTR:
                    continue
                self.errors += 1
                log.warning("write failed: %s", exc)
            except Exception as exc:          # noqa: BLE001 - keep the thread
                if self._stopping.is_set():
                    return
                self.errors += 1
                log.warning("write failed: %s", exc)

    # ------------------------------------------------------------------ #
    def close(self, timeout: float = STOP_TIMEOUT) -> bool:
        """
        Stop the thread and wait for it. Returns True if it has exited.

        Anything still queued is discarded. Call this *before* closing the
        link.
        """
        self._stopping.set()
        while True:                      # make room for the stop marker
            try:
                self._q.put_nowait(_STOP)
                break
            except queue.Full:
                try:
                    self._q.get_nowait()
                except queue.Empty:
                    pass
        t = self._thread
        t.join(min(0.2, timeout))
        deadline = time.monotonic() + timeout
        while t.is_alive() and time.monotonic() < deadline:
            _interrupt(t)
            t.join(0.05)
        if t.is_alive():
            log.error("the writer thread is stuck in a write and could not be "
                      "woken; the link may not be released cleanly")
            return False
        return True


def _interrupt(thread: threading.Thread) -> None:
    """Make a blocked ioctl in *thread* return EINTR, if the handler is set."""
    from . import rawgadget        # late: rawgadget is Linux-specific
    if not getattr(rawgadget, "_interrupt_ready", False):
        return
    if thread.ident is None:
        return
    try:
        signal.pthread_kill(thread.ident, rawgadget.INTERRUPT_SIGNAL)
    except (OSError, ValueError, AttributeError):
        pass
