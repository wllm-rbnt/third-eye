"""
The iOS transport with the Pi as USB host: enumeration of the goggles, iAP2,
the tunnel, and reading it without losing data (PROTOCOL.md sections 3 and
9.3).

On a Raspberry Pi's dwc2, a bulk read longer than one URB loses data the
controller has already acknowledged. libusb splits a long read into chained
16 KiB URBs; every tunnel packet ends with a short packet, which completes the
first URB, and usbfs then cancels the rest. dwc2 has usually started the
second one by then: what arrives in it is lost, and the DATA toggle goes wrong
with it, so the host later ACKs a good packet and drops it as a duplicate.
The wire carries a complete stream while the application misses goggles
requests and pieces of video. The implementation therefore keeps independent
single-URB transfers queued (`pryer.libusb.BulkReader`), and `decode` audits a
capture for the signature (`pryer.linkaudit`).

The groups of tests:

* on a reference capture of a Pi 4B session that read the tunnel with
  256 KiB synchronous transfers (skipped when the captures are not
  available): the handover and enumeration of 2ca3:1002, iAP2 and the
  tunnel, a complete wire stream that ffmpeg decodes, and the two audits --
  goggles requests left unanswered and re-sent, and short packets the host
  ACKed and then dropped -- with `decode`'s report of both;
* the audits on synthetic traffic, including the cases where they must not
  report a loss;
* `BulkReader` and `IapHost` against a fake libusb, and a replay of the
  reference session's transfers through the queued reader into the stream
  pipeline, which delivers every request and the whole H.264 stream;
* the real libusb's asynchronous API (no device needed), the CLI's
  `--transfers` wiring, and `doctor`'s iOS checks.

Run with:  python -m pytest tests/test_host_reads.py
       or:  python tests/test_host_reads.py
"""

from __future__ import annotations

import bisect
import collections
import contextlib
import ctypes
import io
import logging
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pryer import (cli, duml, libusb, linkaudit, mfi, pcapng,  # noqa: E402
                   tunnel)
import support  # noqa: E402
from support import Skip  # noqa: E402

# A Pi 4B session through the whole iOS path, whose tunnel was read with
# 256 KiB synchronous (multi-URB) transfers.
MULTI_URB_SESSION = "11_rpi"


def _find(name: str) -> str:
    """A capture by basename fragment; skips if absent or an LFS stub."""
    return support.capture_path(name, pcapng_only=True)


_CACHE: dict = {}


def _cached(key, make):
    if key not in _CACHE:
        _CACHE[key] = make()
    return _CACHE[key]


def _control(path: str) -> list:
    return _cached(("ct", path), lambda: list(pcapng.control_transfers(path)))


def _transactions(path: str) -> list:
    return _cached(("tx", path), lambda: list(pcapng.transactions(path)))


def _decode_output(path: str) -> str:
    def run():
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = cli.main(["decode", path])
        assert rc == 0, rc
        return out.getvalue()
    return _cached(("decode", path), run)


def _swap_time(path: str) -> int:
    swaps = [c for c in _control(path) if c.bm_request_type == 0x40
             and c.b_request == mfi.APPLE_ROLE_SWAP]
    assert len(swaps) == 1, swaps
    assert swaps[0].addr == 1           # the Pi, enumerated as the iPhone
    return swaps[0].ts


MS = 1_000_000
US = 1_000


# --------------------------------------------------------------------------- #
# Reference capture: the handover and the session
# --------------------------------------------------------------------------- #
def test_the_pi_takes_over_as_host():
    path = _find(MULTI_URB_SESSION)
    t51 = _swap_time(path)
    after = [c for c in _control(path) if c.ts > t51]
    # Linux enumerates the way it always does: a 64-byte device descriptor
    # read at address 0, a second reset, then SET_ADDRESS.
    first = after[0]
    assert first.addr == 0 and first.setup[:4] == bytes.fromhex("80060001")
    assert 450 * MS < first.ts - t51 < 600 * MS, (first.ts - t51) / MS
    addr = [c for c in after if c.bm_request_type == 0 and c.b_request == 5]
    assert addr and addr[0].w_value == 2
    assert 600 * MS < addr[0].ts - t51 < 800 * MS, (addr[0].ts - t51) / MS
    desc = next(c for c in after if c.addr == 2
                and c.setup[:4] == bytes.fromhex("80060001"))
    vid = int.from_bytes(desc.data[8:10], "little")
    pid = int.from_bytes(desc.data[10:12], "little")
    assert (vid, pid) == (mfi.DJI_VID, mfi.MFI_PID)
    assert any(c.addr == 2 and c.bm_request_type == 0 and c.b_request == 9
               and c.w_value == 1 for c in after)          # SET_CONFIGURATION
    # The first high-speed handshake of the new host comes about 390 ms
    # after the swap (an iPhone: about 370 ms).
    hs = [ts for ts, msg in pcapng.log_messages(path)
          if ts > t51 and msg.startswith("Detected speed: High")]
    assert hs and 350 * MS < hs[0] - t51 < 450 * MS, (hs[0] - t51) / MS


def test_iap2_runs_and_the_tunnel_opens():
    path = _find(MULTI_URB_SESSION)
    survey = {(s.addr, s.ep, s.direction): s
              for s in pcapng.endpoint_survey(path)}
    want = {(2, 1, "IN"): (12, 1067), (2, 1, "OUT"): (6, 167),
            (2, 2, "IN"): (9956, 4174530), (2, 2, "OUT"): (89, 2301)}
    for key, (packets, nbytes) in want.items():
        assert key in survey, key
        assert (survey[key].packets, survey[key].bytes) == (packets, nbytes), \
            (key, survey[key])
    alt = [c for c in _control(path) if c.addr == 2
           and c.bm_request_type == 0x01 and c.b_request == 0x0B
           and c.w_index == mfi.EA_INTERFACE]
    assert [c.w_value for c in alt] == [mfi.EA_ALT_SETTING, 0], alt
    assert survey[(2, 2, "IN")].t_first > alt[0].ts
    assert survey[(2, 1, "OUT")].t_first < alt[0].ts


def test_the_wire_stream_is_complete():
    path = _find(MULTI_URB_SESSION)
    assert not pcapng.overflows(path)
    out = _decode_output(path)
    for line in ("usb payload bytes:  4174530",
                 "tunnel packets:     2024  (resynchronised over 0 stray "
                 "bytes)",
                 "video packets:      1086  (4033723 bytes, 173 complete "
                 "access units)",
                 "control frames:     938  (0 with a bad CRC-16)",
                 "non-IDR slice x161, IDR slice x6, SPS x6, PPS x6, AUD x167",
                 "app registration:   1 request(s) from the app, 1 accepted, "
                 "4 goggles heartbeat(s)"):
        assert line in out, (line, out)


def test_the_wire_stream_decodes_with_ffmpeg():
    path = _find(MULTI_URB_SESSION)
    if not (shutil.which("ffmpeg") and shutil.which("ffprobe")):
        raise Skip("ffmpeg/ffprobe not installed")
    tmp = tempfile.mkdtemp()
    try:
        mp4 = os.path.join(tmp, "session.mp4")
        with contextlib.redirect_stdout(io.StringIO()):
            assert cli.main(["decode", path, "-o", "mp4:" + mp4]) == 0
        probe = subprocess.run(
            ["ffprobe", "-v", "error", "-count_frames", "-select_streams",
             "v:0", "-show_entries", "stream=width,height,nb_read_frames",
             "-of", "default=nw=1", mp4],
            capture_output=True, text=True, check=True).stdout
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    assert "width=1920" in probe and "height=1080" in probe, probe
    assert "nb_read_frames=164" in probe, probe    # from the first IDR on


def test_the_session_ended_without_an_orderly_close():
    """
    Both IN endpoints stopped being polled in the same microseconds, and the
    port was never put back into gadget mode. An orderly `IapHost.close()`
    stops EP 0x82 first and EP 0x81 later, then restores the port, so this is
    what a killed process looks like on the wire.
    """
    path = _find(MULTI_URB_SESSION)
    last: dict[int, int] = {}
    for t in _transactions(path):
        if t.type == "IN" and t.addr == 2 and t.ep in (1, 2):
            last[t.ep] = t.ts
    assert abs(last[1] - last[2]) < 10 * US, (last[1] - last[2])
    assert 19.0e9 < last[2] < 19.1e9, last[2]
    back = [c for c in _control(path) if c.addr == 2 and c.b_request == 0x0B
            and c.w_index == mfi.EA_INTERFACE and c.w_value == 0]
    assert back and 300 * MS < back[0].ts - last[2] < 330 * MS
    # The Pi stayed the host: start-of-frame packets for 6 s more.
    folded = 0
    for ts, msg in pcapng.log_messages(path):
        if ts > back[0].ts and msg.startswith("Folded "):
            folded += int(msg.split()[1])
    assert folded > 40_000, folded


# --------------------------------------------------------------------------- #
# Reference capture: what the host lost
# --------------------------------------------------------------------------- #
def test_goggles_requests_went_unanswered_and_were_resent():
    req = linkaudit.request_audit(_find(MULTI_URB_SESSION))
    assert req is not None
    assert (req.sent, req.distinct, req.answered, req.unanswered,
            req.undecided) == (97, 78, 75, 21, 1)
    assert (req.resent, req.never_answered) == (13, 3)
    assert req.most_copies == 6
    assert req.most_copied == (0x03, 0x8F, 29957)   # flight_ctrl, 16.2-17.3 s
    assert req.by_command[(0x03, 0x8F)] == [75, 19]


def test_the_host_acked_and_dropped_short_packets():
    host = linkaudit.host_read_audit(_find(MULTI_URB_SESSION))
    assert host is not None and (host.addr, host.ep) == (2, 2)
    assert host.short_packets == 2023            # = the tunnel's transfers
    assert host.dropped == 102
    assert len(host.accepted_at) + host.dropped == host.short_packets
    # the two populations do not overlap
    assert min(host.repoll_ns) > 16 * US, min(host.repoll_ns)
    assert 35 < host.repoll_percentile(0.5) < 50


def test_every_unanswered_request_is_explained_by_the_host():
    """
    Where each goggles request fell relative to the previous transfer, and
    whether the app answered it:

    * dropped signature (the host re-polled within 12 us): 12, all lost;
    * less than 50 us after an accepted transfer, where the read's second URB
      was polling while usbfs cancelled it: 14, 9 lost (22-44 us after);
    * after a dropped packet, whose transfer the host never saw end, so the
      URB was still open: 14, none lost;
    * anywhere else, i.e. the start of a read of its own: 56, none lost.
    """
    path = _find(MULTI_URB_SESSION)
    req = linkaudit.request_audit(path)
    host = linkaudit.host_read_audit(path)
    dropped = set(host.dropped_at)
    shorts = sorted(host.accepted_at + host.dropped_at)
    kinds: collections.Counter = collections.Counter()
    lost_gaps = []
    for ts in req.answered_at | req.unanswered_at:
        lost = ts in req.unanswered_at
        i = bisect.bisect_left(shorts, ts)
        prev = shorts[i - 1]
        if ts in dropped:
            kind = "dropped"
        elif prev in dropped:
            kind = "after a dropped packet"
        elif ts - prev < 50 * US:
            kind = "second URB"
            if lost:
                lost_gaps.append(ts - prev)
        else:
            kind = "own read"
        kinds[kind, "lost" if lost else "answered"] += 1
    assert kinds == {("dropped", "lost"): 12,
                     ("second URB", "lost"): 9,
                     ("second URB", "answered"): 5,
                     ("after a dropped packet", "answered"): 14,
                     ("own read", "answered"): 56}, kinds
    assert 20 * US < min(lost_gaps) and max(lost_gaps) < 45 * US, lost_gaps
    assert linkaudit.cross_check(req, host) == (12, 12, 84, 9)


def test_decode_reports_what_the_host_lost():
    out = _decode_output(_find(MULTI_URB_SESSION))
    assert ("app replies:        75 of 97 goggles requests that asked for a "
            "reply were answered, 21 were not (1 too close to the end of the "
            "capture to tell)") in out, out
    assert "sent 13 request(s) more than once, one of them 6 times" in out
    assert ("host reads:         102 of 2023 short packets on EP 0x82 IN "
            "were ACKed and then dropped by the host (it polled again within "
            "12 us, as if nothing had arrived)") in out, out
    assert ("after the other short packets, the host polled again a median "
            "42 us later (p99 14.3 ms)") in out, out
    assert ("12 of those packets carried a request: 12 went unanswered, "
            "against 9 of the 84 other requests") in out, out
    assert "-> the host lost data the goggles had delivered" in out
    assert "PROTOCOL.md 9.3" in out


def _describe_with(req, host) -> str:
    saved = linkaudit.request_audit, linkaudit.host_read_audit
    linkaudit.request_audit = lambda _path: req
    linkaudit.host_read_audit = lambda _path: host
    try:
        return "\n".join(linkaudit.describe("unused.pcapng"))
    finally:
        linkaudit.request_audit, linkaudit.host_read_audit = saved


def test_decode_does_not_call_a_fast_host_lossy():
    """The timing alone is not enough: the requests have to agree."""
    req = linkaudit.RequestAudit(sent=10, distinct=10,
                                 answered_at={1000, 2000, 3000})
    host = linkaudit.HostReadAudit(2, 2, short_packets=50,
                                   dropped_at=[1000, 2000, 3000],
                                   accepted_at=[5000], repoll_ns=[1500])
    out = _describe_with(req, host)
    assert "10 of 10 goggles requests that asked for a reply" in out, out
    assert ("3 of 50 short packets on EP 0x82 IN were followed by another IN "
            "token within 12 us") in out, out
    assert "3 of those packets carried a request: 0 went unanswered" in out
    assert "no sign of a loss" in out, out
    assert "dropped" not in out and "lost data" not in out, out
    # With no request among them there is nothing to confirm a loss either.
    host.dropped_at = [1500, 2500]
    out = _describe_with(req, host)
    assert "nothing confirms a loss" in out and "dropped" not in out, out
    assert "of those packets carried a request" not in out, out


def test_decode_survives_an_audit_that_fails():
    saved = linkaudit.describe

    def boom(_path):
        raise ValueError("truncated block")
    linkaudit.describe = boom
    try:
        path = _find(MULTI_URB_SESSION)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            assert cli.main(["decode", path]) == 0
    finally:
        linkaudit.describe = saved
    assert ("link audit:         skipped (ValueError: truncated block)"
            in out.getvalue()), out.getvalue()
    assert "app registration:" in out.getvalue()


def test_decode_on_a_clean_host_read():
    req = linkaudit.RequestAudit(sent=5, distinct=5, answered_at={1, 2})
    host = linkaudit.HostReadAudit(2, 2, short_packets=40,
                                   accepted_at=[1, 2], repoll_ns=[40_000])
    out = _describe_with(req, host)
    assert ("none of 40 short packets on EP 0x82 IN was polled past within "
            "12 us") in out, out
    assert ("after each one, the host polled again a median 40 us later"
            in out), out
    assert "->" not in out


# --------------------------------------------------------------------------- #
# Unit tests: the audits on synthetic traffic
# --------------------------------------------------------------------------- #
def _in(ts_us: float, n: int | None = None, hs: str = "ACK", ep: int = 2,
        addr: int = 2) -> pcapng.Transaction:
    return pcapng.Transaction(int(ts_us * US), "IN", addr, ep,
                              None if n is None else bytes(n),
                              hs if n is not None else "NAK", 0)


def test_audit_host_reads_tells_dropped_from_accepted_packets():
    txs = [
        _in(0, 512),                 # full-size: not the end of a transfer
        _in(10.6, 100),              # short ...
        _in(13.0),                   # ... polled again 2.4 us later: dropped
        _in(20, 200),                # short ...
        _in(21, ep=1),               # (another endpoint)
        _in(22, 64, addr=3),         # (another device)
        _in(60),                     # ... next token 40 us later: accepted
        _in(100, 0),                 # zero-length packet, accepted
        _in(130, 512),
        _in(140, 30),                # short, nothing after it
    ]
    a = linkaudit.audit_host_reads(txs, 2, 2)
    assert a.short_packets == 4
    assert a.dropped_at == [10_600]
    assert a.accepted_at == [20_000, 100_000]
    assert a.repoll_ns == [40_000, 30_000]
    assert a.repoll_percentile(0.5) in (30.0, 40.0)


def _request(seq: int, cmd=(0x03, 0x8F), src: int = 0x03,
             ack_type: int = 2) -> duml.Frame:
    raw = duml.build(src, duml.DEV_MOBILE_APP, seq, cmd[0], cmd[1], b"\x01",
                     ack_type=ack_type)
    return duml.parse_all(raw)[0]


def _reply(req: duml.Frame) -> duml.Frame:
    return duml.parse_all(req.make_ack())[0]


def test_audit_requests_counts_answers_resends_and_the_end_of_capture():
    a, b, c, d = (_request(n) for n in (1, 2, 3, 4))
    ignored = [_request(5, ack_type=0),                 # wants no reply
               duml.parse_all(duml.build(0x03, 0x06, 6, 0, 0x81))[0]]
    requests = [(0, a), (10 * MS, b), (210 * MS, b), (300 * MS, c),
                (950 * MS, d)] + [(5 * MS, f) for f in ignored]
    replies = [(2 * MS, _reply(a)), (212 * MS, _reply(b))]
    r = linkaudit.audit_requests(requests, replies, end_ns=1000 * MS)
    assert (r.sent, r.distinct, r.answered, r.unanswered, r.undecided) \
        == (5, 4, 2, 2, 1)
    assert (r.resent, r.most_copies, r.never_answered) == (1, 2, 2)
    assert r.unanswered_at == {10 * MS, 300 * MS}
    assert r.answered_at == {0, 210 * MS}
    assert r.by_command[(0x03, 0x8F)] == [5, 2]


def test_a_late_reply_does_not_answer_an_earlier_copy():
    b = _request(2)
    r = linkaudit.audit_requests([(0, b), (200 * MS, b)],
                                 [(201 * MS, _reply(b))], end_ns=10 ** 12)
    assert r.unanswered_at == {0} and r.answered_at == {200 * MS}


# --------------------------------------------------------------------------- #
# Unit tests: the queued reader, against a fake libusb
# --------------------------------------------------------------------------- #
class FakeLib:
    """
    libusb's asynchronous API, in Python and driven by the test.

    Submitted transfers wait in `queue` in submission order, as usbfs keeps
    one endpoint's URBs. `deliver()` completes the oldest one the way the
    kernel would. Cancelling completes a transfer with CANCELLED, at once or
    from a timer thread standing in for libusb's event loop.
    """

    def __init__(self, *, cancel_completes: bool = True,
                 threaded: bool = False):
        self.transfers: dict[int, tuple] = {}
        self.queue: list[int] = []
        self.submits: list[tuple] = []
        self.freed: list[int] = []
        self.cancels = 0
        self.cancel_completes = cancel_completes
        self.threaded = threaded
        self.fail_submit = 0
        self.lock = threading.RLock()

    # the libusb entry points BulkReader uses
    def libusb_alloc_transfer(self, iso):
        assert iso == 0
        tr = libusb.Transfer()
        ptr = ctypes.pointer(tr)
        self.transfers[ctypes.addressof(tr)] = (tr, ptr)
        return ptr

    def libusb_free_transfer(self, ptr):
        addr = ctypes.addressof(ptr.contents)
        assert addr not in self.queue, "freed while libusb owns it"
        assert addr not in self.freed, "freed twice"
        self.freed.append(addr)

    def libusb_submit_transfer(self, ptr):
        if self.fail_submit:
            return self.fail_submit
        tr = ptr.contents
        addr = ctypes.addressof(tr)
        with self.lock:
            assert addr not in self.queue, "submitted twice"
            assert addr not in self.freed, "submitted after free"
            self.queue.append(addr)
            self.submits.append((addr, tr.length, tr.flags, tr.timeout,
                                 tr.endpoint, tr.type))
        return 0

    def libusb_cancel_transfer(self, ptr):
        addr = ctypes.addressof(ptr.contents)
        with self.lock:
            self.cancels += 1
            if addr not in self.queue:
                return libusb.ERROR_NOT_FOUND
            if not self.cancel_completes:
                return 0
            self.queue.remove(addr)
        if self.threaded:
            threading.Timer(0.01, self._finish,
                            (addr, libusb.TRANSFER_CANCELLED, b"")).start()
        else:
            self._finish(addr, libusb.TRANSFER_CANCELLED, b"")
        return 0

    def libusb_handle_events_timeout_completed(self, *_a):
        return 0

    # test side
    def deliver(self, data: bytes = b"",
                status: int = libusb.TRANSFER_COMPLETED) -> None:
        with self.lock:
            addr = self.queue.pop(0)
        self._finish(addr, status, data)

    def _finish(self, addr: int, status: int, data: bytes) -> None:
        tr, ptr = self.transfers[addr]
        assert len(data) <= tr.length
        if data:
            ctypes.memmove(tr.buffer, data, len(data))
        tr.actual_length = len(data)
        tr.status = status
        tr.callback(ptr)


class FakeContext:
    def __init__(self):
        self.started = 0

    def start_events(self):
        self.started += 1

    def stop_events(self):
        pass


class FakeDevice:
    """Just what BulkReader and IapHost touch on a libusb.Device."""

    def __init__(self, lib: FakeLib | None = None):
        self.lib = lib or FakeLib()
        self.ctx = FakeContext()
        self.handle = ctypes.c_void_p(0x1000)
        self.calls: list = []
        self.readers: list = []
        self.sync_reads: list = []

    def claim(self, iface):
        self.calls.append(("claim", iface))

    def set_alt(self, iface, alt):
        self.calls.append(("alt", iface, alt))

    def bulk_reader(self, ep, size=libusb.MAX_URB_SIZE, count=8):
        reader = libusb.BulkReader(self, ep, size=size, count=count)
        reader.start()
        self.readers.append(reader)
        self.calls.append(("reader", ep, size, count))
        return reader

    def bulk_read(self, ep, length, timeout=1000):
        self.sync_reads.append((ep, length, timeout))
        return b"sync"

    def bulk_write(self, ep, data, timeout=1000):
        return len(data)

    def close(self):
        assert all(r.in_flight == 0 for r in self.readers), \
            "interfaces released with transfers in flight"
        self.calls.append(("close",))


def _reader(count: int = 4, **kw):
    dev = FakeDevice(FakeLib(**kw))
    reader = libusb.BulkReader(dev, 0x82, size=libusb.MAX_URB_SIZE,
                               count=count)
    reader.start()
    return dev.lib, reader, dev


def test_bulk_reader_queues_independent_single_urb_transfers():
    lib, reader, dev = _reader(count=8)
    assert dev.ctx.started == 1            # completions need an event loop
    assert reader.in_flight == 8 and len(lib.queue) == 8
    for _addr, length, flags, timeout, ep, kind in lib.submits:
        assert length == libusb.MAX_URB_SIZE == 16384
        assert flags == 0                  # no SHORT_NOT_OK, nothing chained
        assert timeout == 0                # a timeout would be a cancellation
        assert ep == 0x82 and kind == libusb.TRANSFER_TYPE_BULK
    assert lib.cancels == 0
    reader.close()


def test_bulk_reader_rejects_a_transfer_longer_than_one_urb():
    for size in (0, libusb.MAX_URB_SIZE + 1, 256 * 1024):
        try:
            libusb.BulkReader(FakeDevice(), 0x82, size=size)
        except ValueError:
            continue
        raise AssertionError("size %d accepted" % size)


def test_bulk_reader_keeps_order_and_resubmits_from_the_callback():
    lib, reader, _dev = _reader(count=4)
    first = list(lib.queue)
    lib.deliver(b"A" * 4104)
    lib.deliver(b"B" * 23)
    lib.deliver(b"")                       # a zero-length packet: no data
    lib.deliver(b"C" * 290)
    # each transfer went straight back to the end of the queue, and nothing
    # was ever cancelled
    assert lib.queue == first and reader.in_flight == 4 and lib.cancels == 0
    assert reader.read(0) == b"A" * 4104 + b"B" * 23 + b"C" * 290
    assert reader.read(0.01) == b""        # nothing more: times out empty
    assert reader.completions == 4 and reader.bytes == 4104 + 23 + 290
    reader.close()


def test_bulk_reader_read_is_bounded_but_never_splits_a_chunk():
    lib, reader, _dev = _reader(count=4)
    for n in range(6):
        lib.deliver(bytes([n]) * 4000)
    assert len(reader.read(0, max_bytes=9000)) == 8000
    assert len(reader.read(0, max_bytes=100)) == 4000
    assert len(reader.read(0)) == 12000
    reader.close()


def test_bulk_reader_wakes_a_blocked_read():
    lib, reader, _dev = _reader(count=2)
    got = []
    t = threading.Thread(target=lambda: got.append(reader.read(5.0)))
    t.start()
    time.sleep(0.05)
    lib.deliver(b"x" * 10)
    t.join(2.0)
    assert got == [b"x" * 10]
    reader.close()


def test_bulk_reader_parks_transfers_when_the_reader_falls_behind():
    dev = FakeDevice()
    lib = dev.lib
    reader = libusb.BulkReader(dev, 0x82, count=3, max_backlog=4)
    reader.start()
    for n in range(4):
        lib.deliver(b"%d" % n)
    # the fourth unread chunk parked its transfer instead of resubmitting it
    assert reader.parks == 1 and reader.in_flight == 2 and len(lib.queue) == 2
    assert reader.read(0) == b"0123"
    assert reader.in_flight == 3 and len(lib.queue) == 3   # revived
    reader.close()


def test_bulk_reader_raises_an_error_after_the_data_before_it():
    lib, reader, _dev = _reader(count=4)
    lib.deliver(b"good")
    lib.deliver(status=libusb.TRANSFER_STALL)
    assert reader.read(0) == b"good"
    try:
        reader.read(0)
    except libusb.UsbError as exc:
        assert exc.code == libusb.ERROR_PIPE, exc
    else:
        raise AssertionError("no error")
    assert reader.in_flight == 0 and not lib.queue   # the rest was cancelled
    reader.close()
    assert len(lib.freed) == 4


def test_bulk_reader_reports_a_vanished_device():
    lib, reader, _dev = _reader(count=2)
    lib.deliver(status=libusb.TRANSFER_NO_DEVICE)
    try:
        reader.read(0)
    except libusb.UsbError as exc:
        assert exc.code == libusb.ERROR_NO_DEVICE
        assert isinstance(exc, OSError)     # what cmd_stream's loop catches
    else:
        raise AssertionError("no error")
    reader.close()


def test_bulk_reader_close_cancels_waits_for_libusb_and_frees():
    lib, reader, _dev = _reader(count=8, threaded=True)
    lib.deliver(b"data")
    reader.close()
    assert reader.in_flight == 0 and not lib.queue
    assert sorted(lib.freed) == sorted(lib.transfers)   # each exactly once
    assert reader.read(0) == b"data"       # what arrived is still readable
    assert reader.read(0) == b""           # then: closed, empty
    reader.close()                         # idempotent


def test_bulk_reader_close_unblocks_a_waiting_read():
    _lib, reader, _dev = _reader(count=2, threaded=True)
    got = []
    t = threading.Thread(target=lambda: got.append(reader.read(None)))
    t.start()
    time.sleep(0.05)
    reader.close()
    t.join(2.0)
    assert got == [b""] and not t.is_alive()


def test_bulk_reader_never_frees_a_transfer_libusb_still_owns():
    lib, reader, _dev = _reader(count=3, cancel_completes=False)
    logging.disable(logging.WARNING)
    try:
        t0 = time.monotonic()
        reader.close(timeout=0.2)
    finally:
        logging.disable(logging.NOTSET)
    assert time.monotonic() - t0 < 1.0
    assert lib.freed == []                 # leaked on purpose ...
    assert reader in libusb._LEAKED        # ... and kept alive for good
    libusb._LEAKED.remove(reader)


def test_bulk_reader_start_failure_cleans_up():
    lib = FakeLib()
    lib.fail_submit = libusb.ERROR_NO_DEVICE
    reader = libusb.BulkReader(FakeDevice(lib), 0x82, count=4)
    try:
        reader.start()
    except libusb.UsbError:
        pass
    else:
        raise AssertionError("start() did not fail")
    assert reader.in_flight == 0 and len(lib.freed) == 4


def test_sync_bulk_read_is_capped_at_one_urb():
    calls = []

    class Lib:
        def libusb_set_auto_detach_kernel_driver(self, *_a):
            return 0

        def libusb_bulk_transfer(self, handle, ep, buf, length, got, timeout):
            calls.append(length)
            return 0

    ctx = type("Ctx", (), {"lib": Lib()})()
    dev = libusb.Device(ctx, ctypes.c_void_p(1), mfi.DJI_VID, mfi.MFI_PID)
    dev.bulk_read(0x82, 256 * 1024)
    dev.bulk_read(0x82, 4096)
    assert calls == [libusb.MAX_URB_SIZE, 4096]
    dev.handle = None


# --------------------------------------------------------------------------- #
# Unit tests: IapHost on the queued reader
# --------------------------------------------------------------------------- #
def _host(**kw) -> tuple[mfi.IapHost, FakeDevice]:
    host = mfi.IapHost(**kw)
    host.dev = FakeDevice()
    host._open_ea()
    return host, host.dev


def test_iap_host_reads_the_tunnel_through_queued_transfers():
    host, dev = _host()
    assert ("claim", mfi.EA_INTERFACE) in dev.calls
    assert ("alt", mfi.EA_INTERFACE, mfi.EA_ALT_SETTING) in dev.calls
    assert ("reader", mfi.EP_EA_IN, 16384, mfi.DEFAULT_TRANSFERS) in dev.calls
    assert len(dev.lib.queue) == mfi.DEFAULT_TRANSFERS == 32
    dev.lib.deliver(b"\x55" * 4104)
    dev.lib.deliver(b"\x55" * 21)
    assert host.read() == b"\x55" * 4125
    assert dev.sync_reads == []
    host.close()
    assert dev.calls[-1] == ("close",)
    assert len(dev.lib.freed) == mfi.DEFAULT_TRANSFERS


def test_the_queued_read_path_delivers_everything_on_the_wire():
    """
    The reference session's goggles transfers, completed in wire order on the
    queued reader and read back in whatever chunks `IapHost.read()` joins,
    give the stream pipeline the same H.264 as feeding it one transfer at a
    time, and every request that asked for a reply reaches the app side: all
    97, where the multi-URB reads answered 75.
    """
    from pryer.pipeline import StreamPipeline
    path = _find(MULTI_URB_SESSION)
    transfers = linkaudit._scan(path).down
    assert len(transfers) == 2023

    class Sink:
        def __init__(self):
            self.data = bytearray()

        def write(self, data):
            self.data += data

    def wants_reply(frame) -> bool:
        return frame.dst == duml.DEV_MOBILE_APP and frame.wants_ack()

    live, requests = Sink(), []
    pipe = StreamPipeline(live, on_control=lambda f: wants_reply(f)
                          and requests.append(f.seq))
    host, dev = _host()
    for i, t in enumerate(transfers):
        dev.lib.deliver(t.data)
        if i % 7 == 3:                     # irregular reads, 1 to 7 chunks
            pipe.feed(host.read())
    while True:
        chunk = host._ea_reader.read(0)
        if not chunk:
            break
        pipe.feed(chunk)
    pipe.finish()
    host.close()

    ref = Sink()
    ref_pipe = StreamPipeline(ref)
    for t in transfers:
        ref_pipe.feed(t.data)
    ref_pipe.finish()

    assert bytes(live.data) == bytes(ref.data)
    assert len(live.data) == 4_033_723 and live.data[4] & 0x1F == 7   # SPS
    st = pipe.stats
    assert (st.tunnel_packets, st.video_packets, st.access_units,
            st.resync_bytes, st.bad_crc) == (2024, 1086, 173, 0, 0)
    assert len(requests) == linkaudit.request_audit(path).sent == 97
    assert dev.lib.cancels == mfi.DEFAULT_TRANSFERS   # only at close


def test_iap_host_transfers_0_reads_synchronously_one_urb_at_a_time():
    host, dev = _host(transfers=0)
    assert not dev.readers
    assert host.read() == b"sync"
    assert dev.sync_reads == [(mfi.EP_EA_IN, 16384, mfi.DEFAULT_TIMEOUT_MS)]
    host.close()


def test_iap_host_clamps_a_read_size_longer_than_one_urb():
    logging.disable(logging.WARNING)
    try:
        host = mfi.IapHost(read_size=256 * 1024)
    finally:
        logging.disable(logging.NOTSET)
    assert host.read_size == libusb.MAX_URB_SIZE
    assert mfi.IapHost().read_size == mfi.DEFAULT_READ_SIZE == 16384
    assert tunnel.DEFAULT_READ_SIZE == libusb.MAX_URB_SIZE


def test_iap_host_falls_back_to_synchronous_reads_without_async_libusb():
    host = mfi.IapHost()
    host.dev = FakeDevice()

    class OldLib:                          # no libusb_submit_transfer & co.
        pass

    host.dev.lib = OldLib()
    logging.disable(logging.WARNING)
    try:
        host._open_ea()
    finally:
        logging.disable(logging.NOTSET)
    assert host._ea_reader is None
    assert host.read() == b"sync"
    host.close()


def test_iap_host_services_iap2_from_its_own_reader():
    host = mfi.IapHost()
    host.dev = FakeDevice()
    host._iap_reader = host._start_reader(mfi.EP_IAP_IN, mfi.IAP_READ_SIZE,
                                          mfi.IAP_TRANSFERS)
    assert ("reader", mfi.EP_IAP_IN, 4096, 2) in host.dev.calls
    host.dev.lib.deliver(b"\xff\x5a\x00")
    assert host._read_iap() == b"\xff\x5a\x00"
    host.close()


def test_iap_host_without_hardware_still_fails_cleanly():
    host = mfi.IapHost()
    try:
        host.read()
    except RuntimeError as exc:
        assert "not open" in str(exc)
    else:
        raise AssertionError("read() on a closed link succeeded")
    host.close()


# --------------------------------------------------------------------------- #
# Unit tests: the real libusb, no device needed
# --------------------------------------------------------------------------- #
def test_real_libusb_async_api_and_event_thread():
    if not libusb.available():
        raise Skip("libusb-1.0 not installed")
    lib = libusb.library()
    assert libusb.async_available(lib)
    ptr = lib.libusb_alloc_transfer(0)
    assert ptr
    tr = ptr.contents
    assert (tr.status, tr.length, tr.num_iso_packets) == (0, 0, 0)
    lib.libusb_free_transfer(ptr)
    try:
        ctx = libusb.Context()
    except OSError as exc:
        raise Skip("libusb_init failed here: %s" % exc)
    try:
        # The timeval must read as 1 s: INVALID_PARAM would mean the layout
        # was misread, returning at once that it read as 0.
        t0 = time.monotonic()
        rc = lib.libusb_handle_events_timeout_completed(
            ctx.ctx, ctypes.cast(libusb._timeval(1), ctypes.c_void_p), None)
        dt = time.monotonic() - t0
        assert rc == 0, rc
        assert 0.8 < dt < 2.5, dt
        ctx.start_events()
        ctx.start_events()                 # once per context
        time.sleep(0.05)
        t0 = time.monotonic()
        ctx.stop_events()                  # interrupted, not waited out
        assert time.monotonic() - t0 < 0.8
    finally:
        ctx.close()


def test_transfer_struct_matches_libusb_h():
    offsets = [getattr(libusb.Transfer, f).offset for f, _t in
               libusb.Transfer._fields_]
    if ctypes.sizeof(ctypes.c_void_p) == 8:
        assert offsets == [0, 8, 9, 10, 12, 16, 20, 24, 32, 40, 48, 56]
        assert ctypes.sizeof(libusb.Transfer) == 64
    else:
        assert offsets == [0, 4, 5, 6, 8, 12, 16, 20, 24, 28, 32, 36]


# --------------------------------------------------------------------------- #
# Unit tests: CLI and doctor
# --------------------------------------------------------------------------- #
def test_stream_passes_transfers_to_the_ios_link():
    seen = []

    class Link:
        def __init__(self, *a, **k):
            seen.append(k)

        def open(self, **_k):
            pass

        def read(self, size=None):
            os.kill(os.getpid(), signal.SIGINT)    # stop after one read
            return b""

        def write(self, data):
            return len(data)

        def close(self):
            pass

    saved = (mfi.ensure_gadget_role, mfi.trigger_mfi_mode,
             mfi.switch_to_gadget_role, mfi.IapHost)
    mfi.ensure_gadget_role = lambda *a: None
    mfi.trigger_mfi_mode = lambda **k: True
    mfi.switch_to_gadget_role = lambda *a: True
    mfi.IapHost = Link
    old = signal.getsignal(signal.SIGINT), signal.getsignal(signal.SIGTERM)
    try:
        for extra in ([], ["--transfers", "0"]):
            rc = cli.main(["stream", "-t", "ios", "-o", "null", "--stats", "0",
                           "--no-register"] + extra)
            assert rc == 0
            signal.signal(signal.SIGINT, old[0])
    finally:
        (mfi.ensure_gadget_role, mfi.trigger_mfi_mode,
         mfi.switch_to_gadget_role, mfi.IapHost) = saved
        signal.signal(signal.SIGINT, old[0])
        signal.signal(signal.SIGTERM, old[1])
    assert [k["transfers"] for k in seen] == [mfi.DEFAULT_TRANSFERS, 0]
    assert all(k["read_size"] == 16384 for k in seen)


def test_cli_transfers_default_is_the_library_default():
    args = cli.build_parser().parse_args(["stream", "-t", "ios"])
    assert args.transfers == mfi.DEFAULT_TRANSFERS


def _goggles_check(devices):
    class Ctx:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def list_devices(self):
            if isinstance(devices, BaseException):
                raise devices
            return list(devices)

    saved = mfi.libusb.Context
    mfi.libusb.Context = Ctx
    try:
        return mfi._goggles_on_the_bus()
    finally:
        mfi.libusb.Context = saved


def test_doctor_does_not_flag_the_goggles_missing_from_the_bus():
    [(ok, msg)] = _goggles_check([(0x1d6b, 0x0002)])
    assert ok, msg
    assert "as expected" in msg and "USB host until the role swap" in msg
    assert "no DJI device" not in msg


def test_doctor_reports_mfi_and_pc_mode():
    [(ok, msg)] = _goggles_check([(mfi.DJI_VID, mfi.MFI_PID)])
    assert ok and "--no-trigger" in msg, msg
    [(ok, msg)] = _goggles_check([(mfi.DJI_VID, mfi.PC_MODE_PID)])
    assert not ok and "PC mode" in msg and "gadget" in msg, msg
    [(ok, msg)] = _goggles_check(OSError("boom"))
    assert not ok and "boom" in msg


def test_doctor_ios_section_has_no_enumeration_failure():
    saved = mfi.libusb.available, mfi.libusb.Context

    class Ctx:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def list_devices(self):
            return []

    mfi.libusb.available = lambda: True
    mfi.libusb.Context = Ctx
    try:
        checks = mfi.diagnose()
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            cli._doctor_ios()
    finally:
        mfi.libusb.available, mfi.libusb.Context = saved
    goggles = [c for c in checks if "goggles" in c[1]]
    assert goggles and all(ok for ok, _msg in goggles), goggles
    text = out.getvalue()
    assert "no DJI device on the USB buses" not in text
    assert "cannot be" in text and "seen on the bus" in text, text


# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    sys.exit(support.main(globals()))
