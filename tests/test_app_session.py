"""
The app side of the control channel: registration, replies and writes
(PROTOCOL.md sections 6 and 7).

A healthy accessory link carries control traffic in both directions, but the
goggles sends no video until the app registers with its fpga_air.1 module
(0x3C) using two 0x00/0x88 requests; video follows 20-40 ms after the second
reply. The groups of tests:

* byte-exact checks of what `AppSession` sends against a handset's frames:
  registration, heartbeat reply, identity reply, generic ACK;
* the registration state machine: retry every second, brought forward by the
  goggles' identity request, stopped once accepted;
* `AsyncWriter` (writes off the read loop) and the accessory read buffer;
* `stream` end to end against a fake goggles that only sends video once
  registered, and the fact that no app start-up traffic is sent on either
  transport;
* on a reference capture of a session without registration (skipped when
  the captures are not available): control traffic, no video, no 0x00/0x88
  in either direction, the goggles repeating its requests, and `decode`
  naming the missing registration.

Run with:  python -m pytest tests/test_app_session.py
       or:  python tests/test_app_session.py
"""

from __future__ import annotations

import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pryer import app, duml, pcapng, tunnel  # noqa: E402
from pryer.app import AppSession  # noqa: E402
from pryer.linkio import AsyncWriter  # noqa: E402
import support  # noqa: E402

# A Pi 4B session with a working accessory link and no app registration.
UNREGISTERED_SESSION = "F_rpi"


def _unregistered_capture() -> str:
    return support.capture_path(UNREGISTERED_SESSION, pcapng_only=True)


_FRAMES: dict = {}


def _frames(direction: str) -> list[duml.Frame]:
    """DUML frames on addr 1 EP 1; OUT = goggles->Pi, IN = Pi->goggles."""
    if direction not in _FRAMES:
        path = _unregistered_capture()
        out, video = [], 0
        for t in pcapng.transfers(path, 1, 1, direction):
            for pkt in tunnel.demux_bytes(t.data)[0]:
                if pkt.is_video:
                    video += 1
                    continue
                out.extend(duml.parse_all(pkt.payload))
        _FRAMES[direction] = (out, video)
    return _FRAMES[direction]


def _unwrap(tunnel_bytes: bytes) -> duml.Frame:
    pkts, _ = tunnel.demux_bytes(tunnel_bytes)
    assert len(pkts) == 1 and pkts[0].channel == tunnel.CH_CONTROL
    frames = duml.parse_all(pkts[0].payload)
    assert len(frames) == 1
    return frames[0]


# --------------------------------------------------------------------------- #
# A session without registration (reference capture)
# --------------------------------------------------------------------------- #
def test_unregistered_session_has_control_traffic_but_no_video():
    frames, video = _frames("OUT")
    assert video == 0
    assert len(frames) == 1790, len(frames)
    assert all(f.valid for f in frames)


def test_unregistered_session_has_no_0088_in_either_direction():
    """No 0x00/0x88 at all, so no heartbeat from the goggles either."""
    for direction in ("OUT", "IN"):
        frames, _ = _frames(direction)
        assert not [f for f in frames if f.key == (0x00, 0x88)], direction


def test_a_generic_identity_ack_makes_the_goggles_keep_asking():
    """fpga_air.5's 0x00/0x81 answered with a bare 00 is asked again."""
    down, _ = _frames("OUT")
    up, _ = _frames("IN")
    asks = [f for f in down if f.key == (0x00, 0x81)]
    replies = [f for f in up if f.key == (0x00, 0x81)]
    assert len(asks) == 4 and {f.src for f in asks} == {app.DEV_FPGA_AIR_5}
    assert asks[0].payload.startswith(b"ZV902")
    assert [f.payload for f in replies] == [b"\x00"] * 4


def test_unregistered_session_flight_ctrl_8f_is_repeated():
    """
    The 03/8f log-file announcement came 394 times, same payload, fresh seq
    each time (~41/s), although every one got the generic 00 ACK.
    """
    down, _ = _frames("OUT")
    up, _ = _frames("IN")
    frames = [f for f in down if f.key == (0x03, 0x8F)
              and f.payload[:3] == b"\x01\x01\x01"]
    assert len(frames) == 394
    assert len({f.payload for f in frames}) == 1
    assert len({f.seq for f in frames}) == 394
    assert b"USR364.DAT" in frames[0].payload
    assert b"DJI_LOG_V3" in frames[0].payload
    acks = [f.payload for f in up if f.key == (0x03, 0x8F)]
    assert acks == [b"\x00"] * 395


def test_decode_reports_the_missing_registration():
    from pryer import cli
    path = _unregistered_capture()

    class St:
        video_packets = 0
        control_frames = 1790
    lines = cli._registration_lines(path, [], St())
    assert lines[0].startswith("app registration:   0 request(s)")
    assert any("never registered" in line for line in lines)


# --------------------------------------------------------------------------- #
# What AppSession sends, against a handset's frames
# --------------------------------------------------------------------------- #
HANDSET_REGISTER = bytes.fromhex(
    "551b0475023c7a954000881700002300415050000000000002dd4e")
HANDSET_VERSION = bytes.fromhex(
    "551d04df023c25964000881d000100000000010700312e32312e3152e1")
GOGGLES_HEARTBEAT = bytes.fromhex("550f04a23c029b064000881900fd53")
HANDSET_HEARTBEAT_REPLY = bytes.fromhex(
    "551204c7023c9b068000881a00000000bd86")
GOGGLES_IDENTIFY = bytes.fromhex(
    "554d04a8bc02860b4000815a563930320000000000000000000000000000000000"
    "00000000000000000000051c000000000000051c00000000000000000000000000"
    "0000000000000000008959")
GOGGLES_REGISTER_OK = bytes.fromhex("551104923c027a95c000881800000043bd")


def _parse(raw: bytes) -> duml.Frame:
    frames = duml.parse_all(raw)
    assert len(frames) == 1 and frames[0].valid
    return frames[0]


def test_registration_frames_match_the_handset_byte_for_byte():
    sent: list[bytes] = []
    s = AppSession(sent.append, seq_start=0x957A)
    s.register()
    assert len(sent) == 2
    first = _unwrap(sent[0])
    assert first.raw == HANDSET_REGISTER
    # The handset's second frame has another seq; rebuild ours with it.
    second = _unwrap(sent[1])
    handset = _parse(HANDSET_VERSION)
    assert duml.build(second.src, second.dst, handset.seq, second.cmd_set,
                      second.cmd_id, second.payload,
                      ack_type=second.ack_type) == HANDSET_VERSION


def test_heartbeat_reply_matches_the_handset():
    sent: list[bytes] = []
    s = AppSession(sent.append)
    s.on_control_frame(_parse(GOGGLES_HEARTBEAT))
    assert [_unwrap(b).raw for b in sent] == [HANDSET_HEARTBEAT_REPLY]
    assert s.heartbeats == 1


def test_identity_reply_matches_the_handset():
    sent: list[bytes] = []
    s = AppSession(sent.append, register=False)
    s.on_control_frame(_parse(GOGGLES_IDENTIFY))
    reply = _unwrap(sent[0])
    assert reply.is_response and reply.ack_type == 0
    assert (reply.src, reply.dst) == (0x02, app.DEV_FPGA_AIR_5)
    assert reply.payload == app.IDENTITY_REPLY
    # Same bytes as the handset's reply, apart from seq and CRC.
    handset = bytes.fromhex(
        "554d04a802bc880b8000810041505000000000000000000000000000000000000000"
        "000000000000000000000002000000000000051c00000000000000000000000000000"
        "0000000000000333d")
    assert reply.raw[:6] == handset[:6] and reply.raw[8:-2] == handset[8:-2]


def test_other_requests_still_get_the_generic_ack():
    req = duml.build(0x28, 0x02, 7, 0x00, 0x82, b"WA020", ack_type=2)
    sent: list[bytes] = []
    AppSession(sent.append).on_control_frame(_parse(req))
    assert _unwrap(sent[0]).payload == b"\x00"


# --------------------------------------------------------------------------- #
# Registration state machine
# --------------------------------------------------------------------------- #
class Clock:
    def __init__(self):
        self.t = 100.0

    def __call__(self):
        return self.t


def _registers(sent) -> int:
    return sum(1 for b in sent if _unwrap(b).payload[:1] == b"\x17")


def test_registration_retries_every_second_until_accepted():
    clock, sent = Clock(), []
    s = AppSession(sent.append, clock=clock)
    s.start()
    assert _registers(sent) == 1
    s.poll()
    assert _registers(sent) == 1                     # not due yet
    clock.t += app.REGISTER_RETRY
    s.poll()
    assert _registers(sent) == 2
    ok = _parse(GOGGLES_REGISTER_OK)                 # 3c -> 02, 18 00 00 00
    s.on_control_frame(ok)
    assert s.registered and s.registered_at == clock.t
    clock.t += 10
    s.poll()
    assert _registers(sent) == 2                     # stops once accepted
    assert not any(_unwrap(b).is_response for b in sent)  # we never ACK an ACK


def test_identity_request_triggers_an_immediate_registration():
    clock, sent = Clock(), []
    s = AppSession(sent.append, clock=clock)
    s.start()
    clock.t += 0.1
    s.on_control_frame(_parse(GOGGLES_IDENTIFY))
    s.poll()
    assert _registers(sent) == 1           # the first attempt may still land
    clock.t += app.REGISTER_MIN_GAP - 0.1
    s.poll()
    assert _registers(sent) == 2           # well before REGISTER_RETRY


def test_identity_before_any_attempt_registers_at_once():
    clock, sent = Clock(), []
    s = AppSession(sent.append, clock=clock)
    s.on_control_frame(_parse(GOGGLES_IDENTIFY))
    s.poll()
    assert _registers(sent) == 1


def test_no_register_sends_nothing():
    sent: list[bytes] = []
    s = AppSession(sent.append, register=False)
    s.start()
    s.poll()
    assert sent == []


def test_registration_does_not_depend_on_init():
    """No app init on either transport, and still registration."""
    import argparse
    from pryer import cli
    for argv in (["stream"], ["stream", "-t", "ios"]):
        ns = cli.build_parser().parse_args(argv)
        assert isinstance(ns, argparse.Namespace) and ns.register is True
    ns = cli.build_parser().parse_args(["stream", "--no-register"])
    assert ns.register is False and ns.read_size is None


# --------------------------------------------------------------------------- #
# Writes off the read loop
# --------------------------------------------------------------------------- #
def test_async_writer_keeps_order_and_never_blocks_the_caller():
    gate = threading.Event()
    got: list[bytes] = []

    def slow_write(data):
        gate.wait(2)                 # the goggles is not polling IN yet
        got.append(data)

    w = AsyncWriter(slow_write)
    t0 = time.monotonic()
    for i in range(50):
        w(bytes([i]))
    assert time.monotonic() - t0 < 0.1
    gate.set()
    deadline = time.monotonic() + 2
    while len(got) < 50 and time.monotonic() < deadline:
        time.sleep(0.01)
    assert got == [bytes([i]) for i in range(50)]
    assert w.close()


def test_async_writer_drops_when_full_and_survives_errors():
    gate = threading.Event()
    calls = []

    def write(data):
        gate.wait(2)
        calls.append(data)
        if data == b"bad":
            raise OSError(5, "EIO")

    w = AsyncWriter(write, max_queue=2)
    w(b"a")
    time.sleep(0.05)                 # "a" is in write(); queue is empty
    w(b"bad")
    w(b"c")
    w(b"d")                          # queue full
    assert w.dropped == 1
    gate.set()
    deadline = time.monotonic() + 2
    while len(calls) < 3 and time.monotonic() < deadline:
        time.sleep(0.01)
    assert calls == [b"a", b"bad", b"c"] and w.errors == 1
    assert w.close()


def test_accessory_reads_are_small_and_reuse_one_buffer():
    from pryer import rawgadget
    assert tunnel.ACCESSORY_READ_SIZE == 16 * 1024
    seen = []

    def fake_ioctl(fd, request, buf):
        seen.append(buf)
        import ctypes
        ctypes.memmove(ctypes.byref(buf, 8), b"hello", 5)
        return 5

    g = rawgadget.RawGadget.__new__(rawgadget.RawGadget)
    g.fd = -1
    old = rawgadget._ioctl
    rawgadget._ioctl = fake_ioctl
    try:
        assert g.ep_read(1, tunnel.ACCESSORY_READ_SIZE) == b"hello"
        assert g.ep_read(1, tunnel.ACCESSORY_READ_SIZE) == b"hello"
    finally:
        rawgadget._ioctl = old
    assert seen[0] is seen[1]


# --------------------------------------------------------------------------- #
# End to end: cmd_stream against a goggles that wants to be registered
# --------------------------------------------------------------------------- #
class RegisteringGoggles:
    """
    A fake AOA link that behaves like the goggles until it is registered:
    control traffic only, one identity request, and video only after
    0x00/0x88 17.. Like the goggles, it never polls IN before its first packet
    has been read (writes block until then), so a client that writes before
    it starts reading would hang.
    """

    def __init__(self):
        self.lock = threading.Lock()
        self.out: list[bytes] = [
            tunnel.encode(tunnel.CH_CONTROL, GOGGLES_IDENTIFY)]
        self.first_read = threading.Event()
        self.writes: list[tuple[str, duml.Frame]] = []
        self.reads = 0
        self.registered = False

    def write(self, data: bytes) -> None:
        self.first_read.wait(5)
        f = _unwrap(data)
        with self.lock:
            self.writes.append((threading.current_thread().name, f))
            if f.key == (0x00, 0x88) and f.payload[:1] == b"\x17":
                self.registered = True
                self.out.append(tunnel.encode(tunnel.CH_CONTROL, duml.build(
                    f.dst, f.src, f.seq, 0x00, 0x88, b"\x18\x00\x00\x00",
                    is_response=True, ack_type=2)))
                au = b"\x00\x00\x00\x01\x65" + bytes(100)
                for _ in range(5):
                    self.out.append(tunnel.encode(tunnel.CH_VIDEO, au))

    def read(self) -> bytes:
        self.reads += 1
        self.first_read.set()
        time.sleep(0.005)
        with self.lock:
            if self.out:
                return self.out.pop(0)
            if self.registered and self.reads > 200:
                raise OSError(5, "end of test")
        heartbeat = duml.build(0x3C, 0x02, self.reads, 0x00, 0x03, b"\x00",
                               ack_type=0)
        return tunnel.encode(tunnel.CH_CONTROL, heartbeat)

    def close(self):
        pass


def test_stream_registers_and_receives_video_end_to_end():
    import logging
    from pryer import cli
    fake = RegisteringGoggles()
    records: list[str] = []

    class Grab(logging.Handler):
        def emit(self, record):
            records.append(record.getMessage())
    h = Grab()
    lg = logging.getLogger("pryer")
    lg.addHandler(h)
    old_level = lg.level
    lg.setLevel(logging.INFO)
    old = cli.TRANSPORTS["aoa"]
    cli.TRANSPORTS["aoa"] = lambda args: fake
    try:
        args = cli.build_parser().parse_args(
            ["stream", "-o", "null", "--stats", "0", "--no-wait-keyframe",
             "--inject", "never"])
        t0 = time.monotonic()
        args.func(args)
        assert time.monotonic() - t0 < 10
    finally:
        cli.TRANSPORTS["aoa"] = old
        lg.removeHandler(h)
        lg.setLevel(old_level)
    assert fake.registered
    # no app init on aoa: the only requests are the registration
    assert all(f.is_response or f.key == app.CMD_LINK
               for _t, f in fake.writes)
    kinds = [(f.key, f.payload[:1]) for _t, f in fake.writes]
    assert ((0x00, 0x81), b"\x00") in kinds             # identity reply
    assert kinds.count(((0x00, 0x88), b"\x17")) == 1     # accepted first time
    assert all(name == "pryer-writer" for name, _f in fake.writes)
    final = [r for r in records if r.startswith("final:")][0]
    assert "  5 frames" in final or " 5 frames" in final, final
    assert any("accepted the app registration" in r for r in records)


# --------------------------------------------------------------------------- #
# stream's app traffic and phase-1 identity are fixed, not options
# --------------------------------------------------------------------------- #
def test_stream_has_no_init_or_phone_profile_option():
    import contextlib
    import io
    from pryer import cli
    for argv in (["stream", "--init", "none"],
                 ["stream", "--phone-profile", "minimal"]):
        with contextlib.redirect_stderr(io.StringIO()):
            try:
                cli.build_parser().parse_args(argv)
            except SystemExit as exc:
                assert exc.code == 2, argv
            else:
                raise AssertionError("%r was accepted" % argv)
    ns = cli.build_parser().parse_args(["stream"])
    assert not hasattr(ns, "init") and not hasattr(ns, "phone_profile")


def test_aoa_presents_the_minimal_phone_profile():
    from pryer import accessory, aoa, cli
    seen = []

    class Accessory:
        def __init__(self, **kw):
            seen.append(kw)

        def open(self):
            pass

    saved = accessory.AoaAccessory
    accessory.AoaAccessory = Accessory
    try:
        cli._open_aoa(cli.build_parser().parse_args(["stream"]))
    finally:
        accessory.AoaAccessory = saved
    assert cli.AOA_PHONE_PROFILE == "minimal"
    assert seen and seen[0]["phone_profile"] == "minimal"
    assert "minimal" in aoa.PHONE_PROFILES


class _RecordingLink:
    """Reads heartbeats a few times, then ends the session; records writes."""

    def __init__(self):
        self.writes: list[duml.Frame] = []
        self.reads = 0

    def write(self, data: bytes) -> None:
        self.writes.append(_unwrap(data))

    def read(self) -> bytes:
        self.reads += 1
        time.sleep(0.005)
        if self.reads > 40:
            raise OSError(5, "end of test")
        return tunnel.encode(tunnel.CH_CONTROL, duml.build(
            0x3C, 0x02, self.reads, 0x00, 0x03, b"\x00", ack_type=0))

    def close(self):
        pass


def _stream_writes(transport: str) -> list[duml.Frame]:
    import signal
    from pryer import cli
    link = _RecordingLink()
    old = cli.TRANSPORTS[transport]
    cli.TRANSPORTS[transport] = lambda args: link
    old_sig = signal.getsignal(signal.SIGINT), signal.getsignal(signal.SIGTERM)
    try:
        args = cli.build_parser().parse_args(
            ["stream", "-t", transport, "-o", "null", "--stats", "0",
             "--no-register"])
        args.func(args)
    finally:
        cli.TRANSPORTS[transport] = old
        signal.signal(signal.SIGINT, old_sig[0])
        signal.signal(signal.SIGTERM, old_sig[1])
    return link.writes


def test_aoa_stream_sends_no_app_init():
    assert _stream_writes("aoa") == []


def test_ios_stream_sends_no_app_init():
    """The ios transport sends no app start-up requests either."""
    assert _stream_writes("ios") == []


# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    sys.exit(support.main(globals()))
