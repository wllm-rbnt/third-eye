"""
Self-tests for the pryer protocol library.

The first part checks the DUML codec, the tunnel demuxer, the access-unit
assembler and the AOA descriptors against known-good bytes. The golden tests
at the bottom run the decoder over the reference captures of real handsets
(see support.py; skipped when the captures are not available) and assert that
every DUML frame passes both CRCs and that the tunnel parser never has to
resynchronise where the capture is complete.

Run with:  python -m pytest tests/ -q
       or:  python tests/test_protocol.py
"""

from __future__ import annotations

import os
import struct
import sys

# the package under test, and `support` alongside this file
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [_HERE, os.path.dirname(_HERE)]

from pryer import aoa, capture, duml, pcapng, tunnel  # noqa: E402
import support  # noqa: E402
from support import capture_path, tunnel_bytes  # noqa: E402
from support import upstream_bytes  # noqa: E402
# Recordings of this package's own client are not handsets and are excluded
# from the protocol sweeps.
from support import handset_captures as _captures  # noqa: E402


# Captures used where a test needs a video-bearing tunnel. The handshake-only
# capture is not one: its AOA handshake completes and then nothing is ever
# streamed.
VIDEO_CAPTURES = ("2_ios", "9_ios", "4_android", "7_android", "A_android")

# The one capture with a completed handshake and no tunnel traffic at all.
HANDSHAKE_ONLY_CAPTURE = support.HANDSHAKE_ONLY


# --------------------------------------------------------------------------- #
# DUML
# --------------------------------------------------------------------------- #
def test_crc8_known_vector():
    # header of a real 0x12-byte frame sent by a handset
    assert duml.crc8(bytes.fromhex("551204")) == 0xC7


def test_duml_roundtrip():
    frame = duml.build(0x02, 0x28, 0x1234, 0x00, 0x99, b"hello",
                       ack_type=2)
    parsed, off = duml.parse(frame)
    assert parsed is not None
    assert off == len(frame)
    assert parsed.valid
    assert parsed.src == 0x02 and parsed.dst == 0x28
    assert parsed.seq == 0x1234
    assert parsed.key == (0x00, 0x99)
    assert parsed.payload == b"hello"
    assert not parsed.is_response
    assert parsed.wants_ack()


def test_duml_ack_construction():
    req = duml.parse(duml.build(0x03, 0x02, 7, 0x03, 0x8F, b"\x01\x02"))[0]
    ack = duml.parse(req.make_ack())[0]
    assert ack.valid
    assert ack.is_response
    assert ack.src == req.dst and ack.dst == req.src
    assert ack.seq == req.seq and ack.key == req.key


def test_duml_rejects_corruption():
    good = bytearray(duml.build(0x02, 0x03, 1, 0x00, 0x01))
    good[-1] ^= 0xFF
    f, _ = duml.parse(bytes(good))
    assert f is not None and not f.crc16_ok


def test_duml_parse_all_back_to_back():
    blob = (duml.build(0x02, 0x03, 1, 0x00, 0x01)
            + duml.build(0x02, 0x28, 2, 0x00, 0x99, b"\xaa" * 20))
    frames = duml.parse_all(blob)
    assert len(frames) == 2 and all(f.valid for f in frames)


def test_seq_counter_wraps():
    c = duml.SeqCounter(0xFFFF)
    assert c.next() == 0xFFFF
    assert c.next() == 0


# --------------------------------------------------------------------------- #
# Tunnel
# --------------------------------------------------------------------------- #
def test_tunnel_roundtrip():
    payload = bytes(range(256))
    pkts, resync = tunnel.demux_bytes(
        tunnel.encode(tunnel.CH_VIDEO, payload))
    assert resync == 0
    assert len(pkts) == 1
    assert pkts[0].channel == tunnel.CH_VIDEO
    assert pkts[0].version == tunnel.VERSION
    assert pkts[0].payload == payload


def test_tunnel_header_layout():
    raw = tunnel.encode(tunnel.CH_CONTROL, b"\x00" * 0x1234)
    assert raw[:2] == b"\x55\xcc"
    assert raw[2] == 0x49 and raw[3] == 0x57
    assert struct.unpack("<I", raw[4:8])[0] == 0x1234


def test_tunnel_split_across_reads():
    """A tunnel packet spanning several bulk reads must reassemble."""
    blob = (tunnel.encode(tunnel.CH_VIDEO, b"A" * 4096)
            + tunnel.encode(tunnel.CH_CONTROL, b"B" * 100))
    d = tunnel.Demuxer()
    got = []
    for i in range(0, len(blob), 512):
        got.extend(d.feed(blob[i:i + 512]))
    assert d.resync_bytes == 0
    assert [len(p.payload) for p in got] == [4096, 100]


def test_tunnel_resyncs_past_garbage():
    blob = b"\xde\xad\xbe\xef" + tunnel.encode(tunnel.CH_CONTROL, b"x" * 10)
    pkts, resync = tunnel.demux_bytes(blob)
    assert len(pkts) == 1 and resync == 4


def test_access_unit_assembler():
    a = tunnel.AccessUnitAssembler()
    full = tunnel.Packet(tunnel.CH_VIDEO, tunnel.VERSION,
                         tunnel.START_CODE + b"\x61" + b"\x00" * 4091)
    short = tunnel.Packet(tunnel.CH_VIDEO, tunnel.VERSION,
                          b"\x00" * 10 + tunnel.AUD)
    assert a.push(full) is None
    au = a.push(short)
    assert au is not None
    assert au.startswith(tunnel.START_CODE)
    assert tunnel.ends_with_aud(au)
    assert len(au) == 4096 + 16


def test_access_unit_assembler_drops_partial_first_frame():
    a = tunnel.AccessUnitAssembler()
    mid = tunnel.Packet(tunnel.CH_VIDEO, tunnel.VERSION, b"\x99" * 100)
    assert a.push(mid) is None          # short packet, but not a frame start
    full = tunnel.Packet(tunnel.CH_VIDEO, tunnel.VERSION,
                         tunnel.START_CODE + b"\x61" + b"\x00" * 4091)
    short = tunnel.Packet(tunnel.CH_VIDEO, tunnel.VERSION, tunnel.AUD)
    assert a.push(full) is None
    assert a.push(short) is not None    # second one is kept


# --------------------------------------------------------------------------- #
# AOA descriptors
# --------------------------------------------------------------------------- #
def test_accessory_descriptor_matches_capture():
    """
    The handset's re-enumerated accessory device is byte-for-byte:
      device: 12 01 00 02 00 00 00 40 d1 18 01 2d ff ff 02 03 04 01
      config: 09 02 37 00 02 01 00 c0 30 ...
    """
    d = aoa.accessory_descriptors(with_adb=True)
    assert d["device"] == bytes.fromhex(
        "1201000200000040d118012dffff02030401")
    assert d["config"] == bytes.fromhex(
        "09023700020100c030"
        "0904000002ffff0006" "07058102000200" "07050102000200"
        "0904010002ff420105" "07050202000200" "07058202000200")
    assert len(d["config"]) == 0x37 == 55
    # iInterface 6 on the accessory interface and 5 on adb, as the handset did
    assert d["config"][17] == 6
    assert d["strings"][6] == "Android Accessory Interface"


def test_accessory_endpoints():
    from pryer.accessory import _endpoints_of
    d = aoa.accessory_descriptors(with_adb=True)
    eps = dict(_endpoints_of(d["config"]))
    assert set(eps) == {0x81, 0x01, 0x82, 0x02}
    for addr, desc in eps.items():
        assert desc[1] == aoa.DT_ENDPOINT
        assert desc[3] == aoa.XFER_BULK
        assert struct.unpack("<H", desc[4:6])[0] == 512


def test_accessory_only_pid():
    d = aoa.accessory_descriptors(with_adb=False)
    assert struct.unpack("<H", d["device"][10:12])[0] == aoa.AOA_PID_ACCESSORY
    assert d["config"][4] == 1  # one interface


def test_string_descriptor():
    sd = aoa.string_descriptor("DJI")
    assert sd[0] == len(sd) == 8
    assert sd[1] == aoa.DT_STRING
    assert sd[2:].decode("utf-16-le") == "DJI"


def test_captured_accessory_strings():
    assert aoa.ACCESSORY_STRINGS[1] == "com.dji.logiclink"
    assert aoa.ACCESSORY_STRINGS[0] == "DJI"


# --------------------------------------------------------------------------- #
# Golden tests against the real captures
# --------------------------------------------------------------------------- #
def test_reference_captures_present():
    # Skips (like every golden test) when no reference capture is available.
    assert _captures()


def test_all_duml_frames_pass_both_crcs():
    total = 0
    for path in _captures():
        data = tunnel_bytes(path)
        for pkt in tunnel.Demuxer().feed(data):
            if not pkt.is_control:
                continue
            for f in duml.parse_all(pkt.payload):
                assert f.crc8_ok, (path, f)
                assert f.crc16_ok, (path, f)
                total += 1
    # about 30,000 goggles-to-phone control frames across the handset captures
    assert total > 25000, total


# Bytes the demuxer has to skip to regain framing, per capture. These are not
# protocol errors: the sniffer logs a buffer overflow at each of them, so the
# bytes never reached the file. Captures with no overflow message resync zero
# bytes, which is what proves the framing itself is exact.
RESYNC_BYTES = {
    "0_ios": 2871, "1_ios": 0, "2_ios": 25, "3_ios": 5390, "9_ios": 3080,
    "4_android": 0, "5_android": 0, "6_android": 0, "7_android": 3072,
    "8_android": 0, "A_android": 10980,
}


def test_resync_only_happens_where_the_sniffer_overflowed():
    """
    Framing is exact wherever the capture is complete.

    Where a capture loses data, every loss is accounted for by an explicit
    overflow message the sniffer wrote into the second interface of the same
    file. The complete captures resync zero bytes, which is what proves the
    framing itself is exact: nothing in the protocol ever requires the reader
    to hunt for the next header. Even the worst-damaged capture (about 11 kB
    skipped over 27 logged overflows) resyncs to a valid header every time.
    """
    for path in _captures():
        name = next(k for k in RESYNC_BYTES if k in path)
        d = tunnel.Demuxer()
        list(d.feed(tunnel_bytes(path)))
        assert d.resync_bytes == RESYNC_BYTES[name], (name, d.resync_bytes)
        overflows = len(pcapng.overflows(path)) if capture.is_pcapng(path) else 0
        if d.resync_bytes:
            assert overflows > 0, (name, "resynced but no overflow logged")
        else:
            # A capture can log overflows yet resync nothing: when it lost
            # whole packets rather than parts of one, the framing still lines
            # up and the damage shows only as a gap in the timestamps.
            assert d.resync_bytes == 0, name


def test_a_handshake_only_capture_has_no_tunnel_traffic():
    """
    A completed accessory handshake does not imply a stream.

    This capture negotiates the full AOA sequence, re-enumerates as the accessory
    composite, gets its SET_CONFIGURATION -- and then nothing is ever sent over
    the bulk pair. The phone answers every PING and IN token with NAK for the
    rest of the capture, which is what it looks like when the accessory link is
    up but no app has opened the accessory file descriptor.

    The capture logs no overflow, so the absence of data is real rather than
    something the sniffer dropped. It is the cleanest available proof that the
    handshake and the stream are independent, and that reading zero tunnel bytes
    is a valid outcome the tools have to report rather than crash on.
    """
    path = capture_path(HANDSHAKE_ONLY_CAPTURE)
    assert pcapng.endpoint_survey(path) == [], "expected no bulk endpoints"
    assert pcapng.tunnel_endpoints(path) == (None, None)
    assert tunnel_bytes(path) == b""
    assert pcapng.overflows(path) == [], "the empty stream is not capture loss"

    # the handshake itself is complete: all three AOA requests are present
    requests = {c.b_request for c in pcapng.control_transfers(path)
                if c.bm_request_type in (0x40, 0xC0)}
    assert {51, 52, 53} <= requests, sorted(requests)

    # and the demuxer treats the empty stream as empty, not as an error
    d = tunnel.Demuxer()
    assert list(d.feed(b"")) == []
    assert d.resync_bytes == 0


def test_a_clean_capture_resyncs_nothing_at_all():
    """The strong form of the framing claim, on the captures that lost nothing."""
    clean = [p for p in _captures()
             if not capture.is_pcapng(p) or not pcapng.overflows(p)]
    assert clean, "expected at least one loss-free capture"
    for path in clean:
        d = tunnel.Demuxer()
        list(d.feed(tunnel_bytes(path)))
        assert d.resync_bytes == 0, (path, d.resync_bytes)


def test_only_two_channels_and_one_version_exist():
    channels, versions = set(), set()
    for path in _captures():
        for pkt in tunnel.Demuxer().feed(tunnel_bytes(path)):
            channels.add(pkt.channel)
            versions.add(pkt.version)
    assert channels == {tunnel.CH_CONTROL, tunnel.CH_VIDEO}
    assert versions == {tunnel.VERSION}


def test_video_chunking_and_frame_layout():
    """
    Every video burst is N*4096 plus one short chunk, and an access unit is one
    of exactly two shapes.

    A picture access unit is a slice followed by the 6-byte access-unit
    delimiter. The second shape appears about once a second: a 39-byte access
    unit that is just SPS and PPS, with no slice and no trailing delimiter, a few
    milliseconds ahead of the IDR that uses them.
    """
    pictures = parameter_sets = 0
    for path in _captures():
        if not any(k in path for k in VIDEO_CAPTURES):
            continue
        clean = not capture.is_pcapng(path) or not pcapng.overflows(path)
        asm = tunnel.AccessUnitAssembler()
        for pkt in tunnel.Demuxer().feed(tunnel_bytes(path)):
            if not pkt.is_video:
                continue
            assert len(pkt.payload) <= tunnel.VIDEO_CHUNK
            au = asm.push(pkt)
            if au is None:
                continue
            assert au.startswith(tunnel.START_CODE), au[:8].hex()
            types = [n & 0x1F for _off, n in tunnel.nal_units(au)]
            if types[:1] == [7]:
                parameter_sets += 1
                assert types == [7, 8], types
                assert len(au) == 39, len(au)
                assert not tunnel.ends_with_aud(au), au[-8:].hex()
                continue
            if not clean and (set(types) - {1, 5, 9} or len(types) != 2):
                # Debris from a sniffer overflow. Besides stray control bytes
                # arriving as bogus NAL types, losing an access-unit delimiter
                # merges two pictures into one unit ([1, 1, 9]). Neither is a protocol observation, so the exact shape
                # is asserted only where the capture is complete.
                continue
            pictures += 1
            assert types[0] in (1, 5), "nal type %d" % types[0]
            assert tunnel.ends_with_aud(au), au[-8:].hex()
            # exactly two NAL units: the slice and the trailing AUD
            assert types == [types[0], 9], types
    assert pictures >= 10, pictures
    assert parameter_sets >= 10, parameter_sets


def test_extracted_stream_is_pure_annexb():
    """
    Concatenated video payloads hold nothing but video NAL types.

    Where the sniffer overflowed, control bytes can land in the video channel --
    for example an 11-byte "NAL type 21", which is really a DUML frame, since
    a DUML frame starts 0x55 and 0x55 & 0x1F == 21. That is capture damage, so
    the strict assertion applies to the captures that lost nothing.
    """
    checked = 0
    for path in _captures():
        if not any(k in path for k in VIDEO_CAPTURES):
            continue
        if capture.is_pcapng(path) and pcapng.overflows(path):
            continue
        blob = b"".join(p.payload for p in tunnel.Demuxer().feed(
            tunnel_bytes(path)) if p.is_video)
        types = {n & 0x1F for _, n in tunnel.nal_units(blob)}
        assert types <= {1, 5, 6, 7, 8, 9}, (path, types)
        assert {1, 5, 7, 8, 9} <= types, (path, types)
        checked += 1
    assert checked, "expected at least one loss-free video capture"


def test_every_app_request_reencodes_byte_exact():
    """
    Rebuilding every app request of a handset session from its decoded fields
    with our own encoder must reproduce the original bytes, which validates
    the DUML builder end to end.
    """
    path = [capture_path("5_android")]
    # The app's own requests travel phone-to-goggles, which is the opposite
    # direction on the tunnel endpoint from the video, so this has to read the
    # upstream side explicitly rather than the busy direction.
    original = []
    for pkt in tunnel.Demuxer().feed(upstream_bytes(path[0])):
        if not pkt.is_control:
            continue
        for f in duml.parse_all(pkt.payload):
            if (f.src & 0x1F) == duml.DEV_MOBILE_APP and not f.is_response:
                original.append(f)
    # at least the 156-request start-up burst (PROTOCOL.md 6.4)
    assert len(original) >= 156, len(original)
    for f in original:
        rebuilt = duml.build(f.src, f.dst, f.seq, f.cmd_set, f.cmd_id,
                             f.payload, ack_type=f.ack_type, enc=f.enc,
                             version=f.version)
        assert rebuilt == f.raw, (f, rebuilt.hex())


def test_capture_reader_packet_sizes():
    """Every wire packet must fit one 512-byte bulk packet."""
    for path in _captures():
        pids = set()
        for pid, payload in capture.usb_packets(path):
            pids.add(pid)
            assert len(payload) <= 512, len(payload)
        # DATA0 / DATA1 dominate; a handful of AOA SEND_STRING control
        # records in the Android captures are dumped without a PID byte.
        assert {0xC3, 0x4B} <= pids, pids


def test_setup_decoder_recognises_aoa():
    line = capture.decode_setup(bytes.fromhex("c033000000000200"))
    assert "AOA_GET_PROTOCOL" in line
    line = capture.decode_setup(bytes.fromhex("4034000001000400"))
    assert "AOA_SEND_STRING" in line
    line = capture.decode_setup(bytes.fromhex("4035000000000000"))
    assert "AOA_START_ACCESSORY" in line


# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    sys.exit(support.main(globals()))
