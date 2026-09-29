"""
Self-tests for `pryer.h264` -- the part that turns the goggles' bare slice
stream into something a player will open.

The golden test here is ``test_inference_on_every_video_capture``: it runs the
slice-header inference over the video-bearing reference captures and asserts
it recovers exactly the parameters documented in PROTOCOL.md section 10.  If a
change to the bit reader or the candidate search breaks it, that test fails on
real goggles bytes rather than on a fixture.  The capture tests are skipped
when the reference captures are not available (see support.py); the builders
and parsers are also checked against the goggles' known SPS/PPS bytes, which
needs no capture.

Run with:  python -m pytest tests/ -q
       or:  python tests/test_h264.py
"""

from __future__ import annotations

import collections
import functools
import os
import sys

# the package under test, and `support` alongside this file
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [_HERE, os.path.dirname(_HERE)]

from pryer import capture, h264, tunnel  # noqa: E402
import support  # noqa: E402
from support import tunnel_bytes  # noqa: E402
from support import capture_path as _capture_path  # noqa: E402


# capture -> (frame_num of the first slices, P slice_qp_delta, IDR
# slice_qp_delta). frame_num starts partway up because the captures begin
# mid-stream; the P and IDR pictures use different QP offsets.
VIDEO_CAPTURES = {
    "2_ios":     ([21, 22, 23, 24, 25, 26], -6, -7),
    "9_ios":     ([25, 26, 27, 28, 29], -11, -12),
    "4_android": ([21, 22, 23, 24, 25], -10, -11),
    "7_android": ([18, 19, 20, 21, 22], -10, -11),
}

# Access units and parameter sets per capture: (access units, SPS count ==
# PPS count == IDR count).
#
# The handshake-only capture is deliberately absent: its AOA handshake
# completes and then no tunnel byte is ever sent, so it has no access units to
# count. See test_a_handshake_only_capture_has_no_video.
CAPTURE_SHAPE = {
    "0_ios": (235, 7), "1_ios": (244, 8), "2_ios": (322, 11),
    "3_ios": (336, 11), "9_ios": (210, 7),
    "4_android": (322, 11), "5_android": (179, 6), "6_android": (74, 3),
    "7_android": (228, 7), "A_android": (158, 5),
}

# Captures with no video at all, excluded from every shape and inference table.
NO_VIDEO_CAPTURES = (support.HANDSHAKE_ONLY,)


def _video(match: str) -> bytes:
    data = tunnel_bytes(_capture_path(match))
    return b"".join(p.payload for p in tunnel.Demuxer().feed(data) if p.is_video)


def _slices(annexb: bytes) -> list[bytes]:
    return [n for n in h264.split_annexb(annexb)
            if (n[0] & 0x1F) in (h264.NAL_SLICE, h264.NAL_IDR)]


@functools.lru_cache(maxsize=None)
def _headerless_excerpt(match: str) -> bytes:
    """
    The leading P slices of a capture, before its first parameter set.

    This is what a reader sees when it attaches mid-second, so the synthesis
    fallback has to work on it.
    """
    video = _video(match)
    cut = h264.first_parameter_set_offset(video)
    assert cut is not None and cut > 0, match
    return video[:cut]


# --------------------------------------------------------------------------- #
# bit codec
# --------------------------------------------------------------------------- #
def test_bits_round_trip():
    w = h264.BitWriter()
    w.bits(0b101, 3).bits(0xFF, 8).bit(0).bits(0x1234, 16)
    r = h264.BitReader(w.trailing().bytes(), unescape_rbsp=False)
    assert r.bits(3) == 0b101
    assert r.bits(8) == 0xFF
    assert r.bit() == 0
    assert r.bits(16) == 0x1234


def test_ue_round_trip():
    values = [0, 1, 2, 3, 4, 5, 16, 17, 255, 256, 65535, 1 << 20]
    w = h264.BitWriter()
    for v in values:
        w.ue(v)
    r = h264.BitReader(w.trailing().bytes(), unescape_rbsp=False)
    assert [r.ue() for _ in values] == values


def test_se_round_trip():
    values = [0, 1, -1, 2, -2, 3, -3, 12, -12, 26, -26, -128, 128]
    w = h264.BitWriter()
    for v in values:
        w.se(v)
    r = h264.BitReader(w.trailing().bytes(), unescape_rbsp=False)
    assert [r.se() for _ in values] == values


def test_ue_encoding_matches_the_spec():
    # ue(0) = "1", ue(1) = "010", ue(2) = "011", ue(3) = "00100"
    assert h264.BitWriter().ue(0).trailing().bytes()[0] >> 7 == 1
    assert h264.BitWriter().ue(1).trailing().bytes()[0] >> 5 == 0b010
    assert h264.BitWriter().ue(2).trailing().bytes()[0] >> 5 == 0b011
    assert h264.BitWriter().ue(3).trailing().bytes()[0] >> 3 == 0b00100


def test_bitreader_remaining_and_alignment():
    r = h264.BitReader(b"\xff\xff", unescape_rbsp=False)
    assert r.remaining == 16 and r.byte_aligned()
    r.bits(3)
    assert r.remaining == 13 and not r.byte_aligned()
    assert r.peek_alignment_ones() == 5      # five ones to the byte boundary


# --------------------------------------------------------------------------- #
# emulation prevention
# --------------------------------------------------------------------------- #
def test_escape_inserts_emulation_prevention():
    assert h264.escape(b"\x00\x00\x00") == b"\x00\x00\x03\x00"
    assert h264.escape(b"\x00\x00\x01") == b"\x00\x00\x03\x01"
    assert h264.escape(b"\x00\x00\x04") == b"\x00\x00\x04"


def test_unescape_is_the_inverse_of_escape():
    for raw in (b"", b"\x00", b"\x00\x00", b"\x00\x00\x00\x00\x00",
                b"\x00\x00\x01\x00\x00\x02\xff\x00\x00\x03"):
        assert h264.unescape(h264.escape(raw)) == raw


def test_reader_removes_emulation_prevention_bytes():
    r = h264.BitReader(b"\x00\x00\x03\x01")
    assert r.bits(24) == 0x000001


# --------------------------------------------------------------------------- #
# SPS
# --------------------------------------------------------------------------- #
def test_sps_round_trip_1080p60():
    sps = h264.build_sps(1920, 1080, fps=60.0)
    got = h264.parse_sps(sps)
    assert (got["width"], got["height"]) == (1920, 1080)
    assert abs(got["fps"] - 60.0) < 1e-6
    assert got["profile_idc"] == 100          # High
    assert got["hypothesis"] == h264.Hypothesis(
        log2_max_frame_num=h264.GOGGLES3.log2_max_frame_num,
        pic_order_cnt_type=h264.GOGGLES3.pic_order_cnt_type,
        log2_max_poc_lsb=h264.GOGGLES3.log2_max_poc_lsb,
        delta_pic_order_always_zero=h264.GOGGLES3.delta_pic_order_always_zero,
        frame_mbs_only=h264.GOGGLES3.frame_mbs_only,
        # parse_sps only knows the SPS half of a Hypothesis, so the PPS fields
        # stay at their dataclass defaults -- which are the Goggles 3 values.
    )


def test_sps_round_trip_other_sizes_and_rates():
    for w, hgt, fps in ((1920, 1080, 30.0), (1280, 720, 59.94),
                        (1440, 810, 60.0), (640, 480, 25.0),
                        (1920, 1088, 50.0)):
        got = h264.parse_sps(h264.build_sps(w, hgt, fps=fps))
        assert (got["width"], got["height"]) == (w, hgt), (w, hgt, got)
        assert abs(got["fps"] - fps) < 0.01, (fps, got["fps"])


def test_sps_cropping_handles_non_multiple_of_16_height():
    # 1080 is not a multiple of 16: the SPS must code 1088 macroblock rows and
    # crop 8 lines, otherwise every player reports 1088.
    got = h264.parse_sps(h264.build_sps(1920, 1080, fps=60.0))
    assert got["height"] == 1080
    assert got.get("crop_bottom", 0) > 0


def test_sps_carries_a_start_code_free_payload():
    sps = h264.build_sps(1920, 1080, fps=30.0)
    assert b"\x00\x00\x01" not in sps and b"\x00\x00\x00" not in sps
    assert sps[0] & 0x1F == h264.NAL_SPS


def test_real_parameter_sets_are_the_goggles_bytes():
    """
    The goggles' own SPS/PPS, byte for byte. The goggles only ever sends this
    one SPS, so this is a hard regression guard. Both are built from fields
    (GOGGLES3_STYLE), so this also checks the SPS writer's VUI and
    bitstream-restriction paths.
    """
    assert h264.GOGGLES3_SPS.hex() == (
        "67640034ac4d00f0044fcb35010101400000fa00003a9803c70ca8")
    assert h264.GOGGLES3_PPS.hex() == "68ee3cb0"
    assert h264.GOGGLES3_PARAMETER_SETS == (
        h264.START_CODE + h264.GOGGLES3_SPS
        + h264.START_CODE + h264.GOGGLES3_PPS)
    assert len(h264.GOGGLES3_SPS) + len(h264.GOGGLES3_PPS) == 31


def test_real_sps_decodes_to_the_measured_geometry():
    got = h264.parse_sps(h264.GOGGLES3_SPS)
    assert got["profile_idc"] == 100                 # High
    assert got["level_idc"] == h264.GOGGLES3_LEVEL_IDC == 52
    assert (got["width"], got["height"]) == (1920, 1080)
    assert got["crop_bottom"] == 4                   # coded 1088, shown 1080
    assert got["fps"] == h264.GOGGLES3_FPS == 30.0
    assert got["max_num_ref_frames"] == 1
    assert got["hypothesis"] == h264.GOGGLES3


def test_real_pps_decodes_to_the_measured_fields():
    got = h264.parse_pps(h264.GOGGLES3_PPS)
    assert got["pic_init_qp"] == h264.GOGGLES3_PIC_INIT_QP == 26
    assert got["entropy_coding_mode"] is True        # CABAC
    assert got["num_ref_idx_l0"] == 1
    assert got["deblocking_filter_control_present"] is True
    assert got["transform_8x8_mode"] is True         # the High-profile tail


def test_synthesised_sps_agrees_with_the_real_one_on_every_decoded_field():
    """
    The generic style writes a different but legal VUI and omits the
    colour-description fields, so compare meaning, not bytes. Anything a
    decoder acts on must match.
    """
    real = h264.parse_sps(h264.GOGGLES3_SPS)
    mine = h264.parse_sps(h264.build_sps(
        h264.GOGGLES3_WIDTH, h264.GOGGLES3_HEIGHT, fps=h264.GOGGLES3_FPS))
    for field in ("profile_idc", "level_idc", "width", "height", "fps",
                  "hypothesis"):
        assert mine[field] == real[field], (field, mine[field], real[field])


def test_goggles_style_reproduces_the_encoders_sps_from_fields():
    """GOGGLES3_SPS is build_sps() with the encoder's decoded choices."""
    sps = h264.build_sps(1920, 1080, fps=30.0, style=h264.GOGGLES3_STYLE)
    assert sps.hex() == (
        "67640034ac4d00f0044fcb35010101400000fa00003a9803c70ca8")
    assert h264.build_pps(pic_init_qp=26, transform_8x8_mode=True).hex() == \
        "68ee3cb0"
    got = h264.parse_sps(sps)
    assert got["gaps_allowed"] is False
    assert got["fixed_frame_rate"] is False
    # only the style differs from the generic SPS, not anything a slice
    # header depends on
    generic = h264.parse_sps(h264.build_sps(1920, 1080, fps=30.0))
    assert generic["hypothesis"] == got["hypothesis"]
    assert generic["gaps_allowed"] is True


def test_goggles_style_follows_an_overridden_rate_and_geometry():
    sps = h264.build_sps(1280, 720, fps=60.0, style=h264.GOGGLES3_STYLE)
    got = h264.parse_sps(sps)
    assert (got["width"], got["height"], got["fps"]) == (1280, 720, 60.0)
    assert got["fixed_frame_rate"] is False


def test_sps_bytes_are_stable():
    # Regression guard on the generic style: this is the SPS quoted in
    # PROTOCOL.md section 10. It is a fallback, not what the goggles sends.
    assert h264.build_sps(1920, 1080, fps=30.0).hex() == (
        "67640034ac4d40f0044fcb08000003000800000301e420")


# --------------------------------------------------------------------------- #
# PPS
# --------------------------------------------------------------------------- #
def test_pps_round_trip():
    pps = h264.build_pps(pic_init_qp=h264.GOGGLES3_PIC_INIT_QP)
    got = h264.parse_pps(pps)
    assert got["pps_id"] == 0 and got["sps_id"] == 0
    assert got["pic_init_qp"] == 26
    assert got["entropy_coding_mode"] is True
    assert got["deblocking_filter_control_present"] is True
    assert got["redundant_pic_cnt_present"] is False
    assert got["num_ref_idx_l0"] == 1
    assert got["num_slice_groups"] == 1


def test_pps_round_trip_over_the_whole_qp_range():
    for qp in range(52):
        assert h264.parse_pps(h264.build_pps(pic_init_qp=qp))["pic_init_qp"] == qp


def test_pps_high_profile_tail_is_optional_and_parses():
    plain = h264.build_pps(pic_init_qp=39, transform_8x8_mode=False)
    fancy = h264.build_pps(pic_init_qp=39, transform_8x8_mode=True)
    assert fancy != plain
    for nal in (plain, fancy):
        assert h264.parse_pps(nal)["pic_init_qp"] == 39
    assert h264.parse_pps(plain)["transform_8x8_mode"] is False
    assert h264.parse_pps(fancy)["transform_8x8_mode"] is True
    assert h264.parse_pps(plain)["constrained_intra_pred"] is False
    assert h264.parse_pps(
        h264.build_pps(pic_init_qp=39, constrained_intra_pred=True)
    )["constrained_intra_pred"] is True


def test_pps_reflects_the_hypothesis():
    cavlc = h264.build_pps(hyp=h264.Hypothesis(entropy_coding_mode=False,
                                               deblocking_filter_control_present=False),
                           pic_init_qp=26)
    got = h264.parse_pps(cavlc)
    assert got["entropy_coding_mode"] is False
    assert got["deblocking_filter_control_present"] is False


def test_parse_rejects_the_wrong_nal_type():
    for fn, nal in ((h264.parse_sps, h264.build_pps(pic_init_qp=26)),
                    (h264.parse_pps, h264.build_sps())):
        try:
            fn(nal)
        except ValueError:
            pass
        else:
            raise AssertionError("%s accepted the wrong NAL type" % fn.__name__)


def test_parameter_sets_defaults_to_the_real_bytes():
    """
    With the Goggles 3 defaults, `parameter_sets()` builds exactly the
    encoder's own bytes.
    """
    assert h264.parameter_sets() == h264.GOGGLES3_PARAMETER_SETS
    # ask for anything else and it is a reconstruction
    assert h264.parameter_sets(1280, 720, fps=30.0) != \
        h264.GOGGLES3_PARAMETER_SETS
    assert h264.parameter_sets(match_encoder=False) != \
        h264.GOGGLES3_PARAMETER_SETS
    assert h264.parameter_sets(match_encoder=False) == (
        h264.START_CODE + h264.build_sps() + h264.START_CODE
        + h264.build_pps(pic_init_qp=26))


def test_overridden_parameter_sets_keep_the_encoders_pps_tail():
    """
    An override changes only the overridden field. In particular the PPS
    keeps transform_8x8_mode, which the goggles' slices are coded with.
    """
    sps, pps = h264.split_annexb(h264.parameter_sets(1280, 720, fps=25.0,
                                                     pic_init_qp=30))
    assert h264.parse_pps(pps)["transform_8x8_mode"] is True
    assert h264.parse_pps(pps)["pic_init_qp"] == 30
    got = h264.parse_sps(sps)
    assert (got["width"], got["height"], got["fps"]) == (1280, 720, 25.0)


def test_parameter_sets_is_annexb():
    ps = h264.parameter_sets(1920, 1080, fps=30.0)
    nals = h264.split_annexb(ps)
    assert [n[0] & 0x1F for n in nals] == [h264.NAL_SPS, h264.NAL_PPS]
    assert ps.startswith(h264.START_CODE)


# --------------------------------------------------------------------------- #
# slice headers and inference -- on the real captures
# --------------------------------------------------------------------------- #
def test_captures_carry_the_goggles_own_parameter_sets():
    """
    The goggles sends SPS, PPS and an IDR together roughly once per second, as
    its own 39-byte access unit with no slice and no trailing delimiter. A short
    excerpt of P slices can easily contain none of them, which is what the
    synthesis fallback exists for.
    """
    for match, (units, sets) in CAPTURE_SHAPE.items():
        counts = collections.Counter(
            n[0] & 0x1F for n in h264.split_annexb(_video(match)) if n)
        assert counts[h264.NAL_SPS] == sets, (match, counts)
        assert counts[h264.NAL_PPS] == sets, (match, counts)
        assert counts[h264.NAL_IDR] == sets, (match, counts)
        assert counts[h264.NAL_SLICE] > 0, (match, counts)
        # one AUD per picture, and none on the parameter-set access unit
        assert counts[h264.NAL_AUD] == units - sets, (match, counts)


def test_every_capture_carries_the_same_single_sps():
    """One distinct SPS across every video capture, and it is GOGGLES3_SPS."""
    seen = set()
    for match in CAPTURE_SHAPE:
        for n in h264.split_annexb(_video(match)):
            if n and (n[0] & 0x1F) == h264.NAL_SPS:
                seen.add(bytes(n))
    assert seen == {h264.GOGGLES3_SPS}, sorted(x.hex() for x in seen)


def test_unexpected_nal_types_only_appear_where_the_sniffer_lost_data():
    """
    2_ios yields one NAL of "type 21". It is not video: it is an 11-byte DUML
    control frame (starts 0x55, and 0x55 & 0x1F == 21) that landed in the video
    channel because the sniffer dropped 25 bytes there, taking a tunnel header
    with it. Captures that lost nothing hold only types 1, 5, 7, 8 and 9.
    """
    clean = {h264.NAL_SLICE, h264.NAL_IDR, h264.NAL_SPS, h264.NAL_PPS,
             h264.NAL_AUD}
    for match in CAPTURE_SHAPE:
        demux = tunnel.Demuxer()
        video = b"".join(
            p.payload for p in demux.feed(tunnel_bytes(_capture_path(match)))
            if p.is_video)
        types = {n[0] & 0x1F for n in h264.split_annexb(video) if n}
        if demux.resync_bytes == 0:
            assert types <= clean, (match, sorted(types))
        else:
            assert types >= clean, (match, sorted(types))


def test_inference_on_every_video_capture():
    for match, (frame_nums, p_qp, idr_qp) in VIDEO_CAPTURES.items():
        inf = h264.infer(_slices(_video(match)))
        assert inf is not None, match
        hyp = inf.hypothesis
        assert hyp.log2_max_frame_num == 5, (match, hyp)
        assert hyp.pic_order_cnt_type == 2, (match, hyp)
        assert hyp.entropy_coding_mode is True, (match, hyp)
        assert hyp.deblocking_filter_control_present is True, (match, hyp)
        assert hyp.frame_mbs_only is True, (match, hyp)
        assert hyp.redundant_pic_cnt_present is False, (match, hyp)
        assert hyp.num_slice_groups == 1, (match, hyp)
        assert hyp == h264.GOGGLES3, (match, hyp)

        head = [s for s in inf.slices if not s.is_idr][:len(frame_nums)]
        assert [s.frame_num for s in head] == frame_nums, match
        assert {s.slice_qp_delta for s in inf.slices if s.is_p} == {p_qp}, match
        assert {s.slice_qp_delta for s in inf.slices
                if s.is_idr} == {idr_qp}, match
        assert all(s.first_mb_in_slice == 0 for s in inf.slices), match
        assert all(s.pps_id == 0 for s in inf.slices), match
        assert all(s.is_p or s.is_i for s in inf.slices), match
        # a run of 16 slices spans one IDR, which resets frame_num to 0
        assert sum(1 for s in inf.slices if s.is_idr) == 1, match
        # only P slices carry num_ref_idx_l0; an I slice has no reference list
        assert all(s.num_ref_idx_l0 == 1 for s in inf.slices if s.is_p), match
        assert inf.candidates >= 1, match


def test_parse_slice_header_agrees_with_inference():
    nals = _slices(_video("4_android"))
    hdr = h264.parse_slice_header(nals[0], h264.GOGGLES3)
    assert hdr.nal_type == h264.NAL_SLICE
    assert hdr.first_mb_in_slice == 0
    assert hdr.slice_type == 0 and hdr.is_p
    assert hdr.frame_num == 21
    assert hdr.slice_qp_delta == -10
    assert hdr.disable_deblocking_idc == 0
    # CABAC: the header is followed by cabac_alignment_one_bit padding.
    assert hdr.alignment_ones > 0


def test_parse_slice_header_rejects_a_wrong_hypothesis():
    nal = _slices(_video("4_android"))[0]
    bad = h264.Hypothesis(entropy_coding_mode=False,   # claim CAVLC
                          deblocking_filter_control_present=True,
                          redundant_pic_cnt_present=True,
                          log2_max_frame_num=16,
                          pic_order_cnt_type=0, log2_max_poc_lsb=16)
    try:
        hdr = h264.parse_slice_header(nal, bad)
    except h264.SliceParseError:
        return
    # If it parsed at all it must at least disagree with the truth.
    assert hdr.frame_num != 21 or hdr.slice_qp_delta != -10


def test_parse_slice_header_rejects_corrupt_data():
    for nal in (b"\x61", b"\x61\x00\x00\x00\x00", b"\x61\xff\xff\xff\xff\xff"):
        try:
            h264.parse_slice_header(nal, h264.GOGGLES3)
        except h264.SliceParseError:
            pass
        except Exception as exc:  # noqa: BLE001
            raise AssertionError("wrong exception for %r: %r" % (nal, exc))


def test_infer_returns_none_without_slices():
    assert h264.infer([]) is None


def test_inference_describe_mentions_the_frame_numbers():
    text = h264.infer(_slices(_video("7_android"))).describe()
    assert "CABAC" in text and "18->19" in text


# --------------------------------------------------------------------------- #
# Annex-B helpers
# --------------------------------------------------------------------------- #
def test_split_annexb_handles_both_start_code_lengths():
    payloads = [b"\x67\x01\x02", b"\x68\x03", b"\x61\x04\x05\x06"]
    stream = (b"\x00\x00\x00\x01" + payloads[0]
              + b"\x00\x00\x01" + payloads[1]
              + b"\x00\x00\x00\x01" + payloads[2])
    assert h264.split_annexb(stream) == payloads


def test_split_annexb_on_junk():
    assert h264.split_annexb(b"") == []
    assert h264.split_annexb(b"\xde\xad\xbe\xef") == []


def test_load_parameter_sets_accepts_annexb_and_hex(tmp="/tmp"):
    ps = h264.parameter_sets(1920, 1080, fps=60.0)
    raw = os.path.join(tmp, "pryer_test_ps.h264")
    with open(raw, "wb") as fh:
        fh.write(ps)
    assert h264.load_parameter_sets(raw) == ps

    hexed = os.path.join(tmp, "pryer_test_ps.hex")
    with open(hexed, "w") as fh:
        fh.write("# comment\n" + ps.hex(" ") + "\n")
    assert h264.load_parameter_sets(hexed) == ps
    for path in (raw, hexed):
        os.unlink(path)


def test_load_parameter_sets_rejects_a_file_without_an_sps():
    path = "/tmp/pryer_test_nops.h264"
    with open(path, "wb") as fh:
        fh.write(h264.START_CODE + b"\x61\x01\x02\x03")
    try:
        h264.load_parameter_sets(path)
    except ValueError:
        pass
    else:
        raise AssertionError("accepted a file with no SPS")
    finally:
        os.unlink(path)


# --------------------------------------------------------------------------- #
# the injector
# --------------------------------------------------------------------------- #
def test_injector_auto_prepends_parameter_sets():
    video = _video("4_android")
    inj = h264.ParameterSetInjector("auto", probe=2)
    out = b"".join(inj.feed(au) for au in _annex_units(video)) + inj.flush()
    assert inj.injected and not inj.stream_had_parameter_sets
    types = [n[0] & 0x1F for n in h264.split_annexb(out)]
    assert types[:2] == [h264.NAL_SPS, h264.NAL_PPS]
    # nothing lost: every original NAL is still there, in order
    assert types[2:] == [n[0] & 0x1F for n in h264.split_annexb(video)]
    assert out.endswith(video[-64:])


def test_injector_auto_leaves_a_full_capture_untouched():
    """
    A complete capture has the encoder's own parameter sets, so "auto" must
    pass it through byte for byte and inject nothing: a synthesised header
    would override the encoder's real one.
    """
    video = _video("4_android")
    inj = h264.ParameterSetInjector("auto", probe=40)
    out = inj.feed(video) + inj.flush()
    assert out == video
    assert inj.stream_had_parameter_sets and not inj.injected


def test_injector_auto_uses_the_inferred_hypothesis_on_a_headerless_excerpt():
    """
    The fallback path: an excerpt that starts mid-second and stops before the
    next SPS. Inference has to recover the hypothesis from the slice headers
    alone.
    """
    excerpt = _headerless_excerpt("4_android")
    inj = h264.ParameterSetInjector("auto", probe=4)
    inj.feed(excerpt)
    inj.flush()
    assert not inj.stream_had_parameter_sets
    assert inj.injected
    # inference lands on GOGGLES3 at the measured geometry, so what the
    # injector builds is byte-identical to the encoder's own
    assert inj.matches_encoder and inj.build() == h264.GOGGLES3_PARAMETER_SETS
    assert inj.inference is not None
    assert inj.inference.hypothesis == h264.GOGGLES3
    assert h264.parse_sps(h264.split_annexb(inj.build())[0])["hypothesis"] \
        .log2_max_frame_num == 5


def test_injector_never_is_byte_exact_passthrough():
    video = _video("7_android")
    inj = h264.ParameterSetInjector("never")
    out = b"".join(inj.feed(au) for au in _annex_units(video)) + inj.flush()
    assert out == video and not inj.injected


def test_injector_always_injects_immediately():
    inj = h264.ParameterSetInjector("always")
    first = inj.feed(b"\x00\x00\x00\x01\x61\x00")
    assert inj.injected
    assert first.startswith(h264.parameter_sets())
    assert inj.flush() == b""


def test_injector_auto_leaves_a_stream_that_already_has_parameter_sets_alone():
    stream = h264.parameter_sets() + h264.START_CODE + b"\x65\x88\x84\x00"
    inj = h264.ParameterSetInjector("auto")
    out = inj.feed(stream) + inj.flush()
    assert out == stream
    assert inj.stream_had_parameter_sets and not inj.injected


def test_injector_always_overrides_even_a_stream_with_parameter_sets():
    stream = h264.parameter_sets(1280, 720, fps=30.0)
    inj = h264.ParameterSetInjector("always", width=1920, height=1080, fps=60.0)
    out = inj.feed(stream) + inj.flush()
    assert out.startswith(h264.parameter_sets(1920, 1080, fps=60.0))
    assert inj.injected


def test_injector_override_is_used_verbatim():
    override = h264.parameter_sets(1280, 720, fps=30.0)
    inj = h264.ParameterSetInjector("always", width=1920, height=1080,
                                    override=override)
    assert inj.build() == override
    assert inj.feed(b"\x00\x00\x00\x01\x61\x00").startswith(override)


def test_injector_works_on_sub_access_unit_chunks():
    video = _headerless_excerpt("4_android")
    inj = h264.ParameterSetInjector("auto", probe=2)
    out = b""
    for i in range(0, len(video), 4096):
        chunk = video[i:i + 4096]
        out += inj.feed(chunk, ends_access_unit=len(chunk) < 4096)
    out += inj.flush()
    assert inj.injected
    assert out == inj.build() + video


def test_injector_flush_emits_even_a_short_stream():
    inj = h264.ParameterSetInjector("auto", probe=99)
    assert inj.feed(b"\x00\x00\x00\x01\x61\x00") == b""   # still buffering
    tail = inj.flush()
    assert tail == inj.build() + b"\x00\x00\x00\x01\x61\x00"
    assert inj.injected


def test_injector_rejects_a_bad_mode():
    try:
        h264.ParameterSetInjector("sometimes")
    except ValueError:
        pass
    else:
        raise AssertionError("accepted an unknown mode")


def test_with_parameter_sets_is_playable_shaped():
    """
    A full capture is made playable by trimming to its own first SPS, not by
    prepending a synthesised one.
    """
    video = _video("4_android")
    out = h264.with_parameter_sets(video)
    assert out.startswith(h264.GOGGLES3_PARAMETER_SETS)
    nals = h264.split_annexb(out)
    assert [n[0] & 0x1F for n in nals[:3]] == [h264.NAL_SPS, h264.NAL_PPS,
                                              h264.NAL_IDR]
    got = h264.parse_sps(nals[0])
    assert (got["width"], got["height"]) == (1920, 1080)
    assert got["fps"] == 30.0
    # the trimmed head is a whole number of undecodable access units, under a
    # second of them, and the tail is untouched
    assert 0 < len(video) - len(out) < 700_000
    assert video.endswith(out[-4096:])


def test_with_parameter_sets_can_keep_every_byte():
    video = _video("4_android")
    assert h264.with_parameter_sets(video, trim=False) == video


def test_with_parameter_sets_synthesises_only_for_a_headerless_excerpt():
    excerpt = _headerless_excerpt("4_android")
    out = h264.with_parameter_sets(excerpt)
    assert out == h264.parameter_sets() + excerpt
    assert h264.split_annexb(out)[0][0] & 0x1F == h264.NAL_SPS


def test_injector_records_when_it_had_to_synthesise():
    """
    `matches_encoder` is what the CLI keys its loud warning off, so it has to
    be False exactly when the emitted header is a reconstruction.
    """
    excerpt = _headerless_excerpt("4_android")
    inj = h264.ParameterSetInjector("auto", probe=4, width=1280, height=720,
                                    fps=25.0)
    inj.feed(excerpt)
    inj.flush()
    assert inj.injected and not inj.matches_encoder
    assert inj.build() != h264.GOGGLES3_PARAMETER_SETS


def test_playable_prefix_is_a_no_op_without_parameter_sets():
    excerpt = _headerless_excerpt("4_android")
    assert h264.playable_prefix(excerpt) == excerpt
    assert h264.first_parameter_set_offset(excerpt) is None


# --------------------------------------------------------------------------- #
def _annex_units(video: bytes) -> list[bytes]:
    """Re-group an Annex-B stream into access units ending at the AUD."""
    units, cur = [], b""
    for nal in h264.split_annexb(video):
        cur += h264.START_CODE + nal
        if (nal[0] & 0x1F) == h264.NAL_AUD:
            units.append(cur)
            cur = b""
    if cur:
        units.append(cur)
    return units


# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    import support  # noqa: E402
    sys.exit(support.main(globals()))
