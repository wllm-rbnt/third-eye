"""
Just enough H.264 to turn the goggles' stream into a file a player will open.

The goggles sends its own parameter sets
----------------------------------------
This needs saying first, because it decides the whole design of this module.
**The goggles transmits SPS, PPS and an IDR once per second.** The median
SPS-to-SPS interval is 1000.5-1002.2 ms, and the parameter sets arrive in
their own 39-byte access unit 1.8-18.4 ms ahead of the IDR that follows
(PROTOCOL.md section 5). The SPS is byte-identical in every session, on both
transports -- exactly one distinct value. `GOGGLES3_SPS` below builds the same
bytes from the decoded fields, so the encoder's configuration is spelled out
field by field in `GOGGLES3_STYLE`.

So the normal path needs no synthesis at all: wait at most ~1 s (see
`PARAMETER_SET_PERIOD_S`) and the encoder hands you authoritative headers.
`pryer stream --wait-keyframe` does exactly that and is the default.

A stream that carries no parameter sets is still a real situation -- an excerpt
trimmed to a run of P slices, or a client that must emit something before the
next parameter-set interval -- so the synthesis path is kept as an explicit
fallback (`--inject always`), not as the default.

What synthesis is still for
---------------------------
Without an SPS a decoder cannot start:

    [h264] non-existing PPS 0 referenced
    Could not find codec parameters for stream 0 (Video: h264, none)

Guessing blindly would be useless, because a decoder parses every slice header
using values that come *from* the SPS and PPS: get `log2_max_frame_num_minus4`
or `entropy_coding_mode_flag` wrong and the slice header misparses. Those
values are recoverable from the slices themselves -- only one combination makes
every slice header parse consistently, which is what `infer()` searches for --
and the answer for the Goggles 3 is in `GOGGLES3` below. Every field `infer()`
recovers is confirmed against the goggles' real SPS by the test suite.

Two fields are *not* recoverable that way at all, because a slice header does
not depend on either: `pic_init_qp` (really **26**) and the frame rate (really
**30 fps**). Both are read from the goggles' own parameter sets. `search_pps()`
and the `tune` subcommand brute-force `pic_init_qp` with a decoder as oracle,
which is only useful for a capture excerpt that carries no parameter sets; the
value they land on is not a measurement of the encoder.

What this buys you, and what it does not
----------------------------------------
Synthesis buys a well-formed, seekable, timestamped file that `ffmpeg -c copy`
will remux. It does not conjure up frames that were never captured: a run of P
slices with no IDR in front of it has nothing to predict from, so a decoder
will emit grey or smeared pictures -- that is the data, not the parameter sets.
On a real stream this does not arise, because an IDR is at most one second
away.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field, replace

log = logging.getLogger("pryer.h264")

START_CODE = b"\x00\x00\x00\x01"

NAL_SLICE = 1
NAL_IDR = 5
NAL_SEI = 6
NAL_SPS = 7
NAL_PPS = 8
NAL_AUD = 9

P_SLICE_TYPES = (0, 5)
I_SLICE_TYPES = (2, 7)


# --------------------------------------------------------------------------- #
# bit-level codec
# --------------------------------------------------------------------------- #
def unescape(data: bytes) -> bytes:
    """Remove emulation-prevention bytes (00 00 03 -> 00 00)."""
    out = bytearray()
    zeros = 0
    for byte in data:
        if zeros >= 2 and byte == 0x03:
            zeros = 0
            continue
        out.append(byte)
        zeros = zeros + 1 if byte == 0 else 0
    return bytes(out)


def escape(data: bytes) -> bytes:
    """Insert emulation-prevention bytes so the payload cannot fake a start code."""
    out = bytearray()
    zeros = 0
    for byte in data:
        if zeros >= 2 and byte <= 0x03:
            out.append(0x03)
            zeros = 0
        out.append(byte)
        zeros = zeros + 1 if byte == 0 else 0
    return bytes(out)


class BitReader:
    """MSB-first bit reader with Exp-Golomb support."""

    def __init__(self, data: bytes, *, unescape_rbsp: bool = True):
        self.data = unescape(data) if unescape_rbsp else data
        self.pos = 0                       # in bits

    @property
    def remaining(self) -> int:
        return len(self.data) * 8 - self.pos

    def bit(self) -> int:
        if self.pos >= len(self.data) * 8:
            raise EOFError("out of bits")
        byte = self.data[self.pos >> 3]
        value = (byte >> (7 - (self.pos & 7))) & 1
        self.pos += 1
        return value

    def bits(self, n: int) -> int:
        value = 0
        for _ in range(n):
            value = (value << 1) | self.bit()
        return value

    def ue(self) -> int:
        zeros = 0
        while self.bit() == 0:
            zeros += 1
            if zeros > 32:
                raise ValueError("Exp-Golomb code too long")
        return (1 << zeros) - 1 + (self.bits(zeros) if zeros else 0)

    def se(self) -> int:
        k = self.ue()
        return (k + 1) // 2 if k % 2 else -(k // 2)

    def byte_aligned(self) -> bool:
        return self.pos % 8 == 0

    def more_rbsp_data(self) -> bool:
        """
        H.264 `more_rbsp_data()`: False when everything left is the
        rbsp_stop_one_bit followed by zero padding, True when a real optional
        tail follows (e.g. the High-profile part of a PPS).

        The stop bit is a single 1 and the padding is zeros, so "more data"
        is exactly "more than one 1-bit left".
        """
        save = self.pos
        try:
            ones = 0
            for _ in range(self.remaining):
                ones += self.bit()
                if ones > 1:
                    return True
            return False
        finally:
            self.pos = save

    def peek_alignment_ones(self) -> int:
        """How many 1-bits remain before the next byte boundary (-1 if a 0 is found)."""
        n = (-self.pos) % 8
        save = self.pos
        try:
            for _ in range(n):
                if self.bit() != 1:
                    return -1
            return n
        except EOFError:
            return -1
        finally:
            self.pos = save


class BitWriter:
    """MSB-first bit writer with Exp-Golomb and RBSP trailing bits."""

    def __init__(self):
        self.buf = bytearray()
        self.nbits = 0

    def bit(self, value: int) -> "BitWriter":
        if self.nbits % 8 == 0:
            self.buf.append(0)
        if value:
            self.buf[-1] |= 1 << (7 - (self.nbits % 8))
        self.nbits += 1
        return self

    def bits(self, value: int, n: int) -> "BitWriter":
        for i in range(n - 1, -1, -1):
            self.bit((value >> i) & 1)
        return self

    def ue(self, value: int) -> "BitWriter":
        assert value >= 0
        value += 1
        n = value.bit_length()
        self.bits(0, n - 1)
        return self.bits(value, n)

    def se(self, value: int) -> "BitWriter":
        return self.ue(2 * value - 1 if value > 0 else -2 * value)

    def trailing(self) -> "BitWriter":
        """rbsp_trailing_bits(): a 1 then zeros to the byte boundary."""
        self.bit(1)
        while self.nbits % 8:
            self.bit(0)
        return self

    def bytes(self) -> bytes:
        return bytes(self.buf)


# --------------------------------------------------------------------------- #
# the parameters a slice header depends on
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Hypothesis:
    """
    The SPS/PPS fields a *non-IDR P slice header* is parsed with -- i.e. exactly
    the set `infer()` has to recover. Everything else in an SPS or PPS affects
    macroblock decoding, not header parsing, and cannot be recovered this way.
    """
    log2_max_frame_num: int = 5             # SPS log2_max_frame_num_minus4 + 4
    pic_order_cnt_type: int = 2             # SPS
    log2_max_poc_lsb: int = 6               # SPS, only when pic_order_cnt_type == 0
    delta_pic_order_always_zero: bool = False   # SPS, pic_order_cnt_type == 1
    frame_mbs_only: bool = True             # SPS
    entropy_coding_mode: bool = True        # PPS  (True = CABAC)
    deblocking_filter_control_present: bool = True   # PPS
    redundant_pic_cnt_present: bool = False          # PPS
    bottom_field_pic_order_present: bool = False     # PPS
    weighted_pred: bool = False                      # PPS
    weighted_bipred_idc: int = 0                     # PPS
    num_slice_groups: int = 1                        # PPS

    def describe(self) -> str:
        poc = ("type %d" % self.pic_order_cnt_type
               + (", log2_max_poc_lsb %d" % self.log2_max_poc_lsb
                  if self.pic_order_cnt_type == 0 else ""))
        return ("log2_max_frame_num %d, pic_order_cnt %s, "
                "entropy %s, deblocking_control %s, frame_mbs_only %s"
                % (self.log2_max_frame_num, poc,
                   "CABAC" if self.entropy_coding_mode else "CAVLC",
                   self.deblocking_filter_control_present,
                   self.frame_mbs_only))


@dataclass
class SliceHeader:
    nal_type: int
    nal_ref_idc: int
    first_mb_in_slice: int
    slice_type: int
    pps_id: int
    frame_num: int
    field_pic: bool = False
    bottom_field: bool = False
    idr_pic_id: int | None = None
    poc_lsb: int | None = None
    num_ref_idx_l0: int | None = None
    slice_qp_delta: int | None = None
    disable_deblocking_idc: int | None = None
    header_bits: int = 0
    alignment_ones: int = 0

    @property
    def is_p(self) -> bool:
        return self.slice_type in P_SLICE_TYPES

    @property
    def is_i(self) -> bool:
        return self.slice_type in I_SLICE_TYPES

    @property
    def is_idr(self) -> bool:
        """An IDR resets frame_num and the picture order count to zero."""
        return self.nal_type == NAL_IDR


class SliceParseError(ValueError):
    pass


def parse_slice_header(nal: bytes, hyp: Hypothesis) -> SliceHeader:
    """
    Parse a slice header under `hyp`. Raises SliceParseError if the bits do not
    make sense -- which is the signal `infer()` uses to reject a hypothesis.

    Only what is needed to reach slice_qp_delta and the byte alignment is
    parsed; reference-list reordering and weighted-prediction tables are parsed
    far enough to stay in sync, and the exotic corners raise instead of
    guessing.
    """
    if not nal:
        raise SliceParseError("empty NAL")
    nal_type = nal[0] & 0x1F
    nal_ref_idc = (nal[0] >> 5) & 3
    if nal_type not in (NAL_SLICE, NAL_IDR):
        raise SliceParseError("not a slice NAL (type %d)" % nal_type)
    if nal[0] & 0x80:
        raise SliceParseError("forbidden_zero_bit set")

    r = BitReader(nal[1:])
    try:
        h = SliceHeader(nal_type=nal_type, nal_ref_idc=nal_ref_idc,
                        first_mb_in_slice=r.ue(), slice_type=r.ue(),
                        pps_id=r.ue(),
                        frame_num=r.bits(hyp.log2_max_frame_num))
        if h.slice_type > 9:
            raise SliceParseError("slice_type %d" % h.slice_type)
        if not hyp.frame_mbs_only:
            h.field_pic = bool(r.bit())
            if h.field_pic:
                h.bottom_field = bool(r.bit())
        if nal_type == NAL_IDR:
            h.idr_pic_id = r.ue()
        if hyp.pic_order_cnt_type == 0:
            h.poc_lsb = r.bits(hyp.log2_max_poc_lsb)
            if hyp.bottom_field_pic_order_present and not h.field_pic:
                r.se()                                  # delta_poc_bottom
        elif hyp.pic_order_cnt_type == 1 and not hyp.delta_pic_order_always_zero:
            r.se()                                      # delta_poc[0]
            if hyp.bottom_field_pic_order_present and not h.field_pic:
                r.se()                                  # delta_poc[1]
        if hyp.redundant_pic_cnt_present:
            r.ue()                                      # redundant_pic_cnt

        stype = h.slice_type % 5
        if stype == 1:
            raise SliceParseError("B slices not supported here")
        if stype == 0:                                  # P
            if r.bit():                                 # num_ref_idx override
                h.num_ref_idx_l0 = r.ue() + 1
            # ref_pic_list_modification_flag_l0
            if r.bit():
                while True:
                    op = r.ue()
                    if op == 3:
                        break
                    if op > 3:
                        raise SliceParseError("reordering op %d" % op)
                    r.ue()
            if hyp.weighted_pred:
                raise SliceParseError("weighted prediction tables unsupported")

        if nal_ref_idc:
            if nal_type == NAL_IDR:
                r.bit()                                 # no_output_of_prior_pics
                r.bit()                                 # long_term_reference
            elif r.bit():                               # adaptive marking
                while True:
                    op = r.ue()
                    if op == 0:
                        break
                    if op > 6:
                        raise SliceParseError("mmco %d" % op)
                    r.ue()
                    if op in (3, 6):
                        r.ue()

        if hyp.entropy_coding_mode and stype != 2:
            cabac_init_idc = r.ue()
            if cabac_init_idc > 2:
                raise SliceParseError("cabac_init_idc %d" % cabac_init_idc)
        h.slice_qp_delta = r.se()
        if hyp.deblocking_filter_control_present:
            h.disable_deblocking_idc = r.ue()
            if h.disable_deblocking_idc > 2:
                raise SliceParseError("disable_deblocking_filter_idc %d"
                                      % h.disable_deblocking_idc)
            if h.disable_deblocking_idc != 1:
                r.se()                                  # slice_alpha_c0_offset
                r.se()                                  # slice_beta_offset
        if hyp.num_slice_groups > 1:
            raise SliceParseError("slice groups unsupported")
    except EOFError as exc:
        raise SliceParseError("ran out of bits: %s" % exc) from exc

    h.header_bits = r.pos
    if hyp.entropy_coding_mode:
        ones = r.peek_alignment_ones()
        if ones < 0:
            raise SliceParseError("cabac_alignment_one_bit is not all ones")
        h.alignment_ones = ones
    return h


# --------------------------------------------------------------------------- #
# inference
# --------------------------------------------------------------------------- #
@dataclass
class Inference:
    hypothesis: Hypothesis
    slices: list[SliceHeader] = field(default_factory=list)
    candidates: int = 0
    qp: int | None = None

    def describe(self) -> str:
        kinds = {}
        for s in self.slices:
            kinds["I" if s.is_i else "P" if s.is_p else "?"] = \
                kinds.get("I" if s.is_i else "P" if s.is_p else "?", 0) + 1
        return ("%s\n  %d slices (%s), frame_num %s, slice_qp_delta %s"
                % (self.hypothesis.describe(), len(self.slices),
                   " ".join("%s=%d" % kv for kv in sorted(kinds.items())),
                   "->".join(str(s.frame_num) for s in self.slices[:8]),
                   ", ".join(sorted({str(s.slice_qp_delta)
                                     for s in self.slices}))))


def _candidate_hypotheses():
    for entropy in (True, False):
        for log2_fn in range(4, 17):
            for poc_type, log2_poc in ([(2, 6)]
                                       + [(0, n) for n in range(4, 17)]
                                       + [(1, 6)]):
                for deblock in (True, False):
                    for redundant in (False, True):
                        yield Hypothesis(
                            log2_max_frame_num=log2_fn,
                            pic_order_cnt_type=poc_type,
                            log2_max_poc_lsb=log2_poc,
                            entropy_coding_mode=entropy,
                            deblocking_filter_control_present=deblock,
                            redundant_pic_cnt_present=redundant)


def _consistent(headers: list[SliceHeader], hyp: Hypothesis) -> bool:
    """Sanity rules that a correct hypothesis must satisfy on a real stream."""
    if not headers:
        return False
    for h in headers:
        if h.first_mb_in_slice != 0:        # the goggles sends one slice/picture
            return False
        if h.pps_id != 0:
            return False
        if h.slice_type not in P_SLICE_TYPES + I_SLICE_TYPES:
            return False
        if h.slice_qp_delta is None or not -26 <= h.slice_qp_delta <= 25:
            return False
        if hyp.entropy_coding_mode and h.alignment_ones > 7:
            return False
    # frame_num advances by exactly one per picture -- except at an IDR, which
    # by specification resets it to 0. The stream carries an IDR roughly
    # every second, so a run of slices will normally contain one, and demanding
    # unbroken monotonicity across it rejects the correct hypothesis outright.
    modulus = 1 << hyp.log2_max_frame_num
    for a, b in zip(headers, headers[1:]):
        if b.is_idr:
            if b.frame_num != 0:
                return False
            continue
        if (a.frame_num + 1) % modulus != b.frame_num % modulus:
            return False
    # In a CBR low-latency encode every picture of a given type shares one QP
    # offset, but I and P pictures do not share it with each other: measured
    # slice_qp_delta is, for example, -10 for the P slices and -11 for the IDRs
    # of one session (-6 / -7 in another). Compare within a slice type, not
    # across.
    for kind in (True, False):
        deltas = {h.slice_qp_delta for h in headers if h.is_i is kind}
        if len(deltas) > 1:
            return False
    if hyp.pic_order_cnt_type == 0:
        # POC also restarts at an IDR, so only check runs between IDRs.
        lsbs: list[int] = []
        runs = [lsbs]
        for h in headers:
            if h.is_idr and lsbs:
                lsbs = []
                runs.append(lsbs)
            lsbs.append(h.poc_lsb)
        for run in runs:
            deltas = {(b - a) % (1 << hyp.log2_max_poc_lsb)
                      for a, b in zip(run, run[1:])}
            if len(deltas) > 1 or (deltas and deltas.pop() == 0):
                return False
        if all(len(run) < 2 for run in runs):
            return False
    return True


def _rank(hyp: Hypothesis) -> tuple:
    """Prefer the simplest explanation when several hypotheses survive."""
    return (0 if hyp.pic_order_cnt_type == 2 else 1,
            hyp.log2_max_frame_num,
            0 if hyp.entropy_coding_mode else 1,
            0 if hyp.deblocking_filter_control_present else 1,
            1 if hyp.redundant_pic_cnt_present else 0,
            hyp.log2_max_poc_lsb)


def infer(slice_nals, *, limit: int = 16) -> Inference | None:
    """
    Recover the slice-header-relevant SPS/PPS fields from a run of slices.

    Returns None if nothing fits (too few slices, B slices, slice groups...).
    """
    nals = [n for n in list(slice_nals)[:limit]
            if n and (n[0] & 0x1F) in (NAL_SLICE, NAL_IDR)]
    if len(nals) < 2:
        return None
    survivors = []
    for hyp in _candidate_hypotheses():
        try:
            headers = [parse_slice_header(n, hyp) for n in nals]
        except SliceParseError:
            continue
        if _consistent(headers, hyp):
            survivors.append((hyp, headers))
    if not survivors:
        return None
    survivors.sort(key=lambda pair: _rank(pair[0]))
    hyp, headers = survivors[0]
    return Inference(hypothesis=hyp, slices=headers, candidates=len(survivors))


# The answer for the DJI Goggles 3. infer() recovers it from slice headers
# alone, and every field agrees with the encoder's real SPS/PPS (see
# GOGGLES3_SPS / GOGGLES3_PPS below); tests/test_h264.py asserts both.
GOGGLES3 = Hypothesis(
    log2_max_frame_num=5,
    pic_order_cnt_type=2,
    entropy_coding_mode=True,
    deblocking_filter_control_present=True,
    frame_mbs_only=True,
    redundant_pic_cnt_present=False,
)


# --------------------------------------------------------------------------- #
# How an encoder presents itself in the SPS
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class VideoSignal:
    """VUI video_signal_type (H.264 E.2.1). The defaults are the goggles'."""
    video_format: int = 5              # 5 = unspecified
    full_range: bool = False
    colour_primaries: int = 1          # 1 = BT.709
    transfer_characteristics: int = 1  # 1 = BT.709
    matrix_coefficients: int = 1       # 1 = BT.709


@dataclass(frozen=True)
class BitstreamRestriction:
    """VUI bitstream_restriction (H.264 E.2.1). The defaults are the goggles'."""
    motion_vectors_over_pic_boundaries: bool = True
    max_bytes_per_pic_denom: int = 0
    max_bits_per_mb_denom: int = 0
    log2_max_mv_length_horizontal: int = 13
    log2_max_mv_length_vertical: int = 11
    max_num_reorder_frames: int = 0
    max_dec_frame_buffering: int = 1


@dataclass(frozen=True)
class EncoderStyle:
    """
    The SPS fields that neither a slice header nor the picture geometry depends
    on: how an encoder chooses to describe its stream. A decoder produces the
    same pictures whichever values these take, which is why `infer()` cannot
    recover them and why they are kept apart from :class:`Hypothesis`.

    `tick_units` fixes num_units_in_tick (time_scale is then 2 * fps * units);
    None picks the smallest exact pair (`_tick`).
    """
    gaps_in_frame_num_allowed: bool = True
    video_signal: VideoSignal | None = None
    tick_units: int | None = None
    fixed_frame_rate: bool = True
    bitstream_restriction: BitstreamRestriction | None = None


# What `build_sps` writes by default: the smallest VUI that carries a frame
# rate, with gaps_in_frame_num allowed because a reader may join mid-stream.
GENERIC_STYLE = EncoderStyle()

# The Goggles 3 encoder's choices, decoded from the SPS it sends (below).
GOGGLES3_STYLE = EncoderStyle(
    gaps_in_frame_num_allowed=False,
    video_signal=VideoSignal(),
    tick_units=1000,
    fixed_frame_rate=False,
    bitstream_restriction=BitstreamRestriction(),
)


# Displayed geometry and the VUI frame rate, from the SPS below.
GOGGLES3_WIDTH = 1920
GOGGLES3_HEIGHT = 1080
GOGGLES3_FPS = 30.0
GOGGLES3_LEVEL_IDC = 52
# pic_init_qp_minus26 is 0 in the real PPS, i.e. the H.264 default. Note that
# the brute-force search in `search_pps` cannot recover this on an excerpt with
# no IDR: with no reference picture only a few per cent of each frame is ever
# painted, so its decoder-error oracle cannot separate nearby candidates.
GOGGLES3_PIC_INIT_QP = 26

# Measured SPS-to-SPS interval, seconds: per-session medians of
# 1.0005-1.0022 s. This is the worst-case wait for `--wait-keyframe`.
PARAMETER_SET_PERIOD_S = 1.0

# Measured access-unit cadence, seconds. Per-session medians 33.07-33.42 ms,
# i.e. 29.9-30.2 fps, in agreement with the VUI above.
GOGGLES3_AU_INTERVAL_S = 1.0 / 30.0

# How many access units ParameterSetInjector("auto") buffers before deciding the
# stream has none of its own. Must exceed one parameter-set interval: 40 units
# at ~30 fps is ~1.33 s against a measured ~1.00 s period.
DEFAULT_PROBE_UNITS = 40


# --------------------------------------------------------------------------- #
# SPS / PPS synthesis
# --------------------------------------------------------------------------- #
def build_sps(width: int = 1920, height: int = 1080, *,
              fps: float = GOGGLES3_FPS,
              hyp: Hypothesis = GOGGLES3, profile_idc: int = 100,
              level_idc: int = GOGGLES3_LEVEL_IDC, sps_id: int = 0,
              max_num_ref_frames: int = 1,
              style: EncoderStyle = GENERIC_STYLE) -> bytes:
    """
    A High-profile SPS carrying `width`x`height`, `fps` and the fields `hyp`
    says the slice headers were written with. Returned as a NAL (no start code).

    `style` sets the fields nothing in the slices depends on. With
    `GOGGLES3_STYLE` and the Goggles 3 geometry this is the goggles' own SPS,
    byte for byte (`GOGGLES3_SPS`).
    """
    if width % 16 or height % 2:
        raise ValueError("width must be a multiple of 16, height even")
    mbs_wide = width // 16
    map_units_high = (height + 15) // 16
    crop_bottom = (map_units_high * 16 - height) // 2   # CropUnitY = 2 for 4:2:0

    w = BitWriter()
    w.bits(profile_idc, 8).bits(0, 8).bits(level_idc, 8)
    w.ue(sps_id)
    if profile_idc in (100, 110, 122, 244, 44, 83, 86, 118, 128, 138, 139, 134):
        w.ue(1)             # chroma_format_idc 4:2:0
        w.ue(0)             # bit_depth_luma_minus8
        w.ue(0)             # bit_depth_chroma_minus8
        w.bit(0)            # qpprime_y_zero_transform_bypass_flag
        w.bit(0)            # seq_scaling_matrix_present_flag
    w.ue(hyp.log2_max_frame_num - 4)
    w.ue(hyp.pic_order_cnt_type)
    if hyp.pic_order_cnt_type == 0:
        w.ue(hyp.log2_max_poc_lsb - 4)
    elif hyp.pic_order_cnt_type == 1:
        w.bit(1 if hyp.delta_pic_order_always_zero else 0)
        w.se(0)             # offset_for_non_ref_pic
        w.se(0)             # offset_for_top_to_bottom_field
        w.ue(0)             # num_ref_frames_in_pic_order_cnt_cycle
    w.ue(max_num_ref_frames)
    w.bit(1 if style.gaps_in_frame_num_allowed else 0)
    w.ue(mbs_wide - 1)
    w.ue(map_units_high - 1)
    w.bit(1 if hyp.frame_mbs_only else 0)
    if not hyp.frame_mbs_only:
        w.bit(0)            # mb_adaptive_frame_field_flag
    w.bit(1)                # direct_8x8_inference_flag
    if crop_bottom:
        w.bit(1)
        w.ue(0).ue(0).ue(0).ue(crop_bottom)
    else:
        w.bit(0)            # frame_cropping_flag

    # VUI: at least a frame rate, plus whatever the style describes
    w.bit(1)                # vui_parameters_present_flag
    w.bit(0)                # aspect_ratio_info_present_flag
    w.bit(0)                # overscan_info_present_flag
    vs = style.video_signal
    w.bit(1 if vs else 0)   # video_signal_type_present_flag
    if vs:
        w.bits(vs.video_format, 3)
        w.bit(1 if vs.full_range else 0)
        w.bit(1)            # colour_description_present_flag
        w.bits(vs.colour_primaries, 8)
        w.bits(vs.transfer_characteristics, 8)
        w.bits(vs.matrix_coefficients, 8)
    w.bit(0)                # chroma_loc_info_present_flag
    w.bit(1)                # timing_info_present_flag
    num_units_in_tick, time_scale = _tick(fps, style.tick_units)
    w.bits(num_units_in_tick, 32)
    w.bits(time_scale, 32)
    w.bit(1 if style.fixed_frame_rate else 0)
    w.bit(0)                # nal_hrd_parameters_present_flag
    w.bit(0)                # vcl_hrd_parameters_present_flag
    w.bit(0)                # pic_struct_present_flag
    br = style.bitstream_restriction
    w.bit(1 if br else 0)   # bitstream_restriction_flag
    if br:
        w.bit(1 if br.motion_vectors_over_pic_boundaries else 0)
        w.ue(br.max_bytes_per_pic_denom)
        w.ue(br.max_bits_per_mb_denom)
        w.ue(br.log2_max_mv_length_horizontal)
        w.ue(br.log2_max_mv_length_vertical)
        w.ue(br.max_num_reorder_frames)
        w.ue(br.max_dec_frame_buffering)
    w.trailing()
    return bytes([0x67]) + escape(w.bytes())        # nal_ref_idc 3, type 7


def _tick(fps: float, units: int | None = None) -> tuple[int, int]:
    """(num_units_in_tick, time_scale) with time_scale = 2 * fps * units."""
    if units is not None:
        return units, int(round(fps * units * 2))
    if abs(fps - round(fps)) < 1e-6:
        return 1, int(round(fps)) * 2
    # 29.97 / 59.94 style rates
    return 1001, int(round(fps * 1001)) * 2


def build_pps(*, hyp: Hypothesis = GOGGLES3, pps_id: int = 0, sps_id: int = 0,
              pic_init_qp: int = 26, num_ref_idx_l0: int = 1,
              transform_8x8_mode: bool = False,
              constrained_intra_pred: bool = False,
              chroma_qp_index_offset: int = 0,
              second_chroma_qp_index_offset: int | None = None) -> bytes:
    """
    A PPS. Note that `pic_init_qp` is not cosmetic: CABAC contexts are
    initialised from SliceQPY = pic_init_qp + slice_qp_delta, so a wrong value
    makes every macroblock decode as garbage even though the headers parse. See
    `search_pps()`.
    """
    w = BitWriter()
    w.ue(pps_id)
    w.ue(sps_id)
    w.bit(1 if hyp.entropy_coding_mode else 0)
    w.bit(1 if hyp.bottom_field_pic_order_present else 0)
    w.ue(hyp.num_slice_groups - 1)
    w.ue(num_ref_idx_l0 - 1)
    w.ue(0)                 # num_ref_idx_l1_default_active_minus1
    w.bit(1 if hyp.weighted_pred else 0)
    w.bits(hyp.weighted_bipred_idc, 2)
    w.se(pic_init_qp - 26)
    w.se(0)                 # pic_init_qs_minus26
    w.se(chroma_qp_index_offset)
    w.bit(1 if hyp.deblocking_filter_control_present else 0)
    w.bit(1 if constrained_intra_pred else 0)
    w.bit(1 if hyp.redundant_pic_cnt_present else 0)
    if transform_8x8_mode or second_chroma_qp_index_offset is not None:
        # the optional High-profile tail
        w.bit(1 if transform_8x8_mode else 0)
        w.bit(0)            # pic_scaling_matrix_present_flag
        w.se(chroma_qp_index_offset if second_chroma_qp_index_offset is None
             else second_chroma_qp_index_offset)
    w.trailing()
    return bytes([0x68]) + escape(w.bytes())        # nal_ref_idc 3, type 8


# --------------------------------------------------------------------------- #
# The encoder's own parameter sets
# --------------------------------------------------------------------------- #
# The goggles sends exactly one distinct SPS and one distinct PPS, on both
# the Android (AOA) and iOS (iAP2) transports. Decoded:
#
#   profile_idc 100 (High)          level_idc 52 (5.2), no constraint flags
#   coded 1920x1088, crop_bottom 4 -> displayed 1920x1080
#   chroma_format_idc 1 (4:2:0)     bit depth 8/8
#   log2_max_frame_num 5            pic_order_cnt_type 2
#   max_num_ref_frames 1            gaps_in_frame_num_allowed 0
#   frame_mbs_only_flag 1 (progressive), direct_8x8_inference 1
#   VUI: video_format 5, full_range 0, primaries/transfer/matrix all 1,
#        num_units_in_tick 1000, time_scale 60000 -> 30.000 fps,
#        fixed_frame_rate_flag 0, bitstream_restriction: mv over picture
#        boundaries 1, log2_max_mv_length 13/11, max_num_reorder_frames 0,
#        max_dec_frame_buffering 1
#   PPS: CABAC, one slice group, num_ref_idx_l0/l1 = 1, no weighted pred,
#        pic_init_qp 26, pic_init_qs 26, chroma_qp_index_offset 0,
#        deblocking_filter_control_present 1, no constrained intra,
#        no redundant_pic_cnt, and the High-profile tail *is* present with
#        transform_8x8_mode_flag 1, no scaling matrices,
#        second_chroma_qp_index_offset 0
#
# Both are built from those fields; the result is byte-identical to what the
# goggles sends (67 64 00 34 ac 4d 00 f0 04 4f cb 35 01 01 01 40 00 00 fa 00
# 00 3a 98 03 c7 0c a8 / 68 ee 3c b0), which tests/test_h264.py asserts.
GOGGLES3_TRANSFORM_8X8 = True

GOGGLES3_SPS = build_sps(GOGGLES3_WIDTH, GOGGLES3_HEIGHT, fps=GOGGLES3_FPS,
                         hyp=GOGGLES3, level_idc=GOGGLES3_LEVEL_IDC,
                         style=GOGGLES3_STYLE)
GOGGLES3_PPS = build_pps(hyp=GOGGLES3, pic_init_qp=GOGGLES3_PIC_INIT_QP,
                         transform_8x8_mode=GOGGLES3_TRANSFORM_8X8)
GOGGLES3_PARAMETER_SETS = (START_CODE + GOGGLES3_SPS
                           + START_CODE + GOGGLES3_PPS)


def parse_sps(nal: bytes) -> dict:
    """
    Read back width/height/fps and the header-relevant fields. Used to check
    build_sps() round-trips and to report what a real stream announced.
    """
    if not nal or (nal[0] & 0x1F) != NAL_SPS:
        raise ValueError("not an SPS NAL")
    r = BitReader(nal[1:])
    out: dict = {}
    out["profile_idc"] = r.bits(8)
    r.bits(8)
    out["level_idc"] = r.bits(8)
    out["sps_id"] = r.ue()
    out["chroma_format_idc"] = 1
    if out["profile_idc"] in (100, 110, 122, 244, 44, 83, 86, 118, 128, 138,
                              139, 134):
        out["chroma_format_idc"] = r.ue()
        if out["chroma_format_idc"] == 3:
            r.bit()
        r.ue(); r.ue(); r.bit()
        if r.bit():
            raise ValueError("scaling matrices not supported")
    log2_fn = r.ue() + 4
    poc_type = r.ue()
    log2_poc = 6
    delta_zero = False
    if poc_type == 0:
        log2_poc = r.ue() + 4
    elif poc_type == 1:
        delta_zero = bool(r.bit())
        r.se(); r.se()
        for _ in range(r.ue()):
            r.se()
    out["max_num_ref_frames"] = r.ue()
    out["gaps_allowed"] = bool(r.bit())
    mbs_wide = r.ue() + 1
    map_units_high = r.ue() + 1
    frame_mbs_only = bool(r.bit())
    if not frame_mbs_only:
        r.bit()
    r.bit()                                     # direct_8x8_inference_flag
    crop = [0, 0, 0, 0]
    if r.bit():
        crop = [r.ue() for _ in range(4)]
    out["crop"] = tuple(crop)
    out["crop_left"], out["crop_right"] = crop[0], crop[1]
    out["crop_top"], out["crop_bottom"] = crop[2], crop[3]
    out["mb_width"], out["mb_height"] = mbs_wide, map_units_high
    out["width"] = mbs_wide * 16 - (crop[0] + crop[1]) * 2
    out["height"] = (map_units_high * 16 * (1 if frame_mbs_only else 2)
                     - (crop[2] + crop[3]) * (2 if frame_mbs_only else 4))
    out["fps"] = None
    if r.bit():                                 # vui_parameters_present_flag
        if r.bit():                             # aspect_ratio_info_present
            if r.bits(8) == 255:
                r.bits(16); r.bits(16)
        if r.bit():
            r.bit()                             # overscan_appropriate
        if r.bit():                             # video_signal_type_present
            r.bits(3); r.bit()
            if r.bit():
                r.bits(8); r.bits(8); r.bits(8)
        if r.bit():
            r.ue(); r.ue()                      # chroma_sample_loc
        if r.bit():                             # timing_info_present
            units = r.bits(32)
            scale = r.bits(32)
            out["fixed_frame_rate"] = bool(r.bit())
            if units:
                out["fps"] = scale / (2.0 * units)
    out["hypothesis"] = Hypothesis(
        log2_max_frame_num=log2_fn, pic_order_cnt_type=poc_type,
        log2_max_poc_lsb=log2_poc, delta_pic_order_always_zero=delta_zero,
        frame_mbs_only=frame_mbs_only)
    return out


def parse_pps(nal: bytes) -> dict:
    if not nal or (nal[0] & 0x1F) != NAL_PPS:
        raise ValueError("not a PPS NAL")
    r = BitReader(nal[1:])
    out = {"pps_id": r.ue(), "sps_id": r.ue(),
           "entropy_coding_mode": bool(r.bit()),
           "bottom_field_pic_order_present": bool(r.bit()),
           "num_slice_groups": r.ue() + 1}
    if out["num_slice_groups"] > 1:
        raise ValueError("slice groups not supported")
    out["num_ref_idx_l0"] = r.ue() + 1
    out["num_ref_idx_l1"] = r.ue() + 1
    out["weighted_pred"] = bool(r.bit())
    out["weighted_bipred_idc"] = r.bits(2)
    out["pic_init_qp"] = r.se() + 26
    r.se()                                      # pic_init_qs_minus26
    out["chroma_qp_index_offset"] = r.se()
    out["deblocking_filter_control_present"] = bool(r.bit())
    out["constrained_intra_pred"] = bool(r.bit())
    out["redundant_pic_cnt_present"] = bool(r.bit())
    out["transform_8x8_mode"] = False
    out["second_chroma_qp_index_offset"] = out["chroma_qp_index_offset"]
    if r.more_rbsp_data():
        # the optional High-profile tail is present
        out["transform_8x8_mode"] = bool(r.bit())
        if r.bit():
            raise ValueError("scaling matrices in the PPS are not supported")
        out["second_chroma_qp_index_offset"] = r.se()
    return out


def parameter_sets(width: int = GOGGLES3_WIDTH, height: int = GOGGLES3_HEIGHT,
                   *, fps: float = GOGGLES3_FPS,
                   hyp: Hypothesis = GOGGLES3,
                   pic_init_qp: int = GOGGLES3_PIC_INIT_QP,
                   match_encoder: bool = True) -> bytes:
    """
    SPS + PPS as an Annex-B byte string, ready to prepend to the stream.

    With `match_encoder` (the default) they are written the way the Goggles 3
    encoder writes its own (`GOGGLES3_STYLE`, and a PPS with
    transform_8x8_mode), so with the Goggles 3 parameters unchanged the result
    is the goggles' own bytes, `GOGGLES3_PARAMETER_SETS`, and an overridden
    geometry, rate, QP or hypothesis changes only those fields.
    `match_encoder=False` writes the generic minimal set instead
    (`GENERIC_STYLE`, no High-profile PPS tail).
    """
    if match_encoder:
        style, transform_8x8 = GOGGLES3_STYLE, GOGGLES3_TRANSFORM_8X8
    else:
        style, transform_8x8 = GENERIC_STYLE, False
    return (START_CODE + build_sps(width, height, fps=fps, hyp=hyp,
                                   style=style)
            + START_CODE + build_pps(hyp=hyp, pic_init_qp=pic_init_qp,
                                     transform_8x8_mode=transform_8x8))


def split_annexb(data: bytes) -> list[bytes]:
    """Split an Annex-B byte string into NAL payloads (3- or 4-byte start codes)."""
    out = []
    i = data.find(b"\x00\x00\x01")
    while i >= 0:
        start = i + 3
        j = data.find(b"\x00\x00\x01", start)
        end = len(data) if j < 0 else j
        nal = data[start:end]
        while nal.endswith(b"\x00"):
            nal = nal[:-1]
        if nal:
            out.append(nal)
        i = j
    return out


def load_parameter_sets(path: str) -> bytes:
    """
    Read SPS/PPS from a file: either raw Annex-B (e.g. the first KiB of a real
    stream, or `ffmpeg -bsf:v extract_extradata` output) or a hex dump.
    """
    with open(path, "rb") as fh:
        blob = fh.read()
    if b"\x00\x00\x01" not in blob:
        try:
            text = "".join(line.split("#")[0]
                           for line in blob.decode("ascii").splitlines())
            blob = bytes.fromhex(text.replace("0x", "").replace(",", " "))
        except (UnicodeDecodeError, ValueError):
            raise ValueError("%s contains no start codes and is not a hex dump"
                             % path) from None
    wanted = [n for n in split_annexb(blob) if (n[0] & 0x1F) in (NAL_SPS,
                                                                NAL_PPS)]
    if not any((n[0] & 0x1F) == NAL_SPS for n in wanted):
        raise ValueError("%s has no SPS" % path)
    if not any((n[0] & 0x1F) == NAL_PPS for n in wanted):
        raise ValueError("%s has no PPS" % path)
    return b"".join(START_CODE + n for n in wanted)


# --------------------------------------------------------------------------- #
# injection
# --------------------------------------------------------------------------- #
class ParameterSetInjector:
    """
    Sits between the tunnel and the sink and guarantees the output starts with
    parameter sets.

    Modes:
      "auto"   inject only if the stream has not produced an SPS by the time
               `probe` access units have gone by (the useful default)
      "always" inject immediately, even if the stream has its own
      "never"   pass everything through untouched

    In "auto" mode the first `probe` access units are buffered, so the SPS ends
    up genuinely first in the file. With `infer_from_stream` the buffered slices
    are also used to recover the encoder's real header parameters instead of
    trusting `GOGGLES3`.

    `probe` must span more than one parameter-set interval, or "auto" will
    synthesise headers for a stream that was about to supply its own. The
    goggles repeats SPS/PPS every ~1 s at ~30 fps, so the default
    (`DEFAULT_PROBE_UNITS`) buffers ~1.3 s of video. A probe of only a few units
    spans ~130 ms and would therefore synthesise almost every time.

    On a live link prefer `mode="never"` together with `--wait-keyframe`: the
    real parameter sets are at most ~1 s away and are always preferable to
    synthesised ones.
    """

    def __init__(self, mode: str = "auto", *, width: int = GOGGLES3_WIDTH,
                 height: int = GOGGLES3_HEIGHT, fps: float = GOGGLES3_FPS,
                 hypothesis: Hypothesis = GOGGLES3,
                 override: bytes | None = None,
                 probe: int = DEFAULT_PROBE_UNITS,
                 infer_from_stream: bool = True,
                 pic_init_qp: int = GOGGLES3_PIC_INIT_QP):
        if mode not in ("auto", "always", "never"):
            raise ValueError("mode must be auto, always or never")
        self.mode = mode
        self.width, self.height, self.fps = width, height, fps
        self.hypothesis = hypothesis
        self.override = override
        self.probe = max(probe, 1)
        self.infer_from_stream = infer_from_stream
        self.pic_init_qp = pic_init_qp

        self.injected = False
        # True when what was injected is byte-identical to the goggles' own
        # parameter sets (GOGGLES3_PARAMETER_SETS), or was supplied by the
        # caller; False when an overridden field made it a reconstruction.
        self.matches_encoder = False
        self.stream_had_parameter_sets = False
        self.inference: Inference | None = None
        self._buffer: list[bytes] = []
        self._units = 0
        self._done = mode == "never"

    # ------------------------------------------------------------------ #
    def build(self) -> bytes:
        if self.override is not None:
            return self.override
        hyp = self.hypothesis
        if self.inference is not None:
            hyp = self.inference.hypothesis
        return parameter_sets(self.width, self.height, fps=self.fps, hyp=hyp,
                              pic_init_qp=self.pic_init_qp)

    def feed(self, data: bytes, *, ends_access_unit: bool = True) -> bytes:
        """Chunk in, chunk out (possibly with parameter sets in front)."""
        if self._done:
            return data
        nal_types = {n[0] & 0x1F for n in split_annexb(data) if n}
        if nal_types & {NAL_SPS}:
            self.stream_had_parameter_sets = True
            if self.mode == "auto":
                return self._flush(data)            # nothing to do, let it go
        if self.mode == "always":
            return self._emit() + data
        self._buffer.append(data)
        if ends_access_unit:
            self._units += 1
        if self._units < self.probe:
            return b""
        return self._flush()

    def flush(self) -> bytes:
        """Call at end of stream so a short capture still gets its headers."""
        return b"" if self._done else self._flush()

    # ------------------------------------------------------------------ #
    def _flush(self, tail: bytes = b"") -> bytes:
        buffered = b"".join(self._buffer) + tail
        self._buffer.clear()
        self._done = True
        if self.stream_had_parameter_sets:
            return buffered
        if self.infer_from_stream:
            slices = [n for n in split_annexb(buffered)
                      if n and (n[0] & 0x1F) in (NAL_SLICE, NAL_IDR)]
            self.inference = infer(slices)
            if self.inference is not None:
                log.info("inferred slice-header parameters: %s",
                         self.inference.hypothesis.describe())
            else:
                log.warning("could not infer slice-header parameters, using the "
                            "Goggles 3 defaults")
        return self._emit() + buffered

    def _emit(self) -> bytes:
        self._done = True
        if self.injected:
            return b""
        self.injected = True
        blob = self.build()
        if self.override is not None:
            self.matches_encoder = True
            log.info("injected %d bytes of supplied parameter sets", len(blob))
        elif blob == GOGGLES3_PARAMETER_SETS:
            self.matches_encoder = True
            log.info("injected %d bytes of parameter sets identical to the "
                     "goggles' own (%dx%d @ %g)", len(blob), self.width,
                     self.height, self.fps)
        else:
            log.warning("injected %d bytes of SYNTHESISED parameter sets "
                        "(%dx%d @ %g, pic_init_qp %d) -- the stream did not "
                        "supply its own within %d access units; on a live link "
                        "the goggles sends real ones every ~%.1fs",
                        len(blob), self.width, self.height, self.fps,
                        self.pic_init_qp, self.probe, PARAMETER_SET_PERIOD_S)
        return blob


def first_parameter_set_offset(annexb: bytes) -> int | None:
    """
    Offset of the start code of the first SPS in `annexb`, or None if there is
    none. This is where a decoder can actually begin.
    """
    i = annexb.find(b"\x00\x00\x01")
    while i >= 0:
        payload = i + 3
        if payload < len(annexb) and annexb[payload] & 0x1F == NAL_SPS:
            # include a 4-byte start code if that is what is actually there
            return i - 1 if i > 0 and annexb[i - 1] == 0 else i
        i = annexb.find(b"\x00\x00\x01", payload)
    return None


def playable_prefix(annexb: bytes) -> bytes:
    """
    Trim `annexb` to start at its first SPS, so it decodes from byte zero.

    The goggles repeats SPS, PPS and an IDR about once a second, so a capture
    that begins mid-stream carries up to a second of P slices in front of the
    first usable entry point. Those slices reference a PPS the decoder has not
    seen and a frame it cannot reconstruct; ffmpeg reports "non-existing PPS 0
    referenced" and discards them anyway. Dropping them costs under a second
    and invents nothing.

    Returns `annexb` unchanged if it has no parameter sets at all -- use
    `with_parameter_sets` for that case.
    """
    offset = first_parameter_set_offset(annexb)
    return annexb if offset is None else annexb[offset:]


def with_parameter_sets(annexb: bytes, *, width: int = GOGGLES3_WIDTH,
                        height: int = GOGGLES3_HEIGHT,
                        fps: float = GOGGLES3_FPS, mode: str = "auto",
                        pic_init_qp: int = GOGGLES3_PIC_INIT_QP,
                        trim: bool = True) -> bytes:
    """
    Return `annexb` in a shape a decoder can open from its first byte.

    Two different situations, and the first one is the normal one:

    * the stream carries the encoder's own SPS/PPS somewhere inside it, which
      every recording longer than about a second does. Nothing needs
      inventing: with `trim` set (the default) the leading undecodable slices
      are cut off so the result begins at a real parameter set. Pass `trim=False` to keep every byte and
      let the decoder skip the head itself.
    * the stream has no parameter sets, because it is a short excerpt or the
      reader joined mid-second and stopped early. Then a parameter set is
      prepended. With the Goggles 3 defaults unchanged it is byte-identical to
      the encoder's own; an overridden geometry or QP makes it a
      reconstruction, and `ParameterSetInjector.matches_encoder` is left False
      to record it.
    """
    inj = ParameterSetInjector(mode, width=width, height=height, fps=fps,
                               pic_init_qp=pic_init_qp)
    out = inj.feed(annexb) + inj.flush()
    if trim and inj.stream_had_parameter_sets:
        return playable_prefix(out)
    return out


# --------------------------------------------------------------------------- #
# using a decoder as an oracle for the fields the headers cannot reveal
# --------------------------------------------------------------------------- #
@dataclass
class TuneResult:
    pic_init_qp: int
    transform_8x8: bool
    constrained_intra: bool
    errors: int
    frames: int
    coverage: float          # fraction of the last picture that is not grey

    @property
    def score(self) -> tuple:
        return (self.errors, -self.coverage, -self.frames)

    def describe(self) -> str:
        return ("pic_init_qp %2d  transform_8x8 %-5s constrained_intra %-5s "
                "-> %2d MB errors, %d frames, %.1f%% of the picture decoded"
                % (self.pic_init_qp, self.transform_8x8,
                   self.constrained_intra, self.errors, self.frames,
                   100 * self.coverage))


def search_pps(annexb: bytes, *, width: int = 1920, height: int = 1080,
               fps: float = 60.0, hyp: Hypothesis = GOGGLES3,
               qps=range(52), transform_8x8=(False, True),
               constrained_intra=(False,), ffmpeg: str = "ffmpeg",
               progress=None) -> list[TuneResult]:
    """
    Brute-force the PPS fields that slice headers cannot reveal, scoring each
    candidate by running a real decoder over the stream.

    `pic_init_qp` matters because CABAC contexts are initialised from
    SliceQPY = pic_init_qp + slice_qp_delta: with the wrong value the headers
    still parse but every macroblock decodes to noise, and the decoder bails
    out in the first row. The right value decodes the whole slice with no
    errors *and* produces a picture that is not uniformly grey -- both halves
    matter, because a desynchronised CABAC decoder can also terminate early and
    silently.

    Returns every candidate, best first. Needs ffmpeg on PATH.
    """
    import subprocess
    import tempfile

    sps = START_CODE + build_sps(width, height, fps=fps, hyp=hyp)
    results: list[TuneResult] = []
    frame_bytes = width * height
    with tempfile.TemporaryDirectory() as tmp:
        path = tmp + "/probe.h264"
        for qp in qps:
            for t8 in transform_8x8:
                for ci in constrained_intra:
                    pps = build_pps(hyp=hyp, pic_init_qp=qp,
                                    transform_8x8_mode=t8,
                                    constrained_intra_pred=ci)
                    with open(path, "wb") as fh:
                        fh.write(sps + START_CODE + pps + annexb)
                    proc = subprocess.run(
                        [ffmpeg, "-v", "error", "-flags2", "+showall",
                         "-i", path, "-pix_fmt", "gray", "-f", "rawvideo", "-"],
                        capture_output=True, check=False)
                    frames = len(proc.stdout) // frame_bytes
                    last = proc.stdout[-frame_bytes:] if frames else b""
                    sampled = last[::37]
                    coverage = (sum(1 for b in sampled if abs(b - 128) > 3)
                                / len(sampled)) if sampled else 0.0
                    res = TuneResult(
                        qp, t8, ci,
                        proc.stderr.decode("utf-8", "replace")
                        .count("error while decoding MB"),
                        frames, coverage)
                    results.append(res)
                    if progress is not None:
                        progress(res)
    results.sort(key=lambda r: r.score)
    return results


__all__ = [name for name in dir() if not name.startswith("_")]


def sizes_from_level(level_idc: int) -> str:      # pragma: no cover - trivia
    return {30: "3.0", 31: "3.1", 40: "4.0", 41: "4.1", 42: "4.2",
            50: "5.0"}.get(level_idc, str(level_idc))


assert replace(GOGGLES3, log2_max_frame_num=5) == GOGGLES3
