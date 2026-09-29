"""
The DJI "LogicLink" tunnel that rides inside the accessory bulk pipe.

Whatever the physical carrier is -- the Android Open Accessory bulk pair, or
the bulk pair of the goggles' "com.dji.logiclink" interface on the iOS
transport -- the byte stream between the DJI Goggles 3 and the phone is the
*same* multiplexed tunnel (PROTOCOL.md section 4):

    off  size  field
    0    2     magic     0x55 0xCC
    2    1     channel   0x49 = control (DUML), 0x4A = video (H.264 Annex-B)
    3    1     version   always 0x57
    4    4     length    payload length, little-endian uint32
    8    n     payload

Observed channel behaviour
--------------------------
* 0x49  Control. Payload is one or more back-to-back DUML frames.
* 0x4A  Video. Payload is a raw slice of an H.264 Annex-B elementary stream.
        The goggles emits each access unit as a run of exactly-4096-byte
        packets followed by one short (<4096) packet, so a short packet is
        a reliable frame boundary. A *slice* access unit looks like

            00 00 00 01 61 <coded slice ...> 00 00 00 01 09 30
                                             ^^^^^^^^^^^^^^^^^
                                             trailing access unit delimiter

        i.e. DJI puts the AUD at the *end* of the frame as an end marker.
        Simply concatenating every 0x4A payload in arrival order yields a
        byte-exact, directly playable Annex-B stream. The AUD byte is 0x30
        (primary_pic_type = 1) in every access unit observed, but only the
        NAL header is relied upon anywhere in this library.

        Not every access unit ends with an AUD. Once per second the goggles
        emits a 39-byte parameter-set access unit -- SPS (27 B) then PPS
        (4 B) and nothing else -- 1.8-18.4 ms (median 5.6 ms) ahead of the
        IDR access unit that follows it. Those are the only units for which
        `ends_with_aud()` is False, so do not assume a trailing AUD when
        splitting or trimming units. See `pryer.h264` for the measured
        cadence and the real parameter-set bytes.

        Control packets are interleaved *inside* an access unit -- a 0x49
        packet can appear between two 4096-byte video chunks of the same
        frame -- so never treat a control packet as a frame boundary.

Because the tunnel header carries an explicit length, the demuxer is a plain
stateful byte-stream parser and does not care about USB packet boundaries.

A zero-length payload is legal on both channels: a zero-length USB packet
(`4b 00 00` in a hex dump) is a valid transfer terminator, and a video access
unit whose payload total happens to be an exact multiple of `VIDEO_CHUNK` can only
be terminated by one. The demuxer therefore accepts `length == 0` and the
assembler treats an empty video payload as an end-of-unit marker.
"""

from __future__ import annotations

from collections.abc import Iterator

MAGIC = b"\x55\xcc"
HEADER_LEN = 8
VERSION = 0x57

CH_CONTROL = 0x49
CH_VIDEO = 0x4A

CHANNEL_NAMES = {CH_CONTROL: "control", CH_VIDEO: "video"}

# Sanity limit used to reject false magic hits while resynchronising.
MAX_PAYLOAD = 0x10000

# Size of a full video chunk; a shorter one ends the access unit.
VIDEO_CHUNK = 4096

# Size of one bulk IN transfer of this tunnel on the iOS transport
# (`pryer.mfi.IapHost`). The AOA gadget uses ACCESSORY_READ_SIZE below.
#
# A bigger buffer would not help. The goggles emits an access unit back to
# back -- packet gaps inside a burst have a median of 0.19 ms (iOS) / 0.27 ms
# (Android) -- and then the bus is idle for the rest of the ~33 ms frame
# period. A median access unit is 22-26 kB and an IDR access unit reaches
# 184 kB. But a bulk transfer ends at the first short packet, and every tunnel
# packet ends with one, so a read never returns more than one tunnel packet
# (4,104 bytes at most), however big its buffer.
#
# On the host side a bigger buffer does harm. libusb splits a transfer larger
# than 16 kiB into 16 kiB URBs when the host controller cannot do
# scatter-gather, and the Pi's dwc2 cannot. A short packet in the first URB
# then makes usbfs cancel the others, and dwc2 has usually started the second
# one by then: whatever it received is lost (PROTOCOL.md section 9.3). So a
# transfer is exactly one URB. Keeping up with a burst is done by queueing
# several of them at once (`mfi.DEFAULT_TRANSFERS`, `libusb.BulkReader`).
DEFAULT_READ_SIZE = 16 * 1024

# Size of one gadget-side read on the AOA transport.
#
# As above, a bulk transfer ends at the first short packet, and every tunnel
# packet ends with one: a 4,104-byte video packet is eight 512-byte packets
# plus an 8-byte one. So a read returns at most one tunnel packet however big
# its buffer is (no goggles transfer on the Android transport is larger than
# 4,104 bytes). A burst is drained by one read per packet, and what matters is
# how fast the next read is queued.
#
# A big read makes that slower, not faster: the kernel has to allocate and
# DMA-map a buffer of the requested size, and the Python side has to provide
# one. `RawGadget._ep_io` therefore reuses one buffer per endpoint and copies
# out only the bytes received. A Pi 4B takes about 1.6 ms to queue the next
# read after a transfer; with video (about 230 video packets/s plus several
# hundred control packets/s) that leaves little margin. 16 kiB is four times
# the largest transfer.
ACCESSORY_READ_SIZE = 16 * 1024


class Packet:
    __slots__ = ("channel", "version", "payload")

    def __init__(self, channel: int, version: int, payload: bytes):
        self.channel = channel
        self.version = version
        self.payload = payload

    @property
    def is_video(self) -> bool:
        return self.channel == CH_VIDEO

    @property
    def is_control(self) -> bool:
        return self.channel == CH_CONTROL

    @property
    def ends_access_unit(self) -> bool:
        """True when this video chunk is the last one of a frame."""
        return self.is_video and len(self.payload) < VIDEO_CHUNK

    def __repr__(self) -> str:
        return "Packet(ch=0x%02x/%s, ver=0x%02x, len=%d)" % (
            self.channel, CHANNEL_NAMES.get(self.channel, "?"),
            self.version, len(self.payload))


def encode(channel: int, payload: bytes, version: int = VERSION) -> bytes:
    """Wrap a payload in a tunnel header."""
    return (MAGIC + bytes((channel & 0xFF, version & 0xFF))
            + len(payload).to_bytes(4, "little") + payload)


class Demuxer:
    """
    Incremental tunnel demuxer.

    Feed it arbitrary chunks of the bulk stream; it yields complete Packets.
    Bytes that do not start a plausible header are dropped one at a time and
    counted in `.resync_bytes`.

    `.resync_bytes` staying at 0 means the *byte stream handed to the demuxer*
    was intact; it does not on its own prove the link is healthy, and a
    non-zero value does not on its own prove it is broken. Lossy capture
    hardware raises it too: a sniffer capture with a non-zero mid-stream
    resync count is one in which the sniffer logged "Hardware buffer
    overflow", and the dropped regions contain ordinary H.264 payload. Joining a stream mid-packet also costs one resync run at
    the head. Treat a *rising* count during steady-state streaming as the
    signal, not any non-zero count.

    A header is only accepted when the version byte and channel match what the
    goggles actually emits, which keeps resynchronisation tight after a gap:
    without that check a stray `55 CC` inside coded video data can be mistaken
    for a header and swallow real payload.
    """

    def __init__(self, max_payload: int = MAX_PAYLOAD, *,
                 strict: bool = True):
        self._buf = bytearray()
        self.max_payload = max_payload
        self.strict = strict
        self.resync_bytes = 0
        self.packets = 0
        self.empty_packets = 0

    def feed(self, data: bytes) -> Iterator[Packet]:
        self._buf += data
        buf = self._buf
        i = 0
        n = len(buf)
        while True:
            # Need at least a header to decide anything.
            if n - i < HEADER_LEN:
                break
            if buf[i] == 0x55 and buf[i + 1] == 0xCC and self._plausible(buf, i):
                length = int.from_bytes(buf[i + 4:i + 8], "little")
                if 0 <= length <= self.max_payload:
                    end = i + HEADER_LEN + length
                    if end > n:
                        break  # incomplete, wait for more data
                    self.packets += 1
                    if length == 0:
                        self.empty_packets += 1
                    yield Packet(buf[i + 2], buf[i + 3], bytes(buf[i + 8:end]))
                    i = end
                    continue
            # Not a valid header start: drop one byte and resynchronise.
            i += 1
            self.resync_bytes += 1
        if i:
            del buf[:i]

    def _plausible(self, buf: bytearray, i: int) -> bool:
        """Reject `55 CC` hits whose version/channel cannot be a real header."""
        if not self.strict:
            return True
        return buf[i + 3] == VERSION and buf[i + 2] in CHANNEL_NAMES

    def pending(self) -> int:
        return len(self._buf)


def demux_bytes(data: bytes) -> tuple[list[Packet], int]:
    """One-shot helper: returns (packets, resync_byte_count)."""
    d = Demuxer()
    pkts = list(d.feed(data))
    return pkts, d.resync_bytes


# --------------------------------------------------------------------------- #
# H.264 helpers
# --------------------------------------------------------------------------- #

START_CODE = b"\x00\x00\x00\x01"
AUD_PREFIX = START_CODE + b"\x09"          # access unit delimiter NAL header
AUD = AUD_PREFIX + b"\x30"                 # the exact 6 bytes DJI emits
AUD_LEN = 6


def ends_with_aud(data: bytes) -> bool:
    """True if `data` ends with a 6-byte access unit delimiter."""
    return len(data) >= AUD_LEN and data[-AUD_LEN:-1] == AUD_PREFIX

NAL_TYPES = {
    1: "non-IDR slice", 5: "IDR slice", 6: "SEI", 7: "SPS", 8: "PPS",
    9: "AUD", 12: "filler",
}


def nal_units(data: bytes) -> Iterator[tuple[int, int]]:
    """Yield (offset_of_start_code, nal_header_byte) for 4-byte start codes."""
    i = data.find(START_CODE)
    while i >= 0 and i + 4 < len(data):
        yield i, data[i + 4]
        i = data.find(START_CODE, i + 4)


class AccessUnitAssembler:
    """
    Groups video-channel payloads into whole H.264 access units.

    `push()` returns a complete access unit (bytes) or None. The very first
    unit is discarded unless it begins with a start code, because a stream
    joined mid-frame would otherwise emit a truncated slice.

    A short payload ends the unit, and a zero-length payload counts as short,
    which is what terminates a unit whose payload total is an exact multiple
    of `VIDEO_CHUNK`. An empty unit is never emitted.
    """

    def __init__(self):
        self._parts: list[bytes] = []
        self._got_first = False

    def push(self, packet: Packet) -> bytes | None:
        if not packet.is_video:
            return None
        self._parts.append(packet.payload)
        if not packet.ends_access_unit:
            return None
        au = b"".join(self._parts)
        self._parts.clear()
        if not au:
            return None  # stray zero-length packet with nothing buffered
        if not self._got_first:
            self._got_first = True
            if not au.startswith(START_CODE):
                return None  # partial first frame, drop it
        return au
