"""
DUML (a.k.a. "SerialTalk" / "V1 protocol") codec for DJI devices.

Frame layout (all multi-byte fields little-endian):

    off  size  field
    0    1     magic          0x55
    1    1     length low 8 bits
    2    1     bits 0..1 = length high bits, bits 2..7 = protocol version
    3    1     CRC-8 over bytes 0..2
    4    1     src   (bits 0..4 = device type, bits 5..7 = device index)
    5    1     dst   (same encoding)
    6    2     sequence number
    8    1     bit 7    = 0 request / 1 response
               bits 5-6 = ack policy
               bits 0-2 = encryption type (0 = none)
    9    1     cmd_set
    10   1     cmd_id
    11   n     payload
    -2   2     CRC-16 over bytes 0 .. length-3

`length` counts the whole frame, so payload length = length - 13.

Both CRC parameter sets below verify byte-for-byte on every frame the DJI
Goggles 3 and the DJI Fly app exchange (PROTOCOL.md section 6.1).
"""

from __future__ import annotations

MAGIC = 0x55
HEADER_LEN = 4
OVERHEAD = 13  # header(4) + src,dst(2) + seq(2) + type(1) + set,id(2) + crc16(2)

# --------------------------------------------------------------------------- #
# CRCs
# --------------------------------------------------------------------------- #

def _mk_table(poly: int) -> list[int]:
    table = []
    for i in range(256):
        crc = i
        for _ in range(8):
            crc = (crc >> 1) ^ poly if crc & 1 else crc >> 1
        table.append(crc)
    return table


_T8 = _mk_table(0x8C)        # reflected x^8 + x^5 + x^4 + 1
_T16 = _mk_table(0x8408)     # reflected CCITT


def crc8(data: bytes, init: int = 0x77) -> int:
    """DUML header CRC-8 (reflected poly 0x8C, init 0x77)."""
    crc = init
    for b in data:
        crc = _T8[(crc ^ b) & 0xFF]
    return crc & 0xFF


def crc16(data: bytes, init: int = 0x3692) -> int:
    """DUML frame CRC-16 (reflected poly 0x8408, init 0x3692)."""
    crc = init
    for b in data:
        crc = (crc >> 8) ^ _T16[(crc ^ b) & 0xFF]
    return crc & 0xFFFF


# --------------------------------------------------------------------------- #
# Symbol tables
# --------------------------------------------------------------------------- #
# NOTE: this is the historic dji-firmware-tools device table. Goggles-3 era
# firmware reuses several of these IDs for different modules, so the *names*
# are a convenience only -- the numeric ids are what matter.
DEV = {
    0x01: "camera", 0x02: "mobile_app", 0x03: "flight_ctrl", 0x04: "gimbal",
    0x05: "center_board", 0x06: "remote_radio", 0x07: "wifi_ground",
    0x08: "dm36x_ground", 0x09: "hdmi_ground", 0x0a: "wifi_air",
    0x0b: "dm36x_air", 0x0c: "hdmi_air", 0x0d: "sim", 0x0e: "esc",
    0x0f: "battery_group", 0x10: "imu", 0x11: "gps", 0x12: "wifi_g_dbg",
    0x13: "video_encoder", 0x14: "mainboard", 0x15: "airborne_ctrl",
    0x16: "camera2", 0x17: "rc", 0x18: "wifi", 0x19: "dm368", 0x1a: "lb_air",
    0x1b: "lb_gnd", 0x1c: "fpga_air", 0x1d: "fpga_gnd", 0x1e: "ofdm_air",
    0x1f: "ofdm_gnd", 0x20: "camera_gimbal", 0x21: "audio", 0x22: "battery",
    0x23: "esc2", 0x24: "dm385_air", 0x25: "dm385_gnd", 0x26: "mono_calc",
    0x27: "gps_air", 0x28: "algorithm", 0x2a: "led", 0x2b: "gimbal2",
    0x2c: "ofdm", 0x2d: "flight_rec", 0x2e: "gyro", 0x2f: "sensor",
    0x31: "smart_bat", 0x33: "test_a", 0x39: "glasses", 0x3b: "perception",
    0x3c: "upgrade",
}

CMDSET = {
    0x00: "general", 0x01: "special", 0x02: "camera", 0x03: "flight_ctrl",
    0x04: "gimbal", 0x05: "center_brd", 0x06: "rc", 0x07: "wifi",
    0x08: "dm36x", 0x09: "hd_link", 0x0a: "mbino", 0x0b: "sim", 0x0c: "esc",
    0x0d: "battery", 0x0e: "data_logger", 0x0f: "rtk", 0x10: "automation",
    0x11: "adsb", 0x12: "bviz", 0xee: "misc",
}

# The mobile app always talks as mobile_app index 0.
DEV_MOBILE_APP = 0x02

REQUEST, RESPONSE = 0, 1


def devname(b: int) -> str:
    return "%s.%d" % (DEV.get(b & 0x1F, "0x%02x" % (b & 0x1F)), b >> 5)


# --------------------------------------------------------------------------- #
# Frame object
# --------------------------------------------------------------------------- #

class Frame:
    __slots__ = ("raw", "length", "version", "src", "dst", "seq", "is_response",
                 "ack_type", "enc", "cmd_set", "cmd_id", "payload",
                 "crc8_ok", "crc16_ok")

    @property
    def valid(self) -> bool:
        return self.crc8_ok and self.crc16_ok

    @property
    def key(self) -> tuple[int, int]:
        return (self.cmd_set, self.cmd_id)

    def wants_ack(self) -> bool:
        """True if the peer expects us to answer this request."""
        return not self.is_response and self.ack_type != 0

    def make_ack(self, payload: bytes = b"\x00") -> bytes:
        """Build a minimal response frame for this request."""
        return build(self.dst, self.src, self.seq, self.cmd_set, self.cmd_id,
                     payload, is_response=True, ack_type=0, version=self.version)

    def __repr__(self) -> str:
        return "DUML %s->%s seq=%-5d %s set=0x%02x(%s) id=0x%02x len=%-4d %s%s" % (
            devname(self.src), devname(self.dst), self.seq,
            "ACK" if self.is_response else "REQ", self.cmd_set,
            CMDSET.get(self.cmd_set, "?"), self.cmd_id, len(self.payload),
            self.payload[:24].hex(" "), "" if self.valid else "  [CRC BAD]")


def parse(buf: bytes, off: int = 0) -> tuple[Frame | None, int]:
    """Parse one frame at buf[off:]. Returns (frame_or_None, next_offset)."""
    if off + HEADER_LEN > len(buf) or buf[off] != MAGIC:
        return None, off + 1
    length = buf[off + 1] | ((buf[off + 2] & 0x03) << 8)
    if length < OVERHEAD or off + length > len(buf):
        return None, off + 1
    f = Frame()
    f.raw = bytes(buf[off:off + length])
    f.length = length
    f.version = buf[off + 2] >> 2
    f.crc8_ok = crc8(f.raw[0:3]) == f.raw[3]
    f.crc16_ok = crc16(f.raw[:-2]) == int.from_bytes(f.raw[-2:], "little")
    if not f.crc8_ok:
        return None, off + 1
    f.src = f.raw[4]
    f.dst = f.raw[5]
    f.seq = int.from_bytes(f.raw[6:8], "little")
    t = f.raw[8]
    f.is_response = bool(t >> 7)
    f.ack_type = (t >> 5) & 3
    f.enc = t & 0x07
    f.cmd_set = f.raw[9]
    f.cmd_id = f.raw[10]
    f.payload = f.raw[11:length - 2]
    return f, off + length


def parse_all(buf: bytes) -> list[Frame]:
    out, off = [], 0
    while off < len(buf):
        f, off = parse(buf, off)
        if f is not None:
            out.append(f)
    return out


def build(src: int, dst: int, seq: int, cmd_set: int, cmd_id: int,
          payload: bytes = b"", *, is_response: bool = False,
          ack_type: int = 2, enc: int = 0, version: int = 1) -> bytes:
    """Serialise a DUML frame."""
    length = OVERHEAD + len(payload)
    if length > 0x3FF:
        raise ValueError("DUML frame too long: %d" % length)
    hdr = bytes((MAGIC, length & 0xFF,
                 ((version & 0x3F) << 2) | ((length >> 8) & 0x03)))
    hdr += bytes((crc8(hdr),))
    body = hdr + bytes((
        src & 0xFF, dst & 0xFF, seq & 0xFF, (seq >> 8) & 0xFF,
        ((1 if is_response else 0) << 7) | ((ack_type & 3) << 5) | (enc & 7),
        cmd_set & 0xFF, cmd_id & 0xFF)) + payload
    return body + crc16(body).to_bytes(2, "little")


class SeqCounter:
    """Rolling 16-bit sequence counter for outgoing app frames."""

    def __init__(self, start: int = 0):
        self._n = start & 0xFFFF

    def next(self) -> int:
        n = self._n
        self._n = (self._n + 1) & 0xFFFF
        return n
