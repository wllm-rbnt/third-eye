"""
Reader for hardware wire-level USB 2.0 captures in pcapng form.

Why this exists
---------------
`pryer.capture` reads Wireshark-style *text* hex dumps. Wire-level captures
are something else entirely: pcapng files written by a hardware sniffer, with

    SHB  shb_hardware = "USB Sniffer by Alex Taradov"
    IDB0 linktype 295 (LINKTYPE_USB_2_0), if_tsresol = 9  -> nanoseconds
    IDB1 linktype 252 (LINKTYPE_SYSTEMD_JOURNAL-ish)      -> sniffer log text

Each packet on interface 0 is one *wire* packet -- a PID byte, an optional
payload and the USB CRC -- so SOF, PING, NAK, ACK and the token packets are all
present. Nothing here is URB-shaped, so this module rebuilds the layers the
rest of the library expects:

    wire_packets()  raw PIDs, addresses, endpoints
      -> transactions()   token + DATAx + handshake, grouped
      -> data_packets()   only the payloads that were actually accepted
      -> transfers()      packets grouped into transfers, ending on a short one
      -> bulk_stream()    the tunnel byte stream, ready for pryer.tunnel

The log interface is worth reading too: `log_messages()` surfaces the sniffer's
own "Hardware buffer overflow" lines, which is what a mid-stream jump in
`Demuxer.resync_bytes` almost always turns out to be.

Timestamps are exposed in nanoseconds throughout, honouring each interface's
`if_tsresol`.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator, Iterable
from dataclasses import dataclass, field

# --------------------------------------------------------------------------- #
# pcapng block layer
# --------------------------------------------------------------------------- #
BT_SHB = 0x0A0D0D0A
BT_IDB = 0x00000001
BT_SPB = 0x00000003
BT_EPB = 0x00000006

BYTE_ORDER_MAGIC = 0x1A2B3C4D

LINKTYPE_USB_2_0 = 295
LINKTYPE_LOG_TEXT = 252          # the sniffer's out-of-band message stream

_CHUNK = 1 << 22                 # 4 MiB read granularity


class PcapngError(ValueError):
    pass


@dataclass
class Interface:
    linktype: int
    tsresol_exp: int = 6         # pcapng default is microseconds
    name: str | None = None

    @property
    def ts_divisor_ns(self) -> float:
        """Multiply a raw timestamp by this to get nanoseconds."""
        return 10.0 ** (9 - self.tsresol_exp)


def _iter_raw_blocks(path: str) -> Iterator[tuple[int, bytes, str]]:
    """Yield (block_type, body, endian) for every block, streaming the file."""
    endian = "<"
    with open(path, "rb") as fh:
        buf = bytearray(fh.read(_CHUNK))
        off = 0
        while True:
            if len(buf) - off < 12:
                more = fh.read(_CHUNK)
                if not more:
                    break
                del buf[:off]
                off = 0
                buf += more
                if len(buf) < 12:
                    break
            btype = struct.unpack_from(endian + "I", buf, off)[0]
            if btype == BT_SHB:
                # The byte-order magic is at body offset 0, block offset 8.
                if len(buf) - off < 12:
                    break
                bom = struct.unpack_from(">I", buf, off + 8)[0]
                endian = ">" if bom == BYTE_ORDER_MAGIC else "<"
            blen = struct.unpack_from(endian + "I", buf, off + 4)[0]
            if blen < 12 or blen % 4:
                raise PcapngError("bad block length %d at offset %d"
                                  % (blen, off))
            while len(buf) - off < blen:
                more = fh.read(max(_CHUNK, blen))
                if not more:
                    return
                del buf[:off]
                off = 0
                buf += more
            yield btype, bytes(buf[off + 8:off + blen - 4]), endian
            off += blen


def _options(body: bytes, endian: str) -> dict[int, bytes]:
    """Parse a trailing pcapng option list."""
    out: dict[int, bytes] = {}
    off = 0
    while off + 4 <= len(body):
        code, length = struct.unpack_from(endian + "HH", body, off)
        off += 4
        if code == 0:
            break
        out.setdefault(code, body[off:off + length])
        off += (length + 3) & ~3
    return out


@dataclass
class Packet:
    """One captured packet, timestamp already normalised to nanoseconds."""
    ts: int
    iface: int
    data: bytes


def raw_packets(path: str) -> Iterator[tuple[list[Interface], Packet]]:
    """Yield (interfaces, Packet) for every packet block in the file."""
    ifaces: list[Interface] = []
    for btype, body, endian in _iter_raw_blocks(path):
        if btype == BT_IDB:
            if len(body) < 8:
                raise PcapngError("truncated IDB")
            linktype, _res, _snap = struct.unpack_from(endian + "HHI", body, 0)
            opts = _options(body[8:], endian)
            iface = Interface(linktype=linktype)
            if 9 in opts and opts[9]:
                exp = opts[9][0]
                if exp & 0x80:          # high bit means power of two
                    raise PcapngError("power-of-two if_tsresol is unsupported")
                iface.tsresol_exp = exp
            if 2 in opts:
                iface.name = opts[2].decode("utf-8", "replace")
            ifaces.append(iface)
        elif btype == BT_EPB:
            if len(body) < 20:
                raise PcapngError("truncated EPB")
            idx, tsh, tsl, caplen, _plen = struct.unpack_from(
                endian + "IIIII", body, 0)
            if idx >= len(ifaces):
                continue
            raw_ts = (tsh << 32) | tsl
            div = ifaces[idx].ts_divisor_ns
            ts = raw_ts if div == 1.0 else int(raw_ts * div)
            yield ifaces, Packet(ts, idx, body[20:20 + caplen])
        elif btype == BT_SPB:
            if not ifaces:
                continue
            yield ifaces, Packet(0, 0, body[4:])


def interfaces(path: str) -> list[Interface]:
    """The interface description blocks, read from the head of the file."""
    out: list[Interface] = []
    for btype, body, endian in _iter_raw_blocks(path):
        if btype == BT_IDB:
            linktype = struct.unpack_from(endian + "H", body, 0)[0]
            opts = _options(body[8:], endian)
            iface = Interface(linktype=linktype)
            if 9 in opts and opts[9]:
                iface.tsresol_exp = opts[9][0] & 0x7F
            if 2 in opts:
                iface.name = opts[2].decode("utf-8", "replace")
            out.append(iface)
        elif btype == BT_EPB:
            break                       # all IDBs precede the first packet
    return out


def _log_text(payload: bytes) -> str:
    """
    Strip the journal-ish framing the sniffer wraps its messages in.

    The payload looks like ``0c 00 06 "syslog" 00 00 00 00 <text>``: a short
    binary header, a facility name and padding. Rather than model that, drop
    everything up to and including the last NUL.
    """
    text = payload.decode("utf-8", "replace")
    cut = text.rfind("\x00")
    if cut >= 0:
        text = text[cut + 1:]
    return text.strip("\x00\r\n ")


def log_messages(path: str) -> Iterator[tuple[int, str]]:
    """
    Yield (timestamp_ns, text) from the sniffer's out-of-band log interface.

    Useful lines include "VBUS ON", "Detected speed: High-Speed",
    "--- Bus Reset ---" (3-4 per enumerating capture, see `pryer.accessory`)
    and "Hardware buffer overflow".
    """
    for ifaces, pkt in raw_packets(path):
        if ifaces[pkt.iface].linktype != LINKTYPE_LOG_TEXT:
            continue
        text = _log_text(pkt.data)
        if text:
            yield pkt.ts, text


def overflows(path: str) -> list[tuple[int, str]]:
    """
    Just the capture-loss messages, if any.

    Check this before blaming the demuxer for a mid-stream resynchronisation.
    The implication runs one way: a capture that logs no overflow has
    `Demuxer.resync_bytes == 0`, and a capture with a non-zero mid-stream
    `resync_bytes` logs at least one. The converse does not hold: a capture
    can log overflows and still resynchronise zero bytes, when the lost bytes
    happened to be whole tunnel packets -- it shows up instead as an unusually
    long inter-packet gap. An overflow
    means *the wire data is missing*, not that the goggles or this decoder
    misbehaved.
    """
    return [(ts, msg) for ts, msg in log_messages(path)
            if "overflow" in msg.lower() or "dropped" in msg.lower()]


# --------------------------------------------------------------------------- #
# USB 2.0 wire layer
# --------------------------------------------------------------------------- #
PID_NAMES = {
    0x1: "OUT", 0x9: "IN", 0x5: "SOF", 0xD: "SETUP",
    0x3: "DATA0", 0xB: "DATA1", 0x7: "DATA2", 0xF: "MDATA",
    0x2: "ACK", 0xA: "NAK", 0xE: "STALL", 0x6: "NYET",
    0xC: "PRE_ERR", 0x8: "SPLIT", 0x4: "PING",
}
TOKEN_PIDS = frozenset(("OUT", "IN", "SETUP", "PING"))
DATA_PIDS = frozenset(("DATA0", "DATA1", "DATA2", "MDATA"))
HANDSHAKE_PIDS = frozenset(("ACK", "NAK", "STALL", "NYET"))

MAX_PACKET_SIZE = 512            # high-speed bulk


@dataclass
class Wire:
    """A decoded wire packet."""
    ts: int
    pid: int | None
    name: str
    raw: bytes
    addr: int | None = None
    ep: int | None = None
    frame: int | None = None
    data: bytes | None = None


def wire_packets(path: str, iface: int | None = None) -> Iterator[Wire]:
    """
    Decode every USB 2.0 wire packet.

    `iface` defaults to the first interface whose linktype is
    LINKTYPE_USB_2_0, so callers do not have to know the layout.
    """
    want = iface
    for ifaces, pkt in raw_packets(path):
        if want is None:
            for i, d in enumerate(ifaces):
                if d.linktype == LINKTYPE_USB_2_0:
                    want = i
                    break
            else:
                continue
        if pkt.iface != want:
            continue
        raw = pkt.data
        if not raw:
            continue
        b0 = raw[0]
        pid = b0 & 0x0F
        if (b0 >> 4) != (~pid & 0x0F):
            # PID check nibble is the complement; a mismatch is a damaged
            # packet, which the sniffer does record.
            yield Wire(pkt.ts, None, "BAD", raw)
            continue
        name = PID_NAMES.get(pid, "PID_0x%X" % pid)
        w = Wire(pkt.ts, pid, name, raw)
        if name in TOKEN_PIDS and len(raw) >= 3:
            v = raw[1] | (raw[2] << 8)
            w.addr = v & 0x7F
            w.ep = (v >> 7) & 0x0F
        elif name == "SOF" and len(raw) >= 3:
            w.frame = (raw[1] | (raw[2] << 8)) & 0x7FF
        elif name in DATA_PIDS:
            w.data = raw[1:-2] if len(raw) >= 3 else b""
        yield w


@dataclass
class Transaction:
    """A token, its optional data packet and its handshake."""
    ts: int
    type: str
    addr: int | None
    ep: int | None
    data: bytes | None = None
    handshake: str | None = None
    toggle: int | None = None


def transactions(path: str, iface: int | None = None) -> Iterator[Transaction]:
    """Group wire packets into transactions."""
    cur: Transaction | None = None
    for w in wire_packets(path, iface):
        if w.name in ("SOF", "BAD", "SPLIT", "PRE_ERR"):
            continue
        if w.name in TOKEN_PIDS:
            if cur is not None:
                yield cur
            cur = Transaction(w.ts, w.name, w.addr, w.ep)
        elif w.name in DATA_PIDS:
            if cur is None:
                continue
            cur.data = w.data or b""
            cur.toggle = 0 if w.name in ("DATA0", "DATA2") else 1
        elif w.name in HANDSHAKE_PIDS:
            if cur is None:
                continue
            cur.handshake = w.name
            yield cur
            cur = None
    if cur is not None:
        yield cur


@dataclass
class DataPacket:
    ts: int
    direction: str               # "IN", "OUT" or "SETUP"
    addr: int
    ep: int
    data: bytes
    toggle: int | None = None


def data_packets(path: str,
                 iface: int | None = None) -> Iterator[DataPacket]:
    """
    Yield only the data packets that actually moved.

    A NAKed OUT or an INed NAK carries nothing; a STALL is an error. The
    sniffer sees every retry, so filtering on the handshake is what keeps
    retried packets from being counted twice.
    """
    for t in transactions(path, iface):
        if t.data is None or t.addr is None or t.ep is None:
            continue
        if t.type == "PING":
            continue
        if t.type in ("OUT", "SETUP"):
            if t.handshake in ("ACK", "NYET"):
                yield DataPacket(t.ts, t.type, t.addr, t.ep, t.data, t.toggle)
        elif t.type == "IN":
            # The host ACKs data it accepted. A trailing packet at the very end
            # of a capture can be cut off before its handshake; keep it.
            if t.handshake in ("ACK", None):
                yield DataPacket(t.ts, "IN", t.addr, t.ep, t.data, t.toggle)


@dataclass
class Transfer:
    """Data packets on one endpoint, grouped up to a short packet."""
    t_start: int
    t_end: int
    data: bytes
    packets: int
    ended_short: bool
    packet_lengths: list[int] = field(default_factory=list)

    @property
    def duration_ns(self) -> int:
        return self.t_end - self.t_start


def transfers(path: str, addr: int, ep: int, direction: str, *,
              mps: int = MAX_PACKET_SIZE,
              iface: int | None = None) -> Iterator[Transfer]:
    """
    Group one endpoint's data packets into USB transfers.

    A transfer ends on a packet shorter than `mps`, a zero-length packet
    included. Each DJI video tunnel packet is its own 4104-byte transfer
    (8-byte tunnel header + 4096 payload = 8x512 + 8 on the wire), so this is
    also the natural unit for timing measurements.
    """
    cur: dict | None = None
    for p in data_packets(path, iface):
        if p.addr != addr or p.ep != ep or p.direction != direction:
            continue
        if cur is None:
            cur = {"t_start": p.ts, "data": bytearray(), "packets": 0,
                   "lengths": []}
        cur["data"] += p.data
        cur["packets"] += 1
        cur["lengths"].append(len(p.data))
        cur["t_end"] = p.ts
        if len(p.data) < mps:
            yield Transfer(cur["t_start"], cur["t_end"], bytes(cur["data"]),
                           cur["packets"], True, cur["lengths"])
            cur = None
    if cur is not None:
        yield Transfer(cur["t_start"], cur["t_end"], bytes(cur["data"]),
                       cur["packets"], False, cur["lengths"])


# --------------------------------------------------------------------------- #
# Finding the tunnel without being told where it is
# --------------------------------------------------------------------------- #
@dataclass
class EndpointStats:
    addr: int
    ep: int
    direction: str
    packets: int = 0
    bytes: int = 0
    t_first: int = 0
    t_last: int = 0


def endpoint_survey(path: str,
                    iface: int | None = None) -> list[EndpointStats]:
    """Byte counts per (address, endpoint, direction), busiest first."""
    seen: dict[tuple[int, int, str], EndpointStats] = {}
    for p in data_packets(path, iface):
        if p.ep == 0:
            continue                      # control traffic, not the tunnel
        key = (p.addr, p.ep, p.direction)
        st = seen.get(key)
        if st is None:
            st = seen[key] = EndpointStats(p.addr, p.ep, p.direction,
                                           t_first=p.ts)
        st.packets += 1
        st.bytes += len(p.data)
        st.t_last = p.ts
    return sorted(seen.values(), key=lambda s: -s.bytes)


def find_tunnel_endpoint(path: str,
                         iface: int | None = None) -> EndpointStats | None:
    """
    The endpoint carrying the DJI tunnel towards the phone.

    On Android the goggles is the USB host and video flows host->device on
    EP 0x01 OUT; on iOS the role swap makes the goggles the device and video
    flows device->host on EP 0x82 IN. Rather than encode that, pick the
    busiest bulk endpoint: video dwarfs everything else by two orders of
    magnitude in every capture.
    """
    survey = endpoint_survey(path, iface)
    return survey[0] if survey else None


def tunnel_endpoints(path: str, iface: int | None = None
                     ) -> tuple[EndpointStats | None, EndpointStats | None]:
    """
    The two directions of the DJI tunnel, as (from_goggles, to_goggles).

    The tunnel is a bidirectional bulk pair on one endpoint number, and the
    surveys are unambiguous about which way the traffic runs (volumes for a
    session of about ten seconds):

        iOS captures      addr 1 EP 0x02 IN  megabytes from the goggles
                          addr 1 EP 0x02 OUT tens of kB to the goggles
                          (addr 1 EP 0x01 carries iAP2, ~1 kB -- see
                          `iap2_endpoints`)
        Android captures  addr 1 EP 0x01 OUT megabytes from the goggles,
                          which is the *host* here, so "OUT" is
                          goggles-to-phone
                          addr 1 EP 0x01 IN  tens of kB to the goggles

    Either element is None if that direction carried nothing.
    """
    survey = endpoint_survey(path, iface)
    if not survey:
        return None, None
    busiest = survey[0]
    other = "OUT" if busiest.direction == "IN" else "IN"
    reverse = next((s for s in survey
                    if s.addr == busiest.addr and s.ep == busiest.ep
                    and s.direction == other), None)
    return busiest, reverse


def iap2_endpoints(path: str, iface: int | None = None
                   ) -> list[EndpointStats]:
    """
    Bulk endpoints that are not the tunnel: the iAP2 link on iOS captures.

    On Android there is no separate pair -- AOA gives the accessory a single
    bulk pair -- so this comes back empty.
    """
    down, _up = tunnel_endpoints(path, iface)
    if down is None:
        return []
    return [s for s in endpoint_survey(path, iface) if s.ep != down.ep]


def iap2_link_bytes(path: str, iface: int | None = None) -> bytes:
    """
    Both directions of the iAP2 control link, merged back into wire order.

    Scoped to the iAP2 endpoints on purpose. Concatenating every USB payload in
    the file and then scanning for the ``ff 5a`` sync word does not work: the
    video channel is megabytes of H.264, and a byte pair that happens to read
    ``ff 5a`` inside a coded slice is indistinguishable from a real packet
    header, so the scan invents packets: typically tens of bogus accessory
    packets against a true count of 5, and a stray match that declares a
    length of several kilobytes desynchronises the rest of the file.

    The link is a conversation, so the two directions are merged by timestamp
    rather than concatenated one side after the other. Returns ``b""`` for a
    capture with no iAP2 traffic, which is every Android capture.
    """
    merged: list[tuple[int, bytes]] = []
    for st in iap2_endpoints(path, iface):
        for t in transfers(path, st.addr, st.ep, st.direction, iface=iface):
            if t.data:
                merged.append((t.t_start, t.data))
    merged.sort(key=lambda pair: pair[0])
    return b"".join(data for _ts, data in merged)


def bulk_stream(path: str, *, addr: int | None = None, ep: int | None = None,
                direction: str | None = None, mps: int = MAX_PACKET_SIZE,
                iface: int | None = None) -> bytes:
    """
    The tunnel byte stream from one endpoint, ready for `pryer.tunnel.Demuxer`.

    With no endpoint given, the busiest bulk endpoint is used, which is the
    video-bearing direction in every reference capture.
    """
    if addr is None or ep is None or direction is None:
        found = find_tunnel_endpoint(path, iface)
        if found is None:
            return b""
        addr, ep, direction = found.addr, found.ep, found.direction
    return b"".join(t.data for t in
                    transfers(path, addr, ep, direction, mps=mps, iface=iface))


def tunnel_transfers(path: str, *, mps: int = MAX_PACKET_SIZE,
                     iface: int | None = None) -> Iterator[Transfer]:
    """`transfers()` on the auto-detected tunnel endpoint, timestamps kept."""
    found = find_tunnel_endpoint(path, iface)
    if found is None:
        return iter(())
    return transfers(path, found.addr, found.ep, found.direction, mps=mps,
                     iface=iface)


def setup_packets(path: str,
                  iface: int | None = None) -> Iterator[tuple[int, int, bytes]]:
    """Yield (timestamp_ns, device_address, 8-byte SETUP payload)."""
    for t in transactions(path, iface):
        if t.type == "SETUP" and t.data and len(t.data) == 8:
            yield t.ts, t.addr or 0, t.data


@dataclass
class ControlTransfer:
    """A SETUP packet together with the data stage that answered it."""
    ts: int
    addr: int
    setup: bytes
    data: bytes
    stalled: bool = False

    @property
    def bm_request_type(self) -> int:
        return self.setup[0]

    @property
    def b_request(self) -> int:
        return self.setup[1]

    @property
    def w_value(self) -> int:
        return self.setup[2] | (self.setup[3] << 8)

    @property
    def w_index(self) -> int:
        return self.setup[4] | (self.setup[5] << 8)

    @property
    def w_length(self) -> int:
        return self.setup[6] | (self.setup[7] << 8)

    @property
    def device_to_host(self) -> bool:
        return bool(self.setup[0] & 0x80)


def control_transfers(path: str,
                      iface: int | None = None) -> Iterator[ControlTransfer]:
    """
    Pair every SETUP with the data stage that follows it on endpoint 0.

    On the wire a control transfer is unambiguous, so descriptors are reached by
    decoding transfers rather than by counting packets from a fixed index:
    a SETUP on ep0, then DATA0/DATA1 packets
    on ep0 for the same address until a zero-length or short packet ends the
    data stage, and the next SETUP or a STALL closes it out.

    `data` is truncated to `w_length`, so a caller can compare it against a
    descriptor directly.
    """
    pending: ControlTransfer | None = None
    for t in transactions(path, iface):
        if t.ep not in (0, None):
            continue
        if t.type == "SETUP":
            if pending is not None:
                yield pending
            pending = (ControlTransfer(t.ts, t.addr or 0, t.data, b"")
                       if t.data and len(t.data) == 8 else None)
            continue
        if pending is None:
            continue
        if t.handshake == "STALL":
            pending.stalled = True
            yield pending
            pending = None
            continue
        if t.type in ("IN", "OUT") and t.data:
            # the status stage is a zero-length packet in the other direction;
            # only accumulate the direction the SETUP asked for
            want_in = pending.device_to_host
            if (t.type == "IN") == want_in:
                pending.data += t.data
                if len(pending.data) >= pending.w_length:
                    pending.data = pending.data[:pending.w_length]
                    yield pending
                    pending = None
    if pending is not None:
        yield pending
