"""
Reader for captured USB traffic, in either of two formats.

Two formats
-----------
* **pcapng**, written by a hardware sniffer (linktype 295, LINKTYPE_USB_2_0).
  This is the authoritative form: real wire packets with nanosecond timestamps. Handled by `pryer.pcapng`;
  `bulk_stream()` and `usb_packets()` below dispatch to it automatically on
  the `.pcapng` extension, so callers do not need to care.
* **text hex dumps** in the Wireshark style. Described below and handled in
  this module.

Text format
-----------
Records look like::

    Frame (21 bytes):
    0000  4b 12 01 00 02 00 00 00 40 e8 04 5d 68 00 04 02   K.......@..]h...
    0010  03 04 01 f4 51                                    ....Q
    USB transfer (18 bytes):
    0000  12 01 00 02 00 00 00 40 e8 04 5d 68 00 04 02 03   .......@..]h....
    0010  04 01                                             ..

    0000  4b 00 00                                          K..

* ``Frame`` = one complete USB packet on the wire:
  1 byte PID + payload + 2 byte USB CRC-16.
* ``USB transfer`` = the same payload without PID/CRC (a decoder convenience
  line, redundant).
* A bare hex dump with no header is also a ``Frame``.
* The maximum frame length is 515 = 1 + 512 + 2, confirming each record is a
  single 512-byte-max bulk packet.

Important gotcha: ``0xC3`` and ``0x4B`` are the USB **DATA0 / DATA1** PIDs
(the data-toggle), *not* direction markers. Grouping by PID produces a
plausible-looking but wrong reassembly. The correct method is to concatenate
every Frame payload in capture order and let the tunnel framing (which
carries an explicit length) find the packet boundaries. ``4b 00 00`` is a
zero-length packet.
"""

from __future__ import annotations

import os
import re

from . import pcapng

_HEXLINE = re.compile(r"^([0-9a-fA-F]{4})\s\s((?:[0-9a-fA-F]{2} ?)+)")
_HEADER = re.compile(r"^(Frame|USB transfer) \((\d+) bytes\)")

ZLP = b"\x4b\x00\x00"


def read_blocks(path: str) -> list[tuple[str, bytes]]:
    """Return [(label, raw_bytes)] for every hex dump in the file."""
    blocks: list[tuple[str, bytes]] = []
    cur: bytearray | None = None
    label = "Frame"
    with open(path, "r", errors="replace") as fh:
        for line in fh:
            m = _HEADER.match(line)
            if m:
                if cur is not None:
                    blocks.append((label, bytes(cur)))
                cur, label = bytearray(), m.group(1)
                continue
            m = _HEXLINE.match(line.rstrip("\n"))
            if not m:
                continue
            off = int(m.group(1), 16)
            data = bytes.fromhex(m.group(2).replace(" ", ""))
            if off == 0 and cur:
                blocks.append((label, bytes(cur)))
                cur, label = bytearray(), "Frame"
            if cur is None:
                cur, label = bytearray(), "Frame"
            cur += data
    if cur is not None:
        blocks.append((label, bytes(cur)))
    return blocks


def is_pcapng(path: str) -> bool:
    """True for a hardware wire-level capture rather than a text hex dump."""
    if os.path.splitext(path)[1].lower() in (".pcapng", ".ntar"):
        return True
    try:
        with open(path, "rb") as fh:
            return fh.read(4) == b"\x0a\x0d\x0d\x0a"
    except OSError:
        return False


def usb_packets(path: str) -> list[tuple[int, bytes]]:
    """
    Return [(pid, payload)] for every wire packet, in capture order.

    Adjacent duplicate blocks are dropped: the format repeats each packet as
    a ``Frame`` and then as a ``USB transfer``, and some captures also repeat
    the dump verbatim.

    `pid` is the *full* PID byte as it appears on the wire, check nibble
    included -- 0xC3 for DATA0, 0x4B for DATA1, 0x2D for SETUP -- for both
    capture formats. A pcapng capture also yields the token and handshake
    packets a text dump omits, and those have an empty payload.
    """
    if is_pcapng(path):
        return [(w.raw[0], w.data or b"") for w in pcapng.wire_packets(path)
                if w.pid is not None]
    deduped: list[tuple[str, bytes]] = []
    for block in read_blocks(path):
        if deduped and deduped[-1] == block:
            continue
        deduped.append(block)
    out = []
    for label, raw in deduped:
        if label != "Frame" or len(raw) < 3:
            continue
        out.append((raw[0], raw[1:-2]))  # strip PID and USB CRC-16
    return out


def bulk_stream(path: str, **kwargs) -> bytes:
    """
    The byte stream the tunnel rides on.

    For a text dump this is every packet payload concatenated, which works
    because those excerpts contain one direction of one endpoint. For a pcapng
    capture the traffic is interleaved across addresses, endpoints and
    directions, so `pryer.pcapng` picks out a single endpoint -- by default the
    busiest bulk one, which is the video-bearing direction in every reference
    capture. Pass `addr=`, `ep=` and `direction=` to choose another.
    """
    if is_pcapng(path):
        return pcapng.bulk_stream(path, **kwargs)
    if kwargs:
        raise TypeError("endpoint selection is only meaningful for pcapng "
                        "captures; %s is a text dump" % path)
    return b"".join(p for _, p in usb_packets(path))


def setup_transfers(path: str) -> list[tuple[int, int, bytes]]:
    """
    Every SETUP packet as (timestamp_ns, device_address, 8 payload bytes).

    Text dumps carry no timestamps, so those come back with ts 0 and address 0.
    Combine with `decode_setup()` to print a handshake timeline.
    """
    if is_pcapng(path):
        return list(pcapng.setup_packets(path))
    out = []
    for pid, payload in usb_packets(path):
        if pid == 0x2D and len(payload) == 8:      # SETUP PID byte
            out.append((0, 0, payload))
    return out


def control_transfers(path: str):
    """
    Every control transfer as a `pcapng.ControlTransfer`: the SETUP plus the
    data stage that answered it.

    Only available for pcapng captures -- a text dump has no endpoint numbers
    or addresses to pair the stages by, so this raises for one.
    """
    if not is_pcapng(path):
        raise ValueError("%s is a text dump: it carries no endpoint or address "
                         "information, so control stages cannot be paired. Use "
                         "setup_transfers() for the SETUP packets alone." % path)
    return list(pcapng.control_transfers(path))


def descriptors(path: str) -> dict[int, dict[tuple[int, int], bytes]]:
    """
    Descriptors seen on the bus: {device_key: {(desc_type, index): bytes}}.

    Grouping matters, because an iOS capture contains descriptors from two
    different devices. The goggles first enumerates as a USB *device* -- that is
    where "DJI_GOGGLES" and "com.dji.logiclink" come from -- and then swaps role
    and enumerates the iPhone as a device of its own. Both use address 1, so
    address alone cannot separate them; devices are keyed by the order their
    descriptor sets appear, so key 0 is the first device enumerated.

    The longest answer wins for each descriptor, because a host normally asks
    twice: once for the 9-byte header to learn the length, then again in full.
    """
    out: dict[int, dict[tuple[int, int], bytes]] = {}
    current: dict[tuple[int, int], bytes] | None = None
    for ct in control_transfers(path):
        if (ct.b_request != 6 or not ct.device_to_host   # GET_DESCRIPTOR
                or not ct.data or ct.stalled):
            continue
        key = (ct.setup[3], ct.setup[2])                 # wValue hi, lo
        if key == (1, 0) and current is not None and current.get(key) not in (
                None, ct.data):
            current = None                               # a different device
        if current is None:
            current = {}
            out[len(out)] = current
        if len(ct.data) > len(current.get(key, b"")):
            current[key] = ct.data
    return out


def device_descriptors(path: str, vid: int, pid: int
                       ) -> dict[tuple[int, int], bytes]:
    """
    The descriptor set of one device, selected by its idVendor / idProduct.

    Raises KeyError if that device never enumerated in this capture, which is
    itself a useful assertion.
    """
    for group in descriptors(path).values():
        dev = group.get((1, 0))
        if not dev or len(dev) < 12:
            continue
        if (dev[8] | dev[9] << 8, dev[10] | dev[11] << 8) == (vid, pid):
            return group
    raise KeyError("%04x:%04x never enumerated in %s" % (vid, pid, path))


# --------------------------------------------------------------------------- #
# Control-transfer decoding, used to document the AOA / iAP2 handshakes
# --------------------------------------------------------------------------- #
STD_REQUESTS = {
    0: "GET_STATUS", 1: "CLEAR_FEATURE", 3: "SET_FEATURE", 5: "SET_ADDRESS",
    6: "GET_DESCRIPTOR", 7: "SET_DESCRIPTOR", 8: "GET_CONFIGURATION",
    9: "SET_CONFIGURATION", 10: "GET_INTERFACE", 11: "SET_INTERFACE",
}
DESC_TYPES = {1: "DEVICE", 2: "CONFIG", 3: "STRING", 4: "INTERFACE",
              5: "ENDPOINT", 6: "DEVICE_QUALIFIER", 7: "OTHER_SPEED",
              0x0F: "BOS"}
VENDOR_REQUESTS = {
    51: "AOA_GET_PROTOCOL", 52: "AOA_SEND_STRING", 53: "AOA_START_ACCESSORY",
    0x51: "APPLE_ROLE_SWAP(0x51)",
}


def decode_setup(pkt: bytes) -> str | None:
    """Decode an 8-byte SETUP packet payload into a readable string."""
    if len(pkt) != 8:
        return None
    bm, br = pkt[0], pkt[1]
    wv = int.from_bytes(pkt[2:4], "little")
    wi = int.from_bytes(pkt[4:6], "little")
    wl = int.from_bytes(pkt[6:8], "little")
    kind = (bm >> 5) & 3
    if kind == 0:
        name = STD_REQUESTS.get(br, "std(%d)" % br)
        if br == 6:
            name += "[%s idx=%d]" % (DESC_TYPES.get(wv >> 8, "0x%02x" % (wv >> 8)),
                                     wv & 0xFF)
    elif kind == 2:
        name = VENDOR_REQUESTS.get(br, "vendor(%d)" % br)
    else:
        name = "%s(%d)" % (("std", "class", "vendor", "reserved")[kind], br)
    return "SETUP %-34s bmRequestType=0x%02x wValue=0x%04x wIndex=0x%04x wLength=%d" % (
        name, bm, wv, wi, wl)
