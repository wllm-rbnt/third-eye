"""
iAP2 (Apple "iPod Accessory Protocol" v2 / MFi) as spoken by the DJI Goggles 3.

Everything in this module is transport agnostic and side-explicit: we always
implement the **Apple device** side, because in this pairing the *goggles* is
the MFi accessory.  That asymmetry is the whole reason a Linux box can join the
conversation at all -- the accessory owns the MFi coprocessor and has to prove
itself to us, not the other way round.

Wire format (all multi-byte fields big-endian, unlike DUML)
-----------------------------------------------------------

Link detect / "start of packet" preamble, sent bare on the bulk pipe::

    ff 55 02 00 ee 10

Link packet::

    +0  ff 5a                 packet magic
    +2  length      u16       total packet length, checksums included
    +4  control     u8        SYN 0x80 | ACK 0x40 | EAK 0x20 | RST 0x10 | SLP 0x08
    +5  seq         u8        sender's sequence number
    +6  ack         u8        highest contiguous peer sequence number seen
    +7  session     u8        session id (0 for link-level packets)
    +8  checksum    u8        -sum(bytes 0..7) & 0xff
    +9  payload     ...       present when length > 9
    -1  checksum    u8        -sum(payload) & 0xff

Control-session payload -- one or more messages back to back::

    +0  40 40                 control session marker
    +2  length      u16       message length, this header included
    +4  message id  u16
    +6  parameters  ...       TLV: u16 length (header included), u16 id, value

Parameters nest: a parameter's value can itself be a parameter list (that is
how `SupportedExternalAccessoryProtocol` and the transport components are
encoded).

Sequence-number rules (PROTOCOL.md section 3.6)
-----------------------------------------------
* Each side owns an independent 8-bit sequence space.  The goggles starts at
  ``0x00``; the iPhone's first sequence number differs from session to
  session (``0xac`` in the example used by the tests).
* ``seq`` advances by one for every packet that carries a payload.
* A pure ACK repeats the sender's current ``seq`` -- it does not consume one.
* ``ack`` is cumulative: acknowledging ``0xb0`` also retires ``0xaf``.
"""

from __future__ import annotations

import logging
import os
import struct
from dataclasses import dataclass, field

log = logging.getLogger("pryer.iap2")

# --------------------------------------------------------------------------- #
# Link layer
# --------------------------------------------------------------------------- #

MAGIC = b"\xff\x5a"
DETECT = bytes.fromhex("ff550200ee10")
HEADER_LEN = 9

CTL_SYN = 0x80
CTL_ACK = 0x40
CTL_EAK = 0x20
CTL_RST = 0x10
CTL_SLP = 0x08

CTL_FLAGS = (
    (CTL_SYN, "SYN"),
    (CTL_ACK, "ACK"),
    (CTL_EAK, "EAK"),
    (CTL_RST, "RST"),
    (CTL_SLP, "SLP"),
)

# Session types from the SYN parameter block.
SESSION_CONTROL = 0x00
SESSION_FILE_TRANSFER = 0x01
SESSION_EXTERNAL_ACCESSORY = 0x02
SESSION_TYPES = {
    SESSION_CONTROL: "Control",
    SESSION_FILE_TRANSFER: "FileTransfer",
    SESSION_EXTERNAL_ACCESSORY: "ExternalAccessory",
}


def checksum(data: bytes) -> int:
    """iAP2 checksum: two's complement of the byte sum."""
    return (-sum(data)) & 0xFF


def flag_names(control: int) -> str:
    names = [name for bit, name in CTL_FLAGS if control & bit]
    rest = control & ~sum(bit for bit, _ in CTL_FLAGS)
    if rest:
        names.append("0x%02x" % rest)
    return "|".join(names) if names else "-"


@dataclass
class Packet:
    control: int
    seq: int
    ack: int
    session: int
    payload: bytes = b""

    # populated by decode()
    header_ok: bool = True
    payload_ok: bool = True
    raw_len: int = 0

    @property
    def is_syn(self) -> bool:
        return bool(self.control & CTL_SYN)

    @property
    def is_ack(self) -> bool:
        return bool(self.control & CTL_ACK)

    @property
    def is_rst(self) -> bool:
        return bool(self.control & CTL_RST)

    def encode(self) -> bytes:
        total = HEADER_LEN + (len(self.payload) + 1 if self.payload else 0)
        head = MAGIC + struct.pack(
            ">HBBBB", total, self.control, self.seq, self.ack, self.session)
        out = head + bytes([checksum(head)])
        if self.payload:
            out += self.payload + bytes([checksum(self.payload)])
        return out

    def __str__(self) -> str:
        return ("iAP2 %-11s seq=%02x ack=%02x sess=%02x len=%d%s%s"
                % (flag_names(self.control), self.seq, self.ack, self.session,
                   self.raw_len or len(self.encode()),
                   "" if self.header_ok else " HDR-CKSUM-BAD",
                   "" if self.payload_ok else " PAY-CKSUM-BAD"))


class NeedMoreData(Exception):
    """The buffer holds the start of a packet but not all of it yet."""


def decode(buf: bytes) -> Packet:
    """Decode exactly one packet from the front of *buf*."""
    if len(buf) < HEADER_LEN:
        raise NeedMoreData
    if buf[:2] != MAGIC:
        raise ValueError("not an iAP2 packet: %s" % buf[:2].hex())
    total = struct.unpack_from(">H", buf, 2)[0]
    if total < HEADER_LEN:
        raise ValueError("implausible iAP2 length %d" % total)
    if len(buf) < total:
        raise NeedMoreData
    control, seq, ack, session, ck = struct.unpack_from(">BBBBB", buf, 4)
    payload = buf[HEADER_LEN:total - 1] if total > HEADER_LEN else b""
    pkt = Packet(control, seq, ack, session, payload)
    pkt.raw_len = total
    pkt.header_ok = checksum(buf[:8]) == ck
    pkt.payload_ok = (not payload) or checksum(payload) == buf[total - 1]
    return pkt


class PacketReader:
    """
    Incremental, resynchronising packet extractor.

    The iOS captures interleave iAP2 traffic (interface 0) with raw DJI tunnel
    traffic (interface 1 alternate setting 1) in a single byte stream, so the
    reader has to skip anything that is not an iAP2 packet and count how much
    it threw away.
    """

    def __init__(self) -> None:
        self.buf = bytearray()
        self.skipped = 0
        self.detects = 0

    def feed(self, data: bytes) -> list[Packet]:
        self.buf += data
        out: list[Packet] = []
        while True:
            idx = self.buf.find(MAGIC)
            det = self.buf.find(DETECT)
            if det != -1 and (idx == -1 or det < idx):
                self.skipped += det
                del self.buf[:det + len(DETECT)]
                self.detects += 1
                continue
            if idx == -1:
                # keep a magic-length tail in case we are mid-magic
                keep = max(0, len(self.buf) - (len(DETECT) - 1))
                self.skipped += keep
                del self.buf[:keep]
                return out
            if idx:
                self.skipped += idx
                del self.buf[:idx]
            try:
                pkt = decode(bytes(self.buf))
            except NeedMoreData:
                return out
            except ValueError:
                self.skipped += 1
                del self.buf[:1]
                continue
            del self.buf[:pkt.raw_len]
            out.append(pkt)


# --------------------------------------------------------------------------- #
# SYN payload -- link parameters
# --------------------------------------------------------------------------- #

@dataclass
class LinkParams:
    version: int = 1
    max_outstanding_packets: int = 0x7F
    max_packet_length: int = 0xFFFF
    retransmission_timeout_ms: int = 2000
    cumulative_ack_timeout_ms: int = 20
    max_retransmissions: int = 30
    max_cumulative_acks: int = 5
    sessions: list[tuple[int, int, int]] = field(default_factory=list)

    def encode(self) -> bytes:
        out = struct.pack(
            ">BBHHHBB", self.version, self.max_outstanding_packets,
            self.max_packet_length, self.retransmission_timeout_ms,
            self.cumulative_ack_timeout_ms, self.max_retransmissions,
            self.max_cumulative_acks)
        for sid, stype, sver in self.sessions:
            out += bytes([sid, stype, sver])
        return out

    @classmethod
    def decode(cls, data: bytes) -> "LinkParams":
        if len(data) < 10:
            raise ValueError("SYN payload too short (%d bytes)" % len(data))
        (version, maxout, maxlen, rto, cato, maxret,
         maxcack) = struct.unpack_from(">BBHHHBB", data, 0)
        sessions = []
        rest = data[10:]
        for i in range(0, len(rest) - 2, 3):
            sessions.append((rest[i], rest[i + 1], rest[i + 2]))
        return cls(version, maxout, maxlen, rto, cato, maxret, maxcack,
                   sessions)

    def control_session_id(self) -> int | None:
        for sid, stype, _ in self.sessions:
            if stype == SESSION_CONTROL:
                return sid
        return None

    def describe(self) -> str:
        parts = [
            "linkVersion=%d" % self.version,
            "maxOutstanding=%d" % self.max_outstanding_packets,
            "maxRecvLen=%d" % self.max_packet_length,
            "retransTimeout=%dms" % self.retransmission_timeout_ms,
            "cumAckTimeout=%dms" % self.cumulative_ack_timeout_ms,
            "maxRetrans=%d" % self.max_retransmissions,
            "maxCumAcks=%d" % self.max_cumulative_acks,
        ]
        for sid, stype, sver in self.sessions:
            parts.append("session(id=0x%02x type=%s v%d)"
                         % (sid, SESSION_TYPES.get(stype, "0x%02x" % stype),
                            sver))
        return " ".join(parts)


# --------------------------------------------------------------------------- #
# Control session messages
# --------------------------------------------------------------------------- #

CONTROL_MARKER = b"\x40\x40"

MSG_REQUEST_AUTH_CERT = 0xAA00
MSG_AUTH_CERT = 0xAA01
MSG_REQUEST_AUTH_CHALLENGE_RESPONSE = 0xAA02
MSG_AUTH_RESPONSE = 0xAA03
MSG_AUTH_FAILED = 0xAA04
MSG_AUTH_SUCCEEDED = 0xAA05
MSG_START_IDENTIFICATION = 0x1D00
MSG_IDENTIFICATION_INFORMATION = 0x1D01
MSG_IDENTIFICATION_ACCEPTED = 0x1D02
MSG_IDENTIFICATION_REJECTED = 0x1D03
MSG_START_POWER_UPDATES = 0xAE00
MSG_POWER_UPDATE = 0xAE01
MSG_STOP_POWER_UPDATES = 0xAE02

MESSAGE_NAMES = {
    MSG_REQUEST_AUTH_CERT: "RequestAuthenticationCertificate",
    MSG_AUTH_CERT: "AuthenticationCertificate",
    MSG_REQUEST_AUTH_CHALLENGE_RESPONSE: "RequestAuthenticationChallengeResponse",
    MSG_AUTH_RESPONSE: "AuthenticationResponse",
    MSG_AUTH_FAILED: "AuthenticationFailed",
    MSG_AUTH_SUCCEEDED: "AuthenticationSucceeded",
    MSG_START_IDENTIFICATION: "StartIdentification",
    MSG_IDENTIFICATION_INFORMATION: "IdentificationInformation",
    MSG_IDENTIFICATION_ACCEPTED: "IdentificationAccepted",
    MSG_IDENTIFICATION_REJECTED: "IdentificationRejected",
    MSG_START_POWER_UPDATES: "StartPowerUpdates",
    MSG_POWER_UPDATE: "PowerUpdate",
    MSG_STOP_POWER_UPDATES: "StopPowerUpdates",
}

# Which side originates each control message.  Every one of these is observed
# on the wire, always in the same direction.
ACCESSORY_MESSAGES = {
    MSG_AUTH_CERT,
    MSG_AUTH_RESPONSE,
    MSG_IDENTIFICATION_INFORMATION,
    MSG_START_POWER_UPDATES,
    MSG_STOP_POWER_UPDATES,
}
DEVICE_MESSAGES = {
    MSG_REQUEST_AUTH_CERT,
    MSG_REQUEST_AUTH_CHALLENGE_RESPONSE,
    MSG_AUTH_FAILED,
    MSG_AUTH_SUCCEEDED,
    MSG_START_IDENTIFICATION,
    MSG_IDENTIFICATION_ACCEPTED,
    MSG_IDENTIFICATION_REJECTED,
    MSG_POWER_UPDATE,
}


def direction(msg_id: int) -> str:
    """Which way a control message travels, from the capture evidence."""
    if msg_id in ACCESSORY_MESSAGES:
        return "goggles->phone"
    if msg_id in DEVICE_MESSAGES:
        return "phone->goggles"
    return "?"


def split_sides(data: bytes):
    """
    Separate a captured, interleaved byte stream into the accessory's packets
    and the Apple device's packets.

    A bare SYN is always the accessory (it opens the link); packets carrying a
    payload are attributed by the direction of the messages inside them; pure
    ACKs are dropped: they carry no message, so there is nothing to compare.
    """
    accessory = []
    device = []
    for pkt in PacketReader().feed(data):
        if pkt.is_syn and not pkt.is_ack:
            accessory.append(pkt)
        elif pkt.is_syn:
            device.append(pkt)
        elif pkt.payload:
            msgs = decode_messages(pkt.payload)
            if msgs and msgs[0].msg_id in ACCESSORY_MESSAGES:
                accessory.append(pkt)
            elif msgs:
                device.append(pkt)
    return accessory, device


# Parameter ids of IdentificationInformation (0x1D01).  Ids 0-10, 12, 13 and 16
# are all present in the goggles' message and their contents match these
# names; the remainder come from the public description of the identification
# message and are unverified here.
IDENT_PARAMS = {
    0: "AccessoryName",
    1: "AccessoryModelIdentifier",
    2: "AccessoryManufacturer",
    3: "AccessorySerialNumber",
    4: "AccessoryFirmwareVersion",
    5: "AccessoryHardwareVersion",
    6: "MessagesSentByAccessory",
    7: "MessagesReceivedFromDevice",
    8: "PowerSourceType",
    9: "MaximumCurrentDrawnFromDevice",
    10: "SupportedExternalAccessoryProtocol",
    11: "AppMatchTeamID",
    12: "CurrentLanguage",
    13: "SupportedLanguage",
    14: "SerialTransportComponent",
    15: "USBDeviceTransportComponent",
    16: "USBHostTransportComponent",
    17: "BluetoothTransportComponent",
}

EA_PROTOCOL_PARAMS = {
    0: "ExternalAccessoryProtocolIdentifier",
    1: "ExternalAccessoryProtocolName",
    2: "ExternalAccessoryProtocolMatchAction",
    3: "NativeTransportComponentIdentifier",
}

TRANSPORT_COMPONENT_PARAMS = {
    0: "TransportComponentIdentifier",
    1: "TransportComponentName",
    2: "TransportSupportsiAP2Connection",
}

# Which identification parameters carry a nested parameter list, and the name
# table to use for the children.
NESTED_IDENT_PARAMS = {
    10: EA_PROTOCOL_PARAMS,
    14: TRANSPORT_COMPONENT_PARAMS,
    15: TRANSPORT_COMPONENT_PARAMS,
    16: TRANSPORT_COMPONENT_PARAMS,
    17: TRANSPORT_COMPONENT_PARAMS,
}


def message_name(msg_id: int) -> str:
    return MESSAGE_NAMES.get(msg_id, "Unknown(0x%04X)" % msg_id)


def encode_params(params: list[tuple[int, bytes]]) -> bytes:
    out = bytearray()
    for pid, value in params:
        out += struct.pack(">HH", 4 + len(value), pid) + value
    return bytes(out)


def decode_params(data: bytes) -> list[tuple[int, bytes]]:
    out: list[tuple[int, bytes]] = []
    off = 0
    while off + 4 <= len(data):
        plen, pid = struct.unpack_from(">HH", data, off)
        if plen < 4 or off + plen > len(data):
            break
        out.append((pid, data[off + 4:off + plen]))
        off += plen
    return out


@dataclass
class Message:
    msg_id: int
    params: list[tuple[int, bytes]] = field(default_factory=list)

    def encode(self) -> bytes:
        body = encode_params(self.params)
        return (CONTROL_MARKER + struct.pack(">HH", 6 + len(body), self.msg_id)
                + body)

    def param(self, pid: int) -> bytes | None:
        for p, value in self.params:
            if p == pid:
                return value
        return None

    @property
    def name(self) -> str:
        return message_name(self.msg_id)

    def __str__(self) -> str:
        return "%s(0x%04X)%s" % (
            self.name, self.msg_id,
            "" if not self.params
            else " [" + ", ".join("%d:%dB" % (p, len(v))
                                  for p, v in self.params) + "]")


def decode_messages(payload: bytes) -> list[Message]:
    """Split a control-session payload into messages."""
    out: list[Message] = []
    off = 0
    while off + 6 <= len(payload):
        if payload[off:off + 2] != CONTROL_MARKER:
            break
        mlen, msg_id = struct.unpack_from(">HH", payload, off + 2)
        if mlen < 6 or off + mlen > len(payload):
            break
        out.append(Message(msg_id, decode_params(payload[off + 6:off + mlen])))
        off += mlen
    return out


def _readable(value: bytes) -> str:
    text = value.split(b"\x00")[0]
    if text and all(0x20 <= b < 0x7F for b in text):
        return repr(text.decode("ascii"))
    if len(value) in (1, 2, 4):
        return "0x%s (%d)" % (value.hex(), int.from_bytes(value, "big"))
    if not value:
        return "<flag>"
    return value.hex(" ")


def format_params(params: list[tuple[int, bytes]], names: dict[int, str],
                  nested: dict[int, dict[int, str]] | None = None,
                  indent: int = 2) -> list[str]:
    """Human-readable, recursive rendering of a parameter list."""
    pad = " " * indent
    lines = []
    for pid, value in params:
        label = names.get(pid, "param%d" % pid)
        kids = (nested or {}).get(pid)
        if kids is not None:
            lines.append("%s%s (id=%d):" % (pad, label, pid))
            lines += format_params(decode_params(value), kids, None, indent + 2)
        elif pid in (6, 7) and names is IDENT_PARAMS and len(value) % 2 == 0:
            ids = [int.from_bytes(value[i:i + 2], "big")
                   for i in range(0, len(value), 2)]
            lines.append("%s%s (id=%d): %s" % (
                pad, label, pid,
                ", ".join("%s(0x%04X)" % (message_name(m), m) for m in ids)))
        else:
            lines.append("%s%s (id=%d): %s" % (pad, label, pid,
                                               _readable(value)))
    return lines


@dataclass
class Identification:
    """Parsed IdentificationInformation, the accessory's self-description."""

    name: str = ""
    model: str = ""
    manufacturer: str = ""
    serial: str = ""
    firmware: str = ""
    hardware: str = ""
    languages: list[str] = field(default_factory=list)
    current_language: str = ""
    messages_sent: list[int] = field(default_factory=list)
    messages_received: list[int] = field(default_factory=list)
    ea_protocols: list[dict] = field(default_factory=list)
    transports: list[dict] = field(default_factory=list)
    raw: list[tuple[int, bytes]] = field(default_factory=list)

    @classmethod
    def from_message(cls, msg: Message) -> "Identification":
        self = cls(raw=list(msg.params))

        def text(v: bytes) -> str:
            return v.split(b"\x00")[0].decode("utf-8", "replace")

        def ids(v: bytes) -> list[int]:
            return [int.from_bytes(v[i:i + 2], "big")
                    for i in range(0, len(v) - 1, 2)]

        for pid, value in msg.params:
            if pid == 0:
                self.name = text(value)
            elif pid == 1:
                self.model = text(value)
            elif pid == 2:
                self.manufacturer = text(value)
            elif pid == 3:
                self.serial = text(value)
            elif pid == 4:
                self.firmware = text(value)
            elif pid == 5:
                self.hardware = text(value)
            elif pid == 6:
                self.messages_sent = ids(value)
            elif pid == 7:
                self.messages_received = ids(value)
            elif pid == 10:
                sub = dict(decode_params(value))
                self.ea_protocols.append({
                    "identifier": int.from_bytes(sub.get(0, b"\x00"), "big"),
                    "name": text(sub.get(1, b"")),
                    "match_action": int.from_bytes(sub.get(2, b"\x00"), "big"),
                    "native_transport":
                        None if 3 not in sub
                        else int.from_bytes(sub[3], "big"),
                })
            elif pid == 12:
                self.current_language = text(value)
            elif pid == 13:
                self.languages.append(text(value))
            elif pid in (14, 15, 16, 17):
                sub = dict(decode_params(value))
                self.transports.append({
                    "kind": IDENT_PARAMS.get(pid, str(pid)),
                    "identifier": int.from_bytes(sub.get(0, b"\x00"), "big"),
                    "name": text(sub.get(1, b"")),
                    "supports_iap2": 2 in sub,
                })
        return self

    def ea_protocol_id(self, name: str) -> int | None:
        for proto in self.ea_protocols:
            if proto["name"] == name:
                return proto["identifier"]
        return None

    def describe(self) -> str:
        lines = [
            "accessory   %s (%s)" % (self.name, self.model),
            "made by     %s" % self.manufacturer,
            "serial      %s" % self.serial,
            "firmware    %s   hardware %s" % (self.firmware, self.hardware),
            "language    %s   supported: %s"
            % (self.current_language, ", ".join(self.languages)),
        ]
        for proto in self.ea_protocols:
            lines.append(
                "EA protocol id=%d %r matchAction=%d nativeTransport=%s"
                % (proto["identifier"], proto["name"], proto["match_action"],
                   "none" if proto["native_transport"] is None
                   else "0x%04x" % proto["native_transport"]))
        for tr in self.transports:
            lines.append("transport   %s id=0x%04x %r iAP2=%s"
                         % (tr["kind"], tr["identifier"], tr["name"],
                            tr["supports_iap2"]))
        return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Apple-device-side state machine
# --------------------------------------------------------------------------- #

# Sizes as on the wire: a 32-byte challenge in
# RequestAuthenticationChallengeResponse, a 64-byte signature back.
CHALLENGE_LEN = 32

# PowerUpdate (0xAE01) parameter 6 carries the phone's battery level as a
# big-endian uint16 percentage (the handset's actual level, e.g. 90). It is the
# only parameter the iPhone sends in answer to StartPowerUpdates.
POWER_PARAM_BATTERY_CHARGE_LEVEL = 6
DEFAULT_BATTERY_PERCENT = 90


def power_update_params(battery_percent: int = DEFAULT_BATTERY_PERCENT
                        ) -> list[tuple[int, bytes]]:
    """The PowerUpdate parameters for a phone at *battery_percent*."""
    if not 0 <= battery_percent <= 100:
        raise ValueError("battery_percent must be 0..100")
    return [(POWER_PARAM_BATTERY_CHARGE_LEVEL,
             struct.pack(">H", battery_percent))]


DEFAULT_POWER_UPDATE = power_update_params()


class DeviceSession:
    """
    The Apple-device half of an iAP2 link.

    Push received bytes in with :meth:`feed`; it returns the bytes to transmit.
    The object is deliberately synchronous and allocation-light so it can be
    driven from a capture file in tests and from a USB pipe at runtime with
    exactly the same code path.

    Authentication note: we are the *verifier*.  The accessory holds the MFi
    coprocessor, produces the certificate and signs our challenge.  Verifying
    that signature needs Apple's root certificate and is pointless for our
    purpose, so :attr:`verify_auth` defaults to False -- we send a random
    challenge, accept whatever comes back and reply AuthenticationSucceeded.
    Set it to True only if you plug in your own ``verifier`` callback.
    """

    def __init__(self, initial_seq: int | None = None, verify_auth: bool = False,
                 verifier=None, power_update=None, rng=None,
                 on_message=None):
        self.rng = rng or os.urandom
        self.seq = (self.rng(1)[0] if initial_seq is None else initial_seq) & 0xFF
        self.peer_seq: int | None = None
        self.session_id = 0
        self.verify_auth = verify_auth
        self.verifier = verifier
        self.power_update = (DEFAULT_POWER_UPDATE if power_update is None
                             else power_update)
        self.on_message = on_message

        self.reader = PacketReader()
        self.peer_params: LinkParams | None = None
        self.certificate = b""
        self.challenge = b""
        self.signature = b""
        self.identification: Identification | None = None

        self.linked = False
        self.authenticated = False
        self.identified = False
        self.log: list[tuple[str, object]] = []

    # -- state -------------------------------------------------------- #
    @property
    def ready(self) -> bool:
        """True once the accessory will accept External Accessory traffic."""
        return self.linked and self.authenticated and self.identified

    def _next_seq(self) -> int:
        self.seq = (self.seq + 1) & 0xFF
        return self.seq

    def _ack(self) -> int:
        return 0 if self.peer_seq is None else self.peer_seq

    # -- outbound helpers --------------------------------------------- #
    def _bare_ack(self) -> bytes:
        return Packet(CTL_ACK, self.seq, self._ack(), 0).encode()

    def _send_messages(self, *messages: Message) -> bytes:
        """
        One control message per link packet.

        The format allows several messages in one packet, but the iPhone put
        each in its own -- AuthenticationSucceeded and StartIdentification go
        out back to back as two packets with consecutive sequence numbers, not
        as one packet with two messages. Matching that keeps our sequence
        numbering identical to the capture and avoids betting on the goggles
        handling a batched payload.
        """
        out = bytearray()
        for m in messages:
            self.log.append(("tx", m))
            log.info("-> %s", m)
            out += Packet(CTL_ACK, self._next_seq(), self._ack(),
                          self.session_id, m.encode()).encode()
        return bytes(out)

    # -- inbound ------------------------------------------------------ #
    def feed(self, data: bytes) -> bytes:
        """Consume received bytes, return bytes to send (possibly empty)."""
        out = bytearray()
        for pkt in self.reader.feed(data):
            out += self._handle_packet(pkt)
        return bytes(out)

    def _handle_packet(self, pkt: Packet) -> bytes:
        log.debug("<- %s", pkt)
        if not pkt.header_ok:
            log.warning("dropping iAP2 packet with bad header checksum")
            return b""
        if pkt.is_rst:
            self.linked = self.authenticated = self.identified = False
            log.warning("accessory sent RST -- link torn down")
            return b""

        if pkt.is_syn and not pkt.is_ack:
            return self._handle_syn(pkt)

        if pkt.payload:
            self.peer_seq = pkt.seq
            if pkt.session == self.session_id:
                return self._handle_control_payload(pkt)
            # Any other session id would be a real iAP2 session (file transfer
            # or External Accessory).  The goggles never opens one -- it uses a
            # native transport instead -- so just acknowledge it.
            log.info("payload on unexpected session 0x%02x (%d bytes)",
                     pkt.session, len(pkt.payload))
            return self._bare_ack()
        return b""

    def _handle_syn(self, pkt: Packet) -> bytes:
        try:
            params = LinkParams.decode(pkt.payload)
        except ValueError as exc:
            log.error("bad SYN: %s", exc)
            return b""
        self.peer_params = params
        self.peer_seq = pkt.seq
        sid = params.control_session_id()
        if sid is None:
            log.error("accessory SYN advertises no control session")
            return b""
        self.session_id = sid
        self.linked = True
        self.log.append(("rx", params))
        log.info("<- SYN %s", params.describe())

        # Mirror the accessory's parameters, but advertise our own limits, and
        # echo the session table exactly -- that is what the iPhone did.
        ours = LinkParams(
            version=params.version,
            max_outstanding_packets=0x7F,
            max_packet_length=0xFFFF,
            retransmission_timeout_ms=params.retransmission_timeout_ms,
            cumulative_ack_timeout_ms=params.cumulative_ack_timeout_ms,
            max_retransmissions=params.max_retransmissions,
            max_cumulative_acks=params.max_cumulative_acks,
            sessions=list(params.sessions),
        )
        synack = Packet(CTL_SYN | CTL_ACK, self.seq, self._ack(), 0,
                        ours.encode()).encode()
        # Kick off authentication immediately, as the iPhone does.
        return synack + self._send_messages(Message(MSG_REQUEST_AUTH_CERT))

    def _handle_control_payload(self, pkt: Packet) -> bytes:
        messages = decode_messages(pkt.payload)
        if not messages:
            log.info("unparsable control payload (%d bytes)", len(pkt.payload))
            return self._bare_ack()
        replies: list[Message] = []
        for msg in messages:
            self.log.append(("rx", msg))
            log.info("<- %s", msg)
            if self.on_message:
                self.on_message(msg)
            replies += self._react(msg)
        if replies:
            # The reply packet's ack field piggybacks the acknowledgement.
            return self._send_messages(*replies)
        return self._bare_ack()

    def _react(self, msg: Message) -> list[Message]:
        mid = msg.msg_id

        if mid == MSG_AUTH_CERT:
            self.certificate = msg.param(0) or b""
            log.info("accessory certificate: %d bytes", len(self.certificate))
            self.challenge = self.rng(CHALLENGE_LEN)
            return [Message(MSG_REQUEST_AUTH_CHALLENGE_RESPONSE,
                            [(0, self.challenge)])]

        if mid == MSG_AUTH_RESPONSE:
            self.signature = msg.param(0) or b""
            log.info("accessory signature: %d bytes", len(self.signature))
            ok = True
            if self.verify_auth:
                ok = bool(self.verifier and self.verifier(
                    self.certificate, self.challenge, self.signature))
            if not ok:
                log.error("MFi authentication rejected")
                return [Message(MSG_AUTH_FAILED)]
            self.authenticated = True
            return [Message(MSG_AUTH_SUCCEEDED),
                    Message(MSG_START_IDENTIFICATION)]

        if mid == MSG_IDENTIFICATION_INFORMATION:
            self.identification = Identification.from_message(msg)
            log.info("identification:\n%s", self.identification.describe())
            self.identified = True
            return [Message(MSG_IDENTIFICATION_ACCEPTED)]

        if mid == MSG_START_POWER_UPDATES:
            wanted = [pid for pid, _ in msg.params]
            log.info("accessory wants power updates for params %s", wanted)
            return [Message(MSG_POWER_UPDATE, list(self.power_update))]

        if mid == MSG_STOP_POWER_UPDATES:
            return []

        log.info("no reply defined for %s -- acknowledging only", msg.name)
        return []


# --------------------------------------------------------------------------- #
# Offline analysis
# --------------------------------------------------------------------------- #

def describe_stream(data: bytes) -> list[str]:
    """Render every iAP2 packet in a raw byte stream, for the `iap2` CLI."""
    reader = PacketReader()
    lines: list[str] = []
    for pkt in reader.feed(data):
        lines.append(str(pkt))
        if pkt.is_syn:
            try:
                lines.append("    " + LinkParams.decode(pkt.payload).describe())
            except ValueError as exc:
                lines.append("    bad SYN payload: %s" % exc)
            continue
        for msg in decode_messages(pkt.payload):
            lines.append("    %s" % msg)
            names = (IDENT_PARAMS if msg.msg_id == MSG_IDENTIFICATION_INFORMATION
                     else {})
            nested = (NESTED_IDENT_PARAMS
                      if msg.msg_id == MSG_IDENTIFICATION_INFORMATION else None)
            lines += format_params(msg.params, names, nested, indent=8)
    if reader.skipped:
        lines.append("(%d bytes were not iAP2 -- DJI tunnel traffic on the "
                     "External Accessory pipe, plus %d link-detect preambles)"
                     % (reader.skipped, reader.detects))
    return lines
