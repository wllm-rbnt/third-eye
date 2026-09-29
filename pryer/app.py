"""
The "mobile app" side of the control channel.

What the goggles expects from the app (PROTOCOL.md sections 6 and 7)
---------------------------------------------------------------------
* **Video has to be asked for.** A healthy accessory link carries control
  traffic in both directions but no video until the app registers itself with
  the goggles' `fpga_air.1` module (DUML address 0x3C) using two `0x00/0x88`
  requests. The first video packet follows 20-40 ms after the second reply:

      app -> 0x3C  0x00/0x88  17 00 00 23 00 "APP" 00*5 02   register
      0x3C -> app  0x00/0x88  18 00 00 00                     accepted
      app -> 0x3C  0x00/0x88  1d 00 01 00 00 00 00 01 07 00 "1.21.1"
      0x3C -> app  0x00/0x88  1d 00 00 00                     accepted
      ... first channel-0x4A packet ...
      0x3C -> app  0x00/0x88  19 00           (once a second from then on)
      app -> 0x3C  0x00/0x88  1a 00 00 00 00  (heartbeat reply)

  The exchange is identical on both transports. Note that the app keeps
  sending `0x00/0x88` after video has started, as the heartbeat reply, so
  the command pair alone does not identify the registration: the first
  payload byte does.
* The goggles' `fpga_air.5` (0xBC) asks who we are with `0x00/0x81`, once a
  second, for the whole session. Every handset answers with the same 64 bytes
  (`IDENTITY_REPLY`, "APP"), and within ~1 ms the goggles follows up with a
  `0x00/0x82` from 0xBC carrying a `02` flag, which the handsets answer with
  `00`. A generic `00` answer to the identity request is not enough: the
  goggles keeps asking and never sends the follow-up. The handsets register
  340-470 ms after their first identity exchange.
* The app answers other goggles requests too (an ACK for flight_ctrl 0x03/0x8F,
  for example). `AppSession.on_control_frame` does that generically, with
  specific payloads for the requests above (`reply_payload`).
* The DJI Fly start-up requests are not needed, and the stream command sends
  none of them on either transport. The one request among them whose meaning
  is known, get version (0x00/0x01, empty payload), is available as
  `AppSession.query_version`. Registration (`AppSession.register`) is on by
  default and is retried every second until the goggles accepts it.
* Every payload this module sends is built from its fields
  (`register_payload`, `version_payload`, `heartbeat_reply_payload`,
  `identity_reply_payload`), byte-identical to what the handsets send. What
  most of the fields mean is unknown (PROTOCOL.md section 7); the names below
  say what is observed, no more.

What the DJI Fly start-up sends (described in PROTOCOL.md section 6.4, not
sent by this package) is mostly:
    general 0x00/0x01  get version, to a list of module ids
    general 0x00/0xB7  module enumeration
    general 0x00/0x99  named-topic get/subscribe -- ASCII topic names such as
                       "camcap_iso", "cam_lens_state", "pano_status"
    general 0x00/0x4F  push-data subscription to dm36x_ground.2, indices 0..4
    flight_ctrl 0x03/* assorted state queries
"""

from __future__ import annotations

import logging
import struct
import time

from . import duml, tunnel

log = logging.getLogger("pryer.app")

# DUML general-set "get version" (0x00/0x01): an empty request that every
# module answers with its version string. DJI Fly sends it to about ten module
# ids at start-up (PROTOCOL.md 6.4); these four are the goggles' main ones.
CMD_GET_VERSION = (0x00, 0x01)
VERSION_QUERY_TARGETS = (0x0E, 0x1F, 0x01, 0x03)


# --------------------------------------------------------------------------- #
# Registration with the goggles' video module (see the module notes)
# --------------------------------------------------------------------------- #
# DUML addresses: bits 0-4 are the device type, bits 5-7 the index.
DEV_FPGA_AIR_1 = 0x3C     # fpga_air.1: registration + once-a-second heartbeat
DEV_FPGA_AIR_5 = 0xBC     # fpga_air.5: asks who we are with 0x00/0x81

CMD_IDENTIFY = (0x00, 0x81)
CMD_LINK = (0x00, 0x88)

# First payload byte of 0x00/0x88 frames.
LINK_REGISTER = 0x17
LINK_REGISTER_OK = 0x18
LINK_HEARTBEAT = 0x19
LINK_HEARTBEAT_REPLY = 0x1A
LINK_VERSION = 0x1D

# What the app calls itself in the registration and the identity reply.
APP_NAME = "APP"
# The DJI Fly version the handsets announce in the 1d request.
APP_VERSION = "1.21.1"


def _name_field(name: str, size: int) -> bytes:
    """An ASCII name, NUL-padded to a fixed-size field."""
    raw = name.encode("ascii")
    if len(raw) > size:
        raise ValueError("%r does not fit a %d-byte field" % (name, size))
    return raw.ljust(size, b"\0")


def register_payload(name: str = APP_NAME, *, field1: int = 0x0000,
                     field2: int = 0x0023, role: int = 0x02) -> bytes:
    """
    The 0x00/0x88 `17` request: register an app with fpga_air.1.

    Layout (14 bytes; meanings of the numeric fields unknown, values as in
    every handset session)::

        u8      op        0x17
        u16 LE  field1    0x0000
        u16 LE  field2    0x0023
        char[8] name      "APP", NUL-padded
        u8      role      0x02

    -> ``17 00 00 23 00 41 50 50 00 00 00 00 00 02``.
    """
    return (struct.pack("<BHH", LINK_REGISTER, field1, field2)
            + _name_field(name, 8) + bytes((role,)))


def version_payload(version: str = APP_VERSION, *, field1: int = 0x00,
                    field2: int = 0x00000001, field3: int = 0x0100) -> bytes:
    """
    The 0x00/0x88 `1d` request: announce the app version.

    Layout (10 + len(version) bytes)::

        u8      op        0x1d
        u8      field1    0x00
        u32 LE  field2    0x00000001
        u16 LE  field3    0x0100
        u16 LE  length    len(version) + 1
        char[]  version   "1.21.1", with no terminating NUL on the wire

    The length counts a terminator that the frame does not carry (7 for the
    six characters of "1.21.1"); that is how the handsets send it.

    -> ``1d 00 01 00 00 00 00 01 07 00 31 2e 32 31 2e 31``.
    """
    raw = version.encode("ascii")
    return (struct.pack("<BBIHH", LINK_VERSION, field1, field2, field3,
                        len(raw) + 1) + raw)


def heartbeat_reply_payload(status: int = 0) -> bytes:
    """
    The answer to fpga_air.1's `19 00` heartbeat: op 0x1a and a u32 status.

    -> ``1a 00 00 00 00``.
    """
    return struct.pack("<BI", LINK_HEARTBEAT_REPLY, status)


# The two fields after the name in the identity reply. The goggles' own
# 0x00/0x81 request has the same layout (name "ZV902", then 05 1c ... at both
# places); the handsets answer 00 02 in the first and repeat the goggles'
# 05 1c in the second.
IDENTITY_FIELD_A = bytes.fromhex("0002")
IDENTITY_FIELD_B = bytes.fromhex("051c")
IDENTITY_REPLY_SIZE = 64


def identity_reply_payload(name: str = APP_NAME, *,
                           field_a: bytes = IDENTITY_FIELD_A,
                           field_b: bytes = IDENTITY_FIELD_B,
                           status: int = 0) -> bytes:
    """
    The answer to fpga_air.5's 0x00/0x81 "who are you".

    Layout (64 bytes, as every handset sends it)::

        u8        status    0x00
        char[32]  name      "APP", NUL-padded
        u8[8]     field_a   00 02 00 00 00 00 00 00
        u8[8]     field_b   05 1c 00 00 00 00 00 00
        u8[15]    zero

    The request carries the goggles' own record in the same layout without the
    status byte: ``"ZV902"`` in 32 bytes, then 05 1c ... and 05 1c ....
    """
    out = (bytes((status,)) + _name_field(name, 32)
           + field_a.ljust(8, b"\0") + field_b.ljust(8, b"\0"))
    return out.ljust(IDENTITY_REPLY_SIZE, b"\0")


# The two app -> 0x3C requests, as the handsets send them on both
# transports.
REGISTER_FRAMES: list[tuple[int, int, int, bytes]] = [
    (DEV_FPGA_AIR_1, CMD_LINK[0], CMD_LINK[1], register_payload()),
    (DEV_FPGA_AIR_1, CMD_LINK[0], CMD_LINK[1], version_payload()),
]

HEARTBEAT_REPLY = heartbeat_reply_payload()

# Answer to fpga_air.5's 0x00/0x81 "who are you" (see identity_reply_payload).
IDENTITY_REPLY = identity_reply_payload()

# Resend the registration this often until the goggles answers it.
REGISTER_RETRY = 1.0
# ...but after the identity exchange, resend as soon as this much time has
# passed since the last attempt (the goggles answers within 1 ms when it
# accepts).
REGISTER_MIN_GAP = 0.25
# Warn if no video has arrived this long after the goggles accepted us. In the
# handset sessions video follows the acceptance within 40 ms.
VIDEO_AFTER_REGISTER_WARN = 3.0


def reply_payload(frame: duml.Frame) -> bytes:
    """The payload to answer a goggles request with."""
    if frame.key == CMD_IDENTIFY:
        return IDENTITY_REPLY
    if (frame.key == CMD_LINK and frame.payload[:1]
            and frame.payload[0] == LINK_HEARTBEAT):
        return HEARTBEAT_REPLY
    return b"\x00"


class AppSession:
    """
    Builds and sends app->goggles control traffic over the tunnel.

    `send` is any callable taking raw bytes to push into the accessory IN
    endpoint; this class wraps frames in the 0x55CC tunnel header for you.
    """

    def __init__(self, send, *, src: int = duml.DEV_MOBILE_APP,
                 seq_start: int = 0, auto_ack: bool = True,
                 register: bool = True, clock=time.monotonic):
        self.send = send
        self.src = src
        self.seq = duml.SeqCounter(seq_start)
        self.auto_ack = auto_ack
        self.sent = 0
        self.acked = 0
        # registration state (see the module notes)
        self.register_enabled = register
        self.clock = clock
        self.registered = False          # goggles answered 17.. with 18..
        self.registered_at: float | None = None
        self.version_accepted = False    # goggles answered 1d.. with 1d..
        self.register_attempts = 0
        self.identified = 0              # 0x00/0x81 requests answered
        self.heartbeats = 0              # 0x00/0x88 19 00 requests answered
        self._next_register: float | None = None
        self._last_register: float | None = None

    # ------------------------------------------------------------------ #
    def send_duml(self, dst: int, cmd_set: int, cmd_id: int,
                  payload: bytes = b"", *, ack_type: int = 2) -> int:
        seq = self.seq.next()
        frame = duml.build(self.src, dst, seq, cmd_set, cmd_id, payload,
                           ack_type=ack_type)
        self.send(tunnel.encode(tunnel.CH_CONTROL, frame))
        self.sent += 1
        return seq

    def send_raw_frame(self, frame: bytes) -> None:
        self.send(tunnel.encode(tunnel.CH_CONTROL, frame))
        self.sent += 1

    # ------------------------------------------------------------------ #
    def query_version(self, targets=VERSION_QUERY_TARGETS) -> list[int]:
        """
        Ask each module in *targets* for its version (0x00/0x01, no payload).

        Not needed for video. The answers come back as responses and show the
        goggles' internal module names (PROTOCOL.md 6.2). Returns the sequence
        numbers used, one per target.
        """
        return [self.send_duml(dst, *CMD_GET_VERSION) for dst in targets]

    def register(self) -> None:
        """Send the two 0x00/0x88 registration requests (see module notes)."""
        self.register_attempts += 1
        log.log(logging.INFO if self.register_attempts == 1 else logging.DEBUG,
                "registering with the goggles (0x00/0x88 to fpga_air.1, "
                "attempt %d)", self.register_attempts)
        for dst, cs, cid, payload in REGISTER_FRAMES:
            self.send_duml(dst, cs, cid, payload)
        self._last_register = self.clock()
        self._next_register = self._last_register + REGISTER_RETRY

    def start(self) -> None:
        """Begin registration, if enabled. Call once, after any init."""
        if self.register_enabled and not self.registered:
            self.register()

    def poll(self) -> None:
        """Resend the registration if it is due. Call from the read loop."""
        if (not self.register_enabled or self.registered
                or self._next_register is None):
            return
        if self.clock() >= self._next_register:
            if self.register_attempts == 5:
                log.warning("the goggles has not answered the app "
                            "registration after %d attempts; still retrying",
                            self.register_attempts)
            self.register()

    # ------------------------------------------------------------------ #
    def on_control_frame(self, frame: duml.Frame) -> None:
        """Handle a goggles->app DUML frame; answer it if it wants an ACK."""
        if frame.dst != self.src:
            return
        if frame.is_response:
            self._on_response(frame)
            return
        if not self.auto_ack or not frame.wants_ack():
            return
        payload = reply_payload(frame)
        try:
            self.send_raw_frame(frame.make_ack(payload))
            self.acked += 1
        except OSError as exc:  # link went away
            log.debug("could not ACK %s: %s", frame.key, exc)
            return
        if frame.key == CMD_IDENTIFY:
            self.identified += 1
            if self.identified == 1:
                log.info("answered the goggles' identity request (0x00/0x81 "
                         "from %s)", duml.devname(frame.src))
                # The handsets register after this exchange. Do not wait a
                # full retry period, but give an attempt that is already on
                # its way REGISTER_MIN_GAP to be answered.
                if self.register_enabled and not self.registered:
                    now = self.clock()
                    soon = now if self._last_register is None else \
                        max(now, self._last_register + REGISTER_MIN_GAP)
                    if self._next_register is None or soon < self._next_register:
                        self._next_register = soon
        elif payload is HEARTBEAT_REPLY:
            self.heartbeats += 1

    def _on_response(self, frame: duml.Frame) -> None:
        if frame.key != CMD_LINK or not frame.payload:
            return
        op = frame.payload[0]
        if op == LINK_REGISTER_OK and not self.registered:
            self.registered = True
            self.registered_at = self.clock()
            log.info("goggles accepted the app registration (0x00/0x88 from "
                     "%s, attempt %d); video should follow within ~40 ms",
                     duml.devname(frame.src), self.register_attempts)
        elif op == LINK_VERSION and not self.version_accepted:
            self.version_accepted = True
            log.debug("goggles accepted the app version (0x00/0x88 1d)")
