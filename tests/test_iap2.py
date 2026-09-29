"""
Self-tests for the iOS / iAP2 transport.

The golden tests here are the two that matter most:

* ``test_every_captured_packet_reencodes_byte_exact`` walks the iOS reference
  captures and asserts that decoding a packet and re-encoding it
  reproduces the original bytes, checksums included.  That is what proves the
  link-layer writer is correct -- and the writer is the half we will actually
  put on the wire.
* ``test_replay_matches_the_iphone`` drives our Apple-device state machine with
  the goggles' captured packets and asserts it answers with exactly the control
  messages, in exactly the order, that the real iPhone sent.

Both need the reference captures and are skipped without them (see
support.py). The link-layer codec, the session state machine and the iPhone
gadget are also tested on known-good bytes, which needs no capture.

Run with:  python -m pytest tests/ -q
       or:  python tests/test_iap2.py
"""

from __future__ import annotations

import os
import sys

# the package under test, and `support` alongside this file
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [_HERE, os.path.dirname(_HERE)]

from pryer import capture, iap2, libusb, mfi  # noqa: E402
from support import MISSING, Skip  # noqa: E402
from support import iap2_link_bytes, iap2_packets  # noqa: E402
from support import captures as _all_captures  # noqa: E402


IOS_HANDSHAKE_CAPTURES = ("0_ios", "1_ios", "3_ios", "9_ios")

# What the iAP2 link measures on every one of those captures: the handshake is
# the same size every time, because it is the same fixed exchange.
IAP2_LINK_SHAPE = {"accessory_packets": 5, "device_packets": 7, "bytes": 1240}


def _captures(match: tuple[str, ...]) -> list[str]:
    files = [p for p in _all_captures()
             if any(m in os.path.basename(p) for m in match)]
    if not files:
        raise Skip(MISSING)
    return files


def _raw(path: str) -> bytes:
    """
    The iAP2 control link of one capture, in wire order.

    The link is not on the tunnel endpoint at all: it runs on addr 1 endpoint
    0x01, carries 1240 bytes in total, and is finished before the first video
    byte. Reading it is therefore endpoint-scoped, never a scan of the whole
    capture -- see test_the_link_is_read_from_its_own_endpoints_only.
    """
    return iap2_link_bytes(path)


# --------------------------------------------------------------------------- #
# Link layer
# --------------------------------------------------------------------------- #
def test_checksum_is_twos_complement_of_the_sum():
    # header of the goggles' SYN; the byte after it is 0xa8
    header = bytes.fromhex("ff5a00178000000 0".replace(" ", ""))
    assert iap2.checksum(header) == (-sum(header)) & 0xFF
    assert (sum(header) + iap2.checksum(header)) & 0xFF == 0


def test_packet_roundtrip():
    pkt = iap2.Packet(iap2.CTL_ACK, 0x12, 0x34, 0x0A, b"payload")
    again = iap2.decode(pkt.encode())
    assert again.control == pkt.control
    assert (again.seq, again.ack, again.session) == (0x12, 0x34, 0x0A)
    assert again.payload == b"payload"
    assert again.header_ok and again.payload_ok


def test_bare_ack_is_nine_bytes():
    data = iap2.Packet(iap2.CTL_ACK, 4, 0xB2, 0).encode()
    assert len(data) == 9
    assert data[:2] == iap2.MAGIC
    assert iap2.decode(data).payload == b""


def test_decode_needs_the_whole_packet():
    full = iap2.Packet(iap2.CTL_ACK, 1, 1, 0x0A, b"x" * 40).encode()
    try:
        iap2.decode(full[:20])
    except iap2.NeedMoreData:
        pass
    else:
        raise AssertionError("expected NeedMoreData")


def test_reader_skips_tunnel_bytes_and_counts_detects():
    pkt = iap2.Packet(iap2.CTL_ACK, 1, 1, 0x0A, b"hello").encode()
    noise = bytes.fromhex("55cc4a57001000000000")  # a DJI tunnel header
    reader = iap2.PacketReader()
    got = reader.feed(noise + iap2.DETECT + pkt)
    assert len(got) == 1
    assert got[0].payload == b"hello"
    assert reader.detects == 1
    assert reader.skipped == len(noise)


def test_reader_reassembles_a_packet_split_across_reads():
    pkt = iap2.Packet(iap2.CTL_ACK, 1, 1, 0x0A, b"y" * 600).encode()
    reader = iap2.PacketReader()
    assert reader.feed(pkt[:512]) == []
    got = reader.feed(pkt[512:])
    assert len(got) == 1 and got[0].payload == b"y" * 600


# --------------------------------------------------------------------------- #
# Golden: the captures
# --------------------------------------------------------------------------- #
def test_every_captured_packet_reencodes_byte_exact():
    total = 0
    for path in _captures(IOS_HANDSHAKE_CAPTURES):
        raw = _raw(path)
        off = 0
        while True:
            idx = raw.find(iap2.MAGIC, off)
            if idx == -1:
                break
            try:
                pkt = iap2.decode(raw[idx:])
            except (ValueError, iap2.NeedMoreData):
                off = idx + 1
                continue
            if not pkt.header_ok:
                off = idx + 1
                continue
            original = raw[idx:idx + pkt.raw_len]
            # Packets can be truncated at the end of a 10k-line capture excerpt.
            if len(original) == pkt.raw_len and pkt.payload_ok:
                assert pkt.encode() == original, (
                    "%s: packet at %d does not re-encode" % (path, idx))
                total += 1
            off = idx + pkt.raw_len
    assert total >= 30, "expected plenty of packets, got %d" % total


def test_the_link_is_read_from_its_own_endpoints_only():
    """
    The iAP2 link must be read from the iAP2 endpoints, never by scanning the
    whole capture for the sync word.

    ``ff 5a`` is two bytes. In several megabytes of coded H.264 it occurs by
    chance, and a scan cannot tell such a match from a real header: it reads the
    next two bytes as a length and desynchronises. Concatenating every USB
    payload and scanning therefore reports far more packets than exist -- and a
    stray match can claim a packet of several kilobytes and swallow the rest of
    the file.

    Scoping to the endpoints makes the measurement exact and identical on
    every capture, which is the real evidence that the handshake is a fixed
    exchange rather than something that varies by session.
    """
    for path in _captures(IOS_HANDSHAKE_CAPTURES):
        accessory, device = iap2.split_sides(_raw(path))
        assert len(accessory) == IAP2_LINK_SHAPE["accessory_packets"], \
            (path, len(accessory))
        assert len(device) == IAP2_LINK_SHAPE["device_packets"], \
            (path, len(device))
        assert len(_raw(path)) == IAP2_LINK_SHAPE["bytes"], (path,
            len(_raw(path)))
        # every packet in the scoped stream is well formed; a scan of the whole
        # capture cannot make this claim because its extra packets are noise
        for pkt in accessory + device:
            assert pkt.header_ok, (path, pkt)
            assert pkt.payload_ok, (path, pkt)

    # and the whole-capture scan really is worse, so the scoping is load-bearing
    from pryer import capture as _capture
    path = _captures(("9_ios",))[0]
    if _capture.is_pcapng(path):
        everything = b"".join(payload for _pid, payload
                              in _capture.usb_packets(path))
        naive, _ = iap2.split_sides(everything)
        assert len(naive) > IAP2_LINK_SHAPE["accessory_packets"], (
            "expected the unscoped scan to invent packets; if it no longer "
            "does, this test's premise needs revisiting")


def test_captured_syn_carries_one_control_session():
    for path in _captures(IOS_HANDSHAKE_CAPTURES):
        syns = [p for p in iap2.PacketReader().feed(_raw(path))
                if p.is_syn and not p.is_ack]
        assert syns, "%s: no accessory SYN" % path
        params = iap2.LinkParams.decode(syns[0].payload)
        assert params.version == 1
        assert params.max_packet_length == 1024
        assert params.retransmission_timeout_ms == 2000
        assert params.cumulative_ack_timeout_ms == 20
        assert params.max_retransmissions == 30
        assert params.sessions == [(0x0A, iap2.SESSION_CONTROL, 1)]
        assert params.control_session_id() == 0x0A


def test_link_params_roundtrip():
    params = iap2.LinkParams(sessions=[(0x0A, iap2.SESSION_CONTROL, 1)])
    assert iap2.LinkParams.decode(params.encode()) == params


def test_captured_identification_is_the_goggles():
    path = _captures(("0_ios",))[0]
    idents = [m for pkt in iap2.PacketReader().feed(_raw(path))
              for m in iap2.decode_messages(pkt.payload)
              if m.msg_id == iap2.MSG_IDENTIFICATION_INFORMATION]
    assert len(idents) == 1
    ident = iap2.Identification.from_message(idents[0])
    assert ident.name == "DJI_GOGGLES"
    assert ident.model == "GLS_MODEL"
    assert ident.manufacturer == "Dajiang Innovation"
    assert ident.firmware == "00.00.00.00"
    assert ident.hardware == "v1.0.0.0"
    assert ident.current_language == "en"
    assert ident.languages == ["zh", "en", "ja", "fr", "de"]
    assert ident.messages_sent == [iap2.MSG_START_POWER_UPDATES,
                                   iap2.MSG_STOP_POWER_UPDATES]
    assert ident.messages_received == [iap2.MSG_POWER_UPDATE]

    # The finding the whole transport rests on: com.dji.logiclink is bound to a
    # *native* transport component, so it is not an iAP2 session -- it is the
    # separate bulk pipe on interface 1 alternate setting 1.
    assert len(ident.ea_protocols) == 1
    proto = ident.ea_protocols[0]
    assert proto["name"] == mfi.EA_PROTOCOL_NAME
    assert proto["identifier"] == 0
    assert proto["native_transport"] == 0
    assert ident.ea_protocol_id(mfi.EA_PROTOCOL_NAME) == 0

    # And the accessory calls its transport a *USBHost* component, i.e. it
    # expects the Apple device to be the USB host. That is the role reversal
    # that makes the Linux side easy.
    assert len(ident.transports) == 1
    assert ident.transports[0]["kind"] == "USBHostTransportComponent"
    assert ident.transports[0]["supports_iap2"] is True


def test_no_external_accessory_session_is_ever_opened():
    """
    If the tunnel were multiplexed into iAP2 we would see a session of type
    ExternalAccessory in a SYN, or payload on a session id other than the
    control session. Neither ever happens.
    """
    for path in _captures(IOS_HANDSHAKE_CAPTURES):
        sessions = set()
        for pkt in iap2.PacketReader().feed(_raw(path)):
            if pkt.is_syn:
                for _sid, stype, _v in iap2.LinkParams.decode(
                        pkt.payload).sessions:
                    assert stype == iap2.SESSION_CONTROL
            if pkt.payload and not pkt.is_syn:
                sessions.add(pkt.session)
        assert sessions == {0x0A}, "%s: unexpected sessions %s" % (path,
                                                                  sessions)


def test_captured_message_directions_are_consistent():
    for path in _captures(IOS_HANDSHAKE_CAPTURES):
        accessory, device = iap2.split_sides(_raw(path))
        assert accessory and device
        for pkt in accessory:
            for msg in iap2.decode_messages(pkt.payload):
                assert iap2.direction(msg.msg_id) == "goggles->phone"
        for pkt in device:
            for msg in iap2.decode_messages(pkt.payload):
                assert iap2.direction(msg.msg_id) == "phone->goggles"


def test_the_handshake_is_fixed_except_for_the_session_secrets():
    """
    Which parts of the handshake repeat verbatim between sessions, and which
    cannot.

    Across all four iOS captures the message sequence is identical and most
    messages are byte-identical, because they carry fixed facts: the accessory's
    certificate, its identification, the acceptance. Exactly three vary, and each
    for a reason:

    * ``RequestAuthenticationChallengeResponse`` -- the iPhone's random challenge
    * ``AuthenticationResponse``                -- the signature over it
    * ``PowerUpdate``                           -- the phone's battery level,
      (90, 88, 79 and 60 percent in four sessions)

    So an implementation may replay the fixed messages, but must actually sign
    the challenge; and it must not expect PowerUpdate to be a constant.
    """
    varies = {"AuthenticationResponse", "PowerUpdate",
              "RequestAuthenticationChallengeResponse"}
    seen: dict[str, set[bytes]] = {}
    order: list[list[str]] = []
    for path in _captures(IOS_HANDSHAKE_CAPTURES):
        names = []
        for pkt in iap2.PacketReader().feed(_raw(path)):
            for msg in iap2.decode_messages(pkt.payload):
                name = iap2.MESSAGE_NAMES.get(msg.msg_id, "0x%04x" % msg.msg_id)
                names.append(name)
                seen.setdefault(name, set()).add(msg.encode())
        order.append(names)

    assert len(order) >= 2, "need several captures to compare"
    assert all(o == order[0] for o in order), order

    for name, encodings in sorted(seen.items()):
        if name in varies:
            assert len(encodings) == len(order), (
                "%s should differ in every session" % name)
        else:
            assert len(encodings) == 1, (
                "%s should be byte-identical across sessions" % name)


def test_replay_matches_the_iphone():
    expected_names = [
        "RequestAuthenticationCertificate",
        "RequestAuthenticationChallengeResponse",
        "AuthenticationSucceeded",
        "StartIdentification",
        "IdentificationAccepted",
        "PowerUpdate",
    ]
    for path in _captures(IOS_HANDSHAKE_CAPTURES):
        accessory, device = iap2.split_sides(_raw(path))
        session = iap2.DeviceSession(initial_seq=0xAC, rng=lambda n: bytes(n))
        produced = []
        for pkt in accessory:
            for reply in iap2.PacketReader().feed(session.feed(pkt.encode())):
                produced += [m.msg_id
                             for m in iap2.decode_messages(reply.payload)]
        wanted = [m.msg_id for pkt in device
                  for m in iap2.decode_messages(pkt.payload)]
        assert produced == wanted, path
        assert [iap2.message_name(m) for m in produced] == expected_names, path
        assert session.ready, path
        assert len(session.certificate) == 607
        assert len(session.signature) == 64
        assert session.identification is not None


def test_replay_seq_and_ack_follow_the_captured_rules():
    """
    seq advances once per payload packet, pure ACKs repeat it, and ack always
    reports the accessory's latest sequence number.
    """
    path = _captures(("0_ios",))[0]
    accessory, _device = iap2.split_sides(_raw(path))
    session = iap2.DeviceSession(initial_seq=0xAC, rng=lambda n: bytes(n))
    seqs, acks, payloads = [], [], []
    for pkt in accessory:
        for out in iap2.PacketReader().feed(session.feed(pkt.encode())):
            seqs.append(out.seq)
            acks.append(out.ack)
            payloads.append(bool(out.payload))

    # exactly the sequence numbers the iPhone used: ac for the SYN|ACK, then
    # one per payload packet
    assert seqs == [0xAC, 0xAD, 0xAE, 0xAF, 0xB0, 0xB1, 0xB2]
    assert payloads == [True, True, True, True, True, True, True]
    # our first two packets go out together, both acking the SYN (seq 0)
    assert acks[:2] == [0x00, 0x00]
    assert acks[2:] == [0x01, 0x02, 0x02, 0x03, 0x04]


def test_syn_ack_echoes_the_session_table():
    path = _captures(("0_ios",))[0]
    accessory, _ = iap2.split_sides(_raw(path))
    session = iap2.DeviceSession(initial_seq=0xAC, rng=lambda n: bytes(n))
    out = iap2.PacketReader().feed(session.feed(accessory[0].encode()))
    synack = out[0]
    assert synack.control == iap2.CTL_SYN | iap2.CTL_ACK
    ours = iap2.LinkParams.decode(synack.payload)
    assert ours.sessions == [(0x0A, iap2.SESSION_CONTROL, 1)]
    assert ours.max_packet_length == 0xFFFF
    assert ours.max_outstanding_packets == 0x7F


def test_authentication_can_be_rejected():
    path = _captures(("0_ios",))[0]
    accessory, _ = iap2.split_sides(_raw(path))
    session = iap2.DeviceSession(initial_seq=0xAC, rng=lambda n: bytes(n),
                                 verify_auth=True,
                                 verifier=lambda c, ch, sig: False)
    produced = []
    for pkt in accessory:
        for reply in iap2.PacketReader().feed(session.feed(pkt.encode())):
            produced += [m.msg_id for m in iap2.decode_messages(reply.payload)]
    assert iap2.MSG_AUTH_FAILED in produced
    assert iap2.MSG_AUTH_SUCCEEDED not in produced
    assert not session.authenticated


# --------------------------------------------------------------------------- #
# Control-session codec
# --------------------------------------------------------------------------- #
def test_message_roundtrip():
    msg = iap2.Message(iap2.MSG_REQUEST_AUTH_CHALLENGE_RESPONSE,
                       [(0, bytes(range(32)))])
    again = iap2.decode_messages(msg.encode())
    assert len(again) == 1
    assert again[0].msg_id == msg.msg_id
    assert again[0].param(0) == bytes(range(32))


def test_two_messages_in_one_payload():
    payload = (iap2.Message(iap2.MSG_AUTH_SUCCEEDED).encode()
               + iap2.Message(iap2.MSG_START_IDENTIFICATION).encode())
    got = iap2.decode_messages(payload)
    assert [m.msg_id for m in got] == [iap2.MSG_AUTH_SUCCEEDED,
                                       iap2.MSG_START_IDENTIFICATION]


def test_empty_message_is_six_bytes():
    assert iap2.Message(iap2.MSG_START_IDENTIFICATION).encode() == \
        bytes.fromhex("40400006 1d00".replace(" ", ""))


def test_nested_params_roundtrip():
    inner = iap2.encode_params([(0, b"\x00"), (1, b"com.dji.logiclink\x00")])
    outer = iap2.decode_params(iap2.encode_params([(10, inner)]))
    assert len(outer) == 1 and outer[0][0] == 10
    assert dict(iap2.decode_params(outer[0][1]))[1] == b"com.dji.logiclink\x00"


# --------------------------------------------------------------------------- #
# MFi-mode descriptors and endpoints
# --------------------------------------------------------------------------- #
DJI_PID_MFI = 0x1002


def _config_descriptor_of_goggles(path: str) -> bytes:
    """
    The 2ca3:1002 configuration descriptor, read off the bus properly.

    An iOS capture contains two enumerations, because the link uses the Apple
    role swap: the goggles first enumerates the iPhone as a device, then swaps
    and presents itself as 2ca3:1002 with the iAP and External Accessory
    interfaces. Both sit at address 1, so this selects by idVendor/idProduct.
    """
    group = capture.device_descriptors(path, mfi.DJI_VID, DJI_PID_MFI)
    return group[(0x02, 0)]


def test_mfi_endpoints_match_the_captured_descriptor():
    desc = _config_descriptor_of_goggles(_captures(("0_ios",))[0])
    assert desc[1] == 0x02 and int.from_bytes(desc[2:4], "little") == 64
    assert desc[4] == 2, "MFi mode has exactly two interfaces"

    interfaces = {}
    off, current = 0, None
    while off < len(desc) and desc[off]:
        length, dtype = desc[off], desc[off + 1]
        if dtype == 0x04:
            current = (desc[off + 2], desc[off + 3])
            interfaces[current] = {
                "class": (desc[off + 5], desc[off + 6], desc[off + 7]),
                "eps": [],
            }
        elif dtype == 0x05 and current is not None:
            interfaces[current]["eps"].append(
                (desc[off + 2], int.from_bytes(desc[off + 4:off + 6], "little")))
        off += length

    iap = interfaces[(mfi.IAP_INTERFACE, 0)]
    assert iap["class"] == mfi.IAP_CLASS
    assert iap["eps"] == [(mfi.EP_IAP_IN, mfi.BULK_MPS),
                          (mfi.EP_IAP_OUT, mfi.BULK_MPS)]

    # alternate setting 0 of the External Accessory interface has no endpoints;
    # that is why the driver has to issue SET_INTERFACE(1, 1).
    assert interfaces[(mfi.EA_INTERFACE, 0)]["eps"] == []
    ea = interfaces[(mfi.EA_INTERFACE, mfi.EA_ALT_SETTING)]
    assert ea["class"] == mfi.EA_CLASS
    assert ea["eps"] == [(mfi.EP_EA_IN, mfi.BULK_MPS),
                         (mfi.EP_EA_OUT, mfi.BULK_MPS)]


def test_iphone_descriptors_are_the_captured_ones():
    group = capture.device_descriptors(_captures(("0_ios",))[0],
                                       mfi.IPHONE_VID, mfi.IPHONE_PID)

    # device descriptor: the goggles must see Apple's vendor id
    assert mfi.IPHONE_DEVICE_DESC == group[(0x01, 0)]
    assert int.from_bytes(mfi.IPHONE_DEVICE_DESC[8:10],
                          "little") == mfi.IPHONE_VID
    assert int.from_bytes(mfi.IPHONE_DEVICE_DESC[10:12],
                          "little") == mfi.IPHONE_PID

    # all four configurations, byte for byte
    for index, cfg in enumerate(mfi.IPHONE_CONFIGS):
        assert cfg == group[(0x02, index)], index
    assert [len(c) for c in mfi.IPHONE_CONFIGS] == [39, 149, 62, 117]


def _without_string_indices(desc: bytes) -> bytes:
    """
    A descriptor blob with every string-table index zeroed.

    String indices are the phone's private numbering for its own string table.
    They are not part of the interface contract and they do differ between
    handsets: see test_iphone_descriptors_vary_only_in_string_indices.
    """
    out = bytearray(desc)
    off = 0
    while off + 2 <= len(out):
        length, dtype = out[off], out[off + 1]
        if length < 2:
            break
        if dtype == 0x02 and length > 6:        # configuration: iConfiguration
            out[off + 6] = 0
        elif dtype == 0x04 and length > 8:      # interface: iInterface
            out[off + 8] = 0
        elif dtype == 0x01 and length > 16:     # device: iMfr/iProd/iSerial
            out[off + 14] = out[off + 15] = out[off + 16] = 0
        off += length
    return bytes(out)


def test_iphone_descriptors_vary_only_in_string_indices():
    """
    Every iOS capture shows the same phone-side interface contract.

    The structure is identical in every capture -- same device descriptor,
    same four configurations, same interfaces and endpoints -- but the string
    indices are not stable: one session reports iInterface 0x0f on
    configuration 0 where the others report 0x1b, which is a different iOS
    build numbering its own string table differently.

    That matters for the emulator: it may hard-code the structure, but it must
    keep its advertised string indices consistent with the string table it
    actually serves, rather than copying indices out of one capture and assuming
    they are universal.
    """
    seen_raw: set[bytes] = set()
    for path in _captures(IOS_HANDSHAKE_CAPTURES):
        group = capture.device_descriptors(path, mfi.IPHONE_VID,
                                           mfi.IPHONE_PID)
        assert group[(0x01, 0)] == mfi.IPHONE_DEVICE_DESC, path
        for index, cfg in enumerate(mfi.IPHONE_CONFIGS):
            got = bytes(group[(0x02, index)])
            assert len(got) == len(cfg), (path, index)
            assert _without_string_indices(got) == \
                _without_string_indices(cfg), (path, index)
            if index == 0:
                seen_raw.add(got)
    # and the variation is real, not hypothetical
    assert len(seen_raw) == 2, sorted(d.hex() for d in seen_raw)


def test_the_goggles_enumerates_as_a_device_after_the_role_swap():
    """
    Ground truth for the role swap: an iOS capture holds two enumerations, the
    iPhone's first and the goggles' own second, and the goggles' descriptors
    name the interfaces the tunnel runs over.
    """
    for path in _captures(IOS_HANDSHAKE_CAPTURES):
        groups = capture.descriptors(path)
        vids = [(g[(0x01, 0)][8] | g[(0x01, 0)][9] << 8,
                 g[(0x01, 0)][10] | g[(0x01, 0)][11] << 8)
                for g in groups.values() if (0x01, 0) in g]
        assert (mfi.IPHONE_VID, mfi.IPHONE_PID) in vids, path
        assert (mfi.DJI_VID, DJI_PID_MFI) in vids, path
        # the iPhone is enumerated first, then the roles swap
        assert vids.index((mfi.IPHONE_VID, mfi.IPHONE_PID)) \
            < vids.index((mfi.DJI_VID, DJI_PID_MFI)), path

        goggles = capture.device_descriptors(path, mfi.DJI_VID, DJI_PID_MFI)
        strings = {i: v[2:].decode("utf-16-le").rstrip("\0")
                   for (t, i), v in goggles.items() if t == 0x03 and i}
        assert strings[2] == "DJI_GOGGLES", path
        assert strings[1] == "Dajiang Innovation", path
        assert strings[5] == "iAP Interface", path
        assert strings[6] == mfi.EA_PROTOCOL_NAME, (path, strings[6])

        # the config descriptor is self-consistent and is the one MFi mode uses
        cfg = goggles[(0x02, 0)]
        assert int.from_bytes(cfg[2:4], "little") == len(cfg) == 64, path


def test_role_swap_request_appears_in_every_ios_capture():
    for path in _captures(IOS_HANDSHAKE_CAPTURES):
        lines = [capture.decode_setup(payload)
                 for _pid, payload in capture.usb_packets(path)]
        swaps = [ln for ln in lines
                 if ln and "0x%02x" % mfi.APPLE_ROLE_SWAP in ln.lower()
                 or (ln and "ROLE_SWAP" in ln)]
        assert swaps, "%s: no Apple role-swap request" % path
        assert "bmRequestType=0x40" in swaps[0]
        assert "wLength=0" in swaps[0]


# --------------------------------------------------------------------------- #
# Gadget-phase state machine (mock raw-gadget, as in test_gadget_handshake.py)
# --------------------------------------------------------------------------- #
def FakeGadget():
    # the direction-enforcing fake shared with test_gadget_handshake.py
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from fakegadget import StrictFakeGadget
    return StrictFakeGadget()


def _iphone_session(gadget):
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from fakegadget import strict
    return strict(mfi._IphoneSession("dwc2", "udc", gadget=gadget), gadget)


def _setup(hexstr: str):
    from pryer.rawgadget import CtrlRequest
    raw = bytes.fromhex(hexstr)
    assert len(raw) == 8, "a setup packet is 8 bytes, got %d" % len(raw)
    return CtrlRequest.from_buffer_copy(raw)


def test_iphone_session_answers_enumeration():
    gadget = FakeGadget()
    session = _iphone_session(gadget)

    session.handle_one(_setup("8006000100004000"))       # GET_DESCRIPTOR DEVICE
    assert gadget.writes[-1] == mfi.IPHONE_DEVICE_DESC

    for index, cfg in enumerate(mfi.IPHONE_CONFIGS):     # all four configs
        session.handle_one(_setup("8006%02x020000%02x00" % (index, len(cfg))))
        assert gadget.writes[-1] == cfg

    session.handle_one(_setup("800600030000ff00"))       # LANGID table
    assert gadget.writes[-1] == bytes.fromhex("04030904")

    for index, text in enumerate(mfi.IPHONE_STRINGS, start=1):
        session.handle_one(_setup("8006%02x030904ff00" % index))
        got = gadget.writes[-1]
        assert got[1] == 0x03 and got[0] == len(got)
        assert got[2:].decode("utf-16-le") == text

    # the real handset stalled these, so we must too
    before = gadget.stalls
    for index in mfi.IPHONE_STALLED_STRINGS:
        session.handle_one(_setup("8006%02x030904ff00" % index))
    assert gadget.stalls == before + len(mfi.IPHONE_STALLED_STRINGS)


def test_iphone_session_reacts_to_the_role_swap():
    gadget = FakeGadget()
    session = _iphone_session(gadget)

    session.handle_one(_setup("0009010000000000"))       # SET_CONFIGURATION 1
    assert session.configured.is_set()
    assert gadget.acks == 1 and gadget.writes == []      # EP0_READ(0) status

    assert not session.role_swap_requested.is_set()
    session.handle_one(_setup("4051000000000000"))       # Apple request 0x51
    assert session.role_swap_requested.is_set()
    assert session.wait_for_role_swap(0.0)
    assert gadget.acks == 2                              # swap acked by a read

    stalls = gadget.stalls
    session.handle_one(_setup("4052000000000000"))       # any other vendor req
    assert gadget.stalls == stalls + 1


def test_iphone_session_acks_no_data_requests_with_a_read():
    gadget = FakeGadget()
    session = _iphone_session(gadget)
    for req in ("0b01000000000000",    # SET_INTERFACE
                "0001010000000000",    # CLEAR_FEATURE
                "0003010000000000"):   # SET_FEATURE
        session.handle_one(_setup(req))
    assert gadget.acks == 3 and gadget.writes == [] and gadget.stalls == 0
    session.handle_one(_setup("8008000000000100"))       # GET_CONFIGURATION
    assert gadget.writes == [b"\x00"]


def test_iphone_session_stalls_class_requests():
    gadget = FakeGadget()
    session = _iphone_session(gadget)
    session.handle_one(_setup("a1fe000000000100"))
    assert gadget.stalls == 1


# --------------------------------------------------------------------------- #
# libusb binding
# --------------------------------------------------------------------------- #
def test_libusb_binding_loads():
    assert libusb.available(), "libusb-1.0 should be present on this machine"
    with libusb.Context() as ctx:
        assert isinstance(ctx.list_devices(), list)


def test_libusb_error_names_are_populated():
    assert "TIMEOUT" in libusb.ERROR_NAMES[libusb.ERROR_TIMEOUT]
    assert issubclass(libusb.UsbTimeout, libusb.UsbError)
    assert issubclass(libusb.UsbError, OSError)


def test_iap_host_reports_a_useful_error_without_hardware():
    host = mfi.IapHost()
    try:
        host.read()
    except RuntimeError as exc:
        assert "not open" in str(exc)
    else:
        raise AssertionError("reading before open() should fail")
    finally:
        host.close()


def test_diagnose_returns_checks():
    checks = mfi.diagnose()
    assert checks and all(isinstance(ok, bool) and isinstance(text, str)
                          for ok, text in checks)


# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    import support  # noqa: E402
    sys.exit(support.main(globals()))
