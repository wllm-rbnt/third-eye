"""
Feed the exact control requests the DJI Goggles 3 sent to a fake
raw-gadget, and check our device side answers the way the real phone did.

This exercises the part of the project that cannot be tested without a
Goggles 3 and a UDC: the descriptor server and the AOA state machine.

The request/response pairs below are transcribed from a real Android
handset's enumeration by the goggles.

Run with:  python -m pytest tests/test_gadget_handshake.py
       or:  python tests/test_gadget_handshake.py
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pryer import aoa  # noqa: E402
from pryer.accessory import _Session, _endpoints_of  # noqa: E402
from pryer.rawgadget import CtrlRequest  # noqa: E402

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fakegadget import StrictFakeGadget, strict  # noqa: E402


# The fake enforces raw-gadget's ep0 direction rule; see tests/fakegadget.py.
# A fake that accepted an EP0_WRITE for any request would let a
# SET_CONFIGURATION status-stage bug pass every test.
FakeGadget = StrictFakeGadget


def setup(hexstr: str) -> CtrlRequest:
    return CtrlRequest.from_buffer_copy(bytes.fromhex(hexstr))


def make_session(descriptors, ep0_out=None, enable_endpoints=True):
    fake = FakeGadget(ep0_out)
    session = _Session(descriptors, "fake", "fake", gadget=fake,
                       enable_endpoints=enable_endpoints)
    return strict(session, fake), fake


# --------------------------------------------------------------------------- #
def test_phone_phase_answers_enumeration_like_the_handset():
    """
    The exact request sequence the goggles sends a real Android handset, in
    order, with the responses the Samsung phone gave -- including the string
    *indices* it advertised.
    """
    s, g = make_session(aoa.phone_descriptors(), enable_endpoints=False)

    # GET_DESCRIPTOR DEVICE wLength=64  -> the handset's 18-byte descriptor
    s.handle_one(setup("8006000100004000"))
    dev = g.writes[-1]
    assert dev == aoa.PHONE_DEVICE_DESC
    assert int.from_bytes(dev[8:10], "little") == aoa.PHONE_VID
    assert int.from_bytes(dev[10:12], "little") == aoa.PHONE_PID
    # iManufacturer 2, iProduct 3, iSerialNumber 4 -- the handset's numbering
    assert tuple(dev[14:17]) == (2, 3, 4)

    # GET_DESCRIPTOR CONFIG wLength=9 -> truncated to 9 bytes, header only
    s.handle_one(setup("8006000200000900"))
    assert len(g.writes[-1]) == 9
    total = int.from_bytes(g.writes[-1][2:4], "little")
    assert total == 121, total

    # GET_DESCRIPTOR CONFIG with the real length -> the whole thing, verbatim
    s.handle_one(setup("800600020000" + "%02x00" % total))
    assert g.writes[-1] == aoa.PHONE_CONFIG

    # string 0 -> LANGID table
    s.handle_one(setup("800600030000ff00"))
    assert g.writes[-1] == bytes.fromhex("04030904")

    # The goggles asks for iProduct, iManufacturer, iSerialNumber (in that
    # order, at indices 3, 2, 4), then for the interface strings 6, 7 and 5.
    texts = {}
    for idx in (3, 2, 4, 6, 7, 5):
        s.handle_one(setup("8006%02x030904ff00" % idx))
        d = g.writes[-1]
        assert d[1] == aoa.DT_STRING and d[0] == len(d), idx
        texts[idx] = d[2:].decode("utf-16-le")
    assert texts[2] == "SAMSUNG"
    assert texts[3] == "SAMSUNG_Android"
    assert texts[6] == "CDC Abstract Control Model (ACM)"
    assert texts[5] == "ADB Interface"
    assert texts[7] == "CDC ACM Data"

    # unknown descriptor type (BOS) -> must STALL, not hang
    before = g.stalls
    s.handle_one(setup("80060f0f0000ff00"))
    assert g.stalls == before + 1

    # SET_CONFIGURATION 1 -> CONFIGURE + status stage. The status stage is a
    # zero-length EP0_READ, not a write; with a write the goggles never gets
    # past this step. Phase 1 enables no endpoint: the goggles moves no bulk
    # data before START_ACCESSORY.
    writes, acks = len(g.writes), g.acks
    s.handle_one(setup("0009010000000000"))
    assert g.configured
    assert s.configured.is_set()
    assert g.acks == acks + 1
    assert len(g.writes) == writes
    assert g.enabled == []


def test_phone_config_is_the_handset_composite():
    """
    The "handset" phase-1 configuration keeps exactly the interface set the
    goggles sees on a real handset.
    """
    cfg = aoa.PHONE_CONFIG
    assert len(cfg) == int.from_bytes(cfg[2:4], "little") == 121
    assert cfg[4] == 4                       # four interfaces
    classes = []
    off = 0
    while off + 2 <= len(cfg):
        length, dtype = cfg[off], cfg[off + 1]
        if dtype == aoa.DT_INTERFACE:
            classes.append(tuple(cfg[off + 5:off + 8]))
        off += length
    assert classes == [(0x02, 0x02, 0x01),   # CDC comm (ACM)
                       (0x0A, 0x00, 0x00),   # CDC data
                       (0xFF, 0x10, 0x01),   # Samsung vendor interface
                       (0xFF, 0x42, 0x01)]   # adb -- the Android signature


def test_every_advertised_string_index_resolves():
    """
    A descriptor may not point at a string the table cannot serve.

    The goggles reads interface strings in the middle of deciding whether we
    are an Android phone, so a stall there is not a harmless one.
    """
    for descriptors in (aoa.phone_descriptors(),
                        aoa.accessory_descriptors(with_adb=True),
                        aoa.accessory_descriptors(with_adb=False)):
        missing = aoa.string_indices_used(descriptors) - set(
            descriptors["strings"])
        assert not missing, missing


def test_string_lookup_uses_handset_indices():
    """
    Index 1 is not served, 2 is the manufacturer.

    A 1-based list would return the *product* string for index 2, while the
    descriptors say index 2 is the manufacturer.
    """
    from pryer.accessory import _string_at
    table = aoa.phone_descriptors()["strings"]
    assert _string_at(table, 1) is None
    assert _string_at(table, 2) == "SAMSUNG"
    assert _string_at(table, 3) == "SAMSUNG_Android"
    # the legacy list form still works for third-party descriptor sets
    assert _string_at(["a", "b"], 1) == "a"
    assert _string_at(["a", "b"], 3) is None


def test_aoa_sequence_matches_the_handset_handshake():
    """
    The six SEND_STRING payloads are the literal ones the goggles sent, and
    START_ACCESSORY must flip the state machine.
    """
    payloads = [aoa.ACCESSORY_STRINGS[i].encode() + b"\x00" for i in range(6)]
    s, g = make_session(aoa.phone_descriptors(), ep0_out=payloads)

    # AOA_GET_PROTOCOL: bmRequestType 0xC0, bRequest 51, wLength 2
    s.handle_one(setup("c033000000000200"))
    assert s.protocol_asked.is_set()
    assert g.writes[-1] == b"\x02\x00", g.writes[-1].hex()

    # AOA_SEND_STRING x6
    for idx, payload in enumerate(payloads):
        s.handle_one(setup("4034" + "0000" + "%02x00" % idx
                           + "%02x00" % len(payload)))
    assert s.strings == aoa.ACCESSORY_STRINGS
    assert s.strings[1] == "com.dji.logiclink"

    # AOA_START_ACCESSORY: no data stage, must ACK and set the flag
    assert not s.start_requested.is_set()
    acks = g.acks
    s.handle_one(setup("4035000000000000"))
    assert s.start_requested.is_set()
    assert g.acks == acks + 1        # zero-length EP0_READ status stage
    assert g.stalls == 0


def test_accessory_phase_enables_the_right_endpoints():
    s, g = make_session(aoa.accessory_descriptors(with_adb=True))

    s.handle_one(setup("8006000100001200"))
    dev = g.writes[-1]
    assert int.from_bytes(dev[8:10], "little") == aoa.AOA_VID
    assert int.from_bytes(dev[10:12], "little") == aoa.AOA_PID_ACCESSORY_ADB

    s.handle_one(setup("0009010000000000"))
    assert g.configured
    # both accessory endpoints must be live and mapped to handles
    assert aoa.ACCESSORY_EP_IN in s.ep_handles
    assert aoa.ACCESSORY_EP_OUT in s.ep_handles
    assert len(s.ep_handles) == 4      # + the two adb endpoints
    for desc in g.enabled:
        assert desc[1] == aoa.DT_ENDPOINT and desc[3] == aoa.XFER_BULK


def test_misc_standard_requests_do_not_stall():
    s, g = make_session(aoa.accessory_descriptors())
    for req in ("8000000000000200",   # GET_STATUS
                "8008000000000100",   # GET_CONFIGURATION
                "0b01000100000000",   # SET_INTERFACE (alt 1, if 0)
                "810a000000000100",   # GET_INTERFACE
                "0201000000000000"):  # CLEAR_FEATURE on ep
        s.handle_one(setup(req))
    assert g.stalls == 0
    assert len(g.writes) == 3          # the three IN requests with data
    assert g.acks == 2                 # SET_INTERFACE, CLEAR_FEATURE


def test_class_requests_stall():
    s, g = make_session(aoa.phone_descriptors())
    s.handle_one(setup("a1fe000000000100"))   # a class request
    assert g.stalls == 1


def test_unknown_vendor_request_stalls():
    s, g = make_session(aoa.phone_descriptors())
    s.handle_one(setup("40aa000000000000"))
    assert g.stalls == 1


def test_endpoint_walker_ignores_other_descriptors():
    cfg = aoa.accessory_descriptors(with_adb=False)["config"]
    assert [a for a, _ in _endpoints_of(cfg)] == [0x81, 0x01]


# --------------------------------------------------------------------------- #
# Status stages: every no-data request is completed with a zero-length read
# --------------------------------------------------------------------------- #
def test_fake_gadget_enforces_the_kernel_direction_rule():
    """The fake must refuse what raw-gadget refuses, or it proves nothing."""
    import errno
    g = FakeGadget()
    g.begin(setup("0009010000000000"))          # OUT, no data
    try:
        g.ep0_write(b"")
    except OSError as exc:
        assert exc.errno == errno.EBUSY
    else:
        raise AssertionError("EP0_WRITE on an OUT request must fail")
    g.ep0_read(0)
    g.begin(setup("8006000100001200"))          # IN with data
    try:
        g.ep0_read(0)
    except OSError as exc:
        assert exc.errno == errno.EBUSY
    else:
        raise AssertionError("EP0_READ on an IN request must fail")


def test_every_no_data_request_is_acked_with_a_zero_length_read():
    """
    SET_CONFIGURATION, SET_INTERFACE, CLEAR/SET_FEATURE, START_ACCESSORY and
    SET_CONFIGURATION 0 all have wLength 0. raw-gadget marks them OUT-pending,
    so each must be completed with EP0_READ(0). `strict()` also fails the test
    if any request is left unanswered.
    """
    s, g = make_session(aoa.accessory_descriptors())
    reqs = ("0009010000000000",   # SET_CONFIGURATION 1
            "0101000000000000",   # CLEAR_FEATURE (interface)
            "0003010000000000",   # SET_FEATURE remote wakeup
            "0b01000000000000",   # SET_INTERFACE
            "4035000000000000",   # AOA START_ACCESSORY
            "0009000000000000")   # SET_CONFIGURATION 0
    for req in reqs:
        s.handle_one(setup(req))
    assert g.acks == len(reqs)
    assert g.writes == []
    assert g.stalls == 0
    assert not s.configured.is_set()   # the final SET_CONFIGURATION 0


def test_send_string_with_no_payload_still_completes():
    s, g = make_session(aoa.phone_descriptors())
    s.handle_one(setup("4034000003000000"))    # SEND_STRING idx 3, wLength 0
    assert g.acks == 1
    assert s.strings[3] == ""


def test_in_request_without_data_stage_is_acked_not_written():
    """The kernel's rule is IN *and* wLength > 0; an IN with wLength 0 reads."""
    s, g = make_session(aoa.accessory_descriptors())
    s.handle_one(setup("8000000000000000"))    # GET_STATUS, wLength 0
    assert g.acks == 1 and g.writes == []


def test_configured_is_reported_only_after_the_status_stage():
    events = []

    class Recording(StrictFakeGadget):
        def configure(self):
            events.append("configure")
            super().configure()

        def ep0_read(self, length):
            events.append("ack")
            return super().ep0_read(length)

        def ep_enable(self, descriptor):
            events.append("enable")
            return super().ep_enable(descriptor)

    fake = Recording()
    s = strict(_Session(aoa.accessory_descriptors(), "f", "f", gadget=fake),
               fake)
    s.configured.clear()
    s.handle_one(setup("0009010000000000"))
    # enable -> CONFIGURE -> ack, the order of the upstream raw-gadget examples
    assert events == ["enable"] * 4 + ["configure", "ack"], events
    assert s.configured.is_set() and s.generation == 1


def test_raw_gadget_routes_replies_by_the_kernel_rule():
    """RawGadget.ep0_ack / ep0_reply issue EP0_READ(0) where required."""
    from pryer import rawgadget
    calls = []
    rg = object.__new__(rawgadget.RawGadget)
    rg._ep_io = lambda ioctl, ep, data, length: calls.append(
        (ioctl, length)) or b""
    rg.ep0_ack()
    rg.ep0_reply(setup("8000000000000000"), b"\x00\x00")   # IN, wLength 0
    rg.ep0_reply(setup("8000000000000200"), b"\x00\x00")   # IN, wLength 2
    assert calls == [(rawgadget.IOCTL_EP0_READ, 0),
                     (rawgadget.IOCTL_EP0_READ, 0),
                     (rawgadget.IOCTL_EP0_WRITE, 2)]


def test_ebusy_on_ep0_is_not_mistaken_for_a_link_reset():
    """
    EBUSY from a wrong-direction ep0 call is a programming error, not a bus
    reset. Treating it as a reset would log it at debug level and carry on,
    hiding the failure; on ep0 it must be a hard error.
    """
    import errno
    from pryer import rawgadget
    busy = OSError(errno.EBUSY, "busy")
    assert rawgadget.is_link_gone(busy)                  # endpoint I/O
    assert not rawgadget.is_link_gone(busy, ep0=True)    # ep0 answer
    assert rawgadget.is_link_gone(OSError(errno.ESHUTDOWN, "x"), ep0=True)


def test_ep0_loop_ends_at_error_level_on_a_wrong_direction_answer():
    import logging
    from pryer import rawgadget

    class OneRequest(StrictFakeGadget):
        def __init__(self):
            super().__init__()
            self.sent = False

        def control_event(self):
            if self.sent:
                raise AssertionError("loop should have ended")
            self.sent = True
            req = setup("0009010000000000")
            self.begin(req)
            return rawgadget.EVENT_CONTROL, req, bytes(req)

    fake = OneRequest()
    s = _Session(aoa.phone_descriptors(), "f", "f", gadget=fake,
                 enable_endpoints=False)
    # a broken handler: acknowledge SET_CONFIGURATION with a write
    s._handle_control = lambda req: fake.ep0_write()

    records = []
    handler = logging.Handler()
    handler.emit = records.append
    logger = logging.getLogger("pryer.accessory")
    logger.addHandler(handler)
    try:
        s._loop()
    finally:
        logger.removeHandler(handler)
    assert s.error is not None and s.error.errno == 16   # EBUSY
    assert any(r.levelno == logging.ERROR and "wrong direction" in
               r.getMessage() for r in records), [r.getMessage()
                                                  for r in records]


def test_endpoint_enable_retries_transient_errors():
    import errno
    s, g = make_session(aoa.accessory_descriptors(with_adb=False))
    g.ep_enable_errors = [errno.EBUSY, errno.EAGAIN]
    s.handle_one(setup("0009010000000000"))
    assert set(s.ep_handles) == {aoa.ACCESSORY_EP_IN, aoa.ACCESSORY_EP_OUT}


def test_endpoint_enable_falls_back_to_64_bytes_on_einval():
    import errno
    s, g = make_session(aoa.accessory_descriptors(with_adb=False))
    g.ep_enable_errors = [errno.EINVAL]
    s.handle_one(setup("0009010000000000"))
    assert int.from_bytes(g.enabled[0][4:6], "little") == 64
    assert int.from_bytes(g.enabled[1][4:6], "little") == 512
    assert len(s.ep_handles) == 2


def test_dji_phone_profile():
    d = aoa.phone_descriptors("dji")
    dev, cfg = d["device"], d["config"]
    assert int.from_bytes(dev[8:10], "little") == 0x18D1
    assert int.from_bytes(dev[10:12], "little") == 0x4EE0
    assert cfg[7] == 0x80 and cfg[8] == 250          # bmAttributes, bMaxPower
    assert d["strings"][dev[14]] == "DJI"
    assert d["strings"][dev[15]] == "com.dji.logiclink"
    missing = aoa.string_indices_used(d) - set(d["strings"])
    assert not missing, missing
    assert "dji" in aoa.PHONE_PROFILES

    s, g = make_session(d, enable_endpoints=False)
    s.handle_one(setup("8006000100001200"))
    assert g.writes[-1] == dev
    s.handle_one(setup("0009010000000000"))
    assert s.configured.is_set() and g.acks == 1


# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    import support  # noqa: E402
    sys.exit(support.main(globals()))
