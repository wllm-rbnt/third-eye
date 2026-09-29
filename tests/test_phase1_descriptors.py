"""
The phase-1 (pre-accessory) identity of the Android transport, checked
against the reference captures.

Two kinds of recording are used (see support.py):

* real Android handsets, where the goggles enumerates the phone, reads its
  configuration and then probes for AOA with GET_PROTOCOL(51);
* this package on a Raspberry Pi 4B presenting the single-interface
  "minimal" identity (`MINIMAL_ENUMERATION`), where the goggles enumerates and
  configures the Pi without a single stall and then sends nothing more. The
  gadget in that recording acknowledged SET_CONFIGURATION in the wrong
  direction, so most likely its status stage never completed (see
  PROTOCOL.md section 8.2), and the recording says nothing about
  whether the goggles would accept the minimal identity; what it does pin
  down is the exact bytes the "minimal" profile puts on the wire, and the
  diagnosis `decode` prints for such a session.

The tests check:

* the handset, accessory and minimal descriptor sets are byte-identical to
  what is on the wire;
* every handset presents a composite configuration that includes adb;
* `decode`'s "enumerated and then ignored" diagnosis fires on the stalled
  session and never on a successful handshake.

All of them are skipped when the reference captures are not available.

Run with:  python -m pytest tests/test_phase1_descriptors.py
       or:  python tests/test_phase1_descriptors.py
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import support  # noqa: E402
from pryer import aoa, pcapng  # noqa: E402
from pryer.cli import _diagnose_declined_enumeration  # noqa: E402
from support import Skip, capture_path, handset_captures  # noqa: E402

# The Pi 4B session that was enumerated with the minimal identity and then
# went quiet.
MINIMAL_ENUMERATION = "B_rpi"
AOA_REQUESTS = (51, 52, 53)
NO_ANDROID_PROBE = "no Android capture with an AOA probe is available"


def _control(path: str) -> list:
    return list(pcapng.control_transfers(path))


def _interface_classes(config: bytes) -> list[tuple[int, int, int]]:
    out, off = [], 0
    while off + 2 <= len(config):
        length, dtype = config[off], config[off + 1]
        if length < 2:
            break
        if dtype == aoa.DT_INTERFACE and length >= 9:
            out.append(tuple(config[off + 5:off + 8]))
        off += length
    return out


def _last_config(transfers: list) -> bytes:
    """The longest CONFIG descriptor the host read (the full one, not the head)."""
    return max((c.data for c in transfers
                if c.b_request == 6 and c.setup[3] == 0x02),
               key=len, default=b"")


def _probed(transfers: list) -> bool:
    return any(c.b_request == 51 and c.bm_request_type == 0xC0
               for c in transfers)


# --------------------------------------------------------------------------- #
# An enumeration that stops after SET_CONFIGURATION
# --------------------------------------------------------------------------- #
def test_minimal_session_was_enumerated_and_configured_without_a_stall():
    transfers = _control(capture_path(MINIMAL_ENUMERATION))
    assert transfers, "the capture has no control transfers"
    assert not any(c.stalled for c in transfers), \
        "a request was stalled"
    assert any(c.b_request == 5 for c in transfers), "no SET_ADDRESS"
    assert any(c.b_request == 9 and c.w_value == 1 for c in transfers), \
        "no SET_CONFIGURATION 1"


def test_minimal_session_never_got_an_aoa_probe():
    """Enumeration completes and the AOA handshake never starts."""
    transfers = _control(capture_path(MINIMAL_ENUMERATION))
    aoa_reqs = [c.b_request for c in transfers
                if c.b_request in AOA_REQUESTS
                and c.bm_request_type in (0x40, 0xC0)]
    assert aoa_reqs == [], aoa_reqs
    # and no iOS role swap either -- the goggles does not try the other path
    assert not any(c.b_request == 0x51 for c in transfers)


def test_minimal_session_goes_quiet_rather_than_resetting():
    """
    The goggles does not retry, it idles.

    Everything happens inside the first ~300 ms; the rest of the minute is SOF
    traffic only. That rules out "it kept re-enumerating us", which would point
    at a descriptor the UDC rejected instead.
    """
    path = capture_path(MINIMAL_ENUMERATION)
    transfers = _control(path)
    span_ms = (transfers[-1].ts - transfers[0].ts) / 1e6
    assert span_ms < 1000, span_ms
    wire = list(pcapng.wire_packets(path))
    total_ms = (wire[-1].ts - wire[0].ts) / 1e6
    assert total_ms > 30_000, total_ms


def test_minimal_session_presented_one_vendor_interface():
    """What the Pi offered: one vendor-specific interface, 32 bytes."""
    config = _last_config(_control(capture_path(MINIMAL_ENUMERATION)))
    assert len(config) == 32, len(config)
    assert config[4] == 1                       # one interface
    assert _interface_classes(config) == [(0xFF, 0xFF, 0x00)]


def test_the_minimal_profile_matches_the_wire_byte_for_byte():
    """
    The "minimal" phone profile (the one the stream command presents) rebuilds
    exactly what the Pi put on the wire, device and configuration descriptor.
    """
    transfers = _control(capture_path(MINIMAL_ENUMERATION))
    minimal = aoa.phone_descriptors("minimal")
    assert minimal["config"] == _last_config(transfers)
    device = next(c.data for c in transfers
                  if c.b_request == 6 and c.setup[3] == 0x01
                  and len(c.data) == 18)
    assert minimal["device"] == device


# --------------------------------------------------------------------------- #
# What the handsets present
# --------------------------------------------------------------------------- #
def test_every_handset_offers_a_composite_configuration_with_adb():
    """
    The Android handsets show the same phase-1 interface set, and for each of
    them the goggles probes for AOA. The adb interface ff/42/01 is always
    present.
    """
    seen = 0
    for path in handset_captures():
        transfers = _control(path)
        if not _probed(transfers):
            continue          # an iOS capture, or one that starts mid-stream
        config = _last_config([c for c in transfers
                               if c.b_request == 6 and c.setup[3] == 0x02])
        classes = _interface_classes(config)
        assert len(classes) > 1, (path, classes)
        assert (0xFF, 0x42, 0x01) in classes, (path, classes)
        seen += 1
    if not seen:
        raise Skip(NO_ANDROID_PROBE)


def test_the_handset_profile_is_what_the_handsets_present():
    descriptors = aoa.phone_descriptors()
    assert descriptors["device"] == aoa.PHONE_DEVICE_DESC
    assert len(descriptors["config"]) == 121
    assert (0xFF, 0x42, 0x01) in _interface_classes(descriptors["config"])
    # and it is byte-identical to what a handset put on the wire
    for path in handset_captures():
        transfers = _control(path)
        if not _probed(transfers):
            continue
        device = next(c.data for c in transfers
                      if c.b_request == 6 and c.setup[3] == 0x01
                      and len(c.data) == 18)
        assert device == aoa.PHONE_DEVICE_DESC, path
        return
    raise Skip(NO_ANDROID_PROBE)


def test_accessory_descriptors_match_the_handsets_accessory_device():
    for path in handset_captures():
        transfers = _control(path)
        configs = [c.data for c in transfers
                   if c.b_request == 6 and c.setup[3] == 0x02
                   and len(c.data) == 55]
        if not configs:
            continue
        assert configs[0] == aoa.ACCESSORY_CONFIG, path
        device = next(c.data for c in transfers
                      if c.b_request == 6 and c.setup[3] == 0x01
                      and len(c.data) == 18
                      and int.from_bytes(c.data[8:10], "little") == aoa.AOA_VID)
        assert device == aoa.ACCESSORY_DEVICE_DESC, path
        return
    raise Skip("no capture reaches accessory mode")


# --------------------------------------------------------------------------- #
# The diagnosis the tooling prints
# --------------------------------------------------------------------------- #
def test_decode_explains_an_ignored_enumeration_instead_of_calling_it_a_fragment():
    lines = _diagnose_declined_enumeration(
        _control(capture_path(MINIMAL_ENUMERATION)))
    text = " ".join(lines)
    assert "declining the device" in text, text
    assert "status stage" in text, text
    assert "ff/42/01" in text, text
    assert "GET_PROTOCOL" in text, text


def test_the_diagnosis_does_not_fire_on_a_successful_handshake():
    for path in handset_captures():
        transfers = _control(path)
        if _probed(transfers):
            lines = _diagnose_declined_enumeration(transfers)
            # a successful capture must not be described as declined
            assert "declining the device" not in " ".join(lines), path
            return
    raise Skip(NO_ANDROID_PROBE)


# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    sys.exit(support.main(globals()))
