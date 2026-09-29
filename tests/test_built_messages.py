"""
Everything this package puts on the wire is built from named fields.

The handset, accessory and iPhone USB descriptors, the app's registration /
identity / heartbeat payloads, the goggles' SPS/PPS and the iPhone's
PowerUpdate are all assembled by builders. The expected values below are the
bytes the real devices send; PROTOCOL.md quotes the same bytes. None of these
tests needs a reference capture, so they run everywhere; the capture-backed
tests (test_phase1_descriptors.py, test_iap2.py, test_h264.py) compare the
same builders with the captures themselves when those are available.

Run with:  python -m pytest tests/test_built_messages.py
       or:  python tests/test_built_messages.py
"""

from __future__ import annotations

import contextlib
import io
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pryer import aoa, app, h264, iap2, mfi, usbdesc  # noqa: E402


# --------------------------------------------------------------------------- #
# USB descriptors, as the handsets presented them
# --------------------------------------------------------------------------- #
HANDSET_DEVICE = "1201000200000040e8045d68000402030401"
HANDSET_CONFIG = (
    "09027900040100c030"
    "080b000202020108"
    "090400000102020106" "0524001001" "0524010001" "04240202" "0524060001"
    "070583030a0009"
    "09040100020a000007" "07058102000200" "07050102000200"
    "0904020002ff100100" "07058402000200" "07050302000200"
    "0904030002ff420105" "07050402000200" "07058502000200")
ACCESSORY_DEVICE = "1201000200000040d118012dffff02030401"
ACCESSORY_CONFIG = (
    "09023700020100c030"
    "0904000002ffff0006" "07058102000200" "07050102000200"
    "0904010002ff420105" "07050202000200" "07058202000200")
IPHONE_DEVICE = "1201000200000040ac05a812041401020304"
IPHONE_CONFIGS = [
    "09022700010105c0fa09040000030601011b070502020002000705810200020007"
    "05830340000a",
    "09029500030206c0fa09040000000101000009240100011e0001010c2402010102"
    "020203000000092403020101010100090401000001020000090401010101020000"
    "072401020101002324020102021009401f00112b00e02e00803e00225600c05d00"
    "007d0044ac0080bb0009058101c0000400000725010100000009040200010300000"
    "009211101000122d00007058303400001",
    "09023e00020307c0fa09040000030601011b070502020002000705810200020007"
    "05830340000a0904010002fffe02140705040200020007058502000200",
    "09027500030408c0fa09040000030601011b070502020002000705810200020007"
    "05830340000a0904010002fffe0214070504020002000705850200020009040200"
    "00fffd01110904020102fffd011107058602000200070505020002000904020202"
    "fffd01110705860200020007050502000200",
]


def test_handset_descriptors_are_built_to_the_real_bytes():
    assert aoa.PHONE_DEVICE_DESC.hex() == HANDSET_DEVICE
    assert aoa.PHONE_CONFIG.hex() == HANDSET_CONFIG
    d = aoa.phone_descriptors("handset")
    assert d["device"] == aoa.PHONE_DEVICE_DESC
    assert d["config"] == aoa.PHONE_CONFIG
    assert aoa.phone_descriptors() == d            # the default profile


def test_accessory_descriptors_are_built_to_the_real_bytes():
    assert aoa.ACCESSORY_DEVICE_DESC.hex() == ACCESSORY_DEVICE
    assert aoa.ACCESSORY_CONFIG.hex() == ACCESSORY_CONFIG


def test_iphone_descriptors_are_built_to_the_real_bytes():
    assert mfi.IPHONE_DEVICE_DESC.hex() == IPHONE_DEVICE
    assert [c.hex() for c in mfi.IPHONE_CONFIGS] == IPHONE_CONFIGS


def test_every_built_configuration_is_self_consistent():
    """wTotalLength and bNumInterfaces agree with what the builders emit."""
    configs = [aoa.PHONE_CONFIG, aoa.ACCESSORY_CONFIG,
               aoa.MINIMAL_PHONE_CONFIG, aoa.DJI_PHONE_CONFIG,
               *mfi.IPHONE_CONFIGS]
    for cfg in configs:
        assert int.from_bytes(cfg[2:4], "little") == len(cfg)
        parts = usbdesc.split(cfg)
        assert sum(len(p) for p in parts) == len(cfg)
        numbers = {p[2] for p in parts if p[1] == usbdesc.DT_INTERFACE}
        assert cfg[4] == len(numbers), cfg.hex()


def test_the_phone_profiles_are_handset_dji_and_minimal():
    assert aoa.PHONE_PROFILES == ("handset", "dji", "minimal")
    try:
        aoa.phone_descriptors("unknown")
    except ValueError:
        pass
    else:
        raise AssertionError("an unknown profile name must be rejected")


def test_class_specific_builders():
    assert usbdesc.cdc_header().hex() == "0524001001"
    assert usbdesc.cdc_call_management(0, 1).hex() == "0524010001"
    assert usbdesc.cdc_acm(0x02).hex() == "04240202"
    assert usbdesc.cdc_union(0, 1).hex() == "0524060001"
    assert usbdesc.interface_association(0, 2, 2, 2, 1, 8).hex() == \
        "080b000202020108"
    assert usbdesc.hid_descriptor(0xD0).hex() == "092111010001 22d000".replace(
        " ", "")
    fmt = usbdesc.uac_format_type_i(2, 2, 16, mfi.AUDIO_SAMPLE_RATES)
    assert len(fmt) == 0x23 and fmt[7] == 9
    assert fmt[8:11].hex() == "401f00"                     # 8000 Hz


# --------------------------------------------------------------------------- #
# The app's DUML payloads
# --------------------------------------------------------------------------- #
def test_registration_payloads_are_built_to_the_handset_bytes():
    assert app.register_payload().hex() == "1700002300415050000000000002"
    assert app.version_payload().hex() == "1d000100000000010700312e32312e31"
    assert [p for _d, _cs, _ci, p in app.REGISTER_FRAMES] == [
        app.register_payload(), app.version_payload()]
    # the declared length counts a terminator the frame does not carry
    assert app.version_payload("1.2")[8:10] == b"\x04\x00"


def test_heartbeat_and_identity_replies_are_built_to_the_handset_bytes():
    assert app.HEARTBEAT_REPLY.hex() == "1a00000000"
    assert app.IDENTITY_REPLY.hex() == (
        "00415050000000000000000000000000000000000000000000000000000000000000"
        "02000000000000051c000000000000000000000000000000000000000000")
    assert len(app.IDENTITY_REPLY) == 64
    assert app.IDENTITY_REPLY[1:33].rstrip(b"\0") == b"APP"


def test_name_fields_reject_what_does_not_fit():
    try:
        app.register_payload("TOO-LONG-NAME")
    except ValueError:
        pass
    else:
        raise AssertionError("an over-long name was accepted")


def test_the_package_ships_no_recorded_traffic():
    """No stored copy of recorded frames is shipped: everything is built."""
    data = os.path.join(os.path.dirname(app.__file__), "data")
    assert not os.path.exists(data)


def test_query_version_sends_empty_get_version_requests():
    from pryer import duml, tunnel
    sent: list[bytes] = []
    s = app.AppSession(sent.append)
    seqs = s.query_version()
    assert len(seqs) == len(app.VERSION_QUERY_TARGETS) == len(sent)
    frames = [duml.parse_all(next(tunnel.Demuxer().feed(b)).payload)[0]
              for b in sent]
    assert [f.dst for f in frames] == list(app.VERSION_QUERY_TARGETS)
    assert all(f.key == app.CMD_GET_VERSION and f.payload == b""
               and not f.is_response for f in frames)


# --------------------------------------------------------------------------- #
# H.264 and iAP2
# --------------------------------------------------------------------------- #
def test_goggles_parameter_sets_are_built_from_fields():
    assert h264.GOGGLES3_SPS.hex() == (
        "67640034ac4d00f0044fcb35010101400000fa00003a9803c70ca8")
    assert h264.GOGGLES3_PPS.hex() == "68ee3cb0"
    assert h264.GOGGLES3_SPS == h264.build_sps(
        1920, 1080, fps=30.0, style=h264.GOGGLES3_STYLE)


def test_power_update_is_built_from_the_battery_level():
    assert iap2.DEFAULT_POWER_UPDATE == [(6, bytes.fromhex("005a"))]
    assert iap2.power_update_params(60) == [(6, b"\x00\x3c")]
    try:
        iap2.power_update_params(101)
    except ValueError:
        pass
    else:
        raise AssertionError("accepted 101 %")


def test_iap2_compare_option_and_its_old_spelling():
    from pryer import cli
    p = cli.build_parser()
    assert p.parse_args(["iap2", "x", "--compare"]).compare is True
    assert p.parse_args(["iap2", "x", "--replay"]).compare is True
    assert p.parse_args(["iap2", "x"]).compare is False
    with contextlib.redirect_stderr(io.StringIO()):
        try:
            p.parse_args(["stream", "--init", "full"])
        except SystemExit as exc:
            assert exc.code == 2
        else:
            raise AssertionError("stream --init is back")


# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    import support  # noqa: E402
    sys.exit(support.main(globals()))
