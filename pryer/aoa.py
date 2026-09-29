"""
Android Open Accessory (AOA) protocol constants and the USB descriptor sets
we need in order to look like an Android phone to the DJI Goggles 3.

Role reminder
-------------
The DJI Goggles 3 USB-C port is a USB *host*. The phone is the *device*.
So a Linux box that wants to receive the video stream must act as a USB
**gadget**, not a host -- which is why every working project in this space
(CosmoStreamer, DigiView-SBC) needs a board with a UDC (Raspberry Pi Zero /
Zero 2 W / 4 / 5 USB-C port, or similar OTG-capable SBC).

The handshake (PROTOCOL.md section 2)
-------------------------------------
1. Goggles enumerates us as an ordinary Android phone and does
   SET_CONFIGURATION 1, reading iManufacturer / iProduct / iSerialNumber.
2. Goggles -> us:  bmRequestType 0xC0, bRequest 51, wLength 2
   We answer `02 00` = AOA protocol version 2.
3. Goggles -> us:  bmRequestType 0x40, bRequest 52, wIndex = 0..5, six times,
   carrying the accessory identity strings (see ACCESSORY_STRINGS).
4. Goggles -> us:  bmRequestType 0x40, bRequest 53, wValue 0, wIndex 0.
5. We must detach and re-enumerate as VID 0x18D1 with an accessory PID,
   exposing one vendor-specific interface with a bulk IN/OUT pair. The DJI
   tunnel then runs over that pair.
"""

from __future__ import annotations

# --------------------------------------------------------------------------- #
# AOA control requests
# --------------------------------------------------------------------------- #
ACCESSORY_GET_PROTOCOL = 51    # 0x33, device-to-host, returns uint16 version
ACCESSORY_SEND_STRING = 52     # 0x34, host-to-device, wIndex = string id
ACCESSORY_START = 53           # 0x35, host-to-device, no data
ACCESSORY_REGISTER_HID = 54
ACCESSORY_UNREGISTER_HID = 55
ACCESSORY_SET_HID_REPORT_DESC = 56
ACCESSORY_SEND_HID_EVENT = 57
ACCESSORY_AUDIO = 58

AOA_PROTOCOL_VERSION = 2

STRING_IDS = {
    0: "manufacturer", 1: "model", 2: "description",
    3: "version", 4: "uri", 5: "serial",
}

# Exactly what the DJI Goggles 3 sends. `com.dji.logiclink` is the DJI
# accessory/EA protocol name and is also what the DJI Fly app declares in
# accessory_filter.xml on Android and UISupportedExternalAccessoryProtocols
# on iOS.
ACCESSORY_STRINGS = {
    0: "DJI",
    1: "com.dji.logiclink",
    2: "DJI glass",
    3: "v0.0.0.0",
    4: "www.dji.com",
    5: "000000000000000",
}

# Google's AOA vendor id and the accessory product ids (AOA 2.0 spec).
AOA_VID = 0x18D1
AOA_PID_ACCESSORY = 0x2D00        # accessory only
AOA_PID_ACCESSORY_ADB = 0x2D01    # accessory + adb  <-- what handsets present
AOA_PID_AUDIO = 0x2D02
AOA_PID_AUDIO_ADB = 0x2D03
AOA_PID_ACCESSORY_AUDIO = 0x2D04
AOA_PID_ACCESSORY_AUDIO_ADB = 0x2D05

ACCESSORY_EP_IN = 0x81    # gadget -> host  (phone -> goggles: app commands)
ACCESSORY_EP_OUT = 0x01   # host -> gadget  (goggles -> phone: video + telemetry)
ACCESSORY_MPS = 512

# --------------------------------------------------------------------------- #
# USB descriptor builders
# --------------------------------------------------------------------------- #
# The builders live in pryer.usbdesc; the names are re-exported here so that
# everything needed to describe an AOA device can be found in this module.
from .usbdesc import (  # noqa: E402,F401
    CLASS_CDC, CLASS_CDC_DATA, CLASS_VENDOR, CDC_PROTOCOL_AT_V250,
    CDC_SUBCLASS_ACM, DT_CONFIG, DT_DEVICE, DT_DEVICE_QUALIFIER, DT_ENDPOINT,
    DT_INTERFACE, DT_INTERFACE_ASSOCIATION, DT_OTHER_SPEED_CONFIG, DT_STRING,
    XFER_BULK, XFER_INTERRUPT, bulk_pair, cdc_acm, cdc_call_management,
    cdc_header, cdc_union, config_descriptor, device_descriptor,
    device_qualifier, endpoint_descriptor, interface_association,
    interface_descriptor, lang_descriptor, other_speed_config,
    string_descriptor)

USB_CLASS_VENDOR = CLASS_VENDOR


# --------------------------------------------------------------------------- #
# Descriptor set 1: the pre-AOA "phone"
# --------------------------------------------------------------------------- #
# Three identities are available for the phase before accessory mode
# (PROTOCOL.md section 2.1). All of them are assembled from named fields with
# the builders in pryer.usbdesc.
#
# "handset" (the default of phone_descriptors()) is the Samsung handset's own
# identity, byte for byte: the 121-byte composite configuration with CDC-ACM
# (02/02/01), CDC data (0a/00/00), Samsung's ff/10/01 interface and adb
# (ff/42/01), with the string table at the handset's own indices (2, 3, 4 for
# the device strings, 5/6/7 for the interface strings). The indices matter:
# the descriptors point at them, and right after SET_CONFIGURATION the goggles
# reads the first interface's iInterface string (6) before it issues
# GET_PROTOCOL about 1 ms later. The goggles is known to accept this identity.
#
# "minimal" is a single vendor-specific interface (ff/ff/00) with no interface
# strings, in a 32-byte configuration. It is the identity `stream` presents
# (cli.AOA_PHONE_PROFILE). The goggles enumerates and configures it; whether
# it then probes for AOA as it does for the handset identity has not been
# confirmed on hardware (PROTOCOL.md section 13).
#
# "dji" is the 18d1:4ee0 identity used by another open-source client, kept for
# experiments.
#
# Whether the goggles looks at the phase-1 configuration at all before it
# probes for AOA is not known. What is known is that a gadget which does not
# complete the status stage of SET_CONFIGURATION is never probed, whatever it
# presents (see rawgadget, "The ep0 direction rule").
PHONE_VID = 0x04E8
PHONE_PID = 0x685D

# Device descriptor as the handset presents it: bcdUSB 0x0200, class 0/0/0,
# mps0 64, bcdDevice 0x0400, iManufacturer 2, iProduct 3, iSerialNumber 4,
# one configuration.
PHONE_DEVICE_DESC = device_descriptor(PHONE_VID, PHONE_PID, bcd_device=0x0400,
                                      i_manufacturer=2, i_product=3,
                                      i_serial=4)

# Configuration 1 (121 bytes, 4 interfaces, self-powered, 96 mA):
#   IAD        first 0, count 2, 02/02/01, iFunction 8
#   iface 0    02/02/01 CDC comm, iInterface 6, header / call management /
#              ACM / union functional descriptors,
#              EP 0x83 interrupt mps 10 interval 9
#   iface 1    0a/00/00 CDC data,  iInterface 7, EP 0x81 IN + 0x01 OUT bulk 512
#   iface 2    ff/10/01 (Samsung),  iInterface 0, EP 0x84 IN + 0x03 OUT
#   iface 3    ff/42/01 adb,        iInterface 5, EP 0x04 OUT + 0x85 IN
# Endpoint *numbering* is not stable across enumerations of the same handset
# (0x82/0x83/0x84 in one session, 0x83/0x84/0x85 in another), so the exact
# numbers carry no meaning; the interface classes do.
ADB_CLASS = (CLASS_VENDOR, 0x42, 0x01)
SAMSUNG_VENDOR_CLASS = (CLASS_VENDOR, 0x10, 0x01)


def _adb_interface(number: int, ep_out: int, ep_in: int,
                   i_interface: int = 5) -> bytes:
    cls, sub, proto = ADB_CLASS
    return (interface_descriptor(number, 2, cls=cls, subcls=sub, proto=proto,
                                 i_interface=i_interface)
            + bulk_pair(ep_out, ep_in))


def _handset_config() -> bytes:
    cdc_comm = (CLASS_CDC, CDC_SUBCLASS_ACM, CDC_PROTOCOL_AT_V250)
    body = (
        interface_association(0, 2, *cdc_comm, i_function=8)
        # interface 0: CDC ACM control
        + interface_descriptor(0, 1, cls=cdc_comm[0], subcls=cdc_comm[1],
                               proto=cdc_comm[2], i_interface=6)
        + cdc_header(0x0110)
        + cdc_call_management(capabilities=0x00, data_interface=1)
        + cdc_acm(capabilities=0x02)
        + cdc_union(0, 1)
        + endpoint_descriptor(0x83, 10, XFER_INTERRUPT, interval=9)
        # interface 1: CDC data
        + interface_descriptor(1, 2, cls=CLASS_CDC_DATA, subcls=0x00,
                               proto=0x00, i_interface=7)
        + bulk_pair(0x81, 0x01)
        # interface 2: Samsung vendor interface
        + interface_descriptor(2, 2, cls=SAMSUNG_VENDOR_CLASS[0],
                               subcls=SAMSUNG_VENDOR_CLASS[1],
                               proto=SAMSUNG_VENDOR_CLASS[2])
        + bulk_pair(0x84, 0x03)
        # interface 3: adb
        + _adb_interface(3, 0x04, 0x85))
    return config_descriptor(body, 4, value=1, attributes=0xC0,
                             max_power=0x30)


PHONE_CONFIG = _handset_config()

# String table at the handset's own indices. Index 1 is never read by the
# goggles and the real phone does not appear to use it. The serial number is
# the handset's: the goggles reads it but nothing depends on its value.
PHONE_STRING_TABLE = {
    2: "SAMSUNG",
    3: "SAMSUNG_Android",
    4: "424242424242424242",
    5: "ADB Interface",
    6: "CDC Abstract Control Model (ACM)",
    7: "CDC ACM Data",
    # The IAD advertises iFunction 8. The goggles never reads it, so the
    # handset's text for it is unknown; serving the function's own name is
    # the conventional value and, more to the point, means every index the
    # descriptors advertise resolves instead of stalling.
    8: "CDC Abstract Control Model (ACM)",
}
# Kept for callers and tests that want the three device strings in order.
PHONE_STRINGS = [PHONE_STRING_TABLE[2], PHONE_STRING_TABLE[3],
                 PHONE_STRING_TABLE[4]]


# The "minimal" identity: one vendor-specific interface, no interface strings,
# 32-byte configuration, the handset's vendor and product ids.
MINIMAL_PHONE_CONFIG = (
    config_descriptor(interface_descriptor(0, 2, cls=USB_CLASS_VENDOR,
                                          subcls=0xFF, proto=0x00)
                      + endpoint_descriptor(0x81)
                      + endpoint_descriptor(0x01), 1))
MINIMAL_PHONE_STRING_TABLE = {1: "SAMSUNG", 2: "SAMSUNG_Android",
                             3: "424242424242424242"}

# The phase-1 identity used by another open-source Goggles 3 client (see
# PROTOCOL.md section 12): Google's 18d1:4ee0, manufacturer "DJI", product
# "com.dji.logiclink", bus-powered (bmAttributes 0x80) with bMaxPower 250
# (500 mA). Only those fields were taken from it; the interface layout below is
# the single vendor interface of the minimal set, and the serial string is our
# own. It is a test identity, not something a real handset presented.
DJI_PHONE_VID = 0x18D1
DJI_PHONE_PID = 0x4EE0
DJI_PHONE_CONFIG = (
    config_descriptor(interface_descriptor(0, 2, cls=USB_CLASS_VENDOR,
                                          subcls=0xFF, proto=0x00)
                      + endpoint_descriptor(0x81)
                      + endpoint_descriptor(0x01), 1,
                      attributes=0x80, max_power=250))
DJI_PHONE_STRING_TABLE = {1: "DJI", 2: "com.dji.logiclink",
                          3: "0123456789ABCDEF"}

PHONE_PROFILES = ("handset", "dji", "minimal")


def phone_descriptors(profile: str = "handset") -> dict:
    """
    The pre-AOA descriptor set: by default the Samsung handset's identity, as
    built by :data:`PHONE_DEVICE_DESC` / :data:`PHONE_CONFIG` (byte-identical
    to what the handset presents).

    No endpoint in this set is ever used -- the goggles moves no bulk data
    before START_ACCESSORY -- so the gadget does not need to
    enable them (see ``accessory._Session(enable_endpoints=False)``). They are
    advertised because the configuration they belong to is what the goggles
    reads before it decides to probe for AOA at all.

    ``profile="minimal"`` serves a single-interface configuration instead
    (:data:`MINIMAL_PHONE_CONFIG`). It is the one the stream command presents.

    ``profile="dji"`` presents 18d1:4ee0 "DJI" / "com.dji.logiclink" with
    bmAttributes 0x80 and bMaxPower 250, the identity another open-source
    client uses. It is kept for tests and library use; see
    :data:`DJI_PHONE_CONFIG`.
    """
    if profile == "dji":
        return {
            "device": device_descriptor(DJI_PHONE_VID, DJI_PHONE_PID,
                                        bcd_device=0x0400, i_manufacturer=1,
                                        i_product=2, i_serial=3),
            "config": DJI_PHONE_CONFIG,
            "strings": dict(DJI_PHONE_STRING_TABLE),
        }
    if profile == "minimal":
        return {
            "device": device_descriptor(PHONE_VID, PHONE_PID,
                                        bcd_device=0x0400, i_manufacturer=1,
                                        i_product=2, i_serial=3),
            "config": MINIMAL_PHONE_CONFIG,
            "strings": dict(MINIMAL_PHONE_STRING_TABLE),
        }
    if profile != "handset":
        raise ValueError("unknown phone profile %r (choose from %s)"
                         % (profile, ", ".join(PHONE_PROFILES)))
    return {
        "device": PHONE_DEVICE_DESC,
        "config": PHONE_CONFIG,
        "strings": dict(PHONE_STRING_TABLE),
    }


# --------------------------------------------------------------------------- #
# Descriptor set 2: the AOA accessory mode device
# --------------------------------------------------------------------------- #
# The handset's accessory-mode identity, built from fields like the phase-1
# set: 18d1:2d01, bcdDevice 0xffff, iManufacturer 2, iProduct 3,
# iSerialNumber 4; configuration total length 55 with
#   iface 0  ff/ff/00 accessory, iInterface 6, EP 0x81 IN + 0x01 OUT bulk 512
#   iface 1  ff/42/01 adb,       iInterface 5, EP 0x02 OUT + 0x82 IN bulk 512
# The adb interface is advertised for fidelity with the handset; nothing is
# ever read from it. Note the accessory-mode string table keeps the *same*
# manufacturer and product strings as phase 1 (the goggles re-reads both), and
# renames string 6 to "Android Accessory Interface" -- exactly what the real
# handset does.
ACCESSORY_CLASS = (CLASS_VENDOR, 0xFF, 0x00)


def _accessory_interface(i_interface: int = 6) -> bytes:
    cls, sub, proto = ACCESSORY_CLASS
    return (interface_descriptor(0, 2, cls=cls, subcls=sub, proto=proto,
                                 i_interface=i_interface)
            + bulk_pair(ACCESSORY_EP_IN, ACCESSORY_EP_OUT, ACCESSORY_MPS))


def _accessory_device(pid: int) -> bytes:
    return device_descriptor(AOA_VID, pid, bcd_device=0xFFFF,
                             i_manufacturer=2, i_product=3, i_serial=4)


ACCESSORY_DEVICE_DESC = _accessory_device(AOA_PID_ACCESSORY_ADB)
ACCESSORY_CONFIG = config_descriptor(
    _accessory_interface() + _adb_interface(1, 0x02, 0x82), 2,
    attributes=0xC0, max_power=0x30)
ACCESSORY_STRING_TABLE = {
    2: "SAMSUNG",
    3: "SAMSUNG_Android",
    4: "424242424242424242",
    5: "ADB Interface",
    6: "Android Accessory Interface",
}


def accessory_descriptors(*, with_adb: bool = True) -> dict:
    """
    The accessory-mode descriptor set.

    With ``with_adb`` (the default, and what handsets present) this is the
    handset's 18d1:2d01 device (:data:`ACCESSORY_DEVICE_DESC`,
    :data:`ACCESSORY_CONFIG`). ``with_adb=False`` drops the adb
    interface and switches to PID 0x2d00; that combination has never been seen
    on the wire, so it is a debugging knob rather than a supported mode.
    """
    if with_adb:
        return {
            "device": ACCESSORY_DEVICE_DESC,
            "config": ACCESSORY_CONFIG,
            "strings": dict(ACCESSORY_STRING_TABLE),
        }
    return {
        "device": _accessory_device(AOA_PID_ACCESSORY),
        "config": config_descriptor(_accessory_interface(), 1,
                                    max_power=0x30),
        "strings": dict(ACCESSORY_STRING_TABLE),
    }


# --------------------------------------------------------------------------- #
# Descriptor-set self-checks
# --------------------------------------------------------------------------- #
def string_indices_used(descriptors: dict) -> set[int]:
    """
    Every non-zero string index the descriptors in *descriptors* point at.

    Used by the tests, and by ``doctor``, to catch the failure mode that is
    invisible until a host actually walks the descriptors: advertising an
    iInterface or iProduct index that the string table does not serve, so the
    host stalls on a read it made in the middle of deciding what we are.
    """
    used: set[int] = set()
    dev = descriptors["device"]
    used.update(b for b in dev[14:17] if b)
    cfg = descriptors["config"]
    off = 0
    while off + 2 <= len(cfg):
        length, dtype = cfg[off], cfg[off + 1]
        if length < 2:
            break
        if dtype == DT_CONFIG and length > 6 and cfg[off + 6]:
            used.add(cfg[off + 6])
        elif dtype == DT_INTERFACE and length > 8 and cfg[off + 8]:
            used.add(cfg[off + 8])
        elif dtype == 0x0B and length > 7 and cfg[off + 7]:   # IAD iFunction
            used.add(cfg[off + 7])
        off += length
    return used
