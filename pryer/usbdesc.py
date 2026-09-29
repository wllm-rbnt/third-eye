"""
USB descriptor builders.

Every descriptor this package serves as a USB device -- the Android handset
and accessory identities in :mod:`pryer.aoa`, the iPhone identity in
:mod:`pryer.mfi` -- is assembled here from named fields, so a reader porting
the protocol to another stack can see what each byte means instead of copying
a hex blob. The tests check that the result is byte-identical to what the real
phones put on the wire.

Field names follow the USB 2.0 specification (chapter 9), the CDC 1.2 PSTN
subclass (ACM), USB Audio Class 1.0 and HID 1.11. Multi-byte fields are
little-endian, as everywhere on USB.
"""

from __future__ import annotations

import struct
from typing import Iterable

# --------------------------------------------------------------------------- #
# Descriptor types (USB 2.0 table 9-5, plus the class-specific ones used here)
# --------------------------------------------------------------------------- #
DT_DEVICE = 0x01
DT_CONFIG = 0x02
DT_STRING = 0x03
DT_INTERFACE = 0x04
DT_ENDPOINT = 0x05
DT_DEVICE_QUALIFIER = 0x06
DT_OTHER_SPEED_CONFIG = 0x07
DT_INTERFACE_ASSOCIATION = 0x0B
DT_HID = 0x21
DT_HID_REPORT = 0x22
DT_CS_INTERFACE = 0x24
DT_CS_ENDPOINT = 0x25

# bmAttributes transfer types
XFER_CONTROL = 0x00
XFER_ISOCHRONOUS = 0x01
XFER_BULK = 0x02
XFER_INTERRUPT = 0x03

# Interface classes that appear in the identities this package presents
CLASS_AUDIO = 0x01
CLASS_CDC = 0x02
CLASS_HID = 0x03
CLASS_STILL_IMAGE = 0x06
CLASS_CDC_DATA = 0x0A
CLASS_VENDOR = 0xFF

# configuration bmAttributes
CONFIG_ATTR_RESERVED = 0x80      # bit 7 must be set
CONFIG_ATTR_SELF_POWERED = 0x40

HIGH_SPEED_BULK_MPS = 512


# --------------------------------------------------------------------------- #
# Standard descriptors
# --------------------------------------------------------------------------- #
def device_descriptor(vid: int, pid: int, *, bcd_usb: int = 0x0200,
                      bcd_device: int = 0x0400, dev_class: int = 0,
                      dev_subclass: int = 0, dev_protocol: int = 0,
                      mps0: int = 64, i_manufacturer: int = 1,
                      i_product: int = 2, i_serial: int = 3,
                      num_configs: int = 1) -> bytes:
    """DEVICE descriptor (18 bytes, USB 2.0 sec. 9.6.1)."""
    return struct.pack("<BBHBBBBHHHBBBB", 18, DT_DEVICE, bcd_usb, dev_class,
                       dev_subclass, dev_protocol, mps0, vid, pid, bcd_device,
                       i_manufacturer, i_product, i_serial, num_configs)


def config_descriptor(body: bytes, num_interfaces: int, *, value: int = 1,
                      i_config: int = 0, attributes: int = 0xC0,
                      max_power: int = 0x30) -> bytes:
    """
    CONFIGURATION descriptor followed by *body* (USB 2.0 sec. 9.6.3).

    wTotalLength is computed. *max_power* is in the descriptor's 2 mA units.
    """
    total = 9 + len(body)
    return struct.pack("<BBHBBBBB", 9, DT_CONFIG, total, num_interfaces,
                       value, i_config, attributes, max_power) + body


def interface_descriptor(number: int, num_eps: int, *, alt: int = 0,
                         cls: int = CLASS_VENDOR, subcls: int = 0xFF,
                         proto: int = 0x00, i_interface: int = 0) -> bytes:
    """INTERFACE descriptor (9 bytes, USB 2.0 sec. 9.6.5)."""
    return struct.pack("<BBBBBBBBB", 9, DT_INTERFACE, number, alt, num_eps,
                       cls, subcls, proto, i_interface)


def endpoint_descriptor(address: int, mps: int = HIGH_SPEED_BULK_MPS,
                        attributes: int = XFER_BULK,
                        interval: int = 0) -> bytes:
    """ENDPOINT descriptor (7 bytes, USB 2.0 sec. 9.6.6)."""
    return struct.pack("<BBBBHB", 7, DT_ENDPOINT, address, attributes,
                       mps, interval)


def bulk_pair(ep_first: int, ep_second: int,
              mps: int = HIGH_SPEED_BULK_MPS) -> bytes:
    """Two bulk endpoints, in the order given (the order is on the wire)."""
    return endpoint_descriptor(ep_first, mps) + endpoint_descriptor(ep_second,
                                                                    mps)


def interface_association(first_interface: int, count: int, cls: int,
                          subcls: int, proto: int, i_function: int = 0
                          ) -> bytes:
    """INTERFACE ASSOCIATION descriptor (8 bytes, USB 2.0 ECN / IAD)."""
    return struct.pack("<BBBBBBBB", 8, DT_INTERFACE_ASSOCIATION,
                       first_interface, count, cls, subcls, proto, i_function)


def string_descriptor(text: str) -> bytes:
    """STRING descriptor: UTF-16LE text, no terminator."""
    body = text.encode("utf-16-le")
    return bytes((len(body) + 2, DT_STRING)) + body


def lang_descriptor(langid: int = 0x0409) -> bytes:
    """String descriptor 0: the supported LANGID table (one entry)."""
    return struct.pack("<BBH", 4, DT_STRING, langid)


def device_qualifier(device: bytes) -> bytes:
    """
    The DEVICE_QUALIFIER that matches a given device descriptor.

    A USB 2.0 device that reports ``bcdUSB >= 0x0200`` is required to answer
    GET_DESCRIPTOR(DEVICE_QUALIFIER); it describes how the device would look at
    its *other* speed. The fields are copied from the device descriptor, per
    USB 2.0 sec. 9.6.2, with bNumConfigurations preserved and a reserved zero
    byte at the end.
    """
    (_len, _type, bcd_usb, dev_class, dev_subclass, dev_protocol, mps0) = \
        struct.unpack("<BBHBBBB", device[:8])
    num_configs = device[17]
    return struct.pack("<BBHBBBBBB", 10, DT_DEVICE_QUALIFIER, bcd_usb,
                       dev_class, dev_subclass, dev_protocol, mps0,
                       num_configs, 0)


def other_speed_config(config: bytes) -> bytes:
    """
    The OTHER_SPEED_CONFIGURATION view of *config*: the same layout with
    bDescriptorType 7 (USB 2.0 sec. 9.6.4).
    """
    return bytes((config[0], DT_OTHER_SPEED_CONFIG)) + config[2:]


# --------------------------------------------------------------------------- #
# CDC (Communications Device Class 1.2, PSTN subclass 1.2)
# --------------------------------------------------------------------------- #
CDC_SUBCLASS_ACM = 0x02
CDC_PROTOCOL_AT_V250 = 0x01

CDC_HEADER = 0x00
CDC_CALL_MANAGEMENT = 0x01
CDC_ACM = 0x02
CDC_UNION = 0x06


def cdc_header(bcd_cdc: int = 0x0110) -> bytes:
    """Header functional descriptor (CDC 1.2 sec. 5.2.3.1)."""
    return struct.pack("<BBBH", 5, DT_CS_INTERFACE, CDC_HEADER, bcd_cdc)


def cdc_call_management(capabilities: int, data_interface: int) -> bytes:
    """Call Management functional descriptor (PSTN 1.2 sec. 5.3.1)."""
    return struct.pack("<BBBBB", 5, DT_CS_INTERFACE, CDC_CALL_MANAGEMENT,
                       capabilities, data_interface)


def cdc_acm(capabilities: int) -> bytes:
    """Abstract Control Management functional descriptor (PSTN sec. 5.3.2).

    Bit 1 (0x02) = the device supports Set_Line_Coding / Get_Line_Coding /
    Set_Control_Line_State / Serial_State.
    """
    return struct.pack("<BBBB", 4, DT_CS_INTERFACE, CDC_ACM, capabilities)


def cdc_union(control_interface: int, *subordinates: int) -> bytes:
    """Union functional descriptor (CDC 1.2 sec. 5.2.3.2)."""
    return (struct.pack("<BBBB", 3 + 1 + len(subordinates), DT_CS_INTERFACE,
                        CDC_UNION, control_interface) + bytes(subordinates))


# --------------------------------------------------------------------------- #
# USB Audio Class 1.0
# --------------------------------------------------------------------------- #
AUDIO_SUBCLASS_CONTROL = 0x01
AUDIO_SUBCLASS_STREAMING = 0x02

UAC_HEADER = 0x01
UAC_INPUT_TERMINAL = 0x02
UAC_OUTPUT_TERMINAL = 0x03
UAC_AS_GENERAL = 0x01
UAC_FORMAT_TYPE = 0x02
UAC_EP_GENERAL = 0x01

UAC_TERMINAL_USB_STREAMING = 0x0101
UAC_TERMINAL_MICROPHONE = 0x0201
UAC_FORMAT_PCM = 0x0001
UAC_FORMAT_TYPE_I = 0x01


def uac_header(interfaces: Iterable[int], total_length: int,
               bcd_adc: int = 0x0100) -> bytes:
    """Class-specific AC interface header (UAC 1.0 sec. 4.3.2).

    *total_length* is wTotalLength: this header plus the unit and terminal
    descriptors that follow it.
    """
    nums = bytes(interfaces)
    return (struct.pack("<BBBHHB", 8 + len(nums), DT_CS_INTERFACE, UAC_HEADER,
                        bcd_adc, total_length, len(nums)) + nums)


def uac_input_terminal(terminal_id: int, terminal_type: int, *,
                       assoc_terminal: int = 0, channels: int = 2,
                       channel_config: int = 0x0003, i_channel_names: int = 0,
                       i_terminal: int = 0) -> bytes:
    """Input Terminal descriptor (UAC 1.0 sec. 4.3.2.1)."""
    return struct.pack("<BBBBHBBHBB", 12, DT_CS_INTERFACE, UAC_INPUT_TERMINAL,
                       terminal_id, terminal_type, assoc_terminal, channels,
                       channel_config, i_channel_names, i_terminal)


def uac_output_terminal(terminal_id: int, terminal_type: int, *,
                        assoc_terminal: int = 0, source_id: int = 0,
                        i_terminal: int = 0) -> bytes:
    """Output Terminal descriptor (UAC 1.0 sec. 4.3.2.2)."""
    return struct.pack("<BBBBHBBB", 9, DT_CS_INTERFACE, UAC_OUTPUT_TERMINAL,
                       terminal_id, terminal_type, assoc_terminal, source_id,
                       i_terminal)


def uac_as_general(terminal_link: int, delay: int = 1,
                   format_tag: int = UAC_FORMAT_PCM) -> bytes:
    """Class-specific AS interface descriptor (UAC 1.0 sec. 4.5.2)."""
    return struct.pack("<BBBBBH", 7, DT_CS_INTERFACE, UAC_AS_GENERAL,
                       terminal_link, delay, format_tag)


def uac_format_type_i(channels: int, subframe_size: int, bit_resolution: int,
                      sample_rates: Iterable[int]) -> bytes:
    """Type I format descriptor with discrete sample rates (UAC Formats 2.2.5).

    Each rate is a 24-bit little-endian value in Hz.
    """
    rates = list(sample_rates)
    body = b"".join(r.to_bytes(3, "little") for r in rates)
    return (struct.pack("<BBBBBBBB", 8 + len(body), DT_CS_INTERFACE,
                        UAC_FORMAT_TYPE, UAC_FORMAT_TYPE_I, channels,
                        subframe_size, bit_resolution, len(rates)) + body)


def uac_endpoint(address: int, mps: int, attributes: int = XFER_ISOCHRONOUS,
                 interval: int = 4, refresh: int = 0,
                 synch_address: int = 0) -> bytes:
    """Standard AS isochronous endpoint (9 bytes, UAC 1.0 sec. 4.6.1.1)."""
    return struct.pack("<BBBBHBBB", 9, DT_ENDPOINT, address, attributes, mps,
                       interval, refresh, synch_address)


def uac_cs_endpoint(attributes: int = 0x01, lock_delay_units: int = 0,
                    lock_delay: int = 0) -> bytes:
    """Class-specific AS isochronous endpoint (UAC 1.0 sec. 4.6.1.2).

    bmAttributes bit 0 = the endpoint supports the sampling-frequency control.
    """
    return struct.pack("<BBBBBH", 7, DT_CS_ENDPOINT, UAC_EP_GENERAL,
                       attributes, lock_delay_units, lock_delay)


# --------------------------------------------------------------------------- #
# HID 1.11
# --------------------------------------------------------------------------- #
def hid_descriptor(report_length: int, *, bcd_hid: int = 0x0111,
                   country_code: int = 0) -> bytes:
    """HID descriptor naming one report descriptor (HID 1.11 sec. 6.2.1)."""
    return struct.pack("<BBHBBBH", 9, DT_HID, bcd_hid, country_code, 1,
                       DT_HID_REPORT, report_length)


# --------------------------------------------------------------------------- #
# Walking descriptors (for tests, diagnostics and doctor)
# --------------------------------------------------------------------------- #
def split(blob: bytes) -> list[bytes]:
    """Split a concatenated descriptor blob into its descriptors."""
    out, off = [], 0
    while off + 2 <= len(blob):
        length = blob[off]
        if length < 2:
            break
        out.append(blob[off:off + length])
        off += length
    return out
