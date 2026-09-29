"""
pryer -- DJI Goggles 3 USB protocol library and Linux streaming client.

Reverse-engineered from USB captures of an Android phone and an iPhone
receiving the live H.264 stream from a DJI Goggles 3.

Modules
-------
duml       DUML / SerialTalk frame codec (CRC-8 + CRC-16 verified)
tunnel     the 0x55CC "LogicLink" multiplexer and H.264 helpers
h264       parameter sets and slice headers: make the stream playable
aoa        Android Open Accessory constants and the handset/accessory descriptors
usbdesc    USB descriptor builders: standard, CDC, UAC 1.0, HID
rawgadget  ctypes binding for Linux /dev/raw-gadget
accessory  two-phase AOA handshake, exposes the bulk pipe (Android transport)
mfi        iPhone impersonation, role switch and iAP2 host (iOS transport)
iap2       the iAP2 link layer and control session the goggles speaks
libusb     ctypes binding for libusb-1.0, with queued bulk reads
linkio     link writes on a thread of their own
app        the mobile-app side of the DUML control channel
pipeline   bulk bytes -> H.264 + telemetry
sinks      output targets (stdout, file, fifo, udp, tcp, subprocess)
capture    reader for the capture formats (pcapng or hex dump)
pcapng     wire-level USB 2.0 captures: transactions, transfers, surveys
linkaudit  what a capture says the app side lost
cli        the third-eye command
"""

__version__ = "1.0.0"

from . import aoa, capture, duml, pipeline, sinks, tunnel  # noqa: F401

__all__ = ["aoa", "capture", "duml", "pipeline", "sinks", "tunnel"]
