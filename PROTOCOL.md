# DJI Goggles 3 — USB video streaming protocol

Reverse-engineered from USB captures of an Android phone and an iPhone
receiving the stream, recorded with a hardware bus sniffer, and from captures
of this implementation running on a Raspberry Pi 4 Model B.

This document describes the protocol as it is understood today: what goes on
the wire, in which order, and what a client has to do to receive the video. It
also records the Linux-specific behaviour an implementation has to get right,
and says plainly where something is observed but not understood.

The reference implementation is the `pryer` package in this repository. Next to
each structure the document names the code that builds or parses it. Nothing
the package sends is a stored copy of captured traffic: every descriptor, DUML
payload, iAP2 message and H.264 parameter set is assembled from named fields,
and the test suite checks the result byte for byte against what real devices
send. Where a field's meaning is unknown it is given a neutral name and the
value every observed session uses (section 13 lists them).

## Contents

1. [Overview](#1-overview)
2. [Android transport: Open Accessory](#2-android-transport-open-accessory)
3. [iOS transport: role swap and iAP2](#3-ios-transport-role-swap-and-iap2)
4. [The LogicLink tunnel](#4-the-logiclink-tunnel)
5. [Video on channel 0x4A](#5-video-on-channel-0x4a)
6. [Control on channel 0x49: DUML](#6-control-on-channel-0x49-duml)
7. [Starting the stream: app registration](#7-starting-the-stream-app-registration)
8. [Linux, gadget side](#8-linux-gadget-side)
9. [Linux, host side](#9-linux-host-side)
10. [Making the stream playable](#10-making-the-stream-playable)
11. [Analysing bus captures](#11-analysing-bus-captures)
12. [Related work](#12-related-work)
13. [Open questions](#13-open-questions)

---

## 1. Overview

### 1.1 The goggles is the USB host

The USB-C port of the DJI Goggles 3 is a **host** port. When a phone is
connected, the goggles issues `GET_DESCRIPTOR` and `SET_ADDRESS`, and the phone
answers as a USB device:

```
SETUP GET_DESCRIPTOR[DEVICE]  bmRequestType=0x80 wValue=0x0100 wLength=64
DATA  12 01 00 02 00 00 00 40 e8 04 5d 68 00 04 02 03 04 01
                              ^^^^^ ^^^^^
                              04e8  685d   (a Samsung handset)
SETUP SET_ADDRESS             wValue=0x0001
```

An iPhone is enumerated the same way, as `05ac:12a8`.

A Linux PC is also a host, so it cannot simply be plugged in and read the
stream. The Linux side has to be a USB **device** (a *gadget*), which needs a
USB Device Controller (UDC). The reference board is a Raspberry Pi 4 Model B,
whose USB-C socket is wired to the SoC's `dwc2` dual-role controller.

The port is USB 2.0 high speed (480 Mbit/s). DJI documents that an OTG cable is
required ([DJI Goggles 3 user manual](https://dl.djicdn.com/downloads/DJI_Goggles_3/20240528/DJI_Goggles_3_User_Manual_EN.pdf)).

### 1.2 Two transports, one payload

The goggles supports both phone ecosystems and picks the transport from what it
sees during enumeration:

| phone | transport | USB host afterwards | section |
|---|---|---|---|
| Android | Android Open Accessory (AOA) 2.0 | the goggles | 2 |
| iPhone | Apple role swap, then iAP2 | the phone | 3 |

After the transport is up, both carry the **identical** byte stream: the DJI
"LogicLink" tunnel of section 4.

### 1.3 Layering

```
+--------------------------------------+------------------------------+
| H.264 Annex-B elementary stream (5)  | DUML control frames (6)      |
+---------------------------------------------------------------------+
| LogicLink tunnel "55 CC": channel 0x4A video, 0x49 control (4)      |
+--------------------------------------+------------------------------+
| Android: AOA accessory bulk pair (2) | iOS: interface 1 alt 1       |
|   the goggles is USB host            |   bulk pair, after the role  |
|                                      |   swap and iAP2 (3)          |
+--------------------------------------+------------------------------+
| USB 2.0 high speed over USB-C                                       |
+---------------------------------------------------------------------+
```

The video does not start by itself: the client has to register with the
goggles over DUML first (section 7).

### 1.4 Conventions

* "Goggles → app" and "app → goggles" name the direction of the data, whichever
  side is USB host. USB direction labels (`IN`, `OUT`) are relative to the host,
  so the same goggles traffic is `OUT` on Android and `IN` on iOS.
* Multi-byte fields are little-endian except in iAP2 (section 3.6), which is
  big-endian.
* Hex dumps are what the real devices put on the wire.
* Times written as `+N ms` are relative to the event named in the same table.

### 1.5 What a minimal client does

**Android transport** (the Linux side is a gadget throughout):

1. Present an Android phone identity and complete enumeration (2.1).
2. Answer AOA `GET_PROTOCOL` with version 2, accept the six identity strings
   and `START_ACCESSORY` (2.2).
3. Detach, re-attach as `18d1:2d01`, wait for `SET_CONFIGURATION` (2.3).
4. Read the tunnel from bulk OUT endpoint `0x01`, write to bulk IN `0x81`.
5. Register with the goggles (7), answer the DUML requests that ask for a reply
   (6.5), and demultiplex the video (4, 5).

**iOS transport** (gadget first, then host):

1. Present the iPhone identity as a gadget until the goggles sends Apple
   request `0x51` (3.3).
2. Release the bus, switch the port to host mode (3.4, 9.1).
3. Enumerate the goggles as `2ca3:1002`, run iAP2 on interface 0 as the Apple
   device (3.6 to 3.10).
4. `SET_INTERFACE(1, 1)`, then read the tunnel from bulk IN `0x82` and write to
   bulk OUT `0x02` (3.5, 9.3).
5. Register, answer requests and demultiplex exactly as on Android.

### 1.6 Verification status

* Every structure below is checked offline, byte for byte, against the
  captures of real handsets by the test suite.
* **Android transport on a Pi 4B:** video received, with the handset identity
  in phase 1 (2.1) and the registration of section 7. The implementation's
  default phase-1 identity (the single-interface "minimal" set) and its
  choice of sending none of the app start-up requests (6.4) are validated
  offline only.
* **iOS transport on a Pi 4B:** every step observed on the wire, up to and
  including a complete, decodable video stream: iPhone impersonation, role
  swap, host switch, enumeration of the goggles, iAP2, the tunnel,
  registration. Reading the tunnel with queued single-URB transfers (9.3), and
  sending no app start-up requests, are validated offline only.

---

## 2. Android transport: Open Accessory

Implementation: `pryer/aoa.py` (constants and descriptor sets),
`pryer/accessory.py` (the two gadget sessions), `pryer/usbdesc.py`
(descriptor builders).

### 2.1 Phase 1: the phone identity

The goggles enumerates the phone as an ordinary USB device:

1. reads the device descriptor, sets the address, reads the configuration
   descriptor (9 bytes, then the full length);
2. reads the LANGID table and the manufacturer, product and serial strings;
3. sends `SET_CONFIGURATION 1`;
4. reads the `iInterface` string of the first interface, and about 1 ms later
   sends AOA `GET_PROTOCOL` (2.2).

A real Samsung handset presents `04e8:685d`, `bcdDevice 0x0400`, strings
2 `"SAMSUNG"`, 3 `"SAMSUNG_Android"`, 4 `"424242424242424242"`, and a 121-byte
composite configuration with four interfaces:

```
config  09 02 79 00 04 01 00 c0 30       121 bytes, 4 interfaces, self-powered
  iad   08 0b 00 02 02 02 01 08          interface association, iFunction 8
  if0   09 04 00 00 01 02 02 01 06       02/02/01 CDC ACM, iInterface 6
    cs  05 24 00 10 01 / 05 24 01 00 01 / 04 24 02 02 / 05 24 06 00 01
    ep  07 05 83 03 0a 00 09             0x83 IN interrupt, mps 10
  if1   09 04 01 00 02 0a 00 00 07       0a/00/00 CDC data, iInterface 7
    ep  07 05 81 02 00 02 00             0x81 IN  bulk 512
    ep  07 05 01 02 00 02 00             0x01 OUT bulk 512
  if2   09 04 02 00 02 ff 10 01 00       ff/10/01 Samsung vendor interface
    ep  07 05 84 02 00 02 00 / 07 05 03 02 00 02 00
  if3   09 04 03 00 02 ff 42 01 05       ff/42/01 adb, iInterface 5
    ep  07 05 04 02 00 02 00 / 07 05 85 02 00 02 00
```

String 6 is `"CDC Abstract Control Model (ACM)"`. Endpoint *numbers* are not
stable between sessions of the same handset (`0x82/0x83/0x84` in one,
`0x83/0x84/0x85` in another), so nothing should key on them; the interface
classes are the same, and `ff/42/01` is the standard adb signature.

The goggles moves no bulk data in phase 1, so a gadget can advertise endpoints
and never enable them.

`pryer.aoa.phone_descriptors(profile)` provides three phase-1 identities:

| profile | identity | status |
|---|---|---|
| `handset` | the Samsung handset above, byte for byte, string table at the handset's indices | **accepted** by the goggles on hardware: `GET_PROTOCOL` follows `SET_CONFIGURATION` |
| `minimal` | `04e8:685d`, one vendor interface `ff/ff/00` with a bulk pair `0x81`/`0x01`, no interface strings, 32-byte configuration, strings at indices 1/2/3 | what `stream` presents (`cli.AOA_PHONE_PROFILE`). The goggles enumerates it and sends `SET_CONFIGURATION`; whether it then probes for AOA is **not confirmed** on hardware |
| `dji` | `18d1:4ee0`, strings `"DJI"` / `"com.dji.logiclink"`, bus-powered, `bMaxPower 250`, the minimal interface layout | the identity another client uses (section 12); **not tried** here |

Whether the goggles inspects the phase-1 configuration at all before it probes
for AOA is not known (section 13). What is known is that a gadget which never
completes the status stage of `SET_CONFIGURATION` is never probed, whatever it
presents (section 8.2).

### 2.2 The AOA handshake

After `SET_CONFIGURATION` the goggles sends the standard
[AOA 2.0](https://source.android.com/docs/core/interaction/accessories/aoa2)
vendor requests:

| request | `bmRequestType` | `bRequest` | `wValue` | `wIndex` | data | answer |
|---|---|---|---|---|---|---|
| `ACCESSORY_GET_PROTOCOL` | `0xC0` | 51 | 0 | 0 | 2 bytes IN | `02 00` (version 2) |
| `ACCESSORY_SEND_STRING` ×6 | `0x40` | 52 | 0 | string id | NUL-terminated string OUT | status |
| `ACCESSORY_START` | `0x40` | 53 | 0 | 0 | none | status |

The six strings are always the same:

| id | meaning | value |
|---|---|---|
| 0 | manufacturer | `DJI` |
| 1 | model | `com.dji.logiclink` |
| 2 | description | `DJI glass` |
| 3 | version | `v0.0.0.0` |
| 4 | URI | `www.dji.com` |
| 5 | serial | `000000000000000` |

`com.dji.logiclink` is DJI's accessory identifier: it is the string DJI's
mobile SDK registers in
[`accessory_filter.xml`](https://github.com/dji-sdk/Mobile-UXSDK-Android/blob/master/sample/app/src/main/res/xml/accessory_filter.xml)
on Android and in `UISupportedExternalAccessoryProtocols` on iOS, and the
External Accessory protocol name on the iOS transport (3.9).

The goggles never requests the AOA audio modes or HID functions.

### 2.3 Accessory mode

On `START_ACCESSORY` the phone drops off the bus and comes back as
**`18d1:2d01`**: Google's AOA vendor id with the "accessory + adb" product id.
The handset's accessory-mode descriptors (built in `aoa.ACCESSORY_DEVICE_DESC`,
`aoa.ACCESSORY_CONFIG`):

```
device  12 01 00 02 00 00 00 40 d1 18 01 2d ff ff 02 03 04 01
config  09 02 37 00 02 01 00 c0 30       55 bytes, 2 interfaces
  if0   09 04 00 00 02 ff ff 00 06       ff/ff/00 accessory, iInterface 6
    ep  07 05 81 02 00 02 00             0x81 IN  bulk 512
    ep  07 05 01 02 00 02 00             0x01 OUT bulk 512
  if1   09 04 01 00 02 ff 42 01 05       ff/42/01 adb, iInterface 5
    ep  07 05 02 02 00 02 00
    ep  07 05 82 02 00 02 00
```

`bcdDevice` is `0xffff`. The device strings are at indices 2/3/4 and the
goggles re-reads the manufacturer and product strings in accessory mode, so the
string table must answer at those indices. The interface strings are 6
`"Android Accessory Interface"` and 5 `"ADB Interface"`.

Interface 0 carries the tunnel. Because the goggles is the host:

* **EP `0x01` (bulk OUT) = goggles → app**: video and telemetry;
* **EP `0x81` (bulk IN) = app → goggles**: the app's DUML traffic.

The adb interface is never used. The accessory-only product id `18d1:2d00`
(no adb interface, `--no-adb`) is untested on the goggles.

### 2.4 Timing

Measured on real handsets:

| event | time |
|---|---|
| `START_ACCESSORY` | 0 |
| goggles reads string 7, then string 5, of the phase-1 identity | ~2 ms, up to 14 ms |
| phone detaches, re-enumerates as `18d1:2d01`, `SET_CONFIGURATION` | 0.243–0.924 s (about 0.5 s typical) |
| first tunnel byte | about 1.2 s |

The goggles resets the bus 3–4 times while bringing the link up, and every
enumerating session contains exactly two `SET_ADDRESS` sequences, one per
identity. A gadget must treat each reset as normal (section 8.3).

The implementation waits 150 ms after `START_ACCESSORY` so the goggles' last
string reads are answered, then leaves the bus, releases the UDC (section 8.4),
stays off the bus for 300 ms and attaches as `18d1:2d01`.

### 2.5 An idle accessory link

A completed handshake is not a working stream. If the app side never opens the
accessory, the goggles polls the accessory endpoints continuously (PING and IN
tokens, hundreds of thousands of them) and is NAKed every time; no bulk
endpoint ever carries data. An implementation should tell "no accessory" from
"accessory attached, endpoints idle": the second is a wait, not an error.
`decode` recognises a capture like this and says so (section 11.4).

---

## 3. iOS transport: role swap and iAP2

Implementation: `pryer/mfi.py` (iPhone impersonation, role switching, the
libusb host driver `IapHost`), `pryer/iap2.py` (link layer, messages, the
Apple-device state machine), `pryer/libusb.py` (ctypes binding for libusb-1.0).

### 3.1 How it works

With an iPhone the goggles **hands the USB host role to the phone** and becomes
a plain USB device. After that, the Linux side is an ordinary libusb host.

The first phase still needs a gadget: something has to look enough like an
iPhone for the goggles to issue the role swap. So this transport needs one port
that can be **both** device and host, such as the Pi 4B's USB-C port with
`dtoverlay=dwc2,dr_mode=otg`.

On this link the goggles is the MFi *accessory* and holds Apple's
authentication coprocessor; the phone is the Apple *device* and only verifies
(section 3.8). No MFi chip or licence is needed on the Linux side.

### 3.2 The goggles' two device identities

| id | when | configuration |
|---|---|---|
| `2ca3:0020` | plugged into a generic USB host (a PC) | 8 interfaces, "PC mode" |
| `2ca3:1002` | only after it has enumerated an Apple device and sent request `0x51` | 2 interfaces, configuration string `"MFI"` |

The MFi identity cannot be reached by plugging the goggles into a laptop.
Reports of a PC-mode `ff/43/01` interface with endpoints `0x04`/`0x85`
([example](https://www.volcengine.com/article/10775)) describe the other
identity.

### 3.3 Phase 1: the iPhone identity

The goggles enumerates the phone:

1. reads the 18-byte device descriptor, which must say `05ac:12a8`;
2. reads **all four** configuration descriptors (39, 149, 62 and 117 bytes);
3. sends `SET_CONFIGURATION 1`, the PTP configuration;
4. reads the LANGID table and strings 1 `"Apple Inc."`, 2 `"iPhone"`,
   3 the serial number, then configuration 1's own strings: its
   `iConfiguration` (5) and its PTP interface's `iInterface`;
5. sends **`bmRequestType 0x40, bRequest 0x51, wValue 0, wIndex 0, wLength 0`**:
   the Apple vendor request that asks the device to take over as host.

The iPhone's device descriptor is

```
12 01 00 02 00 00 00 40 ac 05 a8 12 04 14 01 02 03 04
```

(`bcdUSB 0x0200`, `bcdDevice 0x1404`). Its four configurations, all
self-powered at 500 mA with `iConfiguration` 5 to 8:

| value | size | contents |
|---|---|---|
| 1 | 39 B | PTP `06/01/01`: bulk OUT `0x02`, bulk IN `0x81`, interrupt IN `0x83` |
| 2 | 149 B | USB Audio 1.0 (2-channel 16-bit input terminal, nine rates from 8 to 48 kHz, isochronous IN `0x81`) plus HID (interrupt IN `0x83`, a 208-byte report descriptor the goggles never reads) |
| 3 | 62 B | PTP plus a vendor bulk pair `ff/fe/02` |
| 4 | 117 B | configuration 3 plus `ff/fd/01` with three alternate settings |

The structure is identical across iOS versions, but the **string indices are
not**: the PTP interface's `iInterface` is 27 (`0x1b`) on some iOS builds and
15 on others, and a real iPhone answers both configuration strings with
`"PTP"`. An emulator may hard-code the structure, but its string indices must
agree with the string table it serves.

`pryer/mfi.py` builds the four configurations field by field
(`IPHONE_DEVICE_DESC`, `IPHONE_CONFIGS`) with index 27 and uses a synthetic
serial number. It stalls strings 5 and 27 (`IPHONE_STALLED_STRINGS`). The
goggles retries each stalled string (six attempts, `wLength` 255 then 2) and
sends `0x51` anyway, so the configuration strings are not needed.

Request `0x51` has no data stage. Its status stage must be acknowledged (a
real iPhone does it 54 µs after the SETUP; a raw-gadget implementation needs a
zero-length `EP0_READ`, section 8.2).

### 3.4 The handover

Measured from the `0x51` SETUP, with a real iPhone as the new host:

| event | time |
|---|---|
| iPhone ACKs the status stage | +0.05 ms |
| goggles sends its last SOF as host | +37–40 ms |
| bus reset (SE0) as the goggles lets go | +40–50 ms |
| iPhone drops its pull-up | +75 ms |
| **goggles attaches as a full-speed device** (D+ pull-up, J state) | **+205–218 ms** |
| iPhone, now host, resets it (high-speed handshake) | about +370 ms |
| `SET_ADDRESS` from the new host | about +380 ms |

The goggles behaves the same whoever is on the other end. It waits for a host
for **at least 12 s**; the upper bound is unknown. It does not need a fast
host: a Pi 4B that switches to host mode by rebinding `dwc2` (section 9.1)
resets it at about +390 ms and sends `SET_ADDRESS` at about +690 ms (Linux reads
the device descriptor at address 0 and resets a second time first), and the
goggles enumerates normally.

The phone side must release the bus before the goggles attaches, or two
pull-ups collide. The implementation releases it 50 ms after acknowledging
`0x51` (`mfi.POST_SWAP_DELAY`), inside the iPhone's 75 ms.

VBUS stays driven by the goggles throughout.

### 3.5 The goggles as a USB device: `2ca3:1002`

Strings: 1 `"Dajiang Innovation"`, 2 `"DJI_GOGGLES"`, 3 the goggles' serial
number, 4 `"MFI"`, 5 `"iAP Interface"`, 6 `"com.dji.logiclink"`. The device also
has a BOS descriptor.

The configuration descriptor is 64 bytes, with two interfaces:

```
cfg      09 02 40 00 02 01 04 80 01   iConfiguration 4 "MFI", bus-powered, 2 mA
if0 alt0 09 04 00 00 02 ff f0 00 05   ff/f0/00, iInterface 5 "iAP Interface"
  ep     0x81 IN bulk 512 / 0x01 OUT bulk 512      <- iAP2 link
if1 alt0 09 04 01 00 00 ff f0 01 06   ff/f0/01, no endpoints, iInterface 6
if1 alt1 09 04 01 01 02 ff f0 01 06   ff/f0/01, iInterface 6 "com.dji.logiclink"
  ep     0x82 IN bulk 512 / 0x02 OUT bulk 512      <- the tunnel
```

Interface 1 alternate setting 0 has **no endpoints**, so claiming the interface
is not enough. The host sends `SET_INTERFACE` (`bmRequestType 0x01`,
`wValue 1`, `wIndex 1`) and only then does the tunnel flow. That control
transfer is the "open the pipe" step of the iOS transport. Releasing the
interface sends `SET_INTERFACE(1, 0)`.

Endpoint roles, with the phone as host:

* **EP `0x82` (bulk IN) = goggles → app**, EP `0x02` (bulk OUT) = app →
  goggles: the tunnel (section 4);
* EP `0x81` / `0x01`: the iAP2 link, which carries exactly 1,240 bytes and is
  finished before the tunnel opens.

### 3.6 The iAP2 link layer

Both sides first send the link-detect preamble `ff 55 02 00 ee 10`. Then every
packet on interface 0 is:

```
offset 0  1   2-3      4        5    6    7        8            9 ...
       ff 5a  length   control  seq  ack  session  header cksum payload  payload cksum
```

* `length` (u16) counts the **whole** packet, both checksums included. A packet
  without payload is 9 bytes and has no payload checksum.
* `checksum(b) = (-sum(b)) & 0xFF`, over bytes 0–7 for the header checksum and
  over the payload for the payload checksum.
* Every multi-byte field is **big-endian**, the opposite of DUML.
* `control` bits: `0x80` SYN, `0x40` ACK, `0x20` EAK, `0x10` RST, `0x08` SLP.

Sequence numbers (`pryer.iap2.DeviceSession`):

* each direction has its own 8-bit sequence space with an arbitrary start. The
  goggles starts at `0x00`; an iPhone starts anywhere (`0xac`, `0x04`, `0xd0`
  and `0x54` have been seen). **Take the peer's first value from its SYN**;
* `seq` advances only on a packet that carries a payload; a bare ACK repeats
  the current value;
* `ack` is cumulative: the peer's highest received `seq`;
* one control message per packet, as the iPhone does.

The SYN payload holds the link parameters. The goggles':

```
01 05 04 00 07 d0 00 14 1e 05  0a 00 01
|  |  |___| |___| |___| |  |   |  |  |__ session version 1
|  |  |     |     |     |  |   |  |_____ session type 0 (control)
|  |  |     |     |     |  |   |________ session id 0x0a
|  |  |     |     |     |  |____________ max cumulative ACKs 5
|  |  |     |     |     |_______________ max retransmissions 30
|  |  |     |     |_____________________ cumulative-ACK timeout 20 ms
|  |  |     |___________________________ retransmission timeout 2000 ms
|  |  |_________________________________ max received packet length 1024
|  |____________________________________ max outstanding packets 5
|_______________________________________ link version 1
```

The iPhone's SYN|ACK echoes the session table and advertises its own limits
(`0x7f` outstanding packets, `0xffff` bytes). `iap2.LinkParams` encodes and
decodes this.

The handshake can pause for half a second with nothing sent by either side, so
an implementation must not time out an idle iAP2 link aggressively.

### 3.7 The control session

Session `0x0a` carries control messages:

```
40 40 | length u16 | message id u16 | parameters
```

Each parameter is `length u16 (header included) | id u16 | value`, and
parameters nest (identification uses three levels).

The goggles, as the accessory, sends the requests; the phone answers:

| id | message | from | notes |
|---|---|---|---|
| `0xAA00` | RequestAuthenticationCertificate | phone | |
| `0xAA01` | AuthenticationCertificate | goggles | 607-byte Apple PKCS#7 certificate |
| `0xAA02` | RequestAuthenticationChallengeResponse | phone | 32-byte challenge |
| `0xAA03` | AuthenticationResponse | goggles | 64-byte signature |
| `0xAA05` | AuthenticationSucceeded | phone | (`0xAA04` AuthenticationFailed otherwise) |
| `0x1D00` | StartIdentification | phone | |
| `0x1D01` | IdentificationInformation | goggles | section 3.9 |
| `0x1D02` | IdentificationAccepted | phone | |
| `0xAE00` | StartPowerUpdates | goggles | parameters 0, 1 and 6, empty |
| `0xAE01` | PowerUpdate | phone | parameter 6: the phone's battery charge, u16, e.g. `00 5a` = 90 % |

With an iPhone the whole exchange on EP `0x01`/`0x81`, preambles included, is
12 packets / 1,073 bytes from the goggles and 8 packets / 167 bytes from the
phone, 1,240 bytes in total. It is identical from session to session except
for:

| varies | why |
|---|---|
| the challenge | 32 fresh random bytes per session |
| the signature | computed over that challenge |
| `PowerUpdate` parameter 6 | the phone's own battery level |
| the phone's first `seq` | arbitrary (3.6) |

Everything else is byte-identical, so the phone side can be built from fixed
values with no session state beyond the challenge. Nothing observed reacts to
the battery level.

### 3.8 Authentication is one-way

MFi authentication proves the **accessory** to the device. The goggles is the
accessory, so the Linux side, playing the Apple device:

* sends 32 random bytes as the challenge;
* receives a certificate and a signature, which it is free to accept.

`iap2.DeviceSession` accepts by default (`verify_auth=False`) and answers
`AuthenticationSucceeded`. Real verification would need Apple's root
certificate and the signature scheme; a `verifier` hook is provided, and with
`verify_auth=True` a rejecting verifier makes the session send
`AuthenticationFailed`. The goggles never asks the phone to authenticate.

### 3.9 The tunnel is not an iAP2 session

The goggles' `IdentificationInformation`:

```
AccessoryName                   DJI_GOGGLES
ModelIdentifier                 GLS_MODEL
Manufacturer                    Dajiang Innovation
SerialNumber                    (the goggles' serial)
FirmwareVersion / Hardware      00.00.00.00 / v1.0.0.0
MessagesSentByAccessory         0xAE00 StartPowerUpdates, 0xAE02 StopPowerUpdates
MessagesReceivedFromDevice      0xAE01 PowerUpdate
PowerSourceType                 0
MaximumCurrentDrawnFromDevice   0
CurrentLanguage / Supported     en / zh en ja fr de
SupportedExternalAccessoryProtocol
    identifier                  0
    name                        com.dji.logiclink
    matchAction                 1
    NativeTransportComponentIdentifier  0x0000
USBHostTransportComponent
    identifier                  0x0000
    name                        rc
    TransportSupportsiAP2Connection
```

`com.dji.logiclink` is bound to a **native transport component**, so it is not
multiplexed into the iAP2 link:

* `StartExternalAccessoryProtocolSession` (`0xEA00`) never appears;
* no SYN advertises an External Accessory session, and no packet carries
  payload on any session other than `0x0a`;
* the tunnel runs on the **separate bulk pair of interface 1, alternate
  setting 1**, in exactly the same `55 CC` framing as on Android (section 4).

`USBHostTransportComponent` says the same from the other side: the accessory
expects the Apple device to be the USB host. The demultiplexer, the DUML codec,
the H.264 assembly and the output sinks are the same for both transports.

### 3.10 What the Apple-device side sends

`iap2.DeviceSession` is a pure bytes-in, bytes-out state machine. Fed the
goggles' packets, it produces the iPhone's replies message for message and
sequence number for sequence number:

```
RequestAuthenticationCertificate
RequestAuthenticationChallengeResponse   (fresh challenge)
AuthenticationSucceeded
StartIdentification
IdentificationAccepted
PowerUpdate                              (after StartPowerUpdates)
```

`PowerUpdate` reports 90 % by default (`iap2.power_update_params`); the value
is the phone's own, not a protocol constant. It is answered because the
goggles asked for power updates. `./third-eye iap2 CAPTURE --compare` feeds a
capture's accessory packets to the state machine and compares its replies with
the phone's.

`DeviceSession.ready` becomes true after `IdentificationAccepted`; the host
then opens the tunnel.

### 3.11 Timeline of an iOS session

With a real iPhone, from the first `SET_ADDRESS`:

| t | event |
|---|---|
| 0 | `SET_ADDRESS` for the iPhone |
| +0.11 s | request `0x51` |
| +0.49 s | `SET_ADDRESS` for the goggles as `2ca3:1002` |
| +0.50 s | `SET_CONFIGURATION 1` |
| +0.51 to +1.23 s | the iAP2 exchange of 3.7, with one pause of about 0.5 s |
| +1.53 s | `SET_INTERFACE(1, 1)`: the tunnel endpoints exist |
| about +1.8 s | app registration, then the first video packet (section 7) |

`SET_INTERFACE` comes about 300 ms after the iAP2 exchange ends, so there is
slack rather than a deadline there.

---

## 4. The LogicLink tunnel

Implementation: `pryer/tunnel.py` (`Demuxer`, `AccessUnitAssembler`).

Inside the accessory bulk pair (Android) or the interface-1 bulk pair (iOS),
the byte stream is a length-prefixed multiplexer:

```
offset  size  field
0       2     magic     55 CC
2       1     channel
3       1     version   0x57 in every packet
4       4     length    payload length, little-endian u32
8       n     payload
```

Two channels exist:

| channel | contents |
|---|---|
| `0x49` | control: DUML frames (section 6). In practice exactly one frame per packet, in both directions |
| `0x4A` | video: a piece of an H.264 Annex-B elementary stream (section 5) |

**Every tunnel packet is a USB transfer of its own.** The sender ends each
packet with a short packet: a 4,096-byte video payload is 4,104 bytes on the
wire, eight 512-byte packets and one 8-byte one, and a control packet is nearly
always a single short packet. So a bulk read returns at most one tunnel packet,
whatever its buffer size. A zero-length packet is legal: it terminates a
transfer and is neither an error nor the end of the stream
(`Demuxer.empty_packets` counts them, and an access unit ends on one as it
does on a short packet).

About 99.5 % of the bytes flow from the goggles. The app's direction is small
but carries everything the app says, including the registration.

A reader that loses bytes can resynchronise on the next `55 CC` with a
plausible header (`Demuxer.resync_bytes` counts what it skipped). On a live
link that should never happen; in a sniffer capture it happens where the
sniffer dropped data (section 11.3).

---

## 5. Video on channel 0x4A

Implementation: `pryer/tunnel.py` (access-unit assembly), `pryer/h264.py`
(bitstream codec, parameter sets).

### 5.1 Two shapes of access unit

The goggles sends each access unit as a run of 4,096-byte video packets
followed by one shorter packet. There are exactly two shapes:

**A picture**: one slice, then an access-unit delimiter at the **end**:

```
00 00 00 01 61 <coded slice ......> 00 00 00 01 09 30
            ^^ nal_ref_idc 3, type 1 (or 0x65, type 5 IDR)
                                    ^^^^^^^^^^^^^^^^^ AUD
```

**The parameter sets**: 39 bytes, SPS and PPS, **no AUD**:

```
00 00 00 01 67 64 00 34 ac 4d 00 f0 04 4f cb 35 01 01 01 40
00 00 fa 00 00 3a 98 03 c7 0c a8          <- SPS, 27 bytes
00 00 00 01 68 ee 3c b0                    <- PPS, 4 bytes
```

The H.264 specification puts the AUD at the start of an access unit; DJI puts
it at the end, as an end-of-frame marker. Because the parameter-set access unit
has none, an assembler has to end an access unit on the short (or zero-length)
packet, not on the delimiter. A stream therefore ends on a lone AUD, which
decoders report as a harmless "missing picture in access unit".

Control packets on channel `0x49` can sit **between** two video packets of the
same access unit. A control packet is never a frame boundary.

### 5.2 The goggles sends its own parameter sets once a second

In every session the goggles sends the parameter-set access unit and an IDR
picture at a steady 1 Hz (median period 1000.5–1002.2 ms). The parameter sets
always come **1.8–18.4 ms before an IDR** (median 5.6 ms). So:

* **a client never needs to synthesise parameter sets.** Attaching at a random
  moment costs at most one second: wait for a type-7 NAL, and everything from
  there on decodes;
* there is exactly one SPS and one PPS, the same on both transports and in
  every session. Nothing is renegotiated mid-stream.

### 5.3 What the parameter sets say

`h264.GOGGLES3_SPS` and `h264.GOGGLES3_PPS` build these bytes from fields:

| field | value |
|---|---|
| profile | High (100) |
| `level_idc` | 52 (level 5.2) |
| picture size | 1920×1080 (1088 coded, cropped by 4 chroma rows) |
| frame rate | 30 fps (VUI `num_units_in_tick 1000`, `time_scale 60000`) |
| `pic_init_qp` | 26 |
| entropy coding | CABAC |
| `max_num_ref_frames` | 1 |
| `transform_8x8_mode` | on |
| `pic_order_cnt_type` | 2 |
| `log2_max_frame_num` | 5 |

The access-unit interval, 33.07–33.42 ms, confirms 30 fps independently. Level
5.2 is far more than 1080p30 needs (section 13).

### 5.4 Rate and burst size

| measure | range |
|---|---|
| video bitrate | 6.0–7.1 Mbit/s |
| median picture | 22.6–26.2 kB |
| IDR picture | 53–184 kB |
| packet gap within an access unit | 0.1–0.3 ms |
| access-unit interval, p99 | 36–39 ms on a loss-free capture |

The traffic is bursty: an access unit arrives as a tight run of packets, then
the link is idle for the rest of the 33 ms frame period. An IDR is up to **45
video packets back to back**, once a second. A reader has to keep up with that
burst, one USB transfer per packet, not only with the average rate. A larger
read buffer does not help, because a read never spans two transfers (section
4); what helps is having the next read queued before the next packet arrives
(sections 8.8 and 9.3).

### 5.5 A bare elementary stream

Concatenating every channel-`0x4A` payload in order gives a byte-exact Annex-B
H.264 elementary stream. There is no DJI container, no timestamp and no
per-frame header. Only NAL types 1, 5, 7, 8 and 9 occur. The codec is H.264,
not H.265.

---

## 6. Control on channel 0x49: DUML

Implementation: `pryer/duml.py` (frame codec), `pryer/app.py` (the app side).

Channel `0x49` carries DUML, the framing used across DJI's product line
(documented in [dji-firmware-tools](https://github.com/o-gs/dji-firmware-tools)
and [samuelsadok/dji_protocol](https://github.com/samuelsadok/dji_protocol)).

### 6.1 Frame format and CRCs

```
offset  size  field
0       1     magic    0x55
1       1     length, low 8 bits
2       1     bits 0-1: length, high 2 bits; bits 2-7: protocol version
3       1     CRC-8 over bytes 0..2
4       1     source       bits 0-4 device type, bits 5-7 device index
5       1     destination  same encoding
6       2     sequence number, little-endian
8       1     bit 7: 0 request, 1 response
              bits 5-6: ack policy (whether and how the sender wants a reply)
              bits 0-2: encryption (always 0)
9       1     cmd_set
10      1     cmd_id
11      n     payload
-2      2     CRC-16 over bytes 0 .. length-3, little-endian
```

`length` counts the whole frame, so the payload is `length - 13` bytes.

Both CRCs use non-standard parameters:

* **CRC-8**: reflected polynomial `0x8C`, initial value `0x77`;
* **CRC-16**: reflected polynomial `0x8408`, initial value `0x3692`.

Every DUML frame in every capture, in both directions, passes both.

### 6.2 Module addresses

An address byte is `type | index << 5`, written `name.index`. The addresses
that matter for streaming:

| byte | name | role |
|---|---|---|
| `0x02` | `mobile_app.0` | the app (the client) |
| `0x3C` | `fpga_air.1` | registration and heartbeat (section 7) |
| `0xBC` | `fpga_air.5` | the identity request (6.3) |
| `0x03` | `flight_ctrl.0` | flight-controller telemetry |

The name table in `duml.DEV` is the historical dji-firmware-tools mapping.
Current firmware reuses several ids for other modules, so names such as
`dm36x_ground` or `esc` are labels only; the numeric ids are what matter.
"Get version" requests (`0x00/0x01`, empty payload,
`AppSession.query_version()`) are answered with the goggles' internal module
names: `"zv902_gls rc Ve"`, `"zv902 gl Ver.A"`, `"FC9470"`, `"eagle3"`.

### 6.3 What the goggles sends

Goggles → app traffic is dominated by `0x03/0x8F` (flight controller, large
payloads with a nested `55 ..` sub-framing), plus `0x00/0x99` topic values,
`0x09/0x08` and `0x09/0x75` (HD link), `0x02/0x80`..`0xDC` (camera) and
`0x04/0x05` (gimbal).

Requests that need a specific answer:

| request | when |
|---|---|
| `0x00/0x81` from `fpga_air.5`: the goggles' 64-byte identity record, name `"ZV902"` | once a second for the whole session, from before registration |
| `0x00/0x82` from `fpga_air.5`: the same record with a `02` flag at byte 36 | about 1 ms after the app answers `0x81` with its own identity |
| `0x00/0x88` from `fpga_air.1`, payload `19 00` | once a second, only after registration: the heartbeat |

The identity record is `char[32]` name, then two 8-byte fields (`05 1c 00…` and
`05 1c 00…` in the goggles' own record), then zeros.

The goggles re-sends a request that asked for a reply and got none after
194–229 ms, several times if necessary.

`0x03/0x8F` has sub-types that real apps answer with more than a bare `00`:
`01 04 01 …` is answered `01 04 00 00 <u32>`, where the value differs between
sessions and its derivation is unknown. The goggles can also send a 269-byte
sub-type `01 01 01` announcing a log file (`"USR364.DAT|" … "DJI_LOG_V3"`),
about 40 times a second, and keeps doing so when each copy is acknowledged
with `00`. Neither affects the video (section 13).

### 6.4 What the DJI Fly app sends at start-up

When DJI Fly connects it sends a burst of about 156 requests, then settles into
periodic polling. None of them starts the video, and a client does not need
them. The burst is dominated by:

| cmd_set / cmd_id | purpose |
|---|---|
| `0x00 / 0x01` | get version, sent to about ten module ids |
| `0x00 / 0xB7` | module / capability enumeration |
| `0x00 / 0x99` | named-topic get/subscribe, ASCII topic names |
| `0x00 / 0x4F` | push-data subscription to `dm36x_ground.2`, indices 0–4, payload `01 00 <index> 00 00 ff ff ff ff` |
| `0x00 / 0xB5`, `0x00 / 0x6A`, `0x00 / 0xD5` | assorted set-up |
| `0x03 / *` | flight-controller state queries |
| `0xEE / 0x2C` | UI language, payload `02 65 6e` (`"en"`) |

The `0x00/0x99` topic names map the camera model: `camcap_iso`,
`camcap_shutter`, `camcap_aperture`, `camcap_zoom`, `camcap_video_format`,
`camcap_video_codec`, `camcap_photo_size`, `camcap_exposure_mode`,
`cam_lens_state`, `cam_expo_param`, `pano_status`, `cam_storage_switch_info`,
and about thirty more.

The package does not send this burst. `duml.Frame` decodes and re-encodes every
one of these requests byte for byte, which the tests check.

### 6.5 What the app answers

The app answers every goggles request whose ack-policy bits ask for a reply,
within a few milliseconds (0.5–4.2 ms, median 1.0 ms, on a Pi 4B).
`AppSession.on_control_frame` does the same: a response frame with the
request's sequence number and command, addressed back to the sender
(`Frame.make_ack`), whose payload is chosen by `app.reply_payload()`:

| request | reply payload | builder |
|---|---|---|
| `0x00/0x81` identity | 64 bytes: status `00`, then the app's record: name `"APP"` (32 bytes), first field `00 02 00 …`, second field `05 1c 00 …` (the goggles' value echoed), zeros, truncated to 64 bytes | `app.identity_reply_payload()` |
| `0x00/0x82` identity follow-up | `00` | |
| `0x00/0x88` heartbeat `19 00` | `1a 00 00 00 00` (`u8 0x1a`, `u32le 0`) | `app.heartbeat_reply_payload()` |
| anything else | `00` | |

When the identity request is answered with a bare `00` instead, the goggles
never sends the `0x82` follow-up.

---

## 7. Starting the stream: app registration

**The goggles sends no video until the app registers with it.** Registration
is two `0x00/0x88` requests from `mobile_app.0` to `fpga_air.1`, each with ack
policy 2, each answered at once:

```
app  -> 0x3C  0x00/0x88 REQ  17 00 00 23 00 41 50 50 00 00 00 00 00 02   ("APP")
0x3C -> app   0x00/0x88 RSP  18 00 00 00
app  -> 0x3C  0x00/0x88 REQ  1d 00 01 00 00 00 00 01 07 00 31 2e 32 31 2e 31   ("1.21.1")
0x3C -> app   0x00/0x88 RSP  1d 00 00 00
              ... first channel-0x4A packet, 20-40 ms later ...
0x3C -> app   0x00/0x88 REQ  19 00           once a second from here on
app  -> 0x3C  0x00/0x88 RSP  1a 00 00 00 00
```

The field layout, as `pryer/app.py` builds it (names are neutral where the
meaning is unknown; the values are the ones every handset sends):

```
17 request (register_payload, 14 bytes)
    u8      op      0x17
    u16le   field1  0x0000
    u16le   field2  0x0023
    char[8] name    "APP", NUL-padded
    u8      role    0x02

1d request (version_payload, 16 bytes)
    u8      op      0x1d
    u8      field1  0x00
    u32le   field2  0x00000001
    u16le   field3  0x0100
    u16le   length  7
    char[6] version "1.21.1"   (the DJI Fly version; length counts a NUL that is not sent)
```

The `18 00 00 00` answer means the registration was accepted.

Timing on real handsets: the app registers 340–470 ms after it first answers
the identity request (6.3), and video follows the `1d` answer within 20–40 ms.
The goggles then sends the `19 00` heartbeat once a second; the app answers
each within milliseconds.

`AppSession.register()` sends the two requests as soon as the tunnel is up,
repeats them every second until `18 00 00 00` arrives, and brings the next
attempt forward when the first identity request has been answered, keeping at
least 250 ms between attempts. It warns after five unanswered attempts, and if
no video arrives 3 s after acceptance. `stream --no-register` turns
registration off, for experiments only.

What the registration fields mean, and whether the goggles checks the name or
the version string, is not known (section 13).

The rest of the app's start-up (6.4) keeps DJI Fly's telemetry topics alive,
but nothing shows the video depending on it, so `stream` sends none of it on
either transport. Its periodic `0x09/0xfd` traffic is bitrate configuration
that continues throughout the stream, not a trigger.

---

## 8. Linux, gadget side

Implementation: `pryer/rawgadget.py` (ctypes binding for `/dev/raw-gadget`),
`pryer/accessory.py` (the AOA sessions), `pryer/mfi.py` (the iPhone session),
`pryer/linkio.py` (the asynchronous writer). The test fake
`tests/fakegadget.py` enforces the kernel rules below.

### 8.1 Why USB Raw Gadget

Two ways exist to be a USB device from Linux userspace:

* **configfs / FunctionFS**: the kernel answers enumeration from a fixed
  descriptor set. It cannot deliver the AOA vendor requests 51/52/53 or Apple's
  `0x51` to userspace, and cannot re-enumerate as a different device mid-session.
* **[USB Raw Gadget](https://docs.kernel.org/usb/raw-gadget.html)**
  (`/dev/raw-gadget`, mainline since Linux 5.7, `CONFIG_USB_RAW_GADGET`): every
  control request is delivered to userspace, which answers it. This is what the
  implementation uses.

A session is `open` → `USB_RAW_IOCTL_INIT(speed, driver_name, device_name)` →
`USB_RAW_IOCTL_RUN` → a loop of `EVENT_FETCH` and ep0 I/O on a dedicated
thread, with endpoint I/O on other threads. Each phase of the handshake
(phone identity, accessory identity, iPhone identity) is its own session on its
own file descriptor.

A UDC is required: Raspberry Pi Zero / Zero 2 W / 3 / 4B (`dwc2`), BeagleBone
(`musb-hdrc`), most Allwinner and Rockchip boards (`dwc3`). The Raspberry Pi 5's
USB-C port is behind the RP1 chip, not `dwc2`, and the specifics below do not
apply to it. A desktop or laptop PC has no UDC.

### 8.2 The ep0 direction rule

Raw Gadget fixes the direction of the next ep0 operation when the SETUP
arrives (`gadget_setup` in `drivers/usb/gadget/legacy/raw_gadget.c`):

```c
if ((ctrl->bRequestType & USB_DIR_IN) && ctrl->wLength)
        dev->ep0_in_pending = true;
else
        dev->ep0_out_pending = true;
...
if (ret == 0 && ctrl->wLength == 0)
        return USB_GADGET_DELAYED_STATUS;
```

So:

* a device-to-host request with a data stage is answered with `EP0_WRITE`;
* **everything else**, and in particular every request without a data stage
  (`SET_CONFIGURATION`, `SET_INTERFACE`, `CLEAR/SET_FEATURE`,
  `START_ACCESSORY`, Apple's `0x51`, a `SEND_STRING` with `wLength 0`), is
  completed with a **zero-length `EP0_READ`**. Until that read is queued the
  UDC NAKs the host's status stage.

A call in the wrong direction fails with `EBUSY` ("fail, wrong direction" in
`raw_process_ep0_io`) and queues nothing, so the host polls the status stage
and is NAKed for as long as it keeps trying. On the goggles that is a
`SET_CONFIGURATION` that never completes: enumeration looks finished from the
gadget's side, and the AOA probe never comes. A decoder that pairs SETUPs with
data stages cannot see this; it shows as a long run of NAKed ep0 IN tokens.

`EBUSY` is also what endpoint I/O returns while an endpoint is being disabled,
so on ep0 it must not be mistaken for a bus reset. In the implementation,
`RawGadget.ep0_ack()` and the direction-aware `RawGadget.ep0_reply()` encode
the rule, and any error answering ep0 ends the session with the offending
request logged at `ERROR`.

`SET_CONFIGURATION` is handled as `EP_ENABLE` (each endpoint) →
`USB_RAW_IOCTL_CONFIGURE` → `ep0_ack()`, the order of the upstream examples,
and "configured" is reported only after the acknowledgement.

### 8.3 Bus resets

The goggles resets the bus 3–4 times per enumeration (2.4). On `dwc2` a reset
is reported as `USB_RAW_EVENT_DISCONNECT`, never as `USB_RAW_EVENT_RESET` (a
documented Raw Gadget quirk). On either event the implementation disables every
endpoint, drops the handles, keeps fetching events, and enables the endpoints
again on the **next** non-zero `SET_CONFIGURATION`, every time, not only the
first. Endpoint I/O in flight fails with `ESHUTDOWN`; that is a reset, not a
fault, and the transfer is retried once the host has configured the device
again.

### 8.4 Releasing the UDC between sessions

Phase 2 can only bind the UDC once phase 1 has released it, and releasing it
takes care:

* The ep0 thread spends its time blocked in `USB_RAW_IOCTL_EVENT_FETCH`, which
  sleeps until an event is queued. A thread inside an ioctl holds a reference
  to the open file, so `close(fd)` from another thread only removes the fd
  number. `raw_release()`, which unregisters the gadget driver and drops the
  pull-up, runs on the last reference, when the ioctl returns. After
  `START_ACCESSORY` the goggles sends nothing more, so it would never return.
* While the UDC is still bound, the next session's `RUN` fails with `EBUSY`:
  raw-gadget registers with `match_existing_only`, and since Linux 6.0
  `usb_gadget_register_driver_owner()` returns `-EBUSY` ("couldn't find an
  available UDC or it's busy"). The same errno also covers a bind with the
  wrong driver name (8.7); a UDC still bound shows its driver in
  `/sys/class/udc/<udc>/function` (`USB Raw Gadget` for raw-gadget).

The order that works (`rawgadget.stop_ep0_thread()`, `_Session.close()` in
`accessory.py` and the iPhone session in `mfi.py`):

1. set the session's stop flag;
2. wake the ep0 thread: write `disconnect` to
   `/sys/class/udc/<udc>/soft_connect`. udc-core drops the pull-up, which is
   the detach a real phone does, and calls raw-gadget's `disconnect` callback,
   which queues `USB_RAW_EVENT_DISCONNECT`, so the fetch returns;
3. if the thread is still blocked, send it `SIGUSR1`. A no-op handler is
   installed from the main thread; CPython installs handlers without
   `SA_RESTART`, so the ioctl returns `EINTR`, which `raw_ioctl_event_fetch`
   handles;
4. join the thread, then close the fd;
5. wait for `/sys/class/udc/<udc>/function` to become empty
   (`rawgadget.wait_udc_released()`).

Phase 2 retries `RUN` for up to 2 s while the UDC still names a driver; an
`EBUSY` with the UDC free is a bind failure and is reported at once. The ep0
loops treat a stray `EINTR` (Ctrl-C can land on any thread) as a non-event.

`decode` recognises a capture in which `START_ACCESSORY` is acknowledged and no
`18d1:2d0x` device descriptor follows, and reports how long the phone identity
stayed attached.

### 8.5 All ioctls go through ctypes

`fcntl.ioctl` with a mutable buffer larger than 1,024 bytes passes it in place
and keeps the interpreter lock for the whole call (`Modules/fcntlmodule.c`,
CPython 3.11 to 3.13). A bulk read blocked in `EP_READ` would then stop the
ep0 thread from answering a control request or handling a reset.
`rawgadget._ioctl()` calls libc `ioctl` through ctypes, which always releases
the lock and does not retry on `EINTR`.

### 8.6 Enabling endpoints

`EP_ENABLE` can fail transiently with `EAGAIN` or `EBUSY` (raw-gadget's "no
endpoints available") while a previous session is still letting go of the
UDC; it is retried a few times. On `EINVAL` it is retried once with a 64-byte
`wMaxPacketSize`, logged as a warning because the endpoint then no longer
matches the advertised descriptor.

### 8.7 Raspberry Pi 4B specifics

**The two names in `USB_RAW_IOCTL_INIT`.**

| field | matched against | Pi 4B | Pi Zero / 3 | Dummy HCD |
|---|---|---|---|---|
| `device_name` | the directory in `/sys/class/udc` | `fe980000.usb` | `20980000.usb` | `dummy_udc.0` |
| `driver_name` | `gadget->name` in raw-gadget's `gadget_bind` | `fe980000.usb` | `20980000.usb` | `dummy_udc` |

`dwc2` sets `hsotg->gadget.name = dev_name(dev)`, so the driver name is the
platform device name, **not** `dwc2`. Passing `dwc2` makes the bind fail with
`ENODEV`. The implementation reads the driver name from `USB_UDC_NAME` in
`/sys/class/udc/<udc>/uevent`, as the
[Raw Gadget hardware table](https://github.com/xairy/raw-gadget) lists for the
Pi 4.

**`vbus_draw` always fails.** `dwc2_hsotg_vbus_draw` returns `-ENOTSUPP`
without a `usb_phy`, and none is bound on a Pi. The ioctl is advisory (the host
reads the budget from `bMaxPower`), so its failure is ignored.

**Boot configuration.** The USB-C power socket is the Pi 4B's only
peripheral-capable port; the USB-A ports are behind the VL805 XHCI host
controller. It needs `dtoverlay=dwc2` in `config.txt` (`/boot/firmware/` on
Bookworm and later, `/boot/` before), with `dr_mode=peripheral` for the Android
transport or `dr_mode=otg` for the iOS one. **`otg_mode=1` overrides
`dtoverlay=dwc2`**: it routes the port to the XHCI controller and leaves
`/sys/class/udc` empty
([Raspberry Pi forums](https://forums.raspberrypi.com/viewtopic.php?t=347459)).

**Speed-related descriptors.** `dwc2` here is high-speed only while the
descriptors report `bcdUSB 0x0200`, so the gadget answers `GET_DESCRIPTOR` for
`DEVICE_QUALIFIER` (type 6) and `OTHER_SPEED_CONFIGURATION` (type 7) instead of
stalling them; the Raw Gadget notes warn that descriptors inconsistent with the
emulated speed can make the UDC reset the link.

**Resources.** The controller has 8 endpoints with dedicated FIFOs, ample for
one bulk pair. Gadget transfers need no clamping: raw-gadget's limit is
`KMALLOC_MAX_SIZE`, and dwc2's `get_ep_limit()` allows 523,776 bytes for a
512-byte bulk endpoint, so every gadget read is a single request that a short
packet simply completes.

**Latency.** Userspace ep0 handling is fast enough: the Pi NAKs the first
`GET_DESCRIPTOR` data stage for about 340 µs before answering, where a handset
takes about 100 µs, and the goggles waits without complaint.

`third-eye doctor` checks all of this, and whether another gadget driver owns
the UDC (`/sys/class/udc/*/function` non-empty makes `INIT` fail with `EBUSY`).

**Power.** The USB-C socket is also the Pi 4B's power inlet, with VBUS wired
straight to the 5 V rail. Power the Pi from its GPIO header or a PoE HAT and cut
VBUS in the cable to the goggles, so that two supplies do not meet on one rail.

### 8.8 Reading and writing the accessory link

* **Reads.** 16 KiB per read (`tunnel.ACCESSORY_READ_SIZE`), four times the
  largest transfer, on a thread of its own. `RawGadget._ep_io` reuses one
  buffer per endpoint and copies out only the bytes received, so a read costs
  little more than the ioctl.
* **Writes.** The goggles collects IN data only when it polls, and a write can
  block for well over 100 ms. All app writes (registration, replies) are
  queued to one thread (`linkio.AsyncWriter`) that sends them in order, so a
  write never holds up the next read. At shutdown the writer is stopped before
  the link's fd is closed, with the same wake-up as 8.4 if it is blocked in an
  ioctl.

---

## 9. Linux, host side

Only the iOS transport has a host side.

### 9.1 Switching the port to host mode

After `0x51` the port has to become a USB host. A Pi 4B has no `usb_role`
switch for it (its USB-C CC lines go to plain resistors, so no Type-C driver
registers one), so the controller is re-probed with a different `dr_mode`,
without unloading the module (`mfi.switch_dwc2_role()`):

```bash
$ echo fe980000.usb | sudo tee /sys/bus/platform/drivers/dwc2/unbind
$ sudo dtoverlay dwc2 dr_mode=host      # runtime overlay: updates the live DT property
$ echo fe980000.usb | sudo tee /sys/bus/platform/drivers/dwc2/bind
# back to gadget mode: unbind, sudo dtoverlay -r dwc2, bind
```

This path never loads a module. Unloading and reloading `dwc2` instead
(`modprobe -r dwc2`, `dtoverlay`, `modprobe dwc2`) depends on the module file
on disk matching the running kernel: after a kernel package upgrade without a
reboot, `modprobe` fails with `ENOEXEC` ("Exec format error") and leaves the
board with no `dwc2` driver at all. `doctor` checks for that mismatch (the
loaded module's `srcversion` against the file's, and the file's age against
the boot time).

`mfi.switch_to_host_role()` does this on a Pi 4B or on any machine with the
`dtoverlay` tool; elsewhere it leaves the switch to the user
(`--no-role-switch` does the same on purpose). A failed switch raises
`RoleSwitchError` at once. `mfi.switch_to_gadget_role()` restores gadget mode when the session ends,
and `mfi.ensure_gadget_role()` repairs a port left in host mode, or without a
`dwc2` driver, before phase 1. `third-eye role [status|host|gadget]` does the
same by hand. `modprobe dwc2` is tried only if the driver is not registered at
all. The overlay's parameters are `dr_mode` (`host`, `peripheral`, `otg`),
`g-rx-fifo-size` and `g-np-tx-fifo-size`
([Raspberry Pi forums](https://forums.raspberrypi.com/viewtopic.php?t=391191)).

### 9.2 The host driver: `mfi.IapHost`

`IapHost` waits for `2ca3:1002`, opens it, claims interface 0, sends the
link-detect preamble, runs the iAP2 exchange on a background thread until
`DeviceSession.ready`, then claims interface 1, sends `SET_INTERFACE(1, 1)`,
and exposes `read()` and `write()` over EP `0x82` and `0x02`. These are the
same two methods the Android `AoaAccessory` exposes, so the rest of the
pipeline (`pryer/pipeline.py`) is shared.

At the end of a session it cancels both readers, releases the interfaces
(which sends `SET_INTERFACE(1, 0)`), closes the device and restores the port
role.

### 9.3 Reading the tunnel as host

**A bulk read longer than one URB loses data on a Pi's `dwc2`.** libusb's Linux
backend splits a synchronous transfer longer than 16 KiB into 16 KiB URBs,
chained with `USBFS_URB_BULK_CONTINUATION`, all but the last `SHORT_NOT_OK`.
Every tunnel packet ends with a short packet (section 4), which completes the
first URB; usbfs then cancels the rest from the completion handler. `dwc2`
does not wait for that: it starts the next queued URB as soon as one completes,
and runs the completion handler later. A packet that reaches the second URB
before the cancellation is ACKed on the wire and lost with the URB. The DATA
toggle of what that URB received is lost with it, so the host later expects the
wrong toggle, ACKs the next packet and drops it as a retransmission (USB 2.0
section 8.6).

A capture of a Pi 4B reading with 256 KiB synchronous transfers shows both
consequences, while the stream on the wire is complete and decodes cleanly:

* 21 of the 97 goggles requests that asked for a reply were never answered
  (the app answers every request it receives within milliseconds), and were
  re-sent, one six times;
* 102 of 2,023 short packets were followed by the next IN token only
  2.1–8.8 µs later, where after an accepted packet the host takes at least
  16.4 µs (median 42 µs): the host polled on as if nothing had arrived;
* every lost request is either one of those dropped packets or one that
  arrived less than 44 µs after the previous transfer ended, the window in
  which the second URB was running; no request that arrived later was lost.

The explanation fits the capture and the driver sources; it has not been
traced inside the kernel. On the Android transport the Pi is the device and
each gadget read is a single request (8.7), so it is not affected.

**What the implementation does instead** (`libusb.BulkReader`, used by
`IapHost`):

* EP `0x82` gets **32 independent transfers of 16 KiB**
  (`mfi.DEFAULT_TRANSFERS`, `tunnel.DEFAULT_READ_SIZE`, `libusb.MAX_URB_SIZE`):
  one URB each, so a short packet simply completes it and nothing is ever
  cancelled while data can still arrive. EP `0x81` gets 2 transfers of 4 KiB;
* the transfers have no timeout, are resubmitted from their completion
  callbacks, and are cancelled only at close; one thread per libusb context
  runs the event loop (`Context.start_events`);
* they are queued as soon as `SET_INTERFACE(1, 1)` completes, so the endpoint
  always has a request pending, as with an iPhone;
* `read()` returns everything received since the last call, in order;
* if the application falls 4,096 chunks behind, the reader stops resubmitting
  until the backlog has halved. The endpoint is then NAKed; the goggles holds
  its data, so this delays rather than loses it;
* `--transfers 0` reads synchronously, one 16 KiB transfer at a time. A
  `--read-size` above 16 KiB is cut to 16 KiB, and `Device.bulk_read` never
  asks for more than one URB. Writes and control transfers stay synchronous.

Replaying the goggles' transfers from the capture above through this reader
(on a fake libusb) delivers the whole stream and all 97 requests. It has not
yet run against the goggles on hardware.

**Checking a capture for losses** (`pryer/linkaudit.py`, printed by `decode`
for any pcapng file):

* *requests*: every goggles request that asks for a reply, whether and when the
  app answered it, how many were re-sent;
* *host reads*: every short packet on the tunnel IN endpoint that the host
  polled past within 12 µs, as if nothing had arrived;
* a loss is reported only when the two agree, that is when the requests in
  those packets went unanswered more often than the others. The timing alone
  would also flag a host that simply polls very fast.

```
app replies:        75 of 97 goggles requests that asked for a reply were answered, 21 were not (1 too close to the end of the capture to tell)
                    the goggles sent 13 request(s) more than once, one of them 6 times
host reads:         102 of 2023 short packets on EP 0x82 IN were ACKed and then dropped by the host (it polled again within 12 us, as if nothing had arrived)
                    after the other short packets, the host polled again a median 42 us later (p99 14.3 ms)
                    12 of those packets carried a request: 12 went unanswered, against 9 of the 84 other requests
  -> the host lost data the goggles had delivered. Reads longer than one URB do this on a Pi's dwc2 (PROTOCOL.md 9.3); keep independent single-URB transfers queued instead (the default, --transfers)
```

A clean session shows every request answered (bar one or two at the very end
of the capture) and `host reads: none of … short packets … was polled past
within 12 us`.

---

## 10. Making the stream playable

Implementation: `pryer/h264.py`, `pryer/sinks.py`.

### 10.1 The normal case: wait for the parameter sets

The goggles supplies everything a decoder needs once a second (5.2), so the
only rule is: **start at a type-7 NAL.** `--wait-keyframe` (the default) does
that on a live stream, and `h264.playable_prefix()` does it to bytes already in
hand. It discards up to one second of leading P slices, which reference a
picture and a PPS the decoder never saw.

`--inject never` is also the default. When the encoder sends its own parameter
sets, replacing them can only lose information: a reconstruction with the
wrong frame rate or `pic_init_qp` produces a file that opens and then decodes
to almost nothing.

A loss-free recording decodes with no macroblock errors; the only `ffmpeg`
complaint is the lone AUD at the end (5.1).

### 10.2 The fallback: parameters from the slice headers

An excerpt that starts after a parameter set and ends before the next one has
to be given parameter sets to decode. Part of the SPS can be recovered from the
slices themselves. A slice header cannot be parsed without the parameter sets,
since its fields depend on them and several are variable-length; but a wrong
guess almost always desynchronises the header into impossible values, so the
headers are an oracle. `h264.infer()` parses every slice under each candidate
hypothesis and keeps those that pass: one slice per picture,
`pic_parameter_set_id` 0, a plausible `slice_qp_delta`, and `frame_num`
advancing by exactly one per picture. Two details matter on real streams:

* `frame_num` (and `pic_order_cnt_lsb`) reset to 0 at an IDR, so the rule must
  allow that;
* I and P pictures use different `slice_qp_delta` (for example −11 and −10):
  the rule is one QP offset per slice type.

On the goggles' stream `infer()` recovers `log2_max_frame_num 5`,
`pic_order_cnt_type 2`, CABAC, `deblocking_filter_control_present 1`,
`frame_mbs_only 1`: exactly what the real SPS says. On heavily damaged input it
reports no surviving hypothesis rather than a wrong one.

### 10.3 What slice headers cannot reveal

The picture size, the frame rate and `pic_init_qp` do not affect how a P-slice
header parses, so no search over slice headers can find them. The fallback uses
the measured values: 1920×1080, 30 fps, `pic_init_qp` 26, level 5.2.

`tune` searches `pic_init_qp` by brute force with `ffmpeg` as the oracle,
scoring each candidate by decoder errors and by how much of the picture is not
the grey reference a decoder starts from. On an excerpt with no IDR only a few
per cent of each picture is ever painted, so candidates several steps apart
score alike. It is a diagnostic, not a source of truth.

The rest of the goggles' SPS is the encoder's own style, not reachable from the
slices but readable from the SPS. `h264.EncoderStyle` holds those fields, and
`GOGGLES3_STYLE` is the goggles' choice: `gaps_in_frame_num_allowed 0`; a VUI
with `video_format 5`, `full_range 0`, colour primaries / transfer / matrix
`1/1/1` (BT.709), `num_units_in_tick 1000`, `time_scale` = 2 × fps × 1000,
`fixed_frame_rate_flag 0`; and a bitstream restriction with motion vectors over
picture boundaries allowed, `log2_max_mv_length` 13 horizontal and 11 vertical,
`max_num_reorder_frames 0`, `max_dec_frame_buffering 1`. The PPS adds the
High-profile tail with `transform_8x8_mode_flag 1`. With the defaults,
`build_sps` and `build_pps` produce the goggles' own 31 bytes; an override
(`--size`, `--framerate`, `--pic-init-qp`) changes only that field.

`parameter_sets(match_encoder=False)` writes a generic set instead
(`GENERIC_STYLE`): the smallest VUI that carries a frame rate, and no PPS tail.

```
goggles  67 64 00 34 ac 4d 00 f0 04 4f cb 35 01 01 01 40 00 00 fa 00 00 3a 98 03 c7 0c a8
generic  67 64 00 34 ac 4d 40 f0 04 4f cb 08 00 00 03 00 08 00 00 03 01 e4 20
                           ^^ gaps_in_frame_num_allowed differs from here, then the VUI
```

Both decode as 1920×1080 High level 5.2 at 30 fps.
`ParameterSetInjector.matches_encoder` records whether what was injected is
byte-identical to the goggles' own, and the CLI warns when it is not.

What the fallback yields on a short excerpt with no parameter sets: a file
that opens and decodes without errors, but shows only the intra-coded
macroblocks, grey elsewhere, because every P slice refers to a picture sent
before the excerpt began. `ffmpeg -flags2 +showall -flags +output_corrupt`
displays them.

### 10.4 Muxing into a container

The container sinks (`sinks.ContainerSink`) pipe the stream into `ffmpeg -c
copy`. Two options are needed:

* **`-copyinkf`** (an output option, after `-i`): muxers otherwise drop
  everything before the first keyframe, which on an excerpt without an IDR
  leaves an empty file;
* **`-r 30` on the input**: the raw H.264 demuxer has no timestamps and
  otherwise assumes 25 fps.

```
ffmpeg -fflags +genpts -f h264 -r 30 -i pipe:0 \
       -c copy -copyinkf [-movflags +faststart] -f <muxer> <path>
```

---

## 11. Analysing bus captures

Implementation: `pryer/pcapng.py`, `pryer/capture.py`, `pryer/linkaudit.py`,
and the `decode`, `dump` and `iap2` subcommands.

### 11.1 Capture format

The reference captures are raw USB 2.0 bus captures written by an
[Alex Taradov USB sniffer](https://github.com/ataradov/usb-sniffer) in pcapng,
with two interfaces:

| interface | linktype | contents |
|---|---|---|
| 0 | 295 (`LINKTYPE_USB_2_0`) | every wire packet, nanosecond timestamps |
| 1 | 252 (`LINKTYPE_LOG_TEXT`) | the sniffer's log: bus resets, speed detection, line states, folded empty frames, buffer overflows |

An Enhanced Packet Block on interface 0 holds one wire packet: the PID byte,
the payload and, for data packets, the 2-byte USB CRC-16. Because it is a bus
capture, it includes SOF, ACK, NAK and PING packets and, importantly, the
**device address and endpoint number** of every token. `pryer.capture` also
reads Wireshark-style text hex dumps of the same packets.

### 11.2 Reassembling transfers

`0xC3` and `0x4B` are the **DATA0 / DATA1** PIDs, the data toggle, not
direction markers. Grouping by PID looks almost right, because control packets
are single-packet, and silently corrupts every multi-packet video transfer.
Reassemble by address, endpoint and direction, in capture order, end a transfer
on a short or zero-length packet, and let the tunnel's length field find the
packet boundaries (`pcapng.transactions`, `pcapng.endpoint_survey`,
`pcapng.tunnel_endpoints`, `pcapng.control_transfers`). `4b 00 00` is a
zero-length packet.

| transport | tunnel endpoint | goggles → app | app → goggles | iAP2 |
|---|---|---|---|---|
| Android | address 1, EP 1 | `OUT` | `IN` | — |
| iOS (iPhone as host) | EP 2 | `IN` | `OUT` | EP 1, both directions |

Any analysis of what the app said has to read the low-volume direction
explicitly.

### 11.3 Sniffer overflows

When the sniffer's buffer overruns it logs an overflow on interface 1
(`pcapng.overflows()`). Where no overflow is logged, framing is exact and no
resynchronisation is needed. Where bytes are lost:

* resynchronisation bytes > 0 ⟹ the sniffer logged an overflow, always;
* an overflow does not always cause resynchronisation: whole packets may be
  lost instead, which shows as a gap in the timestamps.

So `Demuxer.resync_bytes` measures the capture hardware, not the protocol.
Downstream effects are capture damage too: a lost tunnel header can splice a
DUML frame into the video channel, which shows up as a "NAL type 21" (a DUML
frame starts with `0x55`, whose low five bits are 21); torn slices appear as
NAL types 0 or 21; lost AUDs merge pictures; and access-unit intervals of two
or three frame periods appear exactly at the overflows. Every DUML frame still
passes both CRCs, because a frame damaged by the loss is dropped, not passed on.

### 11.4 What `decode` diagnoses

`third-eye decode CAPTURE` prints a summary (tunnel, video, control, NAL
histogram, app registration, link audit) and, when there is no tunnel traffic,
says how far the session got:

| on the wire | diagnosis |
|---|---|
| no control request at all | nothing on the bus: cable, port or controller mode |
| enumeration but no `SET_CONFIGURATION` | a descriptor the host rejected |
| configured, then nothing | the goggles declined the device, or its status stage never completed (8.2); lists the advertised interfaces |
| AOA handshake complete, idle endpoints | the accessory was never opened (2.5); exits non-zero |
| `START_ACCESSORY` acknowledged, no `18d1:2d0x` | the phone identity never let go of the UDC (8.4) |
| `0x51` acknowledged, goggles attached, no host | the port never became a host (9.1) |
| tunnel traffic, no `0x00/0x88` | the app never registered (7) |
| requests unanswered and packets polled past | the host lost data (9.3) |

`third-eye dump CAPTURE --control` lists the enumeration, AOA and iAP2 control
transfers; `third-eye iap2 CAPTURE` decodes the iAP2 session message by
message.

---

## 12. Related work

| | FPV Goggles V1/V2 ([voc-poc](https://github.com/fpv-wtf/voc-poc)) | Goggles 3 (this) |
|---|---|---|
| goggles' USB role | device `2ca3:001f` | **host** |
| Linux role | host (libusb) | **gadget** (Android), gadget then host (iOS) |
| start | write `52 4d 56 54` ("RMVT") to a bulk OUT endpoint | DUML registration (section 7) |
| transport | raw bulk on interface 3 | AOA accessory bulk pair, or the MFi interface-1 bulk pair |
| framing | none | `55 CC` tunnel, channels `0x49` / `0x4A` |
| codec | H.264 Annex-B | H.264 Annex-B, AUD at the end of each picture |
| hardware | any PC | a board with a UDC |

[voc-poc's `index.js`](https://github.com/fpv-wtf/voc-poc/blob/master/index.js)
is about 40 lines because on the old goggles the hard parts do not exist.
[fpvout/DigiView-SBC](https://github.com/fpvout/DigiView-SBC) targets the same
older goggles from a Pi. [CosmoStreamer](https://cosmostreamer.com/products/djigoggles2/)
is a closed-source Goggles 2/3 product running on Raspberry Pi boards, which is
consistent with the gadget architecture described here. The AOA and MFi
approaches for the newer goggles are discussed in
[voc-poc issue #15](https://github.com/fpv-wtf/voc-poc/issues/15) and the
[Raspberry Pi forum thread on USB device mode for DJI AOA](https://forums.raspberrypi.com/viewtopic.php?t=373615).

Another open-source Goggles 3 client uses the phase-1 identity `18d1:4ee0`
(`"DJI"` / `"com.dji.logiclink"`, bus-powered, `bMaxPower 250`), available here
as the `dji` profile (2.1). It also describes a separate, network path: with
Share Live View enabled, the goggles sends video over **UDP port 9003**
(`192.168.2.1` over the goggles' Wi-Fi, `192.168.60.2` over USB networking),
with an 8-byte header ending in an XOR check byte, type-4 ACKs that the client
must send or the stream stops, video payload from offset `0x14`, and sequence
numbers stepping by 8. None of this is in the USB captures and it is not
specified precisely enough to implement from that description.

---

## 13. Open questions

* **Phase-1 identity.** The handset identity is accepted. Whether the
  single-interface `minimal` identity that `stream` presents, or the `dji`
  identity, is probed for AOA too has not been confirmed on hardware, and
  whether the goggles looks at the phase-1 configuration at all is unknown.
  If `minimal` is declined, the handset identity is the fallback
  (`AoaAccessory(phone_profile="handset")`).
* **App start-up traffic.** Nothing shows video depending on the DJI Fly
  start-up requests (6.4); a session without any of them has not yet run on
  hardware.
* **Queued host reads on hardware.** The queued single-URB reader (9.3) is
  validated offline; whether `dwc2` completes many queued single-URB IN
  transfers as expected, whether the Python completion callbacks keep up, and
  the shutdown order (cancel readers, release interfaces, restore the role) are
  still to be confirmed against the goggles. `--transfers 0` is the fallback.
* **Registration fields.** The meaning of `field1`, `field2`, `role`, the `1d`
  request's fields and the four zero bytes of the heartbeat reply; whether the
  goggles checks the app name or version, or would accept another version
  string.
* **Identity record fields.** The meaning of the two 8-byte fields
  (`05 1c 00…`, `00 02 00…`).
* **`0x03/0x8F` replies.** How the `u32` in the reply to sub-type `01 04 01` is
  derived, and what answer stops the repeated `01 01 01` log-file
  announcement. Neither blocks the video.
* **`0x00/0x4F` semantics.** The five subscriptions to `dm36x_ground.2` look
  like a push-data table; the index meaning is unconfirmed.
* **Video modes.** Every session is 1920×1080 at 30 fps, and no command selects
  a mode; the goggles appears to send its current display mode. CosmoStreamer
  advertises up to 1080p60 on Goggles 3, so other modes probably exist. Why the
  encoder declares level 5.2 is unknown.
* **Audio.** No audio channel appears in the tunnel, and the AOA audio modes
  are never requested.
* **How long the goggles waits for a host after `0x51`.** At least 12 s.
* **MFi enforcement.** The goggles authenticates itself and never challenges
  the phone. Whether a firmware update could add a device-side check is
  unknown.
* **`PowerUpdate`.** Nothing observed reacts to the reported battery level.
* **The UDP Share Live View path** (section 12): header, XOR and ACK formats,
  and whether it needs DJI Fly to have connected first.
