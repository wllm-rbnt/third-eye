# third-eye

Receive the live H.264 video stream of a **DJI Goggles 3** over USB on Linux.
It can then be displayed on local HDMI output, stored in file, sent over the
network or to a local command.
It is the equivalent of [fpv-wtf/voc-poc](https://github.com/fpv-wtf/voc-poc)
for the current generation of goggles, and an open counterpart to the
closed-source [CosmoStreamer](https://cosmostreamer.com/products/djigoggles2/).

Reverse-engineered from USB captures of an Android phone and an iPhone
receiving the stream. The goal of this work is offering interoperability to the
community. The full protocol write-up is in [PROTOCOL.md](PROTOCOL.md).

The code itself can be used in production setup and it's also a kind of
reference implementation, meant to be read by people implementing the same
protocols in their own tools. Nothing it sends is a stored copy of captured
traffic: every USB descriptor, DUML payload, iAP2 message and H.264 parameter
set is built from named fields, and the test suite checks the result against
what real phones and goggles put on the wire.
It can also be used to debug other implementations.

```bash
# live preview
sudo ./third-eye stream -o 'cmd:ffplay -fflags nobuffer -flags low_delay -i -'

# straight to a playable file
sudo ./third-eye stream -o flight.mp4
```

It runs comfortably on a Raspberry Pi 4B with 2 GB of RAM.

## Contents

* [How it works](#how-it-works)
* [Status](#status)
* [Hardware requirements](#hardware-requirements)
* [Software requirements](#software-requirements)
* [Installation](#installation)
* [Usage](#usage)
* [Offline tools](#offline-tools)
* [Using the library](#using-the-library)
* [Tests](#tests)
* [Troubleshooting](#troubleshooting)
* [Credits](#credits)
* [License](#license)

---

## How it works

On the older DJI FPV Goggles the goggles was a USB *device*, so any laptop could
read the stream. **On the Goggles 3 the roles are reversed: the goggles is the
USB host and the phone is the device.** The Linux machine therefore has to act
as a USB *gadget*, which needs a USB Device Controller (UDC). The tool uses the
kernel's [USB Raw Gadget](https://docs.kernel.org/usb/raw-gadget.html)
interface to impersonate a phone.

The goggles talks to Android phones and iPhones differently, and both
transports are implemented (`--transport`):

| | `aoa` (default) | `ios` |
|---|---|---|
| protocol | Android Open Accessory 2.0 | Apple role swap, then iAP2 |
| USB roles | the goggles stays host; Linux is a gadget throughout | Linux is a gadget until the goggles hands the host role over, then a libusb host talking to the goggles as device `2ca3:1002` |
| port needed | peripheral-capable (`dr_mode=peripheral`) | dual-role (`dr_mode=otg`) |
| moving parts | raw-gadget | raw-gadget, then libusb and iAP2 |

`aoa` is simpler and is the recommended path. `ios` needs **no MFi
coprocessor**: on this link the goggles is the party that authenticates, and
Linux only verifies ([PROTOCOL.md §3.8](PROTOCOL.md#38-authentication-is-one-way)).

Both transports then carry the same DJI tunnel, with the video on one channel
and DUML control frames on another. The goggles sends video only after the app
has registered with it, which the tool does by default.

## Status

Tested on a Raspberry Pi 4 Model B.

* **Android transport**: video received on hardware. The phase-1 phone
  identity the tool presents by default (a minimal single-interface
  descriptor set), and sending none of the DJI Fly start-up requests, are
  validated offline; if the goggles ignores the minimal identity, the
  Samsung handset identity, which is confirmed to work, is available from
  the library ([PROTOCOL.md §2.1](PROTOCOL.md#21-phase-1-the-phone-identity)).
* **iOS transport**: every step observed on the wire on hardware, up to a
  complete, decodable video stream. Reading the tunnel with queued
  single-URB transfers (the default) is validated offline; `--transfers 0`
  is the fallback ([PROTOCOL.md §9.3](PROTOCOL.md#93-reading-the-tunnel-as-host)).
* Offline tools: verified on every reference capture.

Not implemented: audio (none is carried), and any control over resolution or
frame rate (the stream is 1920×1080 at 30 fps). Open questions are listed in
[PROTOCOL.md §13](PROTOCOL.md#13-open-questions).

---

## Hardware requirements

* A Linux board with a **USB Device Controller on a port you can reach**:
  * **Raspberry Pi 4 Model B** (the reference target): the USB-C power socket
    is wired to the SoC's `dwc2` controller, UDC `fe980000.usb`. It is the only
    port that can be a device; the USB-A ports are host-only.
  * Raspberry Pi Zero, Zero 2 W and 3: the OTG port, also `dwc2`, UDC
    `20980000.usb`.
  * BeagleBone (`musb-hdrc`), most Allwinner and Rockchip boards (`dwc3`):
    should work for `aoa`; the Pi-specific role switching of `ios` does not
    apply.
  * **Not** a Raspberry Pi 5 (its USB-C port is behind the RP1 chip, not
    `dwc2`), and **not** a desktop or laptop PC (no UDC).
* For `--transport ios`: a port that can switch between device and host mode
  (the Pi 4B's USB-C port does).
* A **data-capable USB-C cable** between the goggles and the board's USB-C
  port.
* **Power the Pi 4B from its GPIO 5 V pins or a PoE HAT**, and use a cable or
  adapter with the VBUS line cut for the goggles. The Pi 4B's USB-C socket is
  its power inlet, wired straight to the 5 V rail: the goggles' supply and
  yours would otherwise meet on the same rail, and a brownout mid-stream looks
  exactly like a USB fault.
* The DJI Goggles 3, powered on and linked to the aircraft.

## Software requirements

* Linux ≥ 5.7 with `CONFIG_USB_RAW_GADGET` (standard on Raspberry Pi OS).
* Python ≥ 3.9. No third-party Python packages.
* Root, to use `/dev/raw-gadget` and to switch the port role.
* `ffmpeg` for the container outputs (`mp4:`, `mkv:`, …), for `tune`, and
  `ffplay` for live preview.
* For `--transport ios`: `libusb-1.0` (`sudo apt install libusb-1.0-0`) and,
  on a Pi, the `dtoverlay` tool (`raspi-utils`, or `libraspberrypi-bin` on
  older images).
* The offline tools (`decode`, `dump`, `iap2`, `tune`) run on any machine with
  Python.

---

## Installation

The tool runs from the checkout; there is nothing to build.

```bash
sudo apt install git ffmpeg
git clone https://github.com/wllm-rbnt/third-eye.git third-eye
cd third-eye
chmod +x third-eye          # if the executable bit was lost in transit
./third-eye --help          # or: python3 third-eye --help
```

On a Raspberry Pi 4B, prepare the USB-C port once:

```bash
# 1. Put the USB-C port under dwc2. Use dr_mode=otg instead of peripheral if
#    you want --transport ios. On Raspberry Pi OS (previously called Raspbian)
#    the file is /boot/firmware/config.txt; on older images it is
#    /boot/config.txt.
echo 'dtoverlay=dwc2,dr_mode=peripheral' | sudo tee -a /boot/firmware/config.txt

# 2. Make sure otg_mode=1 is NOT set: it routes the USB-C port to the host-only
#    controller and overrides dtoverlay=dwc2, leaving no UDC at all.
grep -n '^otg_mode' /boot/firmware/config.txt      # expect no output

sudo reboot

# 3. Load the raw gadget driver, now and at every boot.
sudo modprobe raw_gadget
echo raw_gadget | sudo tee /etc/modules-load.d/raw_gadget.conf

# 4. For --transport ios only.
sudo apt install libusb-1.0-0 raspi-utils

# 5. Check.
ls /sys/class/udc                 # expect fe980000.usb
sudo ./third-eye doctor
```

`doctor` reports the board model, the UDC device and driver names, what
`config.txt` says about `dwc2`, whether another gadget driver already owns the
controller, the port's current role, and what the iOS transport needs. After a
kernel upgrade, reboot before streaming: `doctor` warns when the `dwc2` module
on disk no longer matches the running kernel.

Then connect the goggles' USB-C port to the Pi's USB-C port, power the goggles
on and link them to the aircraft.

---

## Usage

```
third-eye [-v] COMMAND [options]
```

| command | what it does | needs |
|---|---|---|
| `stream` | negotiate a transport with the goggles and output the live video | root, a UDC |
| `decode CAPTURE` | summarise a USB capture, diagnose it, extract its video | nothing |
| `dump CAPTURE` | annotated listing of the tunnel, or of the control transfers | nothing |
| `iap2 CAPTURE` | decode an iOS capture's iAP2 session | nothing |
| `tune CAPTURE` | search `pic_init_qp` with `ffmpeg` as the oracle | `ffmpeg` |
| `role [status\|host\|gadget]` | show or change the Pi's USB-C port role | root |
| `doctor` | check whether this machine can run `stream` | |

`-v` logs the handshake, `-vv` every control request.

### Streaming

```bash
sudo ./third-eye stream [options]
```

| option | meaning |
|---|---|
| `-o SPEC` | where the H.264 goes (see [Outputs](#outputs)); default stdout |
| `-t`, `--transport aoa\|ios` | which transport to use (default `aoa`) |
| `--udc NAME` | UDC device name, a directory in `/sys/class/udc` (default: detected) |
| `--driver NAME` | UDC driver name for raw-gadget's bind (default: detected from `/sys/class/udc/<udc>/uevent`). Not the module name: on a Pi 4B it is `fe980000.usb`, not `dwc2` |
| `--no-register` | do not register with the goggles. **The goggles then sends no video**; for experiments only |
| `--no-ack` | do not answer the goggles' DUML requests |
| `--no-adb` | in accessory mode, present `18d1:2d00` (no adb interface) instead of `18d1:2d01`; untested on the goggles |
| `--chunks` | one write per 4 KiB video packet instead of one per access unit (local pipes and files only) |
| `--no-wait-keyframe` | start writing at once instead of at the next SPS (at most one second away) |
| `--read-size N` | bytes per bulk read (default 16384) |
| `--timeout S` | handshake timeout (default 60) |
| `--stats S` | print throughput every S seconds (default 5, 0 disables) |

Options for `--transport ios`:

| option | meaning |
|---|---|
| `--no-role-switch` | do not switch the port to host after the role swap; do it yourself. By default the tool unbinds `dwc2`, applies a runtime `dtoverlay dwc2 dr_mode=host` and binds it again (the module is never unloaded) |
| `--keep-host-role` | leave the port in host mode at the end instead of restoring gadget mode |
| `--no-trigger` | skip the iPhone impersonation (the goggles already shows up as `2ca3:1002`) |
| `--no-detect` | do not send the iAP2 link-detect preamble |
| `--iap-timeout S` | limit for the iAP2 handshake (default 15) |
| `--transfers N` | bulk reads kept queued on the tunnel endpoint (default 32). `0` reads synchronously, one transfer at a time |

On `ios`, `--read-size` is also the maximum: a read longer than one 16 KiB URB
loses data on a Pi ([PROTOCOL.md §9.3](PROTOCOL.md#93-reading-the-tunnel-as-host)),
so a larger value is reduced to 16384 with a warning.

The port role can also be inspected and changed by hand. A port left in host
mode is repaired automatically before the next iOS session.

```bash
sudo ./third-eye role            # show controller, role, UDCs, runtime overlay
sudo ./third-eye role host
sudo ./third-eye role gadget
```

### Outputs

| `-o` | effect |
|---|---|
| `-` | raw Annex-B H.264 on stdout (default) |
| `file:PATH` | raw Annex-B to a file |
| `mp4:PATH`, `mkv:PATH`, `mov:PATH`, `ts:PATH`, `flv:PATH` | muxed into a container by `ffmpeg` |
| `PATH.mp4` (a bare path with one of those extensions) | the same, container from the extension |
| `fifo:PATH` | a named pipe, created if missing |
| `udp:HOST:PORT` | UDP datagrams of at most 1400 bytes |
| `tcp:HOST:PORT` | a TCP listener that streams to the first client |
| `cmd:COMMAND` | the standard input of a child process |
| `null` | discard (useful with `--stats`) |

### Video options

The goggles sends its own SPS, PPS and an IDR picture once a second, so the
defaults simply wait for them (`--wait-keyframe`, `--inject never`): attaching
at an arbitrary moment costs at most one second, and every picture after that
decodes. The options below matter only for a stream or capture excerpt that
contains no parameter sets ([PROTOCOL.md §10](PROTOCOL.md#10-making-the-stream-playable)).

| option | meaning |
|---|---|
| `--inject auto\|always\|never` | add built SPS/PPS: never (default), only if none arrive, or always |
| `--parameter-sets FILE` | use the SPS/PPS in FILE (Annex-B or hex) instead of building them |
| `--size WxH` | picture size for a built SPS (default `1920x1080`) |
| `--framerate FPS` | frame rate for a built SPS and for the container (default 30) |
| `--pic-init-qp QP` | `pic_init_qp` for a built PPS (default 26) |

With the defaults, a built SPS/PPS is byte for byte the goggles' own. The
container outputs add the two `ffmpeg` options the stream needs (`-copyinkf`,
`-r 30`), so `-o flight.mp4` is enough.

### Examples

```bash
# lowest-latency local preview
sudo ./third-eye stream -o 'cmd:ffplay -fflags nobuffer -flags low_delay -framedrop -i -'

# serve the stream over TCP and watch it from another machine
sudo ./third-eye stream -o tcp:0.0.0.0:5000
ffplay -fflags nobuffer tcp://raspberrypi.local:5000

# record a playable file (MP4, MKV, MOV, TS or FLV)
sudo ./third-eye stream -o flight.mkv

# raw Annex-B, exactly the bytes off the wire
sudo ./third-eye stream -o file:flight.h264

# measure the link without keeping anything
sudo ./third-eye stream -o null --stats 2

# the iOS transport, with a detailed log kept through Ctrl-C
sudo ./third-eye stream -t ios -vv -o flight.h264 2>&1 | tee -i ios-session.log
```

Stop with Ctrl-C. On `ios` the tool then cancels its reads and restores the
port to gadget mode.

---

## Offline tools

These read hardware USB captures (pcapng from a bus sniffer such as the
[Alex Taradov USB sniffer](https://github.com/ataradov/usb-sniffer), or
Wireshark-style text hex dumps) and need no special hardware. The file names
below are examples.

```bash
# summarise a capture, list the 10 most common DUML commands, extract the video
./third-eye decode android-session.pcapng --commands 10 -o file:out.h264

# extract a capture's video as a playable MP4
./third-eye decode android-session.pcapng -o mp4:out.mp4

# annotated tunnel listing (DUML decoded, frame boundaries marked)
./third-eye dump android-session.pcapng --limit 20

# annotated enumeration and AOA or iAP2 control transfers
./third-eye dump android-session.pcapng --control --limit 30

# decode the iAP2 session of an iOS capture, message by message
./third-eye iap2 ios-session.pcapng

# ...and compare the replies of this package's iAP2 state machine with the iPhone's
./third-eye iap2 ios-session.pcapng --compare

# diagnostic: brute-force pic_init_qp (only useful on an excerpt without
# parameter sets; the real value is 26)
./third-eye tune excerpt.pcapng
```

`decode` on a recording of a handset session:

```
$ ./third-eye decode android-session.pcapng
capture:            android-session.pcapng
usb payload bytes:  9501740
tunnel packets:     5957  (resynchronised over 0 stray bytes)
video packets:      2405  (8956548 bytes, 322 complete access units)
control frames:     3552  (0 with a bad CRC-16)
H.264 NAL units:    non-IDR slice x300, IDR slice x11, SPS x11, PPS x11, AUD x311
...
```

`./third-eye decode -o out.mp4 android-session.pcapng` on the same file gives
302 pictures, 1920×1080 High profile level 5.2, with no decoding errors. The
one `ffmpeg` message, "missing picture in access unit", is cosmetic: DJI puts
the access-unit delimiter at the end of each picture, so the stream ends on a
delimiter with no picture after it.

When a capture holds no video, `decode` says how far the session got and what
that points to: nothing on the bus, a device the goggles enumerated and then
ignored, a status stage that never completed, an accessory that never let go
of the controller, a role swap with no host taking over, or a link with
control traffic but no app registration.

On a capture of an iOS session taken at the Pi's port, `decode` also checks
whether the Pi received what the goggles sent: whether each goggles request
that asked for a reply was answered, and whether the host ACKed and then
dropped any short packets. A healthy session shows every request answered and
`host reads: none of … short packets … was polled past within 12 us`
([PROTOCOL.md §9.3](PROTOCOL.md#93-reading-the-tunnel-as-host)).

---

## Using the library

The protocol layers are plain Python with no dependencies. Demultiplexing a
byte stream read from either transport:

```python
from pryer import duml, tunnel

demux = tunnel.Demuxer()
assembler = tunnel.AccessUnitAssembler()

for packet in demux.feed(bulk_bytes):
    if packet.is_video:
        access_unit = assembler.push(packet)
        if access_unit is not None:
            handle_h264_access_unit(access_unit)
    elif packet.is_control:
        for frame in duml.parse_all(packet.payload):
            print(frame)        # DUML flight_ctrl.0->mobile_app.0 seq=... 0x03/0x8F ...
```

Reading the tunnel out of a capture:

```python
from pryer import capture

data = capture.bulk_stream("android-session.pcapng")    # goggles -> app bytes
```

| module | contents |
|---|---|
| `pryer.tunnel` | the `55 CC` multiplexer, H.264 access-unit assembly |
| `pryer.duml` | DUML frame codec, both CRCs, address and command names |
| `pryer.app` | the app side of the control channel: registration, replies |
| `pryer.pipeline` | bulk bytes → H.264 and decoded control frames, with statistics |
| `pryer.h264` | bitstream reader, slice-header parsing, parameter-set inference and building |
| `pryer.sinks` | the output targets, including container muxing through `ffmpeg` |
| `pryer.aoa` | AOA constants and the phone and accessory descriptor sets |
| `pryer.accessory` | the two-phase AOA handshake on raw-gadget, exposing the bulk pipe (`AoaAccessory`) |
| `pryer.usbdesc` | USB descriptor builders: standard, CDC, USB Audio 1.0, HID |
| `pryer.rawgadget` | ctypes binding for `/dev/raw-gadget` |
| `pryer.linkio` | the asynchronous writer both transports use, so a write never holds up a read |
| `pryer.mfi` | iPhone impersonation, port role switching, the libusb host driver (`IapHost`) |
| `pryer.iap2` | iAP2 link layer, control-message codec, Apple-device state machine |
| `pryer.libusb` | ctypes binding for `libusb-1.0`, including queued asynchronous bulk reads (`BulkReader`) |
| `pryer.capture` | capture readers, dispatching on format |
| `pryer.pcapng` | pcapng / USB 2.0 wire-packet reader: transactions, transfers, endpoints, control transfers |
| `pryer.linkaudit` | checks a capture for goggles requests left unanswered and packets the host dropped |
| `pryer.cli` | the command-line interface |

`AoaAccessory` and `IapHost` both expose `read()` and `write()` over the
tunnel, so everything above the transport is shared. The Android phase-1
identity is chosen with `AoaAccessory(phone_profile=...)`: `"minimal"` (what
`stream` uses), `"handset"` (a Samsung handset's composite configuration,
confirmed to work) or `"dji"`.

### How the wire bytes are built

| what | built by |
|---|---|
| phone, accessory and iPhone USB descriptors | `pryer.usbdesc` builders, composed in `pryer.aoa` and `pryer.mfi` |
| app registration, identity and heartbeat replies | `app.register_payload`, `version_payload`, `identity_reply_payload`, `heartbeat_reply_payload` |
| every other DUML reply | `duml.Frame.make_ack` with `app.reply_payload` |
| the goggles' SPS and PPS | `h264.build_sps(style=GOGGLES3_STYLE)`, `h264.build_pps(transform_8x8_mode=True)` |
| iAP2 link packets and control messages | `iap2.DeviceSession`, `iap2.power_update_params` |

Where a field's meaning is unknown, the builder gives it a neutral name
(`field1`, `field_a`, …) and the value every handset sends.

---

## Tests

```bash
python3 -m pytest tests/ -q
```

Each file also runs on its own, without pytest:

```bash
python3 tests/test_protocol.py
```

| file | covers |
|---|---|
| `test_protocol.py` | tunnel, DUML, capture readers, the pipeline, `decode` |
| `test_h264.py` | the H.264 bitstream code, inference and parameter-set building |
| `test_built_messages.py` | every built descriptor and message against the bytes real devices send |
| `test_gadget_handshake.py` | the AOA gadget against the goggles' control requests, on a fake raw-gadget |
| `test_phase1_descriptors.py` | the Android phase-1 identities |
| `test_gadget_teardown.py` | releasing the UDC between the two gadget sessions |
| `test_app_session.py` | registration, replies and the asynchronous writer, and `stream` end to end against a fake goggles |
| `test_iap2.py` | the iAP2 link layer, messages and state machine |
| `test_role_switch.py` | the Apple role swap and the Pi's gadget/host role switching, against a fake sysfs |
| `test_host_reads.py` | the queued libusb reader, `IapHost`, the link audit, and `doctor`'s iOS checks |

`tests/fakegadget.py` is a fake `/dev/raw-gadget` that enforces the kernel's
ep0 rules (a call in the wrong direction fails, as it does in the kernel), and
`test_host_reads.py` has a fake libusb that fails a test on any misuse of a
transfer.

Some tests also check the implementation against **reference captures**:
bus recordings of the goggles with real iPhones and Android handsets, and with
this package on a Raspberry Pi 4B. They are not distributed with the source.
Without them those tests are skipped and the rest run. To include them, point
`THIRDEYE_CAPTURES` at the directory holding the files (or put them in a
`captures/` directory beside the checkout):

```bash
THIRDEYE_CAPTURES=/path/to/captures python3 -m pytest tests/ -q
```

The test suite needs no hardware, no root and no third-party packages besides
pytest (optional). A few tests use `ffmpeg`/`ffprobe` or `libusb-1.0` when
present and are skipped otherwise.

---

## Troubleshooting

`sudo ./third-eye doctor` is the first step. `-vv` logs every control request,
and [PROTOCOL.md](PROTOCOL.md) describes what each handshake should look like
on the wire.

| symptom | likely cause and fix |
|---|---|
| `doctor`: no UDC in `/sys/class/udc` | `dtoverlay=dwc2` missing, `dr_mode=host`, or `otg_mode=1` set (it overrides the overlay). Reboot after editing `config.txt`. After an iOS session that was killed, `sudo ./third-eye role gadget` |
| bind fails with `ENODEV` | a wrong `--driver` (for instance `dwc2`). Leave the option off and the name is detected |
| `INIT` fails with `EBUSY` | another gadget driver owns the UDC, typically `g_ether`/`g_serial` from `/etc/modules-load.d` or a configfs gadget. `doctor` names it; remove it or `sudo modprobe -r <driver>` |
| "UDC … is still bound to 'USB Raw Gadget'" | another process has `/dev/raw-gadget` open: `sudo fuser -v /dev/raw-gadget` |
| "the ep0 thread is still blocked in raw-gadget" | neither the soft disconnect nor the signal woke it. Check that `/sys/class/udc/<udc>/soft_connect` exists and report the `-vv` log |
| "never sent a single control request" | nothing on the bus: wrong port (it must be the USB-C one), a charge-only cable, or the goggles off |
| "answering ctrl(…) failed, ending the session" at `ERROR` | an ep0 call was rejected; the message names the request. Please report it with the `-vv` log |
| "enumerated and configured us … and then went quiet" | the goggles declined the phase-1 identity. Try the handset identity, `AoaAccessory(phone_profile="handset")`, and capture the bus if you can |
| "asked for the AOA protocol version but never sent START_ACCESSORY" | the handshake stalled on the goggles' side: check it is powered and linked to the aircraft |
| "goggles did not configure us in accessory mode" | look in the `-vv` log for the endpoint-enable lines |
| link up, control frames rising, `video 0.00 MB` | the goggles did not accept the registration. Look for "goggles accepted the app registration". If "registering with the goggles … attempt N" keeps repeating, check the goggles is linked and showing live video |
| stream stops after about a second | bus resets not absorbed; `-vv` should show `bus DISCONNECT` then a new `configured (generation N)` |
| random dropouts, the Pi reboots | power: see [Hardware requirements](#hardware-requirements) |
| iOS: "could not be switched to host mode" | the log line before names the failed step (unbind, `dtoverlay`, bind). Check `sudo ./third-eye role` and `dmesg \| tail -50` |
| iOS: `modprobe dwc2` fails with "Exec format error" | the module on disk does not match the running kernel, usually a kernel upgrade without a reboot. Reboot |
| iOS: "goggles did not appear as 2ca3:1002" | the port became a host but the goggles was not enumerated. Check `lsusb` and `dmesg`; capture the bus if you can |
| `doctor`: "goggles enumerated in PC mode (2ca3:0020)" | the goggles is on a host port: a Pi 4B USB-A port, or the USB-C port left in host mode. Use the USB-C port, or `sudo ./third-eye role gadget` |
| iOS: video arrives but decodes with errors | try `--transfers 0`; `decode` on a capture of the session tells whether the host lost data |
| iOS: "read size N is more than one URB; using 16384" | a `--read-size` above 16384; harmless |

---

## Credits

* [fpv-wtf/voc-poc](https://github.com/fpv-wtf/voc-poc): the original
  goggles-to-PC proof of concept, and the shape this project follows.
* [CosmoStreamer](https://cosmostreamer.com/wiki/index.php?title=Cosmostreamer_for_DJI_Goggles2/Integra):
  prior art showing that a Raspberry Pi as USB device works with the
  Goggles 2/3.
* [fpvout/DigiView-SBC](https://github.com/fpvout/DigiView-SBC): a Pi client
  for the older goggles.
* [dji-firmware-tools](https://github.com/o-gs/dji-firmware-tools) and
  [samuelsadok/dji_protocol](https://github.com/samuelsadok/dji_protocol):
  DUML documentation.
* [Linux USB Raw Gadget](https://docs.kernel.org/usb/raw-gadget.html): what
  makes the device side possible from userspace.
* Apple's Accessory Interface Specification (R29): the reference for the iAP2
  link layer and the power-update messages.
* [voc-poc issue #15](https://github.com/fpv-wtf/voc-poc/issues/15): the
  discussion of AOA and iOS/MFi on the newer goggles.

## License

MIT License

Copyright (c) 2026 William Robinet willi@mrobi.net

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

