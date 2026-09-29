"""Command line entry point for third-eye."""

from __future__ import annotations

import argparse
import errno
import logging
import os
import signal
import sys
import threading
import time

from . import (aoa, capture, duml, h264, linkaudit, pcapng, rawgadget, sinks,
               tunnel)
from .app import AppSession, VIDEO_AFTER_REGISTER_WARN
from .linkio import AsyncWriter
from .pipeline import StreamPipeline

log = logging.getLogger("pryer")

BANNER = "third-eye -- DJI Goggles 3 USB video receiver for Linux"


# --------------------------------------------------------------------------- #
# stream
# --------------------------------------------------------------------------- #
# The aoa transport's phase-1 identity: the single-interface descriptor set
# (aoa.phone_descriptors("minimal")). The other profiles ("handset", "dji")
# are in pryer.aoa for tests and library use.
AOA_PHONE_PROFILE = "minimal"


def _open_aoa(args):
    """Android Open Accessory: we are the USB gadget for the whole session."""
    from .accessory import AoaAccessory  # imported late: Linux-only
    link = AoaAccessory(driver=args.driver, udc=args.udc,
                        with_adb=not args.no_adb,
                        read_size=args.read_size,
                        handshake_timeout=args.timeout,
                        phone_profile=AOA_PHONE_PROFILE)
    link.open()
    return link


def _open_ios(args):
    """
    iOS / MFi: impersonate an iPhone just long enough to make the goggles
    switch to device mode, then drive it as a USB host and run iAP2.

    The port's role is restored to gadget mode when the session ends (or
    fails), unless --keep-host-role is given, so the next run -- either
    transport -- finds a UDC again.
    """
    from . import mfi
    switching = args.trigger and not args.no_role_switch

    def _restore() -> None:
        if switching and not args.keep_host_role:
            log.info("restoring the port to gadget mode")
            if not mfi.switch_to_gadget_role():
                log.warning("could not restore gadget mode; `sudo "
                            "./third-eye role gadget` or a reboot will")

    if args.trigger:
        if not args.no_role_switch:
            mfi.ensure_gadget_role()
        log.info("phase 1: iPhone impersonation to reach MFi mode")
        try:
            swapped = mfi.trigger_mfi_mode(
                driver=args.driver, udc=args.udc, timeout=args.timeout,
                switch_to_host=not args.no_role_switch)
        except mfi.RoleSwitchError:
            _restore()
            raise
        if not swapped:
            raise RuntimeError(
                "the goggles never asked for the Apple role swap; it may not "
                "have recognised us as an Apple device")
    log.info("phase 2: acting as the Apple device over libusb")
    link = mfi.IapHost(read_size=args.read_size or mfi.DEFAULT_READ_SIZE,
                       transfers=getattr(args, "transfers",
                                         mfi.DEFAULT_TRANSFERS),
                       send_detect=not args.no_detect)
    try:
        link.open(timeout=args.timeout, iap_timeout=args.iap_timeout)
    except BaseException:
        link.close()
        _restore()
        raise
    link.after_close = _restore
    return link


TRANSPORTS = {"aoa": _open_aoa, "ios": _open_ios}


def _make_injector(args: argparse.Namespace):
    """Build the SPS/PPS injector from the command line (None if disabled)."""
    if getattr(args, "inject", "auto") == "never":
        return None
    override = None
    if getattr(args, "parameter_sets", None):
        override = h264.load_parameter_sets(args.parameter_sets)
        log.info("using parameter sets from %s (%d bytes)",
                 args.parameter_sets, len(override))
    width, height = args.size
    return h264.ParameterSetInjector(
        args.inject, width=width, height=height, fps=args.framerate,
        override=override, pic_init_qp=args.pic_init_qp)


def _parse_size(text: str) -> tuple[int, int]:
    try:
        w, h = text.lower().replace("*", "x").split("x")
        return int(w), int(h)
    except ValueError:
        raise argparse.ArgumentTypeError(
            "size must look like 1920x1080, got %r" % text) from None


def cmd_stream(args: argparse.Namespace) -> int:
    sink = sinks.make_sink(args.output, fps=args.framerate)
    stop = threading.Event()

    def _sigint(*_):
        stop.set()

    # Ctrl-C during the handshake raises KeyboardInterrupt, so every phase
    # unwinds through its own cleanup. The handler below is installed only
    # afterwards: installed first, it would turn Ctrl-C into a flag nobody
    # reads until streaming begins, and a handshake waiting for a device that
    # cannot appear could not be interrupted.
    try:
        link = TRANSPORTS[args.transport](args)
    except KeyboardInterrupt:
        log.error("interrupted during the handshake")
        sink.close()
        return 130
    except Exception as exc:
        log.error("%s", exc)
        sink.close()
        return 1

    signal.signal(signal.SIGINT, _sigint)
    signal.signal(signal.SIGTERM, _sigint)

    # Writes go through a queue and a thread of their own (pryer.linkio), so
    # a write the goggles is slow to collect never holds up the next read.
    writer = AsyncWriter(link.write)
    app = AppSession(writer, auto_ack=not args.no_ack,
                     register=args.register)
    try:
        injector = _make_injector(args)
    except (OSError, ValueError) as exc:
        log.error("%s", exc)
        writer.close()
        sink.close()
        link.close()
        return 1
    pipe = StreamPipeline(sink, on_control=app.on_control_frame,
                          whole_frames=args.whole_frames,
                          wait_for_keyframe=args.wait_keyframe,
                          injector=injector)

    # Only queued here; the writer thread sends them while we already read.
    # No app start-up traffic on either transport: video needs only this
    # registration (PROTOCOL.md section 7).
    app.start()            # 0x00/0x88 registration: this is what starts video
    if not args.register:
        log.warning("--no-register: the goggles will not send video until "
                    "an app registers with it (see PROTOCOL.md section 7)")

    last_report = time.monotonic()
    warned_no_video = False
    try:
        while not stop.is_set():
            try:
                data = link.read()
            except OSError as exc:
                if exc.errno == errno.EINTR:
                    # Ctrl-C / SIGTERM while blocked in the bulk read. The
                    # read releases the GIL and returns EINTR rather than
                    # holding every other thread up until data arrives.
                    if stop.is_set():
                        break
                    continue
                log.error("bulk read failed: %s", exc)
                break
            if data:
                pipe.feed(data)
            app.poll()
            if (not warned_no_video and app.registered_at is not None
                    and pipe.stats.video_packets == 0
                    and time.monotonic() - app.registered_at
                    >= VIDEO_AFTER_REGISTER_WARN):
                warned_no_video = True
                log.warning("registered %.0f s ago and still no video; the "
                            "handsets get the first packet within 40 ms",
                            VIDEO_AFTER_REGISTER_WARN)
            if args.stats and time.monotonic() - last_report >= args.stats:
                log.info("%s", pipe.stats.summary())
                last_report = time.monotonic()
    finally:
        writer.close()                 # before link.close(): no ioctl in flight
        pipe.finish()
        log.info("final: %s", pipe.stats.summary())
        log.info("app: registered=%s (attempts %d), identity answered %d, "
                 "heartbeats answered %d, writes %d, dropped %d",
                 "yes" if app.registered else "no", app.register_attempts,
                 app.identified, app.heartbeats, writer.written,
                 writer.dropped)
        link.close()
        after = getattr(link, "after_close", None)
        if after is not None:
            after()
        sink.close()
    return 0


# --------------------------------------------------------------------------- #
# role  (iOS transport helper: put the dwc2 port into a given role)
# --------------------------------------------------------------------------- #
def cmd_role(args: argparse.Namespace) -> int:
    from . import mfi
    device = mfi.dwc2_device()
    if args.action == "status":
        print("dwc2 controller:   %s" % (device or "not found"))
        print("  driver           %s" % ("loaded" if mfi.dwc2_driver_loaded()
                                         else "NOT loaded"))
        print("  role             %s" % mfi.dwc2_current_role(device))
        if device:
            print("  host buses       %s"
                  % (", ".join(mfi.dwc2_host_buses(device)) or "none"))
        print("UDCs:              %s" % (", ".join(rawgadget.list_udcs())
                                         or "none"))
        overlay = mfi.runtime_dwc2_overlay()
        print("runtime overlay:   %s" % ("dwc2 %s" % overlay if overlay
                                         is not None else "none"))
        mismatch = mfi.dwc2_module_mismatch()
        if mismatch:
            print("warning:           %s" % mismatch)
        return 0
    if args.action == "host":
        ok = mfi.switch_to_host_role()
    else:
        ok = mfi.switch_to_gadget_role()
    print("%s: %s" % (args.action, "ok" if ok else "FAILED"))
    return 0 if ok else 1


# --------------------------------------------------------------------------- #
# decode  (offline, works on the capture text files)
# --------------------------------------------------------------------------- #
def cmd_decode(args: argparse.Namespace) -> int:
    data = capture.bulk_stream(args.capture)
    if capture.is_pcapng(args.capture):
        lost = pcapng.overflows(args.capture)
        if lost:
            log.warning("the sniffer logged %d capture-loss message(s) for "
                        "this file; missing wire data, not a decode fault "
                        "(see pryer.pcapng.overflows)", len(lost))
        if not data:
            print("capture:            %s" % os.path.basename(args.capture))
            for line in _explain_empty_capture(args.capture, bool(lost)):
                print(line)
            return 1
    sink = sinks.make_sink(args.output, fps=args.framerate) \
        if args.output else sinks.NullSink()
    try:
        injector = _make_injector(args) if args.output else None
    except (OSError, ValueError) as exc:
        log.error("%s", exc)
        sink.close()
        return 1
    link_frames: list = []

    def _keep_link(frame):
        if frame.key == (0x00, 0x88):
            link_frames.append(frame)

    pipe = StreamPipeline(sink, whole_frames=args.whole_frames,
                          wait_for_keyframe=args.wait_keyframe,
                          injector=injector, on_control=_keep_link)
    pipe.feed(data)
    pipe.finish()
    st = pipe.stats
    print("capture:            %s" % os.path.basename(args.capture))
    print("usb payload bytes:  %d" % st.bulk_bytes)
    print("tunnel packets:     %d  (resynchronised over %d stray bytes)"
          % (st.tunnel_packets, st.resync_bytes))
    print("video packets:      %d  (%d bytes, %d complete access units)"
          % (st.video_packets, st.video_bytes, st.access_units))
    print("control frames:     %d  (%d with a bad CRC-16)"
          % (st.control_frames, st.bad_crc))
    if st.nal_types:
        print("H.264 NAL units:    " + ", ".join(
            "%s x%d" % (tunnel.NAL_TYPES.get(t, "type%d" % t), n)
            for t, n in sorted(st.nal_types.items())))
    if (injector is not None and injector.injected
            and not injector.matches_encoder):
        inf = injector.inference
        print("parameter sets:     SYNTHESISED %dx%d @ %g fps, pic_init_qp %d "
              "-- the goggles sends real ones about once a second, so this "
              "usually means the capture is shorter than that window"
              % (args.size[0], args.size[1], args.framerate, args.pic_init_qp))
        if inf is not None:
            print("  from the slice headers: %s" % inf.hypothesis.describe())
            if inf.candidates > 1:
                print("  (%d hypotheses fit the slice headers; the simplest "
                      "was used)" % inf.candidates)
    elif injector is not None and injector.stream_had_parameter_sets:
        print("parameter sets:     the stream had its own, left untouched")
    if capture.is_pcapng(args.capture):
        for line in _registration_lines(args.capture, link_frames, st):
            print(line)
        # Did the app side receive what is on the wire? (PROTOCOL.md 9.3)
        try:
            audit = linkaudit.describe(args.capture)
        except Exception as exc:  # noqa: BLE001 -- a report, never fatal
            log.debug("link audit failed", exc_info=True)
            audit = ["link audit:         skipped (%s: %s)"
                     % (type(exc).__name__, exc)]
        for line in audit:
            print(line)
    if args.commands and st.cmds:
        print("\ntop DUML commands (cmd_set/cmd_id):")
        for (cs, cid), n in st.cmds.most_common(args.commands):
            print("  set=0x%02x(%-11s) id=0x%02x  x%d"
                  % (cs, duml.CMDSET.get(cs, "?"), cid, n))
    sink.close()
    return 0


def _registration_lines(path: str, down_link_frames, st) -> list[str]:
    """
    Report the 0x00/0x88 app registration (PROTOCOL.md section 7).

    *down_link_frames* are the goggles' 0x00/0x88 frames from the decoded
    stream. The app's side is read from the reverse endpoint. With control
    traffic but no video, a missing registration explains the capture: the
    goggles was never asked for video.
    """
    from . import tunnel as _tunnel
    _down, up = pcapng.tunnel_endpoints(path)
    app_ops: list[int] = []
    if up is not None:
        for t in pcapng.transfers(path, up.addr, up.ep, up.direction):
            for pkt in _tunnel.demux_bytes(t.data)[0]:
                if pkt.is_video:
                    continue
                for f in duml.parse_all(pkt.payload):
                    if f.key == (0x00, 0x88) and f.payload:
                        app_ops.append(f.payload[0]
                                       | (0x100 if f.is_response else 0))
    registers = app_ops.count(0x17)
    accepted = sum(1 for f in down_link_frames
                   if f.is_response and f.payload[:1] == b"\x18")
    heartbeats = sum(1 for f in down_link_frames
                     if not f.is_response and f.payload[:1] == b"\x19")
    out = ["app registration:   %d request(s) from the app, %d accepted, "
           "%d goggles heartbeat(s)" % (registers, accepted, heartbeats)]
    if st.video_packets == 0 and st.control_frames and not registers \
            and not heartbeats:
        out.append("  -> control traffic but no video, and the goggles was "
                   "never registered with (no 0x00/0x88 17.. from the app). "
                   "Without it the goggles does not send video; `stream` "
                   "sends it by default.")
    elif not registers and heartbeats:
        out.append("  (no registration on the wire, but the heartbeats show "
                   "one happened before or during a capture gap)")
    return out


def _explain_empty_capture(path: str, had_loss: bool) -> list[str]:
    """
    Say why a capture yielded no tunnel bytes instead of printing zeroes.

    A capture can be complete and still hold no payload: the accessory link is
    negotiated and then nothing is ever streamed over it. A handset with no
    app holding the accessory open does exactly that: a textbook AOA
    handshake, then hundreds of thousands of PING and IN tokens that the phone
    answers with NAK and no data. Reporting "0 tunnel packets" alone reads like a decoder
    fault, so distinguish the possibilities the capture can actually settle.
    """
    out = ["tunnel bytes:       0 -- no bulk data on any endpoint in this file"]
    transfers = list(pcapng.control_transfers(path))
    reqs = {(c.bm_request_type, c.b_request) for c in transfers}
    aoa = sorted(r for bt, r in reqs if r in (51, 52, 53) and bt in (0x40, 0xC0))
    # Distinguish "the device was enumerated and then ignored" from "this is a
    # fragment". The first is a real, reproducible failure, and it points at
    # the device side, not at the capture.
    verdict = _diagnose_declined_enumeration(transfers)
    if verdict:
        out.extend(verdict)
        if had_loss:
            out.append("                    the sniffer also logged capture "
                       "loss, so treat the above as provisional.")
        return out
    stuck = _diagnose_missing_accessory_mode(path, transfers) if 53 in aoa \
        else []
    if stuck:
        out.extend(stuck)
    elif 53 in aoa:
        out.append(
            "                    the AOA handshake did complete "
            "(GET_PROTOCOL/SEND_STRING/START_ACCESSORY all present), so the "
            "link came up and the phone simply never sent anything: no app had "
            "the accessory open. Nothing to decode, and nothing wrong here.")
    elif aoa:
        out.append("                    the AOA handshake is incomplete "
                   "(saw requests %s, expected 51, 52 and 53)." % aoa)
    elif (0x40, 0x51) in reqs:
        handover = _diagnose_ios_handover(path, transfers)
        if handover:
            out.extend(handover)
        else:
            out.append("                    the iOS role swap (request 0x51) "
                       "was issued but no tunnel followed; SET_INTERFACE(1, "
                       "alt 1) is what opens the bulk pair on that path.")
    else:
        out.append("                    no accessory handshake in this file "
                   "either -- it may be a fragment that predates the link "
                   "coming up.")
    if had_loss:
        out.append("                    the sniffer also logged capture loss, "
                   "so treat the above as provisional.")
    return out


def _diagnose_ios_handover(path: str, transfers: list) -> list[str]:
    """
    Report an Apple role swap that nobody took over from.

    After request 0x51 a real iPhone becomes the host: it resets the goggles
    about 370 ms later and sends SET_ADDRESS a few ms after that. If the
    capture holds no control transfer at all after the swap, the device side
    acknowledged it and then never came back as a host: the goggles attaches
    as a device ~200 ms after the request and waits, typically because the
    Pi's switch to host mode failed.
    """
    swaps = [c for c in transfers
             if c.bm_request_type == 0x40 and c.b_request == 0x51]
    if not swaps:
        return []
    t51 = swaps[-1].ts
    if any(c.ts > t51 for c in transfers):
        return []
    events = [(ts, msg) for ts, msg in pcapng.log_messages(path)]
    end = max([ts for ts, _ in events] + [t51])
    attach = None
    for ts, msg in events:
        if ts > t51 and msg.startswith("Line state: J"):
            attach = ts          # the last pull-up seen is the goggles'
    out = ["                    the iOS role swap (request 0x51) was "
           "acknowledged, but nothing enumerated the goggles afterwards: no "
           "control transfer follows it (a real iPhone resets the goggles "
           "~370 ms after the request)."]
    if attach is not None:
        out.append("                    the goggles attached as a USB device "
                   "%.0f ms after the request and waited %.1f s, to the end "
                   "of the capture, with no host on the bus -- this side "
                   "never became the host. Check the role switch in the "
                   "session log (`sudo ./third-eye role status`)."
                   % ((attach - t51) / 1e6, (end - attach) / 1e9))
    return out


# Android Open Accessory product ids (accessory, +adb, audio variants).
_AOA_VID = 0x18D1
_AOA_PIDS = range(0x2D00, 0x2D06)


def _diagnose_missing_accessory_mode(path: str, transfers: list) -> list[str]:
    """
    Report START_ACCESSORY followed by no accessory-mode enumeration.

    A real handset drops off the bus after START_ACCESSORY and comes back as
    ``18d1:2d0x`` about 0.5 s later. The failure this reports looks different:
    the device acknowledges START_ACCESSORY and then stays attached as the
    phone, the bus carrying only SOFs, and never presents the accessory
    device. On a gadget that means phase 1 never released the UDC, so phase
    2's RUN failed with EBUSY (PROTOCOL.md 8.4). It must not be reported as
    "nothing wrong here", the message meant for a link where the accessory
    device *did* enumerate and simply carried no data.

    Returns [] whenever an accessory-mode device descriptor appears after
    START_ACCESSORY, so real handset sessions are unaffected.
    """
    start = next((c.ts for c in transfers
                  if c.bm_request_type == 0x40 and c.b_request == 53), None)
    if start is None:
        return []
    for c in transfers:
        if (c.ts > start and c.b_request == 6 and c.setup[3] == 0x01
                and len(c.data) >= 12):
            vid = int.from_bytes(c.data[8:10], "little")
            pid = int.from_bytes(c.data[10:12], "little")
            if vid == _AOA_VID and pid in _AOA_PIDS:
                return []
    after = [c for c in transfers if c.ts > start]
    last = after[-1].ts if after else start
    resets = []
    try:
        resets = [ts for ts, text in pcapng.log_messages(path)
                  if ts > start and "Bus Reset" in text]
    except (OSError, ValueError):
        pass
    detach = ("the sniffer logs the next bus reset (the detach) %.2f s later"
              % ((resets[0] - start) / 1e9)) if resets else \
        "the sniffer logs no bus reset after it at all"
    return [
        "                    the AOA handshake completed "
        "(GET_PROTOCOL/SEND_STRING/START_ACCESSORY all present), but the "
        "device never came back in accessory mode: no 18d1:2d0x device "
        "descriptor after START_ACCESSORY.",
        "                    after START_ACCESSORY the device finished %d "
        "control transfer(s) within %.0f ms and then went idle; %s. A real "
        "phone detaches at once and re-enumerates about 0.5 s later."
        % (len(after), (last - start) / 1e6, detach),
        "                    On a Pi run this means phase 1 did not let go of "
        "the UDC, so phase 2 never attached: typically an ep0 thread still "
        "blocked on the raw-gadget fd, and RUN failing with EBUSY "
        "(PROTOCOL.md 8.4).",
    ]


def _diagnose_declined_enumeration(transfers: list) -> list[str]:
    """
    Report a capture where the host enumerated a device and then walked away.

    The picture: a gadget is enumerated as 04e8:685d, answers every descriptor
    request without a stall, is put into configuration 1 -- and then the
    goggles issues nothing further. That is not a truncated capture and not a
    cable fault. There are two possible causes: the gadget never completed the
    status stage of SET_CONFIGURATION (the goggles polls it and is NAKed; see
    rawgadget, "The ep0 direction rule"), or the goggles declined the device
    after reading its configuration. This decoder pairs SETUPs with data
    stages only, so it cannot tell the two apart; the message names both.
    Printing "no accessory handshake in this file" for it would hide what the
    capture does prove.
    """
    if not transfers:
        return []
    # Self-gating, so this is safe to call on any capture: if any accessory
    # negotiation happened at all, the device was not declined.
    if any((c.b_request in (51, 52, 53) and c.bm_request_type in (0x40, 0xC0))
           or (c.b_request == 0x51 and c.bm_request_type == 0x40)
           for c in transfers):
        return []
    configured = any(c.b_request == 9 and c.bm_request_type == 0x00
                     and c.w_value != 0 for c in transfers)
    if not configured:
        return ["                    the host began enumerating the device (%d "
                "control transfers) but never issued SET_CONFIGURATION, so "
                "enumeration itself failed." % len(transfers)]
    config = next((c.data for c in transfers
                   if c.b_request == 6 and c.setup[3] == 0x02
                   and len(c.data) > 9), b"")
    classes = _interface_classes(config)
    span_ms = (transfers[-1].ts - transfers[0].ts) / 1e6
    out = [
        "                    the host enumerated this device and selected "
        "configuration 1 (%d control transfers over %.0f ms, %d stalled) and "
        "then issued nothing else -- no AOA GET_PROTOCOL(51), no Apple request "
        "0x51." % (len(transfers), span_ms,
                   sum(1 for c in transfers if c.stalled)),
        "                    That is not a capture or cable problem. Either "
        "the device never completed the status stage of SET_CONFIGURATION -- "
        "look for the goggles' IN tokens on ep0 being NAKed until the end of "
        "the capture (a gadget acknowledging it in the wrong direction; see "
        "PROTOCOL.md 8.2) -- or it is the goggles "
        "declining the device after reading its configuration descriptor.",
    ]
    if config:
        out.append("                    advertised interfaces: %s"
                   % (", ".join(classes) or "none"))
    if not any(c == "ff/42/01" for c in classes):
        out.append("                    the adb interface ff/42/01 that both "
                   "real handsets present is missing; "
                   "the handset's 121-byte composite configuration "
                   "(aoa.phone_descriptors(\"handset\")) includes it.")
    return out


def _interface_classes(config: bytes) -> list[str]:
    """class/subclass/protocol of every interface in a configuration."""
    out, off = [], 0
    while off + 2 <= len(config):
        length, dtype = config[off], config[off + 1]
        if length < 2:
            break
        if dtype == 0x04 and length >= 9:
            out.append("%02x/%02x/%02x" % (config[off + 5], config[off + 6],
                                           config[off + 7]))
        off += length
    return out


# --------------------------------------------------------------------------- #
# dump  (annotated packet-by-packet listing of a capture)
# --------------------------------------------------------------------------- #
def cmd_dump(args: argparse.Namespace) -> int:
    pkts = capture.usb_packets(args.capture)
    if args.control:
        _dump_control_transfers(pkts, args.limit, args.start)
        return 0
    stream = b"".join(p for _, p in pkts)
    demux = tunnel.Demuxer()
    n = 0
    for pkt in demux.feed(stream):
        n += 1
        if n <= args.start:
            continue
        if pkt.is_control:
            for f in duml.parse_all(pkt.payload):
                print("[%5d] ctrl  %s" % (n, f))
        else:
            print("[%5d] %s  %s%s" % (
                n, pkt, pkt.payload[:16].hex(" "),
                "  <END OF ACCESS UNIT>" if pkt.ends_access_unit else ""))
        if args.limit and n - args.start >= args.limit:
            break
    return 0


def _dump_control_transfers(pkts, limit: int, start: int) -> None:
    """Print the enumeration / AOA / iAP2 handshake in readable form."""
    n = 0
    for _pid, payload in pkts:
        setup = capture.decode_setup(payload)
        line = None
        if setup:
            line = setup
        elif payload[:2] == b"\xff\x55":
            line = "iAP2 link detect  %s" % payload.hex(" ")
        elif payload[:2] == b"\xff\x5a":
            line = _iap2(payload)
        elif payload[:2] == tunnel.MAGIC:
            line = "DJI tunnel  ch=0x%02x len=%d" % (
                payload[2], int.from_bytes(payload[4:8], "little"))
        elif len(payload) >= 2 and payload[1] in capture.DESC_TYPES \
                and payload[0] == len(payload):
            line = "descriptor %-8s %s" % (
                capture.DESC_TYPES[payload[1]], payload.hex(" "))
        if line is None:
            if not payload:
                continue
            line = "data(%d) %s" % (len(payload), payload[:32].hex(" "))
        n += 1
        if n <= start:
            continue
        print("[%4d] %s" % (n, line))
        if limit and n - start >= limit:
            break


_IAP2_CONTROL = {0x80: "SYN", 0xC0: "SYN|ACK", 0x40: "ACK", 0x00: "-"}


def _iap2(p: bytes) -> str:
    if len(p) < 9:
        return "iAP2 (short) %s" % p.hex(" ")
    length = int.from_bytes(p[2:4], "big")
    ctl, seq, ack, sess = p[4], p[5], p[6], p[7]
    body = p[9:length - 1] if length <= len(p) else p[9:]
    extra = ""
    if body[:2] == b"\x40\x40" and len(body) >= 6:
        extra = "  ctrl-msg id=0x%04x len=%d" % (
            int.from_bytes(body[4:6], "big"),
            int.from_bytes(body[2:4], "big"))
    return ("iAP2 len=%-4d %-8s seq=0x%02x ack=0x%02x session=0x%02x  %s%s"
            % (length, _IAP2_CONTROL.get(ctl, "0x%02x" % ctl), seq, ack, sess,
               body[:24].hex(" "), extra))


# --------------------------------------------------------------------------- #
# iap2  (offline)
# --------------------------------------------------------------------------- #
def cmd_iap2(args: argparse.Namespace) -> int:
    from . import iap2

    raw = _iap2_link_bytes(args.capture)
    if not raw:
        print("no iAP2 traffic in this capture -- the iAP2 control link only "
              "appears on the iOS transport, on its own bulk endpoint pair "
              "(interface 0). Android/AOA captures have no iAP2 phase.")
        return 1
    if args.compare:
        return _compare_iap2(raw)
    for line in iap2.describe_stream(raw):
        print(line)
    return 0


def _iap2_link_bytes(path: str) -> bytes:
    """
    The iAP2 control link only, never the whole capture.

    Reading every USB payload and scanning for the ``ff 5a`` sync word finds
    stray matches inside the H.264 video channel and invents packets from them,
    so the link is read from its own endpoints instead
    (`pcapng.iap2_link_bytes`). The text dumps carry no endpoint information, so
    for those there is nothing better than the whole stream.
    """
    if capture.is_pcapng(path):
        return pcapng.iap2_link_bytes(path)
    return b"".join(payload for _pid, payload in capture.usb_packets(path))


def _compare_iap2(raw: bytes) -> int:
    """
    Feed the accessory's captured packets to our Apple-device state machine and
    check that it answers with the same control messages the iPhone did.

    This is a conformance check of `iap2.DeviceSession`: every reply is
    generated by the state machine, none is taken from the capture.
    (`--replay` is accepted as an alias.)
    """
    from . import iap2

    accessory, device = iap2.split_sides(raw)
    if not accessory:
        print("no iAP2 traffic in this capture")
        return 1

    session = iap2.DeviceSession(initial_seq=0xAC, rng=lambda n: bytes(n))
    produced: list[int] = []
    for pkt in accessory:
        for reply in iap2.PacketReader().feed(session.feed(pkt.encode())):
            produced += [m.msg_id for m in iap2.decode_messages(reply.payload)]
    expected = [m.msg_id for pkt in device
                for m in iap2.decode_messages(pkt.payload)]

    width = max(len(iap2.message_name(m)) for m in produced + expected)
    print("%-*s   %s" % (width, "our reply", "captured iPhone"))
    for i in range(max(len(produced), len(expected))):
        ours = iap2.message_name(produced[i]) if i < len(produced) else "-"
        theirs = iap2.message_name(expected[i]) if i < len(expected) else "-"
        print("%-*s   %s   %s" % (width, ours, theirs,
                                  "ok" if ours == theirs else "MISMATCH"))
    print()
    if session.identification:
        print(session.identification.describe())
        print()
    print("link=%s authenticated=%s identified=%s"
          % (session.linked, session.authenticated, session.identified))
    return 0 if produced == expected and session.ready else 1


# --------------------------------------------------------------------------- #
# doctor
# --------------------------------------------------------------------------- #
def _loaded_modules() -> set[str]:
    try:
        with open("/proc/modules") as fh:
            return {line.split()[0] for line in fh if line.strip()}
    except OSError:
        return set()


def cmd_doctor(_args: argparse.Namespace) -> int:
    print(BANNER)
    print()
    model = rawgadget.board_model()
    print("board:             %s" % (model or "unknown (not a device tree "
                                             "platform)"))
    print("kernel:            %s" % os.uname().release)
    print("root:              %s" % ("yes" if os.geteuid() == 0 else "no"))
    print("/dev/raw-gadget:   %s" % ("present" if rawgadget.available()
                                     else "MISSING"))
    mods = _loaded_modules()
    print("modules:           %s" % ", ".join(
        "%s=%s" % (m, "loaded" if m in mods else "not loaded")
        for m in ("dwc2", "raw_gadget")))

    # The two names raw-gadget needs, side by side. They are not
    # interchangeable and neither of them is "dwc2" on a Pi 4B, which is the
    # single most common reason a working setup still fails to bind.
    udcs = rawgadget.list_udcs()
    print("UDCs:              %s" % (", ".join(udcs) if udcs else "none"))
    for udc in udcs:
        print("  %-16s driver name %-16s state=%s%s"
              % (udc, repr(rawgadget.udc_driver_name(udc)),
                 rawgadget.udc_state(udc),
                 "  bound to: " + rawgadget.udc_function(udc)
                 if rawgadget.udc_function(udc) else ""))

    cfg = rawgadget.boot_config()
    if cfg["path"]:
        print("config.txt:        %s" % cfg["path"])
        print("  dtoverlay=dwc2   %s" % ("yes" if cfg["dwc2"] else "NO"))
        print("  dr_mode          %s" % (cfg["dr_mode"] or
                                         ("otg (overlay default)"
                                          if cfg["dwc2"] else "n/a")))
        print("  otg_mode         %s" % (cfg["otg_mode"] or "not set (good)"))

    problems = rawgadget.diagnose()
    print()
    if problems:
        print("Not ready to stream:")
        for p in problems:
            print("  - %s" % p)
        print()
        print("Reminder: on the Android transport the Goggles 3 is the USB "
              "*host*, so the Linux side must be a USB *gadget*. A "
              "desktop/laptop PC cannot do this; use a Raspberry Pi "
              "Zero/Zero 2 W or a Pi 4B USB-C port.")
        _doctor_pi_hints()
        _doctor_ios()
        return 1
    print("Ready for the Android (AOA) transport. Connect the goggles to this "
          "board's peripheral port and run `third-eye stream`.")
    _doctor_pi_hints()
    _doctor_ios()
    return 0


def _doctor_pi_hints() -> None:
    """Wiring and power advice that only applies to a Raspberry Pi 4B."""
    if not rawgadget.is_pi4():
        return
    print()
    print("Raspberry Pi 4B notes")
    print("  - Only the USB-C power connector can be a gadget port. The four")
    print("    USB-A ports hang off the VL805 XHCI host controller and cannot")
    print("    act as a device, so the goggles must go to the USB-C port.")
    print("  - The UDC and the gadget driver are both named 'fe980000.usb'")
    print("    here, not 'dwc2'. Both are auto-detected; only pass --udc /")
    print("    --driver if you have a reason to override them.")
    print("  - Power: the USB-C port's VBUS is wired straight to the 5V rail")
    print("    with no USB-PD negotiation. If the goggles also supplies power")
    print("    on that cable while the Pi is fed from GPIO or PoE, the two")
    print("    supplies fight each other. Power the Pi from GPIO 5V or a PoE")
    print("    HAT and use a cable with the VBUS line cut (or a power-blocking")
    print("    adapter) for the data link.")
    print("  - dwc2 here is high speed only (480 Mbit/s), with 8 endpoints --")
    print("    ample for this transport's two bulk endpoints.")
    print("  - dwc2 reports a bus reset as DISCONNECT and never as RESET, and")
    print("    its vbus_draw ioctl always fails (no usb_phy is bound). Both")
    print("    are handled; they are not faults.")


def _doctor_ios() -> None:
    from . import mfi
    print()
    print("iOS / iAP2 transport")
    for ok, text in mfi.diagnose():
        print("  %s %s" % ("ok  " if ok else "no  ", text))
    print()
    print("  The iOS path needs both roles on one port: gadget for the iPhone")
    print("  impersonation, then host for iAP2. On a Pi 4B, stream re-probes")
    print("  dwc2 as a host (unbind, runtime overlay dr_mode=host, bind) and")
    print("  puts it back afterwards; it never unloads the module.")
    print("  `third-eye role` shows the current state.")
    print("  Until the role swap the goggles is the USB host, so it cannot be")
    print("  seen on the bus from here before a run; that is not a fault.")


# --------------------------------------------------------------------------- #
# --------------------------------------------------------------------------- #
# tune  (offline: use a decoder as an oracle for the un-inferable PPS fields)
# --------------------------------------------------------------------------- #
def cmd_tune(args: argparse.Namespace) -> int:
    data = capture.bulk_stream(args.capture)
    video = b"".join(pkt.payload for pkt in tunnel.Demuxer().feed(data)
                     if pkt.is_video)
    if not video:
        print("no video in %s" % os.path.basename(args.capture))
        return 1
    slices = [n for n in h264.split_annexb(video)
              if (n[0] & 0x1F) in (h264.NAL_SLICE, h264.NAL_IDR)]
    inferred = h264.infer(slices)
    print("slice headers:      %s"
          % (inferred.describe() if inferred else "could not infer"))
    if inferred is None:
        return 1
    print()
    print("searching pic_init_qp with ffmpeg as the oracle -- a wrong value")
    print("still parses but decodes to noise, because CABAC contexts are")
    print("initialised from SliceQPY = pic_init_qp + slice_qp_delta.")
    qps = [args.qp] if args.qp is not None else range(52)
    width, height = args.size
    try:
        results = h264.search_pps(video, width=width, height=height,
                                  fps=args.framerate,
                                  hyp=inferred.hypothesis, qps=qps)
    except FileNotFoundError:
        log.error("ffmpeg is not on PATH; `tune` needs a decoder as its oracle")
        return 1
    print()
    for res in results[:max(args.top, 1)]:
        print("  " + res.describe())
    best = results[0]
    print()
    if best.errors == 0 and best.coverage > 0.005:
        print("best: pic_init_qp %d  (use --pic-init-qp %d)"
              % (best.pic_init_qp, best.pic_init_qp))
    else:
        print("inconclusive: no candidate both decoded cleanly and produced a")
        print("non-blank picture. Expected for a short excerpt with no intra")
        print("refresh in it -- a desynchronised CABAC decoder can terminate")
        print("early and silently, so zero errors alone means little.")
    return 0


def _add_video_args(sp: argparse.ArgumentParser) -> None:
    """Options shared by `stream` and `decode`: how the H.264 is made playable."""
    g = sp.add_argument_group(
        "playable output",
        "The goggles sends its own SPS and PPS about once per second, so the "
        "normal path is to wait for them rather than invent any: --inject "
        "never (the default) plus --wait-keyframe (also on by default). These "
        "options only matter if you start mid-stream and cannot afford to wait "
        "a second, or if you are decoding a capture that begins after a "
        "parameter set. See PROTOCOL.md section 10.")
    g.add_argument("--size", type=_parse_size,
                   default=(h264.GOGGLES3_WIDTH, h264.GOGGLES3_HEIGHT),
                   metavar="WxH",
                   help="picture size to write into the synthesised SPS "
                        "(default %dx%d, as measured)"
                        % (h264.GOGGLES3_WIDTH, h264.GOGGLES3_HEIGHT))
    g.add_argument("--framerate", type=float, default=h264.GOGGLES3_FPS,
                   metavar="FPS",
                   help="frame rate for the SPS and for the container muxer "
                        "(default %g, as measured)" % h264.GOGGLES3_FPS)
    g.add_argument("--inject", choices=("auto", "always", "never"),
                   default="never",
                   help="never: rely on the parameter sets the goggles sends "
                        "(default). auto: add them only if none arrive within "
                        "the probe window. always: add them regardless.")
    g.add_argument("--parameter-sets", metavar="FILE", default=None,
                   help="use the SPS/PPS in FILE (Annex-B or hex) instead "
                        "of building them")
    g.add_argument("--pic-init-qp", type=int, default=h264.GOGGLES3_PIC_INIT_QP,
                   metavar="QP",
                   help="pic_init_qp for the built PPS (default %d, read "
                        "straight out of the goggles' own PPS)"
                        % h264.GOGGLES3_PIC_INIT_QP)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="third-eye", description=BANNER)
    p.add_argument("-v", "--verbose", action="count", default=0)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("stream", help="negotiate AOA and stream live video")
    s.add_argument("-o", "--output", default="-",
                   help="sink: - | file:PATH | mp4:PATH | mkv:PATH | fifo:PATH "
                        "| udp:H:P | tcp:H:P | cmd:CMD | null   "
                        "(default: stdout)")
    s.add_argument("--udc", default=None,
                   help="UDC device name, i.e. a directory in /sys/class/udc "
                        "(default: auto-detect; 'fe980000.usb' on a Pi 4B)")
    s.add_argument("--driver", default=None,
                   help="UDC driver name for raw-gadget's bind, i.e. the "
                        "kernel's gadget->name (default: auto-detect from "
                        "/sys/class/udc/<udc>/uevent). This is NOT the module "
                        "name: on a Raspberry Pi 4B it is 'fe980000.usb', not "
                        "'dwc2'.")
    s.add_argument("--no-adb", action="store_true",
                   help="advertise accessory-only 18d1:2d00 instead of 2d01")
    s.add_argument("--no-register", dest="register", action="store_false",
                   help="do not register with the goggles (two 0x00/0x88 "
                        "requests to fpga_air.1, retried every second until "
                        "accepted). Without the registration the goggles "
                        "sends no video; this exists for experiments only.")
    s.add_argument("--no-ack", action="store_true",
                   help="do not answer goggles DUML requests")
    s.add_argument("--chunks", dest="whole_frames", action="store_false",
                   help="emit one write per 4 KiB chunk instead of one per "
                        "access unit; only sensible for a local pipe or file, "
                        "never for a network sink")
    s.add_argument("--no-wait-keyframe", dest="wait_keyframe",
                   action="store_false",
                   help="start writing immediately instead of waiting for the "
                        "goggles' next SPS/IDR (arrives within ~1 s)")
    s.set_defaults(whole_frames=True, wait_keyframe=True)
    s.add_argument("-t", "--transport", choices=("aoa", "ios"), default="aoa",
                   help="aoa: pretend to be an Android phone (the goggles "
                        "stays USB host). ios: pretend to be an iPhone, let "
                        "the goggles switch to USB device mode, then speak "
                        "iAP2 to it as the host.")
    s.add_argument("--no-trigger", dest="trigger", action="store_false",
                   help="ios transport: skip the iPhone impersonation phase "
                        "and assume the goggles is already in MFi mode "
                        "(2ca3:1002)")
    s.add_argument("--no-role-switch", action="store_true",
                   help="ios transport: do not switch the port role at all; "
                        "flip it to host yourself. By default the port is "
                        "flipped by unbinding dwc2, applying a runtime overlay "
                        "with dr_mode=host and binding it again -- no module "
                        "reload")
    s.add_argument("--keep-host-role", action="store_true",
                   help="ios transport: leave the port in host mode when the "
                        "session ends instead of switching it back to gadget "
                        "mode")
    s.add_argument("--no-detect", action="store_true",
                   help="ios transport: do not send the iAP2 link-detect "
                        "preamble (ff 55 02 00 ee 10) on open")
    s.add_argument("--iap-timeout", type=float, default=15.0,
                   help="ios transport: seconds to wait for the iAP2 link, "
                        "MFi authentication and identification to complete")
    s.add_argument("--read-size", type=int, default=None,
                   help="bytes per bulk read or transfer. Default: %d for aoa "
                        "(every tunnel packet ends its USB transfer, so a "
                        "gadget read never returns more than one; see "
                        "pryer.tunnel.ACCESSORY_READ_SIZE), %d for ios, which "
                        "is also its maximum: one URB (PROTOCOL.md 9.3)"
                        % (tunnel.ACCESSORY_READ_SIZE,
                           tunnel.DEFAULT_READ_SIZE))
    s.add_argument("--transfers", type=int, default=32, metavar="N",
                   help="ios transport: bulk IN transfers kept queued on the "
                        "tunnel endpoint (default 32), so it is polled "
                        "without a gap and no transfer is cancelled while "
                        "data can still arrive in it. 0 reads synchronously, "
                        "one transfer at a time")
    s.add_argument("--timeout", type=float, default=60.0,
                   help="handshake timeout in seconds")
    s.add_argument("--stats", type=float, default=5.0,
                   help="stats interval in seconds (0 disables)")
    _add_video_args(s)
    s.set_defaults(func=cmd_stream)

    d = sub.add_parser("decode", help="offline: decode a USB capture text file")
    d.add_argument("capture")
    d.add_argument("-o", "--output", default=None,
                   help="write the extracted video here: mp4:PATH or out.mp4 "
                        "for a playable file, file:PATH for raw Annex-B")
    d.add_argument("--chunks", dest="whole_frames", action="store_false",
                   help="write per 4 KiB chunk instead of per access unit")
    d.add_argument("--no-wait-keyframe", dest="wait_keyframe",
                   action="store_false",
                   help="keep the access units that precede the capture's "
                        "first SPS/PPS; a decoder will complain about them "
                        "because they reference a PPS it has not seen yet")
    d.set_defaults(whole_frames=True, wait_keyframe=True)
    d.add_argument("--commands", type=int, default=0,
                   metavar="N", help="also list the N most common DUML commands")
    _add_video_args(d)
    d.set_defaults(func=cmd_decode)

    u = sub.add_parser("dump", help="offline: annotated packet listing")
    u.add_argument("capture")
    u.add_argument("--control", action="store_true",
                   help="decode the USB control/enumeration/iAP2 phase instead "
                        "of the tunnel")
    u.add_argument("--limit", type=int, default=200)
    u.add_argument("--start", type=int, default=0)
    u.set_defaults(func=cmd_dump)

    i = sub.add_parser("iap2", help="offline: decode the iOS/iAP2 handshake")
    i.add_argument("capture")
    i.add_argument("--compare", "--replay", dest="compare",
                   action="store_true",
                   help="drive our Apple-device state machine with the "
                        "captured accessory packets and compare the replies it "
                        "generates with the iPhone's")
    i.set_defaults(func=cmd_iap2)

    t = sub.add_parser("tune", help="offline: search for the PPS fields the "
                                    "slice headers cannot reveal")
    t.add_argument("capture")
    t.add_argument("--size", type=_parse_size,
                   default=(h264.GOGGLES3_WIDTH, h264.GOGGLES3_HEIGHT),
                   metavar="WxH")
    t.add_argument("--framerate", type=float, default=h264.GOGGLES3_FPS,
                   metavar="FPS")
    t.add_argument("--qp", type=int, default=None, metavar="QP",
                   help="test only this pic_init_qp instead of all 52")
    t.add_argument("--top", type=int, default=8,
                   help="how many candidates to print (default 8)")
    t.set_defaults(func=cmd_tune)

    r = sub.add_parser("role", help="show or change the dwc2 port role "
                                    "(iOS transport helper)")
    r.add_argument("action", nargs="?", default="status",
                   choices=("status", "host", "gadget"))
    r.set_defaults(func=cmd_role)

    doc = sub.add_parser("doctor", help="check whether this host can be a gadget")
    doc.set_defaults(func=cmd_doctor)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    level = logging.WARNING if args.verbose == 0 else (
        logging.INFO if args.verbose == 1 else logging.DEBUG)
    # log to stderr so stdout stays a clean video pipe
    logging.basicConfig(level=level, stream=sys.stderr,
                        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    if args.cmd == "stream" and args.verbose == 0:
        logging.getLogger().setLevel(logging.INFO)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
