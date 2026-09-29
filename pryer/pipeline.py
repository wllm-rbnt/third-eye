"""Glue: raw bulk bytes in, H.264 out, telemetry decoded on the side."""

from __future__ import annotations

import logging
import time
from collections import Counter

from . import duml, h264, tunnel

log = logging.getLogger("pryer.pipeline")


class Stats:
    def __init__(self):
        self.t0 = time.monotonic()
        self.bulk_bytes = 0
        self.tunnel_packets = 0
        self.video_bytes = 0
        self.video_packets = 0
        self.access_units = 0
        self.control_frames = 0
        self.bad_crc = 0
        self.resync_bytes = 0
        self.nal_types: Counter[int] = Counter()
        self.cmds: Counter[tuple[int, int]] = Counter()

    @property
    def elapsed(self) -> float:
        return max(time.monotonic() - self.t0, 1e-6)

    def summary(self) -> str:
        mbps = self.video_bytes * 8 / self.elapsed / 1e6
        fps = self.access_units / self.elapsed
        nals = ", ".join("%s=%d" % (tunnel.NAL_TYPES.get(t, "type%d" % t), n)
                         for t, n in sorted(self.nal_types.items()))
        return ("%.1fs  video %.2f MB (%.2f Mbit/s)  %d frames (%.1f fps)  "
                "control %d frames  resync %d B  bad-crc %d\n  NALs: %s"
                % (self.elapsed, self.video_bytes / 1e6, mbps,
                   self.access_units, fps, self.control_frames,
                   self.resync_bytes, self.bad_crc, nals or "-"))


class StreamPipeline:
    """
    Feed it bulk-endpoint bytes; it writes H.264 to `sink` and hands decoded
    DUML frames to `on_control` (if given).

    `whole_frames=True` buffers each access unit and emits it in one write.
    This is the default, and it is what you want for any network sink. It costs
    no measurable latency: the goggles already sends a whole access unit as one
    uninterrupted burst -- median inter-packet gap inside a burst is 0.105 ms
    on iOS and 0.28 ms on Android -- and then idles for the rest of the ~33 ms
    frame period. Buffering an access unit therefore adds well under a
    millisecond, while chunk-at-a-time output hands a UDP sink fragments of a
    frame and a TCP sink a write per 4 KiB. Pass `whole_frames=False` only for
    a local pipe or file where per-chunk forwarding costs nothing.

    `injector` (a `h264.ParameterSetInjector`) guarantees the output opens with
    an SPS and PPS. The goggles does send its own, roughly once per second, so
    the usual configuration is `wait_for_keyframe=True` with an injector in
    `"never"` mode: within about a second the real parameter sets arrive and
    nothing has to be synthesised. See h264.py.
    """

    def __init__(self, sink, *, on_control=None, whole_frames: bool = True,
                 wait_for_keyframe: bool = True, injector=None):
        self.sink = sink
        self.on_control = on_control
        self.whole_frames = whole_frames
        self.wait_for_keyframe = wait_for_keyframe
        self.injector = injector
        self._started = not wait_for_keyframe
        self.demux = tunnel.Demuxer()
        self.assembler = tunnel.AccessUnitAssembler()
        self.stats = Stats()

    # ------------------------------------------------------------------ #
    def feed(self, data: bytes) -> None:
        st = self.stats
        st.bulk_bytes += len(data)
        for pkt in self.demux.feed(data):
            st.tunnel_packets += 1
            if pkt.is_video:
                self._on_video(pkt)
            elif pkt.is_control:
                self._on_control(pkt)
            else:
                log.warning("unknown tunnel channel 0x%02x (%d bytes)",
                            pkt.channel, len(pkt.payload))
        st.resync_bytes = self.demux.resync_bytes

    # ------------------------------------------------------------------ #
    def _on_video(self, pkt: tunnel.Packet) -> None:
        st = self.stats
        st.video_packets += 1
        for _, nal in tunnel.nal_units(pkt.payload):
            st.nal_types[nal & 0x1F] += 1
        au = self.assembler.push(pkt)
        if au is not None:
            st.access_units += 1
        if not self._started:
            # hold off until we see an SPS or an IDR so decoders can start
            if au is None:
                return
            if not any((n & 0x1F) in (5, 7) for _, n in tunnel.nal_units(au)):
                return
            log.info("keyframe/SPS seen, starting output")
            self._started = True
        if self.whole_frames:
            if au is not None:
                st.video_bytes += len(au)
                self._write(au, True)
        else:
            st.video_bytes += len(pkt.payload)
            self._write(pkt.payload, pkt.ends_access_unit)

    def _write(self, data: bytes, ends_access_unit: bool) -> None:
        if self.injector is not None:
            data = self.injector.feed(data, ends_access_unit=ends_access_unit)
            if not data:
                return
        self.sink.write(data)

    def finish(self) -> None:
        """Flush anything the injector is still holding back. Always call this."""
        if self.injector is not None:
            tail = self.injector.flush()
            if tail:
                self.sink.write(tail)
            self.injector = None

    def _on_control(self, pkt: tunnel.Packet) -> None:
        st = self.stats
        off = 0
        buf = pkt.payload
        while off < len(buf):
            frame, off = duml.parse(buf, off)
            if frame is None:
                continue
            st.control_frames += 1
            st.cmds[frame.key] += 1
            if not frame.crc16_ok:
                st.bad_crc += 1
            if self.on_control is not None:
                self.on_control(frame)
