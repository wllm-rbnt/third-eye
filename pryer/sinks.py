"""Output sinks for the extracted H.264 elementary stream."""

from __future__ import annotations

import logging
import os
import socket
import subprocess
import sys

log = logging.getLogger("pryer.sinks")


class Sink:
    def write(self, data: bytes) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    def close(self) -> None:
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class StdoutSink(Sink):
    """Raw Annex-B to stdout, e.g. `... | ffplay -fflags nobuffer -i -`."""

    def write(self, data: bytes) -> None:
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()


class FileSink(Sink):
    def __init__(self, path: str):
        self.path = path
        self.fh = open(path, "wb")

    def write(self, data: bytes) -> None:
        self.fh.write(data)

    def close(self) -> None:
        self.fh.close()
        log.info("wrote %s (%d bytes)", self.path,
                 os.path.getsize(self.path) if os.path.exists(self.path) else 0)


class FifoSink(Sink):
    """Named pipe; created if missing. Blocks until a reader attaches."""

    def __init__(self, path: str):
        self.path = path
        if not os.path.exists(path):
            os.mkfifo(path)
        log.info("waiting for a reader on %s ...", path)
        self.fd = os.open(path, os.O_WRONLY)

    def write(self, data: bytes) -> None:
        os.write(self.fd, data)

    def close(self) -> None:
        os.close(self.fd)


class UdpSink(Sink):
    """
    Datagram sink. Annex-B chunks are sent as-is, one datagram per access
    unit slice, so keep `mtu` below the path MTU.
    """

    def __init__(self, host: str, port: int, mtu: int = 1400):
        self.addr = (host, port)
        self.mtu = mtu
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1 << 20)

    def write(self, data: bytes) -> None:
        for i in range(0, len(data), self.mtu):
            self.sock.sendto(data[i:i + self.mtu], self.addr)

    def close(self) -> None:
        self.sock.close()


class TcpServerSink(Sink):
    """Listens once and streams to the first client that connects."""

    def __init__(self, host: str, port: int):
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind((host, port))
        self.srv.listen(1)
        log.info("waiting for a TCP client on %s:%d "
                 "(try: ffplay -fflags nobuffer tcp://%s:%d)",
                 host, port, host or "127.0.0.1", port)
        self.conn, peer = self.srv.accept()
        self.conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        log.info("client connected from %s", peer)

    def write(self, data: bytes) -> None:
        self.conn.sendall(data)

    def close(self) -> None:
        try:
            self.conn.close()
        finally:
            self.srv.close()


class CommandSink(Sink):
    """Pipe the stream into a child process (ffplay, ffmpeg, gst-launch...)."""

    def __init__(self, command: str):
        log.info("launching: %s", command)
        self.proc = subprocess.Popen(command, shell=True,
                                     stdin=subprocess.PIPE)

    def write(self, data: bytes) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.write(data)

    def close(self) -> None:
        if self.proc.stdin:
            try:
                self.proc.stdin.close()
            except OSError:
                pass
        self.proc.wait(timeout=5)


CONTAINERS = {
    "mp4": ["-movflags", "+faststart"],
    "mov": ["-movflags", "+faststart"],
    "mkv": [],
    "ts":  [],
    "flv": [],
}


class ContainerSink(Sink):
    """
    Mux the Annex-B stream into a real container with ffmpeg, so the result is
    a file players will open and seek in.

    Two flags matter and are easy to get wrong by hand:

    * `-r FPS` on the *input*, because a raw H.264 stream has no timestamps of
      its own -- without it ffmpeg guesses 25 fps and the file plays at the
      wrong speed.
    * `-copyinkf` on the *output*, because muxers drop everything before the
      first keyframe. When you attach mid-flight there is no leading keyframe,
      so without this the file comes out empty. (`-copyinkf` is why this class
      exists rather than a `cmd:` one-liner in the README.)
    """

    def __init__(self, path: str, container: str | None = None, *,
                 fps: float = 60.0, ffmpeg: str = "ffmpeg",
                 extra: list[str] | None = None):
        if container is None:
            container = os.path.splitext(path)[1].lstrip(".").lower() or "mp4"
        if container not in CONTAINERS:
            raise ValueError("unsupported container %r (have: %s)"
                             % (container, ", ".join(sorted(CONTAINERS))))
        self.path = path
        self.container = container
        self.command = ([ffmpeg, "-hide_banner", "-loglevel", "warning", "-y",
                         "-fflags", "+genpts",
                         "-f", "h264", "-r", "%g" % fps, "-i", "pipe:0",
                         "-c", "copy", "-copyinkf"]
                        + CONTAINERS[container] + (extra or [])
                        + ["-f", _muxer(container), path])
        log.info("muxing into %s: %s", path, " ".join(self.command))
        try:
            self.proc = subprocess.Popen(self.command, stdin=subprocess.PIPE)
        except FileNotFoundError:
            raise RuntimeError(
                "%s is not on PATH -- container sinks need ffmpeg; use "
                "file:%s.h264 for a raw stream instead" % (ffmpeg, path)) from None

    def write(self, data: bytes) -> None:
        assert self.proc.stdin is not None
        try:
            self.proc.stdin.write(data)
        except BrokenPipeError:
            raise RuntimeError("ffmpeg exited (%s); see its output above"
                               % self.proc.poll()) from None

    def close(self) -> None:
        if self.proc.stdin:
            try:
                self.proc.stdin.close()
            except OSError:
                pass
        try:
            rc = self.proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            rc = self.proc.wait()
        if rc:
            log.error("ffmpeg exited with status %d; %s may be unusable",
                      rc, self.path)
        else:
            log.info("wrote %s", self.path)


def _muxer(container: str) -> str:
    return {"mkv": "matroska", "ts": "mpegts"}.get(container, container)


class NullSink(Sink):
    def write(self, data: bytes) -> None:
        pass


class TeeSink(Sink):
    def __init__(self, *sinks: Sink):
        self.sinks = [s for s in sinks if s is not None]

    def write(self, data: bytes) -> None:
        for s in self.sinks:
            s.write(data)

    def close(self) -> None:
        for s in self.sinks:
            s.close()


def make_sink(spec: str, *, fps: float = 60.0) -> Sink:
    """
    Build a sink from a short spec string:

        -                 stdout
        file:PATH         write to a file (raw Annex-B)
        mp4:PATH          mux into MP4 with ffmpeg (also mov, mkv, ts, flv)
        fifo:PATH         named pipe
        udp:HOST:PORT     UDP datagrams
        tcp:HOST:PORT     TCP listener (HOST may be empty for all interfaces)
        cmd:COMMAND       pipe into a shell command
        null              discard

    A bare path is a raw file, except for the container extensions above:
    `out.mp4` muxes, `out.h264` does not.
    """
    if spec in ("-", "stdout"):
        return StdoutSink()
    if spec == "null":
        return NullSink()
    kind, _, rest = spec.partition(":")
    if kind in CONTAINERS:
        return ContainerSink(rest, kind, fps=fps)
    if kind == "file":
        return FileSink(rest)
    if kind == "fifo":
        return FifoSink(rest)
    if kind == "cmd":
        return CommandSink(rest)
    if kind in ("udp", "tcp"):
        host, _, port = rest.rpartition(":")
        cls = UdpSink if kind == "udp" else TcpServerSink
        return cls(host, int(port))
    # bare path: mux if it looks like a container, otherwise raw
    ext = os.path.splitext(spec)[1].lstrip(".").lower()
    if ext in CONTAINERS:
        return ContainerSink(spec, ext, fps=fps)
    return FileSink(spec)
