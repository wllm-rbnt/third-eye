"""
Shared helpers for the tests.

Most tests are self-contained: they check the byte-level builders, the codecs
and the gadget state machines against known-good bytes written into the test
files. Some tests additionally check the implementation against *reference
captures*: hardware-sniffer pcapng recordings of the goggles talking to real
iPhone and Android handsets, and to this package's own client on a Raspberry
Pi 4B. The captures are not distributed. When they are absent every test that
needs them is skipped (never failed); the rest still run.

To run the capture tests, point `DJIG3_CAPTURES` at the directory holding the
files (a glob also works), or put them in a `captures/` directory beside this
checkout. The files are named `dji_trace_<id>_<source>.pcapng`, where
`<source>` says what was on the other end of the cable:

* `ios` -- an iPhone running DJI Fly;
* `android` -- an Android handset running DJI Fly;
* `rpi` -- this package on a Raspberry Pi 4B. These are excluded from the
  "every handset capture" sweeps.

The `<id>` only identifies one recording; the tests that need a particular
one name it. One Android recording (`HANDSHAKE_ONLY`) is a completed AOA
handshake with no tunnel traffic, so tests that need pictures go through
`video_captures()` and tests about the handset handshake go through
`handset_captures()`, rather than treating an empty stream as a failure.

Decoding one pcapng costs several seconds, so `tunnel_bytes()` memoises per
path. Tests should go through it rather than calling
`pryer.capture.bulk_stream` directly.

Every test file can also be run directly (`python tests/test_x.py`); `main()`
below is the runner they share.
"""

from __future__ import annotations

import functools
import glob
import os
import sys
import traceback
import unittest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from pryer import capture, pcapng  # noqa: E402


def default_capture_glob() -> str:
    """Best guess at where the reference captures are."""
    candidates = (
        os.path.join(_ROOT, "captures", "dji_trace_*.pcapng"),
        # a captures/ directory shared by several checkouts
        os.path.join(_ROOT, "..", "captures", "dji_trace_*.pcapng"),
        os.path.join(_ROOT, "..", "..", "captures", "dji_trace_*.pcapng"),
        # simplified text dumps (see pryer.capture) are accepted too
        os.path.join(_ROOT, "captures", "dji_trace_*.txt"),
    )
    for pattern in candidates:
        if glob.glob(pattern):
            return pattern
    return candidates[0]


def _as_glob(value: str) -> str:
    """Accept either a directory or a glob in DJIG3_CAPTURES.

    The variable is documented as "the directory holding dji_trace_*.pcapng",
    so a directory must not silently match nothing.
    """
    if os.path.isdir(value):
        return os.path.join(value, "dji_trace_*.pcapng")
    return value


CAPTURE_GLOB = _as_glob(os.environ.get("DJIG3_CAPTURES",
                                      default_capture_glob()))

MISSING = ("no reference captures matched %s -- set DJIG3_CAPTURES to the "
           "directory holding dji_trace_*.pcapng" % CAPTURE_GLOB)


class Skip(unittest.SkipTest):
    """A test that cannot run here (reference capture or tool missing).

    Subclassing unittest.SkipTest makes pytest and unittest report it as a
    skip; `main()` does the same for direct runs.
    """


def captures() -> list[str]:
    """Every reference capture, sorted by name."""
    return sorted(glob.glob(CAPTURE_GLOB))


def require_captures() -> list[str]:
    """Every reference capture; skips the calling test if there are none."""
    files = captures()
    if not files:
        raise Skip(MISSING)
    return files


# Captures that are not a phone talking to the goggles, and so are excluded
# from the "every handset capture" sweeps: every recording of this package's
# own client is named dji_trace_<id>_rpi.
NON_HANDSET_CAPTURES = ("_rpi",)

# The Android recording with a completed AOA handshake and no tunnel traffic.
HANDSHAKE_ONLY = "8_android"


def handset_captures() -> list[str]:
    """Every capture of a real handset; skips the test if there are none."""
    files = [p for p in require_captures()
             if not any(tag in os.path.basename(p)
                        for tag in NON_HANDSET_CAPTURES)]
    if not files:
        raise Skip("no handset captures in %s" % CAPTURE_GLOB)
    return files


def video_captures() -> list[str]:
    """Handset captures that actually carry tunnel traffic."""
    files = [p for p in handset_captures()
             if HANDSHAKE_ONLY not in os.path.basename(p)]
    if not files:
        raise Skip("no video-bearing captures in %s" % CAPTURE_GLOB)
    return files


def capture_path(match: str, *, pcapng_only: bool = False) -> str:
    """
    The one capture whose basename contains `match`, e.g. "4_android".

    Skips the calling test if there is none, or, with *pcapng_only*, if the
    file is not a real pcapng (a git-lfs pointer, for example).
    """
    files = [p for p in captures() if match in os.path.basename(p)]
    if not files:
        raise Skip("reference capture *%s* not available (%s)"
                   % (match, MISSING))
    path = files[0]
    if pcapng_only and not capture.is_pcapng(path):
        raise Skip("%s is not a pcapng (git-lfs pointer?)" % path)
    return path


@functools.lru_cache(maxsize=None)
def tunnel_bytes(path: str) -> bytes:
    """
    Goggles-to-phone tunnel bytes for one capture, decoded once and cached.

    This is the video-bearing direction -- EP 0x02 IN on the iOS captures, EP
    0x01 OUT on the Android ones, where the goggles is the host. The goggles'
    own DUML frames ride the same endpoint, so control tests can use this too.
    """
    return capture.bulk_stream(path)


@functools.lru_cache(maxsize=None)
def upstream_bytes(path: str) -> bytes:
    """
    Phone-to-goggles tunnel bytes: what the app sends, tens of kB per capture.

    Needed by anything that checks what the *phone* said, since that travels
    the opposite direction on the same endpoint and so is absent from
    `tunnel_bytes`. The text dumps only ever held one direction, so for those
    this returns the same bytes.
    """
    if not capture.is_pcapng(path):
        return capture.bulk_stream(path)
    _down, up = pcapng.tunnel_endpoints(path)
    if up is None:
        return b""
    return capture.bulk_stream(path, addr=up.addr, ep=up.ep,
                               direction=up.direction)


@functools.lru_cache(maxsize=None)
def iap2_packets(path: str, direction: str = "IN") -> tuple[bytes, ...]:
    """
    iAP2 control-link packets (iOS captures only; empty on the Android ones).

    `direction="IN"` is goggles-to-phone, `"OUT"` is phone-to-goggles. The
    packets are kept separate rather than concatenated because an iAP2 message
    is delimited by its transfer.
    """
    if not capture.is_pcapng(path):
        return ()
    for st in pcapng.iap2_endpoints(path):
        if st.direction == direction:
            return tuple(t.data for t in
                         pcapng.transfers(path, st.addr, st.ep, st.direction)
                         if t.data)
    return ()


@functools.lru_cache(maxsize=None)
def iap2_link_bytes(path: str) -> bytes:
    """
    Both directions of the iAP2 control link, merged back into wire order.

    Delegates to `pryer.pcapng.iap2_link_bytes`, which is the same endpoint-
    scoped extraction the `iap2` CLI subcommand uses, so the tests exercise the
    shipped path rather than a private copy of it.
    """
    if not capture.is_pcapng(path):
        return b""
    return pcapng.iap2_link_bytes(path)


def main(namespace: dict) -> int:
    """
    Run every ``test_*`` function in *namespace* (a test module's globals())
    and report ok / skip / FAIL for each. Returns the process exit status.
    """
    tests = [(n, f) for n, f in sorted(namespace.items())
             if n.startswith("test_") and callable(f)]
    failed = skipped = 0
    for name, fn in tests:
        try:
            fn()
            print("ok      %s" % name)
        except unittest.SkipTest as exc:
            skipped += 1
            print("skip    %s  (%s)" % (name, exc))
        except Exception as exc:  # noqa: BLE001
            failed += 1
            print("FAIL    %s  %r" % (name, exc))
            traceback.print_exc()
    print("\n%d passed, %d failed, %d skipped"
          % (len(tests) - failed - skipped, failed, skipped))
    return 1 if failed else 0
