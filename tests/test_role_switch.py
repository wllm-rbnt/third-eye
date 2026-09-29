"""
The iOS handover: the Apple role swap, and switching a Raspberry Pi's dwc2
port from gadget to host (PROTOCOL.md sections 3.4 and 9.1).

After request 0x51 the goggles stops being the USB host and, about 205-218 ms
later, attaches as a USB device; a real iPhone resets it as the new host
about 370 ms after the request. This package has to do the same with one
port: release the bus, re-probe dwc2 in host mode without reloading the
module, enumerate the goggles, and put the port back into gadget mode
afterwards. A failed switch must abort at once, because the goggles would
otherwise wait on the bus for a host that never comes.

The groups of tests:

* the role switch, the gadget restore and `ensure_gadget_role` against a fake
  Pi (sysfs, `dtoverlay`, `modprobe`), including a module on disk that the
  running kernel refuses (ENOEXEC);
* the phase sequence: `trigger_mfi_mode` raises when the port cannot become
  host, `stream` restores gadget mode, Ctrl-C during the handshake;
* boot configuration and the `role` command;
* on reference captures (skipped when not available): a Pi session in which
  the iPhone impersonation and the role swap succeed and nothing takes over
  as host, compared with an iPhone session where the iPhone does; and
  `decode`'s diagnosis of the former.

Run with:  python -m pytest tests/test_role_switch.py
       or:  python tests/test_role_switch.py
"""

from __future__ import annotations

import io
import logging
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pryer import cli, mfi, pcapng, rawgadget  # noqa: E402
import support  # noqa: E402


# A Pi 4B session: iPhone impersonation and role swap, then no host.
NO_HOST_AFTER_SWAP = "10_rpi"
# An iPhone session with the handover as the iPhone performs it.
IPHONE_HANDOVER = "9_ios"


def _find(name: str) -> str:
    """A capture by basename fragment; skips if absent or an LFS stub."""
    return support.capture_path(name, pcapng_only=True)


_CT: dict = {}


def _transfers(name: str) -> list:
    if name not in _CT:
        _CT[name] = list(pcapng.control_transfers(_find(name)))
    return _CT[name]


def _swap(transfers) -> "pcapng.ControlTransfer":
    swaps = [c for c in transfers
             if c.bm_request_type == 0x40 and c.b_request == mfi.APPLE_ROLE_SWAP]
    assert len(swaps) == 1, swaps
    return swaps[0]


def _attach_after(path: str, t51: int) -> int:
    """Timestamp of the last pull-up (line state J) after the swap."""
    js = [ts for ts, msg in pcapng.log_messages(path)
          if ts > t51 and msg.startswith("Line state: J")]
    assert js, "no line-state J after the role swap"
    return js[-1]


# --------------------------------------------------------------------------- #
# Reference captures
# --------------------------------------------------------------------------- #
def test_pi_phase_1_completes_as_on_the_iphone():
    ct = _transfers(NO_HOST_AFTER_SWAP)
    dev = [c for c in ct if c.setup[:4] == bytes.fromhex("80060001")]
    assert dev and dev[0].data == mfi.IPHONE_DEVICE_DESC
    setcfg = [c for c in ct if c.setup[:2] == b"\x00\x09"]
    assert [c.w_value for c in setcfg] == [1]
    swap = _swap(ct)
    assert swap.setup == bytes.fromhex("4051000000000000")
    assert swap.ts > setcfg[0].ts
    # the four configurations the goggles read are the ones we serve
    cfgs = {c.w_value & 0xFF: c.data for c in ct
            if c.setup[:4] in (bytes([0x80, 6, i, 2]) for i in range(4))
            and len(c.data) > 9}
    assert [cfgs[i] for i in range(4)] == mfi.IPHONE_CONFIGS


def test_pi_acknowledges_the_role_swap_status_stage():
    """The Pi answers 0x51's status stage: zero-length DATA1, ACKed."""
    path = _find(NO_HOST_AFTER_SWAP)
    t51 = _swap(_transfers(NO_HOST_AFTER_SWAP)).ts
    seq = []
    for w in pcapng.wire_packets(path):
        if w.ts < t51 or w.name == "SOF":
            continue
        seq.append(w)
        if len(seq) > 1 and seq[-2].name == "DATA1" and w.name == "ACK":
            break
        if w.ts > t51 + 5_000_000:
            break
    assert seq[-2].name == "DATA1" and seq[-2].data == b""
    assert seq[-1].name == "ACK"
    assert seq[-1].ts - t51 < 1_000_000        # well inside 1 ms


def test_without_a_new_host_the_goggles_waits_as_a_device():
    path = _find(NO_HOST_AFTER_SWAP)
    ct = _transfers(NO_HOST_AFTER_SWAP)
    t51 = _swap(ct).ts
    assert not [c for c in ct if c.ts > t51], "something enumerated after 0x51"
    attach = _attach_after(path, t51)
    # the goggles attached as a device about 200 ms after the request ...
    assert 150e6 < attach - t51 < 260e6, (attach - t51) / 1e6
    # ... and was still waiting, with no host, when the capture ended
    end = max(ts for ts, _ in pcapng.log_messages(path))
    assert end - attach > 10e9, (end - attach) / 1e9


def test_the_iphone_takes_over_within_half_a_second():
    """The iPhone resets and addresses the goggles about 380 ms after 0x51."""
    path = _find(IPHONE_HANDOVER)
    ct = _transfers(IPHONE_HANDOVER)
    t51 = _swap(ct).ts
    after = [c for c in ct if c.ts > t51]
    assert after and after[0].setup[:2] == b"\x00\x05"     # SET_ADDRESS
    assert after[0].addr == 0
    assert 300e6 < after[0].ts - t51 < 500e6, (after[0].ts - t51) / 1e6
    # the goggles attached (pull-up) before the new host reset it
    js = [ts for ts, msg in pcapng.log_messages(path)
          if t51 < ts < after[0].ts and msg.startswith("Line state: J")]
    assert js and 150e6 < js[-1] - t51 < 260e6
    # and the device the new host found is the goggles in MFi mode
    dev = [c for c in after if c.setup[:4] == bytes.fromhex("80060001")
           and len(c.data) == 18]
    assert dev and dev[0].data[8:12] == bytes.fromhex("a32c0210")


def test_the_goggles_attaches_at_the_same_time_with_the_pi_and_the_iphone():
    """Up to the handover, the Pi's session matches the iPhone's."""
    a10 = _attach_after(_find(NO_HOST_AFTER_SWAP),
                        _swap(_transfers(NO_HOST_AFTER_SWAP)).ts) \
        - _swap(_transfers(NO_HOST_AFTER_SWAP)).ts
    p9 = _find(IPHONE_HANDOVER)
    t9 = _swap(_transfers(IPHONE_HANDOVER)).ts
    js = [ts for ts, msg in pcapng.log_messages(p9)
          if ts > t9 and msg.startswith("Line state: J")]
    a9 = [ts for ts in js if ts - t9 < 300e6][-1] - t9
    assert abs(a10 - a9) < 30e6, (a10 / 1e6, a9 / 1e6)


def test_decode_explains_a_swap_with_no_new_host():
    path = _find(NO_HOST_AFTER_SWAP)
    buf = io.StringIO()
    saved = sys.stdout
    sys.stdout = buf
    try:
        rc = cli.main(["decode", path])
    finally:
        sys.stdout = saved
    out = buf.getvalue()
    assert rc == 1
    assert "acknowledged, but nothing enumerated the goggles" in out, out
    assert "attached as a USB device" in out and "never became the host" in out


def test_a_refused_module_is_explained():
    assert "Exec format error" in mfi.explain_module_load_failure(
        "modprobe: ERROR: could not insert 'dwc2': Exec format error")


# --------------------------------------------------------------------------- #
# A fake Raspberry Pi: sysfs, dtoverlay and modprobe
# --------------------------------------------------------------------------- #
class FakePi:
    """
    Just enough of a Pi 4B for the role-switching code.

    * /sys/bus/platform/drivers/dwc2 holds a symlink per bound device;
    * binding creates /sys/class/udc/<dev> for peripheral/otg, or
      /sys/bus/platform/devices/<dev>/usb3 for host;
    * `dtoverlay dwc2 dr_mode=X` / `dtoverlay -r dwc2` / `dtoverlay -l`
      keep a runtime-overlay list; the effective dr_mode is the runtime one if
      present, else the boot one;
    * `modprobe dwc2` registers the driver and binds, unless told to fail.
    """

    DEV = "fe980000.usb"

    def __init__(self, boot_mode="otg", driver_loaded=True, bound=True,
                 modprobe_error: str | None = None):
        self.root = tempfile.mkdtemp(prefix="fakepi-")
        self.drivers = os.path.join(self.root, "drivers", "dwc2")
        self.devices = os.path.join(self.root, "devices")
        self.udc = os.path.join(self.root, "udc")
        os.makedirs(os.path.join(self.devices, self.DEV))
        os.makedirs(self.udc)
        self.boot_mode = boot_mode
        self.overlay: str | None = None        # runtime dr_mode
        self.calls: list[list[str]] = []
        self.writes: list[tuple[str, str]] = []
        self.modprobe_error = modprobe_error
        if driver_loaded:
            self._register()
            if bound:
                self._bind()

    # -- kernel model -------------------------------------------------- #
    @property
    def mode(self) -> str:
        return self.overlay or self.boot_mode

    def _register(self):
        os.makedirs(self.drivers, exist_ok=True)
        for f in ("bind", "unbind", "uevent"):
            open(os.path.join(self.drivers, f), "w").close()

    def _bind(self):
        link = os.path.join(self.drivers, self.DEV)
        if not os.path.islink(link):
            os.symlink(os.path.join(self.devices, self.DEV), link)
        if self.mode == "host":
            os.makedirs(os.path.join(self.devices, self.DEV, "usb3"),
                        exist_ok=True)
        else:
            os.makedirs(os.path.join(self.udc, self.DEV), exist_ok=True)

    def _unbind(self):
        link = os.path.join(self.drivers, self.DEV)
        if os.path.islink(link):
            os.unlink(link)
        shutil.rmtree(os.path.join(self.devices, self.DEV, "usb3"),
                      ignore_errors=True)
        shutil.rmtree(os.path.join(self.udc, self.DEV), ignore_errors=True)

    # -- patched entry points ------------------------------------------ #
    def write(self, path, value):
        self.writes.append((os.path.basename(path), value))
        assert value == self.DEV, value
        if path.endswith("/unbind"):
            assert os.path.islink(os.path.join(self.drivers, self.DEV)), \
                "unbind of a device that is not bound -> ENODEV"
            self._unbind()
        elif path.endswith("/bind"):
            assert not os.path.islink(os.path.join(self.drivers, self.DEV)), \
                "bind of a bound device -> EBUSY"
            self._bind()
        else:
            raise AssertionError(path)

    def run(self, cmd):
        self.calls.append(list(cmd))
        if cmd[:2] == ["dtoverlay", "-l"]:
            if self.overlay is None:
                return 0, "No overlays loaded"
            return 0, "Overlays (in load order):\n0:  dwc2  dr_mode=%s" % \
                self.overlay
        if cmd[:3] == ["dtoverlay", "-r", "dwc2"]:
            if self.overlay is None:
                return 1, "* overlay 'dwc2' is not loaded"
            self.overlay = None
            return 0, ""
        if cmd[:2] == ["dtoverlay", "dwc2"]:
            params = dict(p.split("=", 1) for p in cmd[2:])
            self.overlay = params["dr_mode"]
            return 0, ""
        if cmd[:2] == ["modprobe", "dwc2"]:
            if self.modprobe_error:
                return 1, self.modprobe_error
            self._register()
            self._bind()
            return 0, ""
        if cmd[:2] == ["modinfo", "-n"]:
            return 1, "modinfo: ERROR: Module dwc2 not found."
        raise AssertionError("unexpected command %r" % (cmd,))

    # -- install / uninstall ------------------------------------------- #
    def __enter__(self):
        self._saved = (mfi.DWC2_DRIVER_DIR, mfi.PLATFORM_DEVICES_DIR,
                       rawgadget.SYS_UDC, mfi._run, mfi._write,
                       mfi.dtoverlay_available, os.geteuid,
                       rawgadget.is_pi4, mfi.ROLE_SETTLE_TIMEOUT)
        mfi.DWC2_DRIVER_DIR = self.drivers
        mfi.PLATFORM_DEVICES_DIR = self.devices
        rawgadget.SYS_UDC = self.udc
        mfi._run = self.run
        mfi._write = self.write
        mfi.dtoverlay_available = lambda: True
        os.geteuid = lambda: 0
        rawgadget.is_pi4 = lambda: True
        mfi.ROLE_SETTLE_TIMEOUT = 0.2
        return self

    def __exit__(self, *exc):
        (mfi.DWC2_DRIVER_DIR, mfi.PLATFORM_DEVICES_DIR, rawgadget.SYS_UDC,
         mfi._run, mfi._write, mfi.dtoverlay_available, os.geteuid,
         rawgadget.is_pi4, mfi.ROLE_SETTLE_TIMEOUT) = self._saved
        shutil.rmtree(self.root, ignore_errors=True)


class _Records(logging.Handler):
    def __init__(self):
        super().__init__(logging.DEBUG)
        self.lines: list[str] = []

    def emit(self, record):
        self.lines.append(record.getMessage())

    def __enter__(self):
        logging.getLogger("pryer").addHandler(self)
        self._level = logging.getLogger("pryer").level
        logging.getLogger("pryer").setLevel(logging.DEBUG)
        return self

    def __exit__(self, *exc):
        logging.getLogger("pryer").removeHandler(self)
        logging.getLogger("pryer").setLevel(self._level)


# --------------------------------------------------------------------------- #
# Unit tests: role switching
# --------------------------------------------------------------------------- #
def test_host_switch_rebinds_and_never_touches_the_module():
    with FakePi() as pi:
        assert rawgadget.list_udcs() == [pi.DEV]
        assert mfi.dwc2_current_role() == "gadget"
        assert mfi.switch_to_host_role()
        assert not any(c[0] in ("modprobe", "rmmod") for c in pi.calls), \
            pi.calls
        assert [w[0] for w in pi.writes] == ["unbind", "bind"]
        assert ["dtoverlay", "dwc2", "dr_mode=host"] in pi.calls
        # the overlay is applied while the device is unbound
        assert pi.mode == "host"
        assert mfi.dwc2_host_buses(pi.DEV) == ["usb3"]
        assert rawgadget.list_udcs() == []
        assert mfi.dwc2_current_role() == "host"


def test_host_switch_replaces_a_stale_runtime_overlay():
    with FakePi() as pi:
        pi.overlay = "peripheral"          # left over from something else
        assert mfi.runtime_dwc2_overlay() == "dr_mode=peripheral"
        assert mfi.switch_dwc2_role("host")
        i_rm = pi.calls.index(["dtoverlay", "-r", "dwc2"])
        i_add = pi.calls.index(["dtoverlay", "dwc2", "dr_mode=host"])
        assert i_rm < i_add
        assert pi.mode == "host"


def test_gadget_restore_drops_the_runtime_overlay():
    with FakePi(boot_mode="peripheral") as pi:
        assert mfi.switch_to_host_role()
        pi.calls.clear()
        pi.writes.clear()
        assert mfi.switch_to_gadget_role()
        assert ["dtoverlay", "-r", "dwc2"] in pi.calls
        assert not any(c[:2] == ["dtoverlay", "dwc2"] for c in pi.calls)
        assert pi.overlay is None and pi.mode == "peripheral"
        assert rawgadget.list_udcs() == [pi.DEV]
        # and doing it again is a no-op
        pi.calls.clear()
        assert mfi.switch_to_gadget_role()
        assert pi.writes[-1][0] == "bind" and len(pi.writes) == 2
        assert not any(c[:2] == ["dtoverlay", "-r"] for c in pi.calls)


def test_ensure_gadget_role_repairs_a_port_left_in_host_mode():
    with FakePi() as pi:
        assert mfi.switch_to_host_role()
        assert rawgadget.list_udcs() == []
        mfi.ensure_gadget_role()
        assert rawgadget.list_udcs() == [pi.DEV]


def test_ensure_gadget_role_reloads_a_missing_driver():
    """dwc2 unloaded altogether: the gadget role is restored by loading it."""
    with FakePi(driver_loaded=False) as pi:
        assert mfi.dwc2_current_role() == "no driver"
        mfi.ensure_gadget_role()
        assert ["modprobe", "dwc2"] in pi.calls
        assert rawgadget.list_udcs() == [pi.DEV]


def test_enoexec_from_modprobe_is_explained_and_fails_cleanly():
    err = "modprobe: ERROR: could not insert 'dwc2': Exec format error"
    with FakePi(driver_loaded=False, modprobe_error=err) as pi, \
            _Records() as rec:
        try:
            mfi.ensure_gadget_role()
        except mfi.RoleSwitchError as exc:
            assert "doctor" in str(exc) and "reboot" in str(exc)
        else:
            raise AssertionError("expected RoleSwitchError")
        assert ["modprobe", "dwc2"] in pi.calls
        joined = "\n".join(rec.lines)
        assert "Exec format error" in joined
        assert "kernel upgrade" in joined and "Reboot" in joined, joined


def test_failed_overlay_leaves_the_controller_bound():
    with FakePi() as pi:
        real = pi.run

        def run(cmd):
            if cmd[:2] == ["dtoverlay", "dwc2"]:
                pi.calls.append(list(cmd))
                return 1, "* Failed to apply overlay"
            return real(cmd)
        mfi._run = run
        assert not mfi.switch_dwc2_role("host")
        assert rawgadget.list_udcs() == [pi.DEV]     # still a gadget


def test_no_switch_is_attempted_where_dwc2_cannot_be_re_probed():
    with FakePi() as pi:
        rawgadget.is_pi4 = lambda: False
        mfi.dtoverlay_available = lambda: False
        assert not mfi.role_switching_available()
        assert not mfi.switch_to_host_role()
        assert mfi.switch_to_gadget_role()          # already a gadget
        assert pi.calls == [] and pi.writes == []


def test_dwc2_device_is_found_in_every_state():
    with FakePi() as pi:
        assert mfi.dwc2_device() == pi.DEV          # bound
        pi._unbind()
        assert mfi.dwc2_device() == pi.DEV          # unbound: known name
    with FakePi(driver_loaded=False) as pi:
        assert mfi.dwc2_device() == pi.DEV


def test_runtime_overlay_list_is_parsed():
    with FakePi() as pi:
        assert mfi.runtime_overlays() == []
        pi.overlay = "host"
        assert mfi.runtime_overlays() == [("dwc2", "dr_mode=host")]
        assert mfi.runtime_dwc2_overlay() == "dr_mode=host"


def test_module_mismatch_is_detected_by_srcversion():
    saved = mfi._run, mfi._module_file
    real_open = open
    try:
        mfi._module_file = lambda name: "/lib/modules/x/dwc2.ko.xz"
        mfi._run = lambda cmd: (0, "NEWSRC")

        def fake_open(path, *a, **k):
            if path == "/sys/module/dwc2/srcversion":
                return io.StringIO("OLDSRC\n")
            return real_open(path, *a, **k)
        mfi.open = fake_open
        msg = mfi.dwc2_module_mismatch()
        assert msg and "upgraded since boot" in msg, msg
    finally:
        mfi._run, mfi._module_file = saved
        del mfi.open


# --------------------------------------------------------------------------- #
# Unit tests: the phase sequence
# --------------------------------------------------------------------------- #
class _SwapNow:
    """Stands in for _IphoneSession: the goggles asks for the swap at once."""

    def __init__(self, *_a, **_k):
        self.requests = []
        self.error = None
        self.role_swap_at = 0.0
        self.closed = False

    def start(self):
        pass

    def wait_for_role_swap(self, timeout):
        return True

    def close(self):
        self.closed = True
        return True


def _patched_trigger(switch_result: bool):
    saved = (mfi._IphoneSession, rawgadget.pick_udc,
             rawgadget.udc_driver_name, rawgadget.install_interrupt_handler,
             mfi.switch_to_host_role, mfi.role_switching_available,
             mfi.POST_SWAP_DELAY)
    mfi._IphoneSession = _SwapNow
    rawgadget.pick_udc = lambda udc=None: "fe980000.usb"
    rawgadget.udc_driver_name = lambda udc: "fe980000.usb"
    rawgadget.install_interrupt_handler = lambda: True
    mfi.switch_to_host_role = lambda: switch_result
    mfi.role_switching_available = lambda: True
    mfi.POST_SWAP_DELAY = 0.0
    return saved


def _restore_trigger(saved):
    (mfi._IphoneSession, rawgadget.pick_udc, rawgadget.udc_driver_name,
     rawgadget.install_interrupt_handler, mfi.switch_to_host_role,
     mfi.role_switching_available, mfi.POST_SWAP_DELAY) = saved


def test_trigger_raises_when_the_port_cannot_become_host():
    saved = _patched_trigger(False)
    try:
        try:
            mfi.trigger_mfi_mode()
        except mfi.RoleSwitchError as exc:
            assert "waiting on the bus as a USB device" in str(exc)
        else:
            raise AssertionError("carried on into phase 2 without a host")
        # a machine that cannot re-probe dwc2 leaves the switch to the user
        mfi.role_switching_available = lambda: False
        assert mfi.trigger_mfi_mode() is True
    finally:
        _restore_trigger(saved)


def test_trigger_succeeds_when_the_switch_does():
    saved = _patched_trigger(True)
    try:
        assert mfi.trigger_mfi_mode() is True
    finally:
        _restore_trigger(saved)


def test_post_swap_delay_is_inside_the_iphones_window():
    # The iPhone releases the bus at +75 ms and the goggles attaches at
    # +205..218 ms; the gadget must be gone well before that.
    assert 0.0 < mfi.POST_SWAP_DELAY <= 0.075


def test_stream_stops_at_a_failed_switch_and_restores_gadget_mode():
    calls = []
    saved = (mfi.ensure_gadget_role, mfi.trigger_mfi_mode,
             mfi.switch_to_gadget_role, mfi.IapHost)

    def trigger(**_k):
        calls.append("trigger")
        raise mfi.RoleSwitchError("no host")

    def iap(*_a, **_k):
        raise AssertionError("phase 2 must not start")

    mfi.ensure_gadget_role = lambda *a: calls.append("ensure")
    mfi.trigger_mfi_mode = trigger
    mfi.switch_to_gadget_role = lambda *a: calls.append("restore") or True
    mfi.IapHost = iap
    try:
        rc = cli.main(["stream", "-t", "ios", "-o", "null", "--stats", "0"])
    finally:
        (mfi.ensure_gadget_role, mfi.trigger_mfi_mode,
         mfi.switch_to_gadget_role, mfi.IapHost) = saved
    assert rc == 1
    assert calls == ["ensure", "trigger", "restore"], calls


def test_stream_restores_gadget_mode_after_the_session():
    calls = []

    class Link:
        def __init__(self, *a, **k):
            self.reads = 0

        def open(self, **_k):
            calls.append("open")

        def read(self, size=None):
            import signal
            self.reads += 1
            os.kill(os.getpid(), signal.SIGINT)    # stop after one read
            return b""

        def write(self, data):
            return len(data)

        def close(self):
            calls.append("close")

    saved = (mfi.ensure_gadget_role, mfi.trigger_mfi_mode,
             mfi.switch_to_gadget_role, mfi.IapHost)
    mfi.ensure_gadget_role = lambda *a: calls.append("ensure")
    mfi.trigger_mfi_mode = lambda **k: calls.append("trigger") or True
    mfi.switch_to_gadget_role = lambda *a: calls.append("restore") or True
    mfi.IapHost = Link
    import signal
    old = signal.getsignal(signal.SIGINT), signal.getsignal(signal.SIGTERM)
    try:
        rc = cli.main(["stream", "-t", "ios", "-o", "null", "--stats", "0",
                       "--no-register"])
    finally:
        (mfi.ensure_gadget_role, mfi.trigger_mfi_mode,
         mfi.switch_to_gadget_role, mfi.IapHost) = saved
        signal.signal(signal.SIGINT, old[0])
        signal.signal(signal.SIGTERM, old[1])
    assert rc == 0
    assert calls[:3] == ["ensure", "trigger", "open"], calls
    assert calls.index("restore") > calls.index("close"), calls


def test_ctrl_c_during_the_handshake_returns_130():
    saved = cli.TRANSPORTS["ios"]

    def interrupted(_args):
        raise KeyboardInterrupt

    cli.TRANSPORTS["ios"] = interrupted
    try:
        assert cli.main(["stream", "-t", "ios", "-o", "null"]) == 130
    finally:
        cli.TRANSPORTS["ios"] = saved


# --------------------------------------------------------------------------- #
# Unit tests: configuration
# --------------------------------------------------------------------------- #
def test_boot_config_recognises_the_dwc2_overlay():
    saved = rawgadget._config_txt_lines, rawgadget.config_txt_path
    rawgadget.config_txt_path = lambda: "/boot/firmware/config.txt"
    try:
        rawgadget._config_txt_lines = lambda: ["dtoverlay=dwc2,dr_mode=otg"]
        cfg = rawgadget.boot_config()
        assert cfg["dwc2"] and cfg["dr_mode"] == "otg"
        rawgadget._config_txt_lines = lambda: ["dtoverlay=dwc2"]
        cfg = rawgadget.boot_config()
        assert cfg["dwc2"] and cfg["params"] == {}
        assert cfg["dr_mode"] is None
        rawgadget._config_txt_lines = lambda: ["dtoverlay=dwc2foo"]
        assert not rawgadget.boot_config()["dwc2"]
    finally:
        rawgadget._config_txt_lines, rawgadget.config_txt_path = saved


def test_role_command_is_wired_up():
    args = cli.build_parser().parse_args(["role", "host"])
    assert args.func is cli.cmd_role and args.action == "host"
    assert cli.build_parser().parse_args(["role"]).action == "status"
    s = cli.build_parser().parse_args(["stream", "-t", "ios",
                                       "--keep-host-role"])
    assert s.keep_host_role


# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    sys.exit(support.main(globals()))
