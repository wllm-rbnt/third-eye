"""
Impersonate an Android phone over USB Raw Gadget and negotiate Android Open
Accessory mode with the DJI Goggles 3, then expose the resulting bulk pair.

Flow implemented here (PROTOCOL.md sections 2 and 8):

    session 1   present as a phone: 04e8:685d "SAMSUNG_Android" with the
                phase-1 identity chosen by *phone_profile* (see
                aoa.phone_descriptors; the stream command presents the
                "minimal" one, the default here is the handset's 121-byte
                composite configuration, aoa.PHONE_CONFIG)
                serve GET_DESCRIPTOR / SET_CONFIGURATION
                answer AOA GET_PROTOCOL(51) with version 2
                collect the six SEND_STRING(52) values
                on START_ACCESSORY(53): tear the session down

    session 2   present as 18d1:2d01 with the vendor accessory interface
                (EP 0x81 IN, EP 0x01 OUT, bulk, 512 bytes)
                on SET_CONFIGURATION: enable both endpoints
                -> read() / write() carry the DJI LogicLink tunnel

`read()` returns bytes the goggles sent us (video + telemetry); `write()`
sends app -> goggles traffic.

Raspberry Pi 4B / dwc2 notes
----------------------------
These dwc2 behaviours shape the code below. See ``pryer/rawgadget.py`` for
the kernel details.

1. **A bus reset is delivered as ``DISCONNECT``, not ``RESET``.** dwc2 never
   raises ``USB_RAW_EVENT_RESET``, and the goggles resets the bus several times
   on the way up (3-4 bus resets per enumeration). So the ep0 loop treats both
   events as "the link restarted": disable every endpoint, forget the handles,
   keep fetching events, and re-enable on the *next* ``SET_CONFIGURATION``.
   An endpoint handle from before a reset is never reused.
2. **Endpoint I/O returns ``ESHUTDOWN`` across a reset.** That is not a fault,
   so :meth:`AoaAccessory.read` waits for the link to come back instead of
   aborting the stream.
3. **Phase 1 needs no endpoints at all.** The goggles moves no bulk data before
   START_ACCESSORY, so that session advertises the handset's endpoints and
   enables none of them.
4. **``vbus_draw`` always fails**, because no ``usb_phy`` is bound on a Pi. It
   is advisory only and its failure is ignored.

Acknowledging requests without a data stage
-------------------------------------------
Raw Gadget expects ``EP0_READ`` of length 0 -- not ``EP0_WRITE`` -- as the
status stage of every request that has no data stage (see
:func:`pryer.rawgadget.ep0_is_in`): SET_CONFIGURATION, SET_INTERFACE,
CLEAR/SET_FEATURE, START_ACCESSORY and a zero-length SEND_STRING. A
zero-length ``EP0_WRITE`` is rejected with EBUSY and queues nothing, and the
UDC then NAKs the host's status stage indefinitely: the goggles never gets
past SET_CONFIGURATION and never sends GET_PROTOCOL. Every no-data request
therefore goes through :meth:`RawGadget.ep0_ack`, and any error answering ep0
ends the session at ERROR level instead of being mistaken for a bus reset.

Letting go of the UDC between the two sessions
----------------------------------------------
Phase 2 can only bind the UDC once phase 1 has released it, and the kernel
does not release a raw-gadget file until every ioctl on it has returned.
After START_ACCESSORY the goggles sends nothing more, so an ep0 thread
blocked in EVENT_FETCH would never return: closing the fd from another thread
would leave phase 1 bound and attached to the bus (a real phone detaches at
once), and phase 2's ``USB_RAW_IOCTL_RUN`` would fail with EBUSY.

``_Session.close`` therefore sets the stop flag and wakes the thread with a
soft disconnect, or a signal if that does not work
(:func:`pryer.rawgadget.stop_ep0_thread`). It closes the fd only once the
thread has exited, then checks that the UDC is free
(:func:`pryer.rawgadget.wait_udc_released`). The soft disconnect also drops
the pull-up at the moment a real phone would disappear. Phase 2's RUN is
retried for up to 2 s while the UDC still reports a bound driver, and any
other failure is reported by what actually holds the UDC.
"""

from __future__ import annotations

import errno
import logging
import threading
import time

from . import aoa, rawgadget, tunnel
from .rawgadget import CtrlRequest, RawGadget

log = logging.getLogger("pryer.accessory")

# Standard USB requests
REQ_GET_STATUS = 0x00
REQ_CLEAR_FEATURE = 0x01
REQ_SET_FEATURE = 0x03
REQ_SET_ADDRESS = 0x05
REQ_GET_DESCRIPTOR = 0x06
REQ_SET_DESCRIPTOR = 0x07
REQ_GET_CONFIGURATION = 0x08
REQ_SET_CONFIGURATION = 0x09
REQ_GET_INTERFACE = 0x0A
REQ_SET_INTERFACE = 0x0B

# Endpoint enabling on a UDC that is still releasing the previous session's
# endpoints can fail transiently; see _Session._enable_endpoint.
EP_ENABLE_RETRIES = 5
EP_ENABLE_RETRY_DELAY = 0.02
EP_ENABLE_TRANSIENT = frozenset((errno.EAGAIN, errno.EBUSY))
FALLBACK_MPS = 64

# Pause between RUN attempts while the previous session is letting go of the
# UDC; see AoaAccessory._start_session.
RUN_RETRY_DELAY = 0.1


class AccessoryTimeout(RuntimeError):
    pass


class _Session:
    """One raw-gadget enumeration with a fixed descriptor set."""

    def __init__(self, descriptors: dict, driver: str | None = None,
                 udc: str | None = None,
                 speed: int = rawgadget.SPEED_HIGH, gadget=None,
                 enable_endpoints: bool = True):
        self.desc = descriptors
        # Phase 1 advertises the handset's seven endpoints but never moves a
        # byte on any of them -- the goggles does control
        # transfers only until START_ACCESSORY -- so there is nothing to enable
        # and no reason to ask dwc2 for an interrupt endpoint with a 10-byte
        # max packet that we would then leave idle.
        self.enable_endpoints = enable_endpoints
        # `gadget` is an injection point for tests; normally we open the real
        # /dev/raw-gadget here. Both names default to None so RawGadget can
        # resolve them from sysfs -- on a Pi 4B they are 'fe980000.usb', and a
        # hard-coded 'dwc2' would fail to bind.
        self.gadget = gadget if gadget is not None else RawGadget(
            driver, udc, speed)
        self.speed = speed
        # The UDC device name, for checking in sysfs that close() released it.
        self.udc = getattr(self.gadget, "device", None) or udc or ""
        self.configured = threading.Event()
        self.stop = threading.Event()
        self.ep_handles: dict[int, int] = {}
        # Bumped on every successful SET_CONFIGURATION so that readers can tell
        # "the link came back" from "the link never went away".
        self.generation = 0
        self._ep_lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self.error: BaseException | None = None
        # Enumeration progress, for diagnosing a handshake that never starts:
        # a run that gets no control requests at all is a cable, power or UDC
        # problem, whereas one that is enumerated and configured and then goes
        # quiet has a problem at the status stage or with the phase-1
        # identity (see _phase1_timeout_message).
        self.control_requests = 0
        self.descriptors_read: set[tuple[int, int]] = set()
        self.configured_once = threading.Event()
        # AOA state
        self.strings: dict[int, str] = {}
        self.start_requested = threading.Event()
        self.protocol_asked = threading.Event()

    # ------------------------------------------------------------------ #
    def start(self) -> None:
        self.gadget.run()
        self._thread = threading.Thread(target=self._loop, name="ep0",
                                        daemon=True)
        self._thread.start()

    def close(self, wait_release: bool = True) -> bool:
        """
        End the session and give the UDC back. Returns True once it is free.

        Pass ``wait_release=False`` for a session whose RUN failed. It never
        bound the UDC, so the driver still listed there belongs to someone
        else and waiting for it to leave would only waste time.

        The order matters. Closing the fd first would leave the gadget bound
        for as long as the ep0 thread stays blocked in EVENT_FETCH, and after
        START_ACCESSORY that is indefinitely. So: stop flag, wake and join the
        thread, close the fd, then confirm in sysfs that the UDC is unbound.
        """
        self.stop.set()
        exited = rawgadget.stop_ep0_thread(self.gadget, self._thread, log=log)
        self.gadget.close()
        if not exited:
            log.error("the ep0 thread is still blocked in raw-gadget after "
                      "%.1f s; UDC %s stays bound until that call returns",
                      rawgadget.EP0_STOP_TIMEOUT, self.udc)
            return False
        if not wait_release:
            return True
        if not rawgadget.wait_udc_released(self.udc):
            log.warning("UDC %s still reports the gadget driver %r after the "
                        "session was closed", self.udc,
                        rawgadget.udc_function(self.udc))
            return False
        return True

    def handle_one(self, req: CtrlRequest) -> None:
        """Dispatch a single control request (used by the test harness)."""
        self._handle_control(req)

    # ------------------------------------------------------------------ #
    def _loop(self) -> None:
        """
        Service endpoint 0 for the life of the session.

        This loop must survive bus resets rather than exit on them. dwc2 reports
        a reset as DISCONNECT and the goggles issues several while bringing the
        link up, so exiting on the first one would look exactly like the goggles
        never answering.
        """
        while not self.stop.is_set():
            try:
                etype, req, _ = self.gadget.control_event()
            except OSError as exc:
                if self.stop.is_set():
                    return
                if exc.errno == errno.EINTR:
                    # A signal (Ctrl-C, or a stray INTERRUPT_SIGNAL) woke the
                    # fetch; nothing happened on the bus.
                    continue
                if rawgadget.is_link_gone(exc):
                    # The UDC dropped off mid-fetch: tear the endpoints down and
                    # keep waiting for the host to re-enumerate us.
                    log.debug("ep0 fetch interrupted by a link reset: %s", exc)
                    self._on_link_reset()
                    continue
                self.error = exc
                log.error("ep0 event fetch failed, ending the session: %s", exc)
                return
            try:
                if etype == rawgadget.EVENT_CONTROL and req is not None:
                    self._handle_control(req)
                elif etype in rawgadget.RESET_EVENTS:
                    log.debug("bus %s -- disabling endpoints, waiting for "
                              "re-enumeration",
                              rawgadget.EVENT_NAMES.get(etype, etype))
                    self._on_link_reset()
                elif etype == rawgadget.EVENT_CONNECT:
                    log.debug("bus connect; UDC endpoints: %s",
                              self._describe_eps())
                else:
                    log.debug("event %s",
                              rawgadget.EVENT_NAMES.get(etype, etype))
            except OSError as exc:
                if self.stop.is_set():
                    return
                if exc.errno == errno.EINTR:
                    log.debug("answering %r was interrupted by a signal", req)
                    continue
                # ep0=True: on ep0, EBUSY is raw-gadget refusing the call
                # (typically the wrong direction for the pending request), not
                # a reset. Treating it as a reset would hide the error.
                if rawgadget.is_link_gone(exc, ep0=True):
                    log.debug("control request aborted by a link reset: %s",
                              exc)
                    self._on_link_reset()
                    continue
                self.error = exc
                log.error("answering %r failed, ending the session: %s%s",
                          req, exc,
                          " (raw-gadget rejects an ep0 call in the wrong "
                          "direction with EBUSY)"
                          if getattr(exc, "errno", None) == errno.EBUSY
                          else "")
                return

    def _describe_eps(self) -> str:
        """UDC endpoint inventory, for -vv triage of EP_ENABLE failures."""
        info = getattr(self.gadget, "eps_info", None)
        if info is None:
            return "unknown"
        try:
            eps = info()
        except OSError as exc:
            return "unavailable (%s)" % exc
        return ", ".join(
            "%s(addr=0x%02x%s%s max=%d)"
            % (e["name"], e["addr"], " bulk" if e.get("bulk") else "",
               " in" if e.get("dir_in") else (" out" if e.get("dir_out") else ""),
               e["maxpacket_limit"])
            for e in eps) or "none reported"

    def _on_link_reset(self) -> None:
        """
        Bring the endpoints down after a reset/disconnect.

        The Raw Gadget hardware notes require exactly this for dwc2: disable
        every endpoint, drop the handles, keep fetching events, and re-enable
        only after the next SET_CONFIGURATION. Keeping a stale handle is worse
        than having none, since raw-gadget indexes its endpoint table by handle.
        """
        with self._ep_lock:
            handles, self.ep_handles = self.ep_handles, {}
        disable = getattr(self.gadget, "ep_disable", None)
        if disable is not None:
            for addr, handle in handles.items():
                try:
                    disable(handle)
                except OSError as exc:
                    log.debug("ep 0x%02x already gone: %s", addr, exc)
        self.configured.clear()

    # ------------------------------------------------------------------ #
    def _handle_control(self, req: CtrlRequest) -> None:
        g = self.gadget
        self.control_requests += 1
        if req.req_type == 2:  # vendor
            self._handle_vendor(req)
            return
        if req.req_type != 0:  # class requests: nothing to do
            g.ep0_stall()
            return

        if req.bRequest == REQ_GET_DESCRIPTOR:
            dtype = req.wValue >> 8
            index = req.wValue & 0xFF
            self.descriptors_read.add((dtype, index))
            if dtype == aoa.DT_DEVICE:
                g.ep0_reply(req, self.desc["device"])
            elif dtype == aoa.DT_CONFIG:
                g.ep0_reply(req, self.desc["config"])
            elif dtype == aoa.DT_STRING:
                if index == 0:
                    g.ep0_reply(req, aoa.lang_descriptor())
                else:
                    # The string table is keyed by the *handset's own* indices,
                    # which start at 2 and are what the descriptors point at,
                    # so it is a dict, not a list counted from 1.
                    text = _string_at(self.desc["strings"], index)
                    if text is None:
                        log.debug("no string at index %d -- stalling", index)
                        g.ep0_stall()
                    else:
                        g.ep0_reply(req, aoa.string_descriptor(text))
            elif dtype == aoa.DT_DEVICE_QUALIFIER:
                # Answer instead of stalling. dwc2 is high-speed-only and the
                # Raw Gadget notes warn that descriptors inconsistent with the
                # emulated speed can make the UDC reset the link, which looks
                # like an enumeration that restarts forever.
                g.ep0_reply(req, aoa.device_qualifier(self.desc["device"]))
            elif dtype == aoa.DT_OTHER_SPEED_CONFIG:
                g.ep0_reply(req, aoa.other_speed_config(self.desc["config"]))
            else:
                # BOS (SuperSpeed), debug descriptor, ... -- we are a plain
                # high-speed device, so stalling these is correct.
                g.ep0_stall()
            return

        # Requests without a data stage are acknowledged with ep0_ack(), i.e.
        # a zero-length EP0_READ -- never ep0_write(). See the module notes.
        if req.bRequest == REQ_SET_CONFIGURATION:
            # Enable endpoints and CONFIGURE first, then complete the status
            # stage, then report "configured" -- the order of the upstream
            # raw-gadget examples. Until the ack is queued the UDC NAKs the
            # host's status stage, which is harmless for the few ms this takes.
            self._configure(req.wValue)
            g.ep0_ack()
            if req.wValue:
                self._mark_configured()
            return

        if req.bRequest == REQ_GET_CONFIGURATION:
            g.ep0_reply(req, b"\x01" if self.configured.is_set() else b"\x00")
            return

        if req.bRequest == REQ_SET_INTERFACE:
            g.ep0_ack()
            return

        if req.bRequest == REQ_GET_INTERFACE:
            g.ep0_reply(req, b"\x00")
            return

        if req.bRequest == REQ_GET_STATUS:
            g.ep0_reply(req, b"\x00\x00")
            return

        if req.bRequest in (REQ_CLEAR_FEATURE, REQ_SET_FEATURE):
            g.ep0_ack()
            return

        log.debug("unhandled standard request %s", req)
        g.ep0_stall()

    # ------------------------------------------------------------------ #
    def _handle_vendor(self, req: CtrlRequest) -> None:
        g = self.gadget
        if req.bRequest == aoa.ACCESSORY_GET_PROTOCOL and req.is_in:
            log.info("AOA: goggles asked for protocol version")
            self.protocol_asked.set()
            g.ep0_reply(req, aoa.AOA_PROTOCOL_VERSION.to_bytes(2, "little"))
            return

        if req.bRequest == aoa.ACCESSORY_SEND_STRING and not req.is_in:
            # Always read, even for wLength 0: that read *is* the status stage.
            data = g.ep0_read(req.wLength)
            text = data.split(b"\x00")[0].decode("utf-8", "replace")
            self.strings[req.wIndex] = text
            log.info("AOA: string[%d] %-12s = %r", req.wIndex,
                     aoa.STRING_IDS.get(req.wIndex, "?"), text)
            return

        if req.bRequest == aoa.ACCESSORY_START:
            log.info("AOA: START_ACCESSORY -- switching to accessory mode")
            # No data stage: a zero-length read completes it (a write would
            # be refused and leave the status stage NAKed).
            g.ep0_ack()
            self.start_requested.set()
            return

        log.debug("unhandled vendor request %s", req)
        g.ep0_stall()

    # ------------------------------------------------------------------ #
    def _configure(self, value: int) -> None:
        """
        Handle SET_CONFIGURATION.

        Endpoints are re-enabled on *every* non-zero SET_CONFIGURATION, not
        just the first. dwc2 invalidates its endpoint state on each bus reset
        (which it reports as DISCONNECT), and :meth:`_on_link_reset` drops the
        handles in response, so a second enumeration -- the normal case with the
        goggles, which resets the bus repeatedly -- has to allocate fresh ones.
        Enabling only once would leave the endpoints down after the first
        reset, and every transfer would fail on a stale handle.

        SET_CONFIGURATION 0 is the host un-configuring us; that is a teardown,
        not a no-op.
        """
        g = self.gadget
        if value == 0:
            log.debug("SET_CONFIGURATION 0 -- host un-configured us")
            self._on_link_reset()
            return

        handles: dict[int, int] = {}
        for addr, desc in (_endpoints_of(self.desc["config"])
                           if self.enable_endpoints else []):
            try:
                handles[addr] = self._enable_endpoint(addr, desc)
                log.debug("enabled ep 0x%02x -> handle %d", addr, handles[addr])
            except OSError as exc:
                log.warning("could not enable ep 0x%02x: %s (UDC endpoints: "
                            "%s)", addr, exc, self._describe_eps())
        with self._ep_lock:
            self.ep_handles = handles

        # Advisory only, and it always fails on a Raspberry Pi: dwc2 has no
        # usb_phy bound, so dwc2_hsotg_vbus_draw() returns -ENOTSUPP. Letting
        # that OSError escape would kill the ep0 thread in the middle of the
        # handshake. The host takes our current budget from bMaxPower in the
        # configuration descriptor regardless.
        if not g.vbus_draw(500 // 2):
            log.debug("vbus_draw not supported by this UDC (expected on a "
                      "Raspberry Pi); ignoring")

        g.configure()

    def _mark_configured(self) -> None:
        """Called once the SET_CONFIGURATION status stage has been queued."""
        self.generation += 1
        self.configured.set()
        self.configured_once.set()
        log.debug("configured (generation %d)", self.generation)

    def _enable_endpoint(self, addr: int, desc: bytes) -> int:
        """
        EP_ENABLE with two recoveries.

        * EAGAIN / EBUSY: raw-gadget returns EBUSY when no UDC endpoint is free
          ("no endpoints available"), which is transient right after the
          previous session let go of the UDC. Retry a few times.
        * EINVAL: some UDCs reject a 512-byte bulk wMaxPacketSize (e.g. when
          the link came up at full speed). Retry once with 64 bytes. That no
          longer matches the descriptor the host read, so it is logged as a
          warning; on a Pi 4B's high-speed dwc2 it should never trigger.
        """
        g = self.gadget
        fallback_tried = False
        attempt = 0
        while True:
            try:
                return g.ep_enable(desc)
            except OSError as exc:
                if (exc.errno in EP_ENABLE_TRANSIENT
                        and attempt < EP_ENABLE_RETRIES - 1):
                    attempt += 1
                    log.debug("ep 0x%02x enable: %s -- retry %d/%d", addr,
                              exc, attempt, EP_ENABLE_RETRIES - 1)
                    time.sleep(EP_ENABLE_RETRY_DELAY * attempt)
                    continue
                mps = int.from_bytes(desc[4:6], "little") & 0x7FF
                if (exc.errno == errno.EINVAL and not fallback_tried
                        and mps > FALLBACK_MPS):
                    fallback_tried = True
                    log.warning("ep 0x%02x: UDC rejected wMaxPacketSize %d "
                                "(%s); retrying with %d, which no longer "
                                "matches the advertised descriptor", addr,
                                mps, exc, FALLBACK_MPS)
                    desc = (desc[:4] + FALLBACK_MPS.to_bytes(2, "little")
                            + desc[6:])
                    continue
                raise


def _ids_of(descriptors: dict) -> tuple[int, int]:
    """(idVendor, idProduct) of a descriptor set."""
    dev = descriptors["device"]
    return (int.from_bytes(dev[8:10], "little"),
            int.from_bytes(dev[10:12], "little"))


def _string_at(strings, index: int) -> str | None:
    """
    Look a string descriptor up by the index the descriptors advertise.

    Accepts either the dict form used by :mod:`pryer.aoa` (real handset indices,
    starting at 2) or the legacy 1-based list, so a caller passing its own
    descriptor set keeps working.
    """
    if isinstance(strings, dict):
        return strings.get(index)
    if 1 <= index <= len(strings):
        return strings[index - 1]
    return None


def _endpoints_of(config: bytes) -> list[tuple[int, bytes]]:
    """Walk a configuration descriptor and yield (address, 7-byte descriptor)."""
    out, i = [], 0
    while i + 2 <= len(config):
        blen, btype = config[i], config[i + 1]
        if blen == 0:
            break
        if btype == aoa.DT_ENDPOINT and blen >= 7:
            out.append((config[i + 2], bytes(config[i:i + 7])))
        i += blen
    return out


def _phase1_timeout_message(s: _Session, timeout: float) -> str:
    """
    Explain a phase-1 timeout in terms of how far the goggles actually got.

    "Check the cable" is the wrong advice for most of these: a goggles that
    enumerated the gadget, read its descriptors and selected configuration 1
    without a single stall has proved the cable and the UDC work. The states
    below need different next steps, so name them.
    """
    if s.control_requests == 0:
        return ("the goggles never sent a single control request in %.0f s, so "
                "we were never enumerated. Check that the cable carries data "
                "(many USB-C cables are power-only), that it goes to the "
                "peripheral-capable port (the USB-C socket on a Pi 4B, not a "
                "USB-A one), and that dwc2 is in peripheral or OTG mode."
                % timeout)
    if not s.configured_once.is_set():
        return ("enumeration started but never completed: %d control requests, "
                "descriptors read %s, no acknowledged SET_CONFIGURATION in "
                "%.0f s. Run with -vv to see which request the goggles stopped "
                "at."
                % (s.control_requests, sorted(s.descriptors_read), timeout))
    if not s.protocol_asked.is_set():
        vid, pid = _ids_of(s.desc)
        return ("the goggles enumerated and configured us as %04x:%04x (status "
                "stage of SET_CONFIGURATION completed) and then went quiet: no "
                "AOA GET_PROTOCOL(51) in %.0f s (%d control requests total). "
                "That is the goggles declining this phase-1 identity. Capture "
                "the bus and compare with a real handset's enumeration; the "
                "handset identity (AoaAccessory(phone_profile=\"handset\"), "
                "see aoa.PHONE_PROFILES) is the one the goggles is known to "
                "accept."
                % (vid, pid, timeout, s.control_requests))
    return ("the goggles asked for the AOA protocol version%s but never sent "
            "START_ACCESSORY(53) within %.0f s. Strings received: %r. This is "
            "usually the goggles waiting on its own side of the link -- check "
            "that they are powered on and bound to the aircraft."
            % (" and sent %d identity strings" % len(s.strings)
               if s.strings else "", timeout, dict(s.strings)))


class AoaAccessory:
    """
    High-level: run the two-phase handshake and hand back a byte pipe.

    Usage::

        with AoaAccessory() as link:      # UDC and driver auto-detected
            while True:
                data = link.read()

    Leave *driver* and *udc* as None unless you have two UDCs and want a
    specific one. On a Raspberry Pi 4B the correct values are both
    ``fe980000.usb``, which is why nothing here hard-codes ``"dwc2"``.
    """

    def __init__(self, driver: str | None = None, udc: str | None = None,
                 *, with_adb: bool = True,
                 read_size: int | None = None,
                 handshake_timeout: float = 60.0,
                 relink_timeout: float = 5.0,
                 accessory_strings: dict | None = None,
                 phone_profile: str = "handset"):
        self.udc = rawgadget.pick_udc(udc)
        self.driver = driver or rawgadget.udc_driver_name(self.udc)
        self.with_adb = with_adb
        self.read_size = read_size or tunnel.ACCESSORY_READ_SIZE
        self.handshake_timeout = handshake_timeout
        # How long a read/write waits for the host to finish re-enumerating us
        # after a bus reset before giving up. dwc2 surfaces a reset as
        # ESHUTDOWN on in-flight endpoint I/O; the goggles normally comes back
        # within a few hundred ms.
        self.relink_timeout = relink_timeout
        self.expected_strings = accessory_strings or aoa.ACCESSORY_STRINGS
        # "handset" presents the Samsung handset's descriptor layout; "dji"
        # is the 18d1:4ee0 identity another open-source client uses;
        # "minimal" is a single vendor interface. See aoa.phone_descriptors().
        self.phone_profile = phone_profile
        self.session: _Session | None = None
        self.ep_in = None
        self.ep_out = None
        self.observed_strings: dict[int, str] = {}

    # ------------------------------------------------------------------ #
    def __enter__(self) -> "AoaAccessory":
        self.open()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def open(self) -> None:
        problems = rawgadget.diagnose()
        if problems:
            raise RuntimeError("USB Raw Gadget unusable:\n  - "
                               + "\n  - ".join(problems))
        log.info("UDC %s, gadget driver name %r%s", self.udc, self.driver,
                 " on " + rawgadget.board_model()
                 if rawgadget.board_model() else "")
        # Lets close() fall back to a signal if the soft disconnect does not
        # wake the ep0 thread. Must run in the main thread; harmless if not.
        if not rawgadget.install_interrupt_handler():
            log.debug("could not install the %s handler (not the main "
                      "thread); session teardown relies on the soft "
                      "disconnect alone", rawgadget.INTERRUPT_SIGNAL.name)
        self._phase_phone()
        self._phase_accessory()

    def close(self) -> None:
        if self.session:
            self.session.close()
            self.session = None

    # ------------------------------------------------------------------ #
    def _new_session(self, desc: dict, enable_endpoints: bool = True
                     ) -> _Session:
        """One raw-gadget session on our UDC (tests override this)."""
        return _Session(desc, self.driver, self.udc,
                        enable_endpoints=enable_endpoints)

    def _start_session(self, desc: dict, enable_endpoints: bool = True
                       ) -> _Session:
        """
        Open a session and RUN it, retrying while the UDC is still bound.

        RUN fails with EBUSY for as long as the previous session's driver is
        bound to the UDC. close() waits for the release, but the kernel
        unbinds on the last file reference and that is not always this
        program's to control. So the call is retried for up to
        :data:`rawgadget.UDC_RELEASE_TIMEOUT` seconds while
        ``/sys/class/udc/<udc>/function`` still names a driver. An EBUSY with
        the UDC free is a bind failure, such as a wrong driver name, and is
        raised at once.
        """
        deadline = time.monotonic() + rawgadget.UDC_RELEASE_TIMEOUT
        attempt = 0
        while True:
            s = self._new_session(desc, enable_endpoints)
            try:
                s.start()
                if attempt:
                    log.info("RUN succeeded on attempt %d", attempt + 1)
                return s
            except OSError as exc:
                s.close(wait_release=False)
                owner = rawgadget.udc_function(self.udc)
                if (exc.errno == errno.EBUSY and owner
                        and time.monotonic() < deadline):
                    attempt += 1
                    log.warning("UDC %s is still bound to %r; retrying RUN "
                                "(attempt %d)", self.udc, owner, attempt + 1)
                    time.sleep(RUN_RETRY_DELAY)
                    continue
                raise

    def _phase_phone(self) -> None:
        desc = aoa.phone_descriptors(self.phone_profile)
        vid, pid = _ids_of(desc)
        log.info("phase 1: presenting as %04x:%04x (%s, profile %r, %d-byte "
                 "configuration) on UDC %s", vid, pid,
                 _string_at(desc["strings"], desc["device"][15]) or "?",
                 self.phone_profile, len(desc["config"]), self.udc)
        s = self._start_session(desc, enable_endpoints=False)
        deadline = time.monotonic() + self.handshake_timeout
        while not s.start_requested.is_set():
            if s.error is not None:
                # Already logged at ERROR by the ep0 thread; re-raise so the
                # run ends now rather than after the 60 s timeout.
                s.close()
                raise s.error
            if time.monotonic() > deadline:
                message = _phase1_timeout_message(s, self.handshake_timeout)
                s.close()
                raise AccessoryTimeout(message)
            time.sleep(0.02)
        self.observed_strings = dict(s.strings)
        model = self.observed_strings.get(1, "")
        if model and model != self.expected_strings.get(1):
            log.warning("unexpected accessory model %r (expected %r)",
                        model, self.expected_strings.get(1))
        # Give the host time to finish the control transfers that follow
        # START_ACCESSORY before dropping off the bus. This is not a formality:
        # the goggles issues START_ACCESSORY and then keeps reading string
        # descriptors -- GET_DESCRIPTOR for string 7 lands ~2 ms later and
        # string 5 up to 14 ms later. 150 ms leaves room for a slow gadget
        # to answer both.
        time.sleep(0.15)
        # Leave the bus and release the UDC; see the module notes on why the
        # ep0 thread has to be woken before the fd is closed. A False here is
        # logged by close(), and phase 2 still retries its RUN for a while
        # before giving up.
        released = s.close()
        log.debug("phase 1 closed; UDC %s %s", self.udc,
                  "released" if released else "NOT released")
        # Then stay off the bus long enough for the host to notice the
        # disconnect and begin a fresh enumeration. With a real handset the
        # re-enumeration starts ~500 ms after the accessory-mode switch, and
        # the goggles resets the bus 3-4 times on the way up, so several
        # resets are expected rather than a fault. 300 ms sits well inside
        # that window.
        time.sleep(0.3)

    def _phase_accessory(self) -> None:
        desc = aoa.accessory_descriptors(with_adb=self.with_adb)
        pid = int.from_bytes(desc["device"][10:12], "little")
        log.info("phase 2: re-enumerating as %04x:%04x (accessory mode)",
                 aoa.AOA_VID, pid)
        s = self._start_session(desc)
        if not s.configured.wait(self.handshake_timeout):
            s.close()
            raise AccessoryTimeout(
                "goggles did not configure us in accessory mode")
        self.ep_in = s.ep_handles.get(aoa.ACCESSORY_EP_IN)
        self.ep_out = s.ep_handles.get(aoa.ACCESSORY_EP_OUT)
        if self.ep_out is None:
            eps = s._describe_eps()
            s.close()
            raise RuntimeError(
                "accessory OUT endpoint 0x01 was not enabled. The UDC "
                "reported these endpoints: %s. A Pi 4B's dwc2 has 8 "
                "bidirectional endpoints and supports this layout, so an "
                "EP_ENABLE failure here usually means the previous session did "
                "not release the UDC -- re-run after `sudo modprobe -r "
                "raw_gadget && sudo modprobe raw_gadget`." % eps)
        self.session = s
        log.info("accessory link up: reading from EP 0x%02x, writing to EP 0x%02x",
                 aoa.ACCESSORY_EP_OUT, aoa.ACCESSORY_EP_IN)

    # ------------------------------------------------------------------ #
    def _await_relink(self, addr: int) -> int:
        """
        Block until the link is configured again, then return a fresh handle.

        dwc2 fails in-flight endpoint I/O with ESHUTDOWN when the host resets
        the bus, and reports the reset itself as DISCONNECT. The ep0 thread
        disables the endpoints and re-enables them on the next
        SET_CONFIGURATION, so the right response here is to wait for that and
        pick up the new handle rather than to abort the stream.
        """
        s = self.session
        assert s is not None
        if not s.configured.wait(self.relink_timeout):
            raise RuntimeError(
                "USB link went down and the goggles did not re-enumerate us "
                "within %.1f s" % self.relink_timeout)
        handle = s.ep_handles.get(addr)
        if handle is None:
            raise RuntimeError(
                "endpoint 0x%02x was not re-enabled after the bus reset" % addr)
        return handle

    def read(self, size: int | None = None) -> bytes:
        """
        Read one bulk transfer from the goggles (blocking).

        `size` defaults to `read_size`, 16 kiB unless overridden. A transfer
        ends at the goggles' first short packet, so one read returns at most
        one tunnel packet (4,104 bytes for video) whatever the size; see
        `pryer.tunnel.ACCESSORY_READ_SIZE` for why a large buffer only slowed
        the loop down. dwc2's per-request limit (~512 KiB for a 512-byte bulk
        endpoint) is far above either value.

        A bus reset mid-read is transparent: the transfer is retried once the
        host has re-configured us.
        """
        assert self.session is not None
        length = size or self.read_size
        try:
            return self.session.gadget.ep_read(self.ep_out, length)
        except OSError as exc:
            if not rawgadget.is_link_gone(exc):
                raise
            log.info("bulk IN interrupted by a bus reset (%s); waiting for "
                     "re-enumeration", exc)
            self.ep_out = self._await_relink(aoa.ACCESSORY_EP_OUT)
            self.ep_in = self.session.ep_handles.get(aoa.ACCESSORY_EP_IN)
            return self.session.gadget.ep_read(self.ep_out, length)

    def write(self, data: bytes) -> None:
        """Send data to the goggles."""
        assert self.session is not None
        if self.ep_in is None:
            raise RuntimeError("accessory IN endpoint 0x81 was not enabled")
        try:
            self.session.gadget.ep_write(self.ep_in, data)
        except OSError as exc:
            if not rawgadget.is_link_gone(exc):
                raise
            log.info("bulk OUT interrupted by a bus reset (%s); waiting for "
                     "re-enumeration", exc)
            self.ep_in = self._await_relink(aoa.ACCESSORY_EP_IN)
            self.ep_out = self.session.ep_handles.get(aoa.ACCESSORY_EP_OUT)
            self.session.gadget.ep_write(self.ep_in, data)
