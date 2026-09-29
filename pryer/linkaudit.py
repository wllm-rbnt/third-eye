"""
Did the app side receive what the goggles put on the wire?

A bus capture shows what crossed the cable, which is not always what reached
the application. A USB host can acknowledge a packet on the wire and still
lose it in its own stack (PROTOCOL.md section 9.3 describes how a Raspberry
Pi 4B running libusb does that with multi-URB reads). The wire stream is then
complete and decodes cleanly, and yet the application saw less. Two checks
find such losses from the capture alone.

`request_audit()`
    Every DUML request the goggles sends to the app that asks for a reply,
    and whether the app's reply came before the goggles gave up and sent the
    request again. On a working link the reply follows within a few
    milliseconds. A request that goes unanswered and is re-sent about 200 ms
    later never reached the app. This works on every capture with both tunnel
    directions, whichever side is the host.

`host_read_audit()`
    For a bulk IN endpoint, i.e. when the capturing side's peer is the host
    (the iOS topology): short packets that the host ACKed and then dropped.
    A short packet ends a transfer. Once the host has accepted it, the next IN
    token on that endpoint has to wait for the driver to start the next
    transfer, which takes 16 us or more on a Pi 4B's dwc2 (median about
    40 us). If the host keeps polling within a few microseconds, its channel
    never saw the transfer end: the packet's DATA toggle was one the host
    believed it had already received, and USB 2.0 (section 8.6 of the USB
    specification) has the host ACK such a packet and ignore it. Dropped
    packets show the next token 2-9 us after the packet.

    The signature is about timing, and a host controller that restarts a
    channel faster than 12 us would look the same. So `decode` prints it
    together with the request cross-check, which tells the two apart: a
    packet that was really dropped is never answered, so the requests it
    carried go unanswered while requests elsewhere are answered.
"""

from __future__ import annotations

import collections
from collections.abc import Iterable
from dataclasses import dataclass, field

from . import duml, pcapng, tunnel

# A request the app has not answered within this long counts as unanswered
# when the goggles does not send it again. The goggles re-sends after
# ~200-230 ms; the app's replies take 0.5-4 ms.
REPLY_WINDOW_NS = 150_000_000

# The host polls again this soon after a short packet only if it did not
# accept the packet (see the module docstring). Measured on a Pi 4B host:
# dropped packets are followed by the next token after 2.1-8.8 us, accepted
# ones after 16.4 us or more.
DROP_GAP_NS = 12_000


# --------------------------------------------------------------------------- #
# Requests and replies
# --------------------------------------------------------------------------- #
@dataclass
class RequestAudit:
    """Goggles requests that asked for a reply, and what became of them."""
    sent: int = 0                 # transmissions, re-sent ones included
    distinct: int = 0             # by (src, seq, cmd_set, cmd_id)
    unanswered: int = 0           # transmissions no reply followed
    resent: int = 0               # distinct requests sent more than once
    never_answered: int = 0       # distinct requests with no reply at all
    undecided: int = 0            # too close to the end of the capture to tell
    most_copies: int = 0          # the most transmissions of one request
    most_copied: tuple[int, int, int] | None = None   # (cmd_set, cmd_id, seq)
    by_command: dict[tuple[int, int], list[int]] = field(default_factory=dict)
    unanswered_at: set[int] = field(default_factory=set)   # timestamps (ns)
    answered_at: set[int] = field(default_factory=set)

    @property
    def answered(self) -> int:
        return self.sent - self.unanswered - self.undecided


def _request_key(f: duml.Frame) -> tuple[int, int, int, int]:
    return (f.src, f.seq, f.cmd_set, f.cmd_id)


def _reply_key(f: duml.Frame) -> tuple[int, int, int, int]:
    return (f.dst, f.seq, f.cmd_set, f.cmd_id)


def audit_requests(requests: Iterable[tuple[int, duml.Frame]],
                   replies: Iterable[tuple[int, duml.Frame]], *,
                   end_ns: int | None = None,
                   window_ns: int = REPLY_WINDOW_NS) -> RequestAudit:
    """
    Match the goggles' requests with the app's replies.

    *requests* are (timestamp, frame) for goggles -> app frames, *replies* the
    same for app -> goggles; non-requests and non-replies are ignored. A
    transmission counts as answered if a reply with the same source, sequence
    number and command arrives before the next copy of the request, or within
    *window_ns* for the last copy. A last copy sent less than *window_ns*
    before *end_ns* (the end of the capture) counts as undecided.
    """
    copies: dict[tuple, list[int]] = collections.defaultdict(list)
    for ts, f in requests:
        if f.dst == duml.DEV_MOBILE_APP and f.wants_ack():
            copies[_request_key(f)].append(ts)
    answers: dict[tuple, list[int]] = collections.defaultdict(list)
    for ts, f in replies:
        if f.is_response:
            answers[_reply_key(f)].append(ts)
    out = RequestAudit()
    for key, times in copies.items():
        times.sort()
        got = sorted(answers.get(key, ()))
        _src, seq, cmd_set, cmd_id = key
        stats = out.by_command.setdefault((cmd_set, cmd_id), [0, 0])
        out.distinct += 1
        out.sent += len(times)
        stats[0] += len(times)
        if len(times) > 1:
            out.resent += 1
        if len(times) > out.most_copies:
            out.most_copies = len(times)
            out.most_copied = (cmd_set, cmd_id, seq)
        if not got:
            out.never_answered += 1
        for n, t0 in enumerate(times):
            last = n + 1 == len(times)
            t1 = times[n + 1] if not last else t0 + window_ns
            if any(t0 <= a < t1 for a in got):
                out.answered_at.add(t0)
                continue
            if last and end_ns is not None and end_ns < t1:
                out.undecided += 1
                continue
            out.unanswered += 1
            stats[1] += 1
            out.unanswered_at.add(t0)
    return out


def _frames(transfers, *, at_end: bool) -> list[tuple[int, duml.Frame]]:
    """(timestamp, frame) for every DUML frame in the control channel."""
    out = []
    for t in transfers:
        ts = t.t_end if at_end else t.t_start
        for pkt in tunnel.demux_bytes(t.data)[0]:
            if pkt.is_control:
                out.extend((ts, f) for f in duml.parse_all(pkt.payload))
    return out


def request_audit(path: str) -> RequestAudit | None:
    """`audit_requests` on a pcapng capture; None without both directions."""
    sc = _scan(path)
    if sc is None:
        return None
    # A request is timed by its transfer's last packet, which is the packet
    # `host_read_audit` classifies; a reply by its first.
    return audit_requests(_frames(sc.down, at_end=True),
                          _frames(sc.up, at_end=False), end_ns=sc.end_ns)


# --------------------------------------------------------------------------- #
# Packets the host acknowledged and dropped
# --------------------------------------------------------------------------- #
@dataclass
class HostReadAudit:
    addr: int
    ep: int
    short_packets: int = 0        # ACKed packets shorter than max packet size
    dropped_at: list[int] = field(default_factory=list)   # timestamps (ns)
    accepted_at: list[int] = field(default_factory=list)  # timestamps (ns)
    repoll_ns: list[int] = field(default_factory=list)    # after accepted ones

    @property
    def dropped(self) -> int:
        return len(self.dropped_at)

    def repoll_percentile(self, q: float) -> float | None:
        """Gap from an accepted short packet to the next IN token, in us."""
        if not self.repoll_ns:
            return None
        gaps = sorted(self.repoll_ns)
        i = min(len(gaps) - 1, max(0, int(round(q * (len(gaps) - 1)))))
        return gaps[i] / 1e3


def audit_host_reads(transactions: Iterable[pcapng.Transaction], addr: int,
                     ep: int, *, mps: int = pcapng.MAX_PACKET_SIZE,
                     gap_ns: int = DROP_GAP_NS) -> HostReadAudit:
    """
    Classify every ACKed short IN packet on (*addr*, *ep*) as accepted or
    dropped, by how soon the host sent the endpoint its next IN token.
    """
    out = HostReadAudit(addr, ep)
    pending: int | None = None          # timestamp of the last short packet
    for t in transactions:
        if t.type != "IN" or t.addr != addr or t.ep != ep:
            continue
        if pending is not None:
            gap = t.ts - pending
            if gap < gap_ns:
                out.dropped_at.append(pending)
            else:
                out.accepted_at.append(pending)
                out.repoll_ns.append(gap)
            pending = None
        if t.handshake == "ACK" and t.data is not None and len(t.data) < mps:
            out.short_packets += 1
            pending = t.ts
    # A short packet with no token after it (the end of the capture) stays
    # unclassified.
    return out


def host_read_audit(path: str) -> HostReadAudit | None:
    """
    `audit_host_reads` on the goggles -> app endpoint of a pcapng capture.

    None unless that endpoint is an IN endpoint, i.e. unless the goggles is
    the USB device (the iOS transport after the role swap). On Android the
    goggles is the host, and its own drops would not show this way.
    """
    sc = _scan(path)
    return None if sc is None else sc.host


# --------------------------------------------------------------------------- #
# One pass over the capture for both checks
# --------------------------------------------------------------------------- #
@dataclass
class _Scan:
    down: list[pcapng.Transfer]
    up: list[pcapng.Transfer]
    host: HostReadAudit | None
    end_ns: int


_CACHE: dict[tuple[str, int, int], _Scan | None] = {}


def _scan(path: str) -> _Scan | None:
    """
    Both tunnel directions as transfers, plus the host-read audit, from a
    single walk of the capture's transactions (it is the slow part), cached
    per file. Same grouping as `pcapng.data_packets` / `pcapng.transfers`.
    """
    import os
    st = os.stat(path)
    key = (os.path.abspath(path), st.st_size, int(st.st_mtime))
    if key in _CACHE:
        return _CACHE[key]
    down, up = pcapng.tunnel_endpoints(path)
    result = None
    if down is not None and up is not None:
        mps = pcapng.MAX_PACKET_SIZE
        want = {(down.addr, down.ep, down.direction): [],
                (up.addr, up.ep, up.direction): []}
        cur: dict[tuple, list] = {}

        def _all():
            for t in pcapng.transactions(path):
                if t.data is not None and t.addr is not None \
                        and t.ep is not None and t.type != "PING":
                    ok = (t.handshake in ("ACK", "NYET")
                          if t.type in ("OUT", "SETUP")
                          else t.handshake in ("ACK", None))
                    k = (t.addr, t.ep, t.type)
                    if ok and k in want:
                        c = cur.setdefault(k, [t.ts, t.ts, bytearray(), []])
                        c[1] = t.ts
                        c[2] += t.data
                        c[3].append(len(t.data))
                        if len(t.data) < mps:
                            want[k].append(pcapng.Transfer(
                                c[0], c[1], bytes(c[2]), len(c[3]), True,
                                c[3]))
                            del cur[k]
                yield t

        host = None
        if down.direction == "IN":
            host = audit_host_reads(_all(), down.addr, down.ep, mps=mps)
        else:
            for _ in _all():
                pass
        for k, c in cur.items():           # unterminated transfers at the end
            want[k].append(pcapng.Transfer(c[0], c[1], bytes(c[2]),
                                           len(c[3]), False, c[3]))
        result = _Scan(want[(down.addr, down.ep, down.direction)],
                       want[(up.addr, up.ep, up.direction)], host,
                       max(down.t_last, up.t_last))
    if len(_CACHE) > 4:
        _CACHE.clear()
    _CACHE[key] = result
    return result


# --------------------------------------------------------------------------- #
# Both, as `decode` prints them
# --------------------------------------------------------------------------- #
def cross_check(req: RequestAudit,
                host: HostReadAudit) -> tuple[int, int, int, int]:
    """
    (dropped requests, of them unanswered, other requests, of them unanswered).

    A request is "dropped" if the packet that ended its transfer has the
    dropped signature. Timestamps line up because both come from the same
    data packets.
    """
    dropped = set(host.dropped_at)
    d_total = d_lost = o_total = o_lost = 0
    for ts in req.unanswered_at | req.answered_at:
        lost = ts in req.unanswered_at
        if ts in dropped:
            d_total += 1
            d_lost += lost
        else:
            o_total += 1
            o_lost += lost
    return d_total, d_lost, o_total, o_lost


def describe(path: str) -> list[str]:
    """The `decode` lines for a pcapng capture (empty if nothing applies)."""
    req = request_audit(path)
    if req is None or not req.sent:
        return []
    line = ("app replies:        %d of %d goggles requests that asked for a "
            "reply were answered" % (req.answered, req.sent))
    if req.unanswered:
        line += ", %d were not" % req.unanswered
    if req.undecided:
        line += " (%d too close to the end of the capture to tell)" \
            % req.undecided
    out = [line]
    if req.resent:
        out.append("                    the goggles sent %d request(s) more "
                   "than once, one of them %d times"
                   % (req.resent, req.most_copies))
    host = host_read_audit(path)
    if host is None or not host.short_packets:
        return out
    ep = 0x80 | host.ep
    gap_us = DROP_GAP_NS // 1000
    med = host.repoll_percentile(0.5)
    p99 = host.repoll_percentile(0.99)
    d_total, d_lost, o_total, o_lost = cross_check(req, host)
    # The timing is only a mark. It is called a loss when the requests among
    # those packets went unanswered; a fast host would show the same timing.
    confirmed = bool(d_total) and d_lost * 2 > d_total
    if not host.dropped:
        out.append("host reads:         none of %d short packets on EP 0x%02x "
                   "IN was polled past within %d us: no sign of the host "
                   "dropping data" % (host.short_packets, ep, gap_us))
    elif confirmed:
        out.append("host reads:         %d of %d short packets on EP 0x%02x "
                   "IN were ACKed and then dropped by the host (it polled "
                   "again within %d us, as if nothing had arrived)"
                   % (host.dropped, host.short_packets, ep, gap_us))
    else:
        out.append("host reads:         %d of %d short packets on EP 0x%02x "
                   "IN were followed by another IN token within %d us"
                   % (host.dropped, host.short_packets, ep, gap_us))
    if med is not None:
        out.append("                    after %s, the host polled again a "
                   "median %.0f us later (p99 %.1f ms)"
                   % ("the other short packets" if host.dropped
                      else "each one", med, (p99 or 0) / 1e3))
    if not host.dropped:
        return out
    if d_total:
        out.append("                    %d of those packets carried a "
                   "request: %d went unanswered, against %d of the %d other "
                   "requests" % (d_total, d_lost, o_lost, o_total))
    if confirmed:
        out.append("  -> the host lost data the goggles had delivered. Reads "
                   "longer than one URB do this on a Pi's dwc2 (PROTOCOL.md "
                   "9.3); keep independent single-URB transfers queued "
                   "instead (the default, --transfers)")
    elif d_total:
        out.append("  -> those requests were answered, so this host simply "
                   "polls again that fast; the timing alone is no sign of a "
                   "loss")
    else:
        out.append("  -> none of them carried a request, so nothing confirms "
                   "a loss; the timing alone is no proof")
    return out
