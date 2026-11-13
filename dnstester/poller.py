"""Continuous DNS quality poller (the *poll* part).

Where :mod:`dnstester.loadgen` blasts a resolver at high QPS to find its
breaking point, this module does the opposite: it sends a slow, steady stream
of identical queries to one or more DNS servers and measures the *stability and
quality* of the answers over time — the kind of thing you would leave running
to characterise a resolver or compare several side by side.

Each server is polled by its own thread on a fixed wall-clock cadence (so a
slow answer does not slow the cadence of the others). Every probe records a
latency, an outcome (answered / timed out / errored), the RCODE, and a
TTL-independent signature of the answer section. The :class:`ServerStats`
accumulator turns that raw stream into the KPIs rendered by :mod:`dnstester.tui`.

Pure stdlib: one connected UDP socket per server, ``threading`` for concurrency.
"""

from __future__ import annotations

import math
import random
import re
import socket
import sqlite3
import subprocess
import sys
import threading
import time
from collections import Counter, deque
from collections.abc import Callable
from dataclasses import dataclass, field

from . import wire
from .dblog import EventLog

# How many recent latency samples to retain for percentile / sparkline / the
# "recent window" KPIs. At one probe/second this is ~5 min of history.
_WINDOW = 300


def parse_server(spec: str, default_port: int) -> tuple[str, int]:
    """Parse a ``host``, ``host:port`` or ``[v6]:port`` server spec.

    Bare IPv6 literals (which contain colons) must be bracketed to carry a port,
    e.g. ``[2606:4700:4700::1111]:53``; an unbracketed IPv6 literal is taken
    verbatim with the default port.
    """
    spec = spec.strip()
    if spec.startswith("["):  # [v6]  or  [v6]:port
        host, _, rest = spec[1:].partition("]")
        port = int(rest[1:]) if rest.startswith(":") and rest[1:] else default_port
        return host, port
    if spec.count(":") == 1:  # host:port  (single colon -> not a bare v6 literal)
        host, _, port = spec.partition(":")
        return host, int(port)
    return spec, default_port  # bare v4/hostname, or unbracketed v6 literal


def parse_query(token: str, default_qtype: str) -> tuple[str, str]:
    """Parse one query-pool entry into ``(name, qtype)``.

    Accepts a bare name (``example.com``) or a name with an explicit record
    type written as ``name:AAAA`` or ``name AAAA``. Names never contain a colon
    or whitespace, so the split is unambiguous; an unrecognised/empty type falls
    back to ``default_qtype``.
    """
    token = token.strip()
    parts = token.split()
    if len(parts) == 2:  # "name AAAA"
        name, qtype = parts
    elif ":" in token:  # "name:AAAA"
        name, _, qtype = token.rpartition(":")
    else:
        name, qtype = token, ""
    qtype = qtype.upper()
    if qtype not in wire.QTYPES:
        return token if not name else name, default_qtype
    return name, qtype


def load_queries(
    names: list[str] | None,
    file: str | None,
    default_name: str,
    default_qtype: str,
) -> list[tuple[str, str]]:
    """Build the query pool from ``--qnames`` tokens and/or a ``--qname-file``.

    File format: one entry per line (``name`` or ``name:QTYPE`` / ``name QTYPE``);
    blank lines and ``#`` comments are ignored. If neither source yields an
    entry, the pool is the single ``(default_name, default_qtype)`` query.
    """
    pool: list[tuple[str, str]] = []
    if file:
        with open(file, encoding="utf-8") as fh:
            for line in fh:
                line = line.split("#", 1)[0].strip()
                if line:
                    pool.append(parse_query(line, default_qtype))
    for tok in names or []:
        tok = tok.strip()
        if tok:
            pool.append(parse_query(tok, default_qtype))
    return pool or [(default_name, default_qtype)]


class PingUnavailable(Exception):
    """Raised when the system ``ping`` binary cannot be found/run at all."""


_PING_TIME_RE = re.compile(r"time[=<]\s*([\d.]+)")
# IPv4 replies report ``ttl=NN``; IPv6 reports the hop limit as ``hlim=NN``.
_PING_TTL_RE = re.compile(r"(?:ttl|hlim)[=\s]*(\d+)", re.IGNORECASE)


def ping_once(host: str, timeout: float) -> tuple[float | None, int | None]:
    """Send one ICMP echo via the system ``ping``.

    Returns ``(rtt_ms, ttl)`` for the reply. ``rtt_ms`` is ``None`` when the
    host did not reply within ``timeout`` (loss / unreachable / firewalled —
    ICMP is frequently blocked even where DNS works), and ``ttl`` is ``None``
    when there was no reply or the value could not be parsed. The TTL of a
    received echo is the remaining hop limit, so its variation hints at routing
    changes between us and the resolver. Raises :class:`PingUnavailable` if
    ``ping`` itself is missing, so the caller can disable the ICMP column rather
    than counting bogus losses forever.

    Shells out instead of using a raw socket so it needs no elevated privileges
    on either macOS or Linux. Flag spellings differ between the two: macOS takes
    the per-reply wait in milliseconds, Linux in seconds.
    """
    is_v6 = ":" in host
    if sys.platform == "darwin":
        base = ["ping6"] if is_v6 else ["ping"]
        cmd = base + ["-c", "1", "-W", str(max(1, int(timeout * 1000))), host]
    else:
        base = ["ping", "-6"] if is_v6 else ["ping"]
        cmd = base + ["-c", "1", "-W", str(max(1, round(timeout))), host]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout + 1.0
        )
    except subprocess.TimeoutExpired:
        return None, None  # ping hung past its own deadline -> treat as loss
    except FileNotFoundError as exc:
        raise PingUnavailable(str(exc)) from exc
    if proc.returncode != 0:
        return None, None  # no reply (return 1 on Linux, 2 on macOS, ...)
    m = _PING_TIME_RE.search(proc.stdout)
    rtt = float(m.group(1)) if m else None
    mt = _PING_TTL_RE.search(proc.stdout)
    ttl = int(mt.group(1)) if mt else None
    return rtt, ttl


# Reading the DSCP (top 6 bits of the IPv4 TOS / IPv6 Traffic Class byte) of a
# received datagram needs IP-level ancillary data, which means recvmsg(2) plus
# the per-protocol "deliver TOS/TClass" socket option. Both exist on Linux and
# macOS; anywhere they don't we degrade gracefully and the DSCP stays None.
_HAS_RECVMSG = hasattr(socket.socket, "recvmsg")
_CMSG_BUF = socket.CMSG_SPACE(16) if hasattr(socket, "CMSG_SPACE") else 0
_IPV6_TCLASS = getattr(socket, "IPV6_TCLASS", 36)


def _dscp_from_ancdata(ancdata, is_v6: bool) -> int | None:
    """Pull the DSCP (TOS/TClass byte >> 2) out of recvmsg ancillary data.

    The byte arrives as a single octet on some platforms and a native-endian int
    on others, so we handle both. Returns ``None`` when no IP-level TOS/TClass
    control message is present (option unsupported, or stripped en route).
    """
    for level, ctype, data in ancdata:
        if not data:
            continue
        if is_v6:
            if level == socket.IPPROTO_IPV6 and ctype == _IPV6_TCLASS:
                byte = data[0] if len(data) == 1 else int.from_bytes(data[:4], sys.byteorder)
                return byte >> 2
        elif level == socket.IPPROTO_IP:
            byte = data[0] if len(data) == 1 else int.from_bytes(data[:4], sys.byteorder)
            return byte >> 2
    return None


def _pct(sorted_vals: list[float], q: float) -> float:
    """Linear-interpolation percentile of an already-sorted list (q in 0..1)."""
    if not sorted_vals:
        return math.nan
    if len(sorted_vals) == 1:
        return sorted_vals[0]
    pos = q * (len(sorted_vals) - 1)
    lo = math.floor(pos)
    hi = math.ceil(pos)
    if lo == hi:
        return sorted_vals[lo]
    return sorted_vals[lo] * (hi - pos) + sorted_vals[hi] * (pos - lo)


def _ttl_stats(
    counts: Counter,
) -> tuple[int | None, int | None, int | None, int | None]:
    """Summarise a ``ttl -> occurrences`` Counter.

    Returns ``(min, max, most_frequent, least_frequent)``. Ties on frequency are
    broken toward the smaller TTL so the result is stable across snapshots.
    """
    if not counts:
        return None, None, None, None
    values = sorted(counts)
    most = min(counts, key=lambda v: (-counts[v], v))
    least = min(counts, key=lambda v: (counts[v], v))
    return values[0], values[-1], most, least


@dataclass(slots=True)
class StatsSnapshot:
    """An immutable read-out of one server's KPIs, taken under the stats lock."""

    host: str
    port: int
    # Counters.
    sent: int
    answered: int
    timeouts: int
    errors: int  # socket/network errors (not the same as a DNS error RCODE)
    elapsed: float
    # Latency (milliseconds) over all answered probes.
    last_ms: float
    min_ms: float
    max_ms: float
    mean_ms: float
    stdev_ms: float
    # Latency percentiles over the recent window.
    p50_ms: float
    p90_ms: float
    p95_ms: float
    p99_ms: float
    jitter_ms: float  # RFC 3550-style smoothed interarrival jitter
    ewma_ms: float  # exponentially weighted moving average latency
    cv: float  # coefficient of variation (stdev/mean) — pure stability number
    # Outcome rates.
    availability: float  # answered / sent, all time
    recent_availability: float  # answered / sent over the recent window
    timeout_rate: float
    error_rate: float
    # State / streaks.
    up: bool
    cur_streak: int  # length of the current up- or down-streak (sign = direction)
    longest_ok: int
    longest_fail: int
    last_error: str
    last_query: str  # the most recently sent query (any outcome)
    last_error_query: str  # the query of the most recent failed probe
    # DNS-level detail.
    rcodes: Counter
    unique_queries: int  # distinct (name, qtype) probed from the pool
    inconsistent_queries: int  # queries that returned >1 distinct answer set
    answer_flaps: int  # times a query's answer signature changed between probes
    last_rcode: int | None
    # DSCP (DiffServ marking) on received answer packets — how the resolver/path
    # classifies its replies. Usually CS0 (0); a non-zero or shifting value is
    # worth noticing.
    dns_dscp_last: int | None  # marking on the most recent answer
    dns_dscp_mode: int | None  # most frequently seen marking over the run
    # Retry-aware loss accounting (probes retransmit before failing, like a
    # real stub resolver): raw packet loss vs. effective failure.
    raw_lost: int  # non-final attempts that got no answer (retry may have saved the probe)
    recovered: int  # probes rescued by a retransmit
    raw_loss_rate: float  # unanswered packets / all packets sent (incl. retransmits)
    late_answers: int  # answers that straggled in after their probe timed out
    last_late_ms: float  # total time the most recent late answer took
    tc_answers: int  # truncated (TC=1) answers — response didn't fit in UDP
    # NXDOMAIN-hijack canary (see PollConfig.canary_zone).
    canary_sent: int
    canary_hijacks: int
    canary_last: str  # outcome of the most recent canary ("NXDOMAIN" is the honest one)
    last_triage: str  # verdict of the most recent triage battery for this server
    worst_query: str  # pool query with the most failed probes so far
    # Cumulative per-query stats for the sampler / dashboard:
    # (label, sent, answered, failed, mean_ms, stdev_ms, last_ttl, last_answer)
    query_stats: list[tuple]
    # Visualisation data.
    recent_ms: list[float]  # recent latencies (timeouts recorded as NaN gaps)
    stability: float  # 0..100 heuristic combining availability/latency/jitter
    # ICMP / ping reachability (independent of DNS).
    icmp_enabled: bool
    icmp_unavailable: bool  # the `ping` binary itself is missing
    icmp_up: bool  # last echo replied
    icmp_sent: int
    icmp_recv: int
    icmp_last_ms: float
    icmp_min_ms: float
    icmp_mean_ms: float
    icmp_max_ms: float
    icmp_jitter_ms: float
    icmp_recent_ms: list[float]  # recent RTTs (losses recorded as NaN gaps)
    # TTL (IPv6: hop limit) of received echoes — varies when the route does.
    icmp_ttl_min: int | None
    icmp_ttl_max: int | None
    icmp_ttl_mode: int | None  # most frequently seen TTL
    icmp_ttl_least: int | None  # least frequently seen TTL

    @property
    def effective_qps(self) -> float:
        return self.sent / self.elapsed if self.elapsed > 0 else 0.0

    @property
    def icmp_success(self) -> float:
        return self.icmp_recv / self.icmp_sent if self.icmp_sent else 0.0

    @property
    def icmp_loss(self) -> float:
        return 1.0 - self.icmp_success if self.icmp_sent else 0.0

    @property
    def recursion_overhead_ms(self) -> float:
        """Mean DNS latency minus mean ICMP RTT — the resolver's own
        processing/recursion time, separated from network distance.

        ICMP measures the round-trip to the host; DNS measures round-trip *plus*
        whatever the resolver does to answer (cache lookup or full recursion).
        The difference isolates that work. ``NaN`` when ICMP is off or no echo /
        answer has landed yet; can read slightly negative when answers are
        served from cache faster than ICMP is scheduled, which is itself a
        "this is cached and local" signal.
        """
        if not self.icmp_enabled or self.icmp_recv == 0:
            return math.nan
        if math.isnan(self.mean_ms) or math.isnan(self.icmp_mean_ms):
            return math.nan
        return self.mean_ms - self.icmp_mean_ms


class ServerStats:
    """Thread-safe accumulator of one server's probe stream.

    The polling thread calls :meth:`record_*`; the UI thread calls
    :meth:`snapshot`. All access is guarded by a single lock; updates are O(1)
    and snapshots are O(window).
    """

    def __init__(self, host: str, port: int, ewma_alpha: float = 0.2, icmp: bool = True) -> None:
        self.host = host
        self.port = port
        self._alpha = ewma_alpha
        self.icmp_enabled = icmp
        self._lock = threading.Lock()
        self._start = time.monotonic()
        self.reset()

    def reset(self) -> None:
        with self._lock:
            self._start = time.monotonic()
            self.sent = 0
            self.answered = 0
            self.timeouts = 0
            self.errors = 0
            # Welford running mean/variance over all answered latencies — drives
            # the overall mean and absolute min/max.
            self._n = 0
            self._mean = 0.0
            self._m2 = 0.0
            self.min_ms = math.inf
            self.max_ms = 0.0
            self.last_ms = math.nan
            self._ewma = math.nan
            self._jitter = 0.0
            # Per-query latency accumulators keyed by query label: [n, mean, m2,
            # prev_ms]. Tracking each (name, qtype) separately keeps the spread
            # metrics (std dev, jitter, cv) measuring the resolver's *own*
            # consistency rather than the latency gap between different pool
            # names — otherwise a diverse pool looks like an erratic resolver.
            self._q_lat: dict[str, list] = {}
            self.recent: deque[float] = deque(maxlen=_WINDOW)  # NaN marks a miss
            self.recent_ok = deque(maxlen=_WINDOW)  # bool per probe, for window availability
            self.rcodes: Counter = Counter()
            self.dns_dscps: Counter = Counter()  # answer DSCP value -> times seen
            self.dns_dscp_last: int | None = None
            # Answer-section signatures tracked *per query* (name, qtype) so the
            # consistency KPIs stay meaningful when probing a pool of different
            # names — otherwise every distinct name would look like a "flap".
            self._query_sigs: dict[object, set[frozenset]] = {}
            self._query_last: dict[object, frozenset] = {}
            self.answer_flaps = 0
            # Per-query outcome counters and last-answer detail, keyed by label:
            # [sent, answered, failed] / (min_ttl, rdata). These give the
            # failure-by-query matrix its denominators.
            self._q_counts: dict[str, list[int]] = {}
            self._q_answer: dict[str, tuple[int | None, str]] = {}
            # Retry / late / truncation accounting.
            self.raw_lost = 0
            self.recovered = 0
            self.late_answers = 0
            self.last_late_ms = math.nan
            self.tc_answers = 0
            # Canary + triage.
            self.canary_sent = 0
            self.canary_hijacks = 0
            self.canary_last = ""
            self.last_triage = ""
            self.up = False
            self._streak = 0  # >0 consecutive ok, <0 consecutive fail
            self.longest_ok = 0
            self.longest_fail = 0
            self.last_error = ""
            self.last_rcode: int | None = None
            self.last_query = ""  # query of the most recent probe (any outcome)
            self.last_error_query = ""  # query of the most recent failed probe
            # ICMP / ping side-channel.
            self.icmp_sent = 0
            self.icmp_recv = 0
            self.icmp_last = math.nan
            self.icmp_min = math.inf
            self.icmp_max = 0.0
            self._i_n = 0  # Welford count for ICMP RTT
            self._i_mean = 0.0
            self.icmp_jitter = 0.0
            self._i_prev: float | None = None
            self.icmp_up = False
            self.icmp_unavailable = False
            self.recent_icmp: deque[float] = deque(maxlen=_WINDOW)
            self.icmp_ttls: Counter = Counter()  # TTL value -> times seen

    def _note_outcome(self, ok: bool) -> None:
        """Update up/down state and streak counters (call with lock held)."""
        self.up = ok
        if ok:
            self._streak = self._streak + 1 if self._streak > 0 else 1
            self.longest_ok = max(self.longest_ok, self._streak)
        else:
            self._streak = self._streak - 1 if self._streak < 0 else -1
            self.longest_fail = max(self.longest_fail, -self._streak)

    def _q_count(self, label: str) -> list[int]:
        """The [sent, answered, failed] counter row for a query (lock held)."""
        row = self._q_counts.get(label)
        if row is None:
            row = self._q_counts[label] = [0, 0, 0]
        return row

    def record_answer(
        self,
        latency_ms: float,
        rcode: int,
        sig: frozenset | None,
        query_key: object | None = None,
        label: str = "",
        dscp: int | None = None,
        recovered: bool = False,
        tc: bool = False,
        ans_ttl: int | None = None,
        ans_text: str = "",
    ) -> None:
        with self._lock:
            self.sent += 1
            self.answered += 1
            if recovered:
                self.recovered += 1
            if tc:
                self.tc_answers += 1
            qc = self._q_count(label)
            qc[0] += 1
            qc[1] += 1
            self._q_answer[label] = (ans_ttl, ans_text)
            self.last_query = label
            self.last_ms = latency_ms
            self.recent.append(latency_ms)
            self.recent_ok.append(True)
            self.rcodes[rcode] += 1
            self.last_rcode = rcode
            if dscp is not None:
                self.dns_dscps[dscp] += 1
                self.dns_dscp_last = dscp
            # Global Welford for the overall mean and absolute min/max.
            self._n += 1
            delta = latency_ms - self._mean
            self._mean += delta / self._n
            self._m2 += delta * (latency_ms - self._mean)
            self.min_ms = min(self.min_ms, latency_ms)
            self.max_ms = max(self.max_ms, latency_ms)
            # EWMA.
            self._ewma = latency_ms if math.isnan(self._ewma) else (
                self._alpha * latency_ms + (1 - self._alpha) * self._ewma
            )
            # Per-query Welford + jitter, keyed by label so a pool of different
            # names can't masquerade as latency instability. Jitter is the RFC
            # 3550 smoothed change between consecutive answers to the *same*
            # query — real resolver jitter, not the gap between pool names.
            q = self._q_lat.get(label)
            if q is None:
                q = self._q_lat[label] = [0, 0.0, 0.0, None]
            qn, qmean, qm2, qprev = q
            qn += 1
            qd = latency_ms - qmean
            qmean += qd / qn
            qm2 += qd * (latency_ms - qmean)
            if qprev is not None:
                self._jitter += (abs(latency_ms - qprev) - self._jitter) / 16.0
            q[0], q[1], q[2], q[3] = qn, qmean, qm2, latency_ms
            # Answer consistency, per query. A flap is a query whose answer
            # signature differs from the previous answer to that *same* query.
            if sig is not None and query_key is not None:
                last = self._query_last.get(query_key)
                if last is not None and sig != last:
                    self.answer_flaps += 1
                self._query_last[query_key] = sig
                self._query_sigs.setdefault(query_key, set()).add(sig)
            self._note_outcome(True)

    def record_timeout(self, label: str = "") -> None:
        with self._lock:
            self.sent += 1
            self.timeouts += 1
            qc = self._q_count(label)
            qc[0] += 1
            qc[2] += 1
            self.last_query = label
            self.last_error_query = label
            self.last_ms = math.nan
            self.recent.append(math.nan)
            self.recent_ok.append(False)
            self.last_error = "timeout"
            self._note_outcome(False)

    def record_error(self, msg: str, label: str = "") -> None:
        with self._lock:
            self.sent += 1
            self.errors += 1
            qc = self._q_count(label)
            qc[0] += 1
            qc[2] += 1
            self.last_query = label
            self.last_error_query = label
            self.last_ms = math.nan
            self.recent.append(math.nan)
            self.recent_ok.append(False)
            self.last_error = msg
            self._note_outcome(False)

    def record_raw_loss(self, label: str = "") -> None:
        """A non-final attempt got no answer; a retransmit is about to go out.

        Not a probe outcome — the probe is still pending. This only feeds the
        raw-packet-loss KPI so first-try loss stays visible even when the retry
        saves the probe.
        """
        with self._lock:
            self.raw_lost += 1

    def record_late(self, total_ms: float) -> None:
        """An answer arrived for a probe already declared timed out.

        Distinguishes "the resolver answers, just slower than the timeout"
        (overload) from "the query was dropped outright" (loss / policer).
        """
        with self._lock:
            self.late_answers += 1
            self.last_late_ms = total_ms

    def record_canary(self, outcome: str, hijacked: bool) -> None:
        with self._lock:
            self.canary_sent += 1
            if hijacked:
                self.canary_hijacks += 1
            self.canary_last = outcome

    def set_triage(self, verdict: str) -> None:
        with self._lock:
            self.last_triage = verdict

    def record_ping(self, rtt_ms: float | None, ttl: int | None = None) -> None:
        """Record one ICMP echo: an RTT in ms (and the reply TTL) on reply,
        ``None`` on loss."""
        with self._lock:
            self.icmp_sent += 1
            if rtt_ms is None or math.isnan(rtt_ms):
                self.icmp_up = False
                self.recent_icmp.append(math.nan)
                return
            self.icmp_recv += 1
            self.icmp_up = True
            self.icmp_last = rtt_ms
            self.recent_icmp.append(rtt_ms)
            if ttl is not None:
                self.icmp_ttls[ttl] += 1
            self.icmp_min = min(self.icmp_min, rtt_ms)
            self.icmp_max = max(self.icmp_max, rtt_ms)
            self._i_n += 1
            d = rtt_ms - self._i_mean
            self._i_mean += d / self._i_n
            if self._i_prev is not None:
                self.icmp_jitter += (abs(rtt_ms - self._i_prev) - self.icmp_jitter) / 16.0
            self._i_prev = rtt_ms

    def mark_icmp_unavailable(self) -> None:
        with self._lock:
            self.icmp_unavailable = True

    def snapshot(self) -> StatsSnapshot:
        with self._lock:
            elapsed = time.monotonic() - self._start
            window = [v for v in self.recent if not math.isnan(v)]
            window.sort()
            mean = self._mean if self._n else math.nan
            # Pooled within-query standard deviation: combine each query's own
            # variance (Welford m2) across the pool so std dev / cv measure the
            # resolver's per-query consistency, not the spread between different
            # pool names. Falls back to 0 until a query has >1 sample.
            within_m2 = sum(qq[2] for qq in self._q_lat.values())
            within_dof = sum(qq[0] for qq in self._q_lat.values()) - len(self._q_lat)
            stdev = math.sqrt(within_m2 / within_dof) if within_dof > 0 else 0.0
            recent_ok = sum(self.recent_ok)
            recent_total = len(self.recent_ok)
            availability = self.answered / self.sent if self.sent else 0.0
            recent_av = recent_ok / recent_total if recent_total else 0.0
            jitter = self._jitter
            p95 = _pct(window, 0.95)
            ttl_min, ttl_max, ttl_mode, ttl_least = _ttl_stats(self.icmp_ttls)
            dscp_mode = (
                min(self.dns_dscps, key=lambda v: (-self.dns_dscps[v], v))
                if self.dns_dscps else None
            )
            # Stability index (0..100): a dropped query is the worst failure
            # mode, so recent availability dominates — each 1% of recent loss
            # costs ~4 points, and 25% loss zeroes the backbone. Tail latency
            # (p95) and (now per-query) jitter only shave a little off the top.
            # Documented heuristic, not an official metric.
            loss = 1.0 - recent_av
            stability = max(
                0.0,
                (100.0 - min(100.0, loss * 400.0))
                - (0.0 if math.isnan(p95) else min(15.0, p95 / 20.0))
                - min(10.0, jitter / 10.0),
            )
            # Raw packet loss: every probe is one packet plus one per
            # retransmit (raw_lost); unanswered packets are the raw losses
            # plus the final attempts of probes that fully timed out.
            packets = self.sent + self.raw_lost
            raw_loss_rate = (self.raw_lost + self.timeouts) / packets if packets else 0.0
            worst = max(
                self._q_counts.items(),
                key=lambda kv: kv[1][2],
                default=None,
            )
            worst_query = (
                f"{worst[0]} ({worst[1][2]}x)" if worst and worst[1][2] > 0 else ""
            )
            query_stats = []
            for qlabel, (q_sent, q_ans, q_fail) in self._q_counts.items():
                lat = self._q_lat.get(qlabel)
                if lat is not None and lat[0] > 0:
                    q_mean = lat[1]
                    q_stdev = math.sqrt(lat[2] / (lat[0] - 1)) if lat[0] > 1 else 0.0
                else:
                    q_mean = q_stdev = math.nan
                ttl, ans = self._q_answer.get(qlabel, (None, ""))
                query_stats.append((qlabel, q_sent, q_ans, q_fail, q_mean, q_stdev, ttl, ans))
            return StatsSnapshot(
                host=self.host,
                port=self.port,
                sent=self.sent,
                answered=self.answered,
                timeouts=self.timeouts,
                errors=self.errors,
                elapsed=elapsed,
                last_ms=self.last_ms,
                min_ms=0.0 if math.isinf(self.min_ms) else self.min_ms,
                max_ms=self.max_ms,
                mean_ms=mean,
                stdev_ms=stdev,
                p50_ms=_pct(window, 0.50),
                p90_ms=_pct(window, 0.90),
                p95_ms=p95,
                p99_ms=_pct(window, 0.99),
                jitter_ms=jitter,
                ewma_ms=self._ewma,
                cv=(stdev / mean) if mean and not math.isnan(mean) and mean > 0 else 0.0,
                availability=availability,
                recent_availability=recent_av,
                timeout_rate=self.timeouts / self.sent if self.sent else 0.0,
                error_rate=self.errors / self.sent if self.sent else 0.0,
                up=self.up,
                cur_streak=self._streak,
                longest_ok=self.longest_ok,
                longest_fail=self.longest_fail,
                last_error=self.last_error,
                last_query=self.last_query,
                last_error_query=self.last_error_query,
                rcodes=Counter(self.rcodes),
                unique_queries=len(self._query_sigs),
                inconsistent_queries=sum(1 for s in self._query_sigs.values() if len(s) > 1),
                answer_flaps=self.answer_flaps,
                last_rcode=self.last_rcode,
                dns_dscp_last=self.dns_dscp_last,
                dns_dscp_mode=dscp_mode,
                raw_lost=self.raw_lost,
                recovered=self.recovered,
                raw_loss_rate=raw_loss_rate,
                late_answers=self.late_answers,
                last_late_ms=self.last_late_ms,
                tc_answers=self.tc_answers,
                canary_sent=self.canary_sent,
                canary_hijacks=self.canary_hijacks,
                canary_last=self.canary_last,
                last_triage=self.last_triage,
                worst_query=worst_query,
                query_stats=query_stats,
                recent_ms=list(self.recent),
                stability=stability,
                icmp_enabled=self.icmp_enabled,
                icmp_unavailable=self.icmp_unavailable,
                icmp_up=self.icmp_up,
                icmp_sent=self.icmp_sent,
                icmp_recv=self.icmp_recv,
                icmp_last_ms=self.icmp_last,
                icmp_min_ms=0.0 if math.isinf(self.icmp_min) else self.icmp_min,
                icmp_mean_ms=self._i_mean if self._i_n else math.nan,
                icmp_max_ms=self.icmp_max,
                icmp_jitter_ms=self.icmp_jitter,
                icmp_recent_ms=list(self.recent_icmp),
                icmp_ttl_min=ttl_min,
                icmp_ttl_max=ttl_max,
                icmp_ttl_mode=ttl_mode,
                icmp_ttl_least=ttl_least,
            )


@dataclass(slots=True)
class PollConfig:
    servers: list[str]
    port: int = 53
    qname: str = "example.com"
    qname_strategy: str = "fixed"  # "fixed" | "random" (forces cache miss / recursion)
    qtype: str = "A"
    interval: float = 1.0  # seconds between probes per server
    timeout: float = 2.0  # per-probe timeout
    # Pool of queries to rotate through, each a (name, qtype) pair. Defaults to
    # the single (qname, qtype) query. Build with :func:`load_queries`.
    queries: list[tuple[str, str]] | None = None
    pool_order: str = "roundrobin"  # "roundrobin" (even coverage) | "random"
    icmp: bool = True  # also ICMP-ping each server (reachability / RTT side-channel)
    log_db: str | None = None  # if set, log every DNS probe failure to this SQLite file
    sample_interval: float = 5.0  # seconds between periodic KPI snapshots (0 disables)
    # Retransmits before a probe is declared failed. Real stub resolvers retry,
    # so with the default of 1 the KPIs separate *raw* packet loss (first-try
    # losses, visible as `raw loss`) from *effective* failure (no answer even
    # after the retry — what a user would actually experience).
    retries: int = 1
    # EDNS0 advertised UDP size on probes (0 = plain queries, 512-byte limit).
    # Sending EDNS matches real-world traffic and exposes EDNS-mangling
    # middleboxes; truncated (TC) answers are counted either way.
    edns_size: int = 1232
    # NXDOMAIN-hijack canary: when set (e.g. "cl" or "example.com"), every
    # canary_interval seconds each server is asked for a random label under
    # this zone, which cannot exist. The only honest answer is NXDOMAIN — an
    # address back means the resolver rewrites NXDOMAIN (ad/search hijacking).
    # Use a zone with no wildcard record.
    canary_zone: str | None = None
    canary_interval: float = 60.0
    # Triage battery: when a probe still has no answer after its retries, run a
    # short cross-check against the failing server from a side thread — another
    # UDP retry, the same query over TCP, a recently-answered (cached) name,
    # and the same query at a healthy reference server — and classify the
    # failure. Rate-limited per server; results go to stats + the triage table.
    triage: bool = True
    triage_cooldown: float = 30.0  # min seconds between batteries per server
    # Network watchdog: if the box running the tests loses its *own* network,
    # every probe fails no matter how healthy the resolvers are — and logging
    # that would poison the statistics. When enabled, the default gateway is
    # pinged continuously and all probing (DNS, ICMP, canary, sampling)
    # pauses while it is unreachable; explicit net-down / net-up marker events
    # are written to the log instead of thousands of bogus timeouts.
    gateway_pause: bool = True
    gateway: str | None = None  # explicit watchdog target; None = autodetect
    gateway_interval: float = 2.0  # seconds between gateway pings
    gateway_fails: int = 2  # consecutive lost pings before pausing

    def __post_init__(self) -> None:
        if not self.queries:
            self.queries = [(self.qname, self.qtype)]


class _ServerPoller:
    """Owns one server's socket, polling thread and :class:`ServerStats`."""

    def __init__(
        self,
        host: str,
        port: int,
        cfg: PollConfig,
        stop: threading.Event,
        net_up: threading.Event,
        on_fail: Callable[[str, str, tuple[bytes, int, str] | None], None] | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.cfg = cfg
        self._stop = stop
        # Set = local network healthy. Cleared by the manager's gateway
        # watchdog; probing holds fire while it is down.
        self._net_up = net_up
        # Called (kind, detail, query) from the polling thread on each DNS
        # probe failure; the manager uses it to snapshot all servers into the
        # log and to launch the triage battery. ``query`` is the failing
        # question as (qname_wire, qtype_int, label), or None when there was
        # no specific query (socket setup failures).
        self._on_fail = on_fail
        self.stats = ServerStats(host, port, icmp=cfg.icmp)
        # qids of attempts that timed out, mapped to their send time, so a
        # straggling answer read during a later probe is counted as "late".
        self._late_pending: dict[int, float] = {}
        # Most recent successfully answered question — the triage battery
        # re-asks it as a "this should be cached" canary. Written only by the
        # polling thread; read by the triage thread (tuple swap is atomic).
        self.last_ok: tuple[bytes, int, str] | None = None
        # Pre-encode the pool: (name, qtype_str, qtype_int, fixed_wire). The wire
        # form is reused for every "fixed" probe; "random" re-encodes per probe.
        self._pool = [
            (name, qt, wire.QTYPES.get(qt.upper(), 1), wire.encode_name(name))
            for name, qt in (cfg.queries or [(cfg.qname, cfg.qtype)])
        ]
        self._rr = 0
        self._thread = threading.Thread(target=self._run, name=f"poll-{host}", daemon=True)
        # ICMP runs on its own thread so a slow/blocked ping never disturbs the
        # DNS probe cadence (and vice versa).
        self._icmp_thread = (
            threading.Thread(target=self._run_icmp, name=f"ping-{host}", daemon=True)
            if cfg.icmp
            else None
        )

    def start(self) -> None:
        self._thread.start()
        if self._icmp_thread is not None:
            self._icmp_thread.start()

    def _make_socket(self) -> socket.socket:
        family = socket.AF_INET6 if ":" in self.host else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.settimeout(self.cfg.timeout)
        # Ask the kernel to deliver each reply's DSCP via ancillary data so we
        # can observe how the resolver marks its answers. Best-effort: platforms
        # without the option simply never report a DSCP.
        try:
            if family == socket.AF_INET6:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_RECVTCLASS, 1)
            else:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_RECVTOS, 1)
        except (OSError, AttributeError):
            pass
        sock.connect((self.host, self.port))
        return sock

    def _select(self) -> tuple[bytes, int, object | None]:
        """Pick the next query: ``(qname_wire, qtype_int, consistency_key, label)``.

        The key identifies the question for per-query answer-consistency
        tracking; it is ``None`` in "random" mode (every probe uses a unique
        label, so consistency is undefined and intentionally skipped). The label
        is a human-readable form of the query for the dashboard.
        """
        if self.cfg.pool_order == "random":
            name, qt, qtype_int, fixed_wire = random.choice(self._pool)
        else:
            name, qt, qtype_int, fixed_wire = self._pool[self._rr % len(self._pool)]
            self._rr += 1
        if self.cfg.qname_strategy == "random":
            prefix = f"{random.randrange(1 << 32):08x}-{random.randrange(1 << 32):08x}"
            return wire.encode_name(f"{prefix}.{name}"), qtype_int, None, f"*.{name} {qt}"
        return fixed_wire, qtype_int, (name, qt), f"{name} {qt}"

    def _probe(self, sock: socket.socket) -> None:
        is_v6 = ":" in self.host
        qname_wire, qtype_int, key, label = self._select()
        attempts = max(1, self.cfg.retries + 1)
        for attempt in range(attempts):
            qid = random.randrange(1 << 16)
            t0 = time.perf_counter()
            timed_out = False
            try:
                sock.send(wire.build_query(qid, qname_wire, qtype_int, edns_size=self.cfg.edns_size))
                deadline = t0 + self.cfg.timeout
                while True:
                    if _HAS_RECVMSG:
                        data, ancdata, _flags, _addr = sock.recvmsg(4096, _CMSG_BUF)
                    else:
                        data, ancdata = sock.recv(4096), ()
                    parsed = wire.parse_response(data)
                    if parsed is not None:
                        rqid, rcode, tc = parsed
                        if rqid == qid:
                            latency_ms = (time.perf_counter() - t0) * 1000.0
                            details = wire.answer_details(data)
                            ans_ttl, ans_text = details if details is not None else (None, "")
                            self.stats.record_answer(
                                latency_ms, rcode, wire.answer_signature(data), key, label,
                                dscp=_dscp_from_ancdata(ancdata, is_v6),
                                recovered=attempt > 0, tc=tc,
                                ans_ttl=ans_ttl, ans_text=ans_text,
                            )
                            self.last_ok = (qname_wire, qtype_int, label)
                            return
                        # Response to something else: a straggler from an
                        # attempt that already timed out? Count it — "answers
                        # late" and "never answers" are different diagnoses.
                        sent_at = self._late_pending.pop(rqid, None)
                        if sent_at is not None:
                            self.stats.record_late((time.perf_counter() - sent_at) * 1000.0)
                    if time.perf_counter() >= deadline:
                        timed_out = True
                        break
                    sock.settimeout(max(0.0, deadline - time.perf_counter()))
            except socket.timeout:
                timed_out = True
            except OSError as exc:
                detail = exc.strerror or str(exc)
                self.stats.record_error(detail, label)
                self._notify_fail("error", f"{label}: {detail}", (qname_wire, qtype_int, label))
                return
            finally:
                sock.settimeout(self.cfg.timeout)
            if not timed_out:
                return
            # This attempt got nothing — remember its qid so a late answer is
            # still recognised, then either retransmit or declare the probe
            # failed.
            self._late_pending[qid] = t0
            if len(self._late_pending) > 32:
                for old in sorted(self._late_pending, key=self._late_pending.get)[
                    : len(self._late_pending) - 32
                ]:
                    del self._late_pending[old]
            if attempt < attempts - 1:
                self.stats.record_raw_loss(label)
            else:
                self.stats.record_timeout(label)
                self._notify_fail("timeout", label, (qname_wire, qtype_int, label))

    def _canary_probe(self, sock: socket.socket) -> None:
        """Ask for a name that cannot exist; the only honest answer is NXDOMAIN.

        A NOERROR with answer records means the resolver rewrites NXDOMAIN
        (ad/search-page hijacking, historically popular with ISP resolvers).
        The canary stays out of the regular KPIs — it has its own counters.
        """
        zone = self.cfg.canary_zone
        name = f"dnstester-canary-{random.getrandbits(48):012x}.{zone}"
        qid = random.randrange(1 << 16)
        try:
            sock.send(wire.build_query(qid, wire.encode_name(name), 1, edns_size=self.cfg.edns_size))
            deadline = time.perf_counter() + self.cfg.timeout
            while True:
                data = sock.recv(4096)
                parsed = wire.parse_response(data)
                if parsed is not None and parsed[0] == qid:
                    _rqid, rcode, _tc = parsed
                    ancount = (data[6] << 8) | data[7] if len(data) >= 8 else 0
                    hijacked = rcode == 0 and ancount > 0
                    outcome = "HIJACK" if hijacked else wire.RCODES.get(rcode, str(rcode))
                    self.stats.record_canary(outcome, hijacked)
                    return
                if time.perf_counter() >= deadline:
                    self.stats.record_canary("timeout", False)
                    return
                sock.settimeout(max(0.0, deadline - time.perf_counter()))
        except socket.timeout:
            self.stats.record_canary("timeout", False)
        except OSError:
            self.stats.record_canary("error", False)
        finally:
            sock.settimeout(self.cfg.timeout)

    def _notify_fail(self, kind: str, detail: str, query: tuple[bytes, int, str] | None) -> None:
        """Hand a DNS failure to the manager's logger, if one is attached.

        Invoked outside the stats lock so the manager can freely snapshot every
        server (including this one, already updated) without lock contention.
        """
        if self._on_fail is not None:
            self._on_fail(kind, detail, query)

    def _run(self) -> None:
        try:
            sock = self._make_socket()
        except OSError as exc:
            # Permanent setup failure: keep recording errors so it shows DOWN.
            detail = exc.strerror or str(exc)
            while not self._stop.is_set():
                self.stats.record_error(detail)
                self._notify_fail("error", f"socket setup: {detail}", None)
                self._stop.wait(self.cfg.interval)
            return
        next_t = time.monotonic()
        next_canary = (
            time.monotonic() + self.cfg.canary_interval
            if self.cfg.canary_zone
            else math.inf
        )
        with sock:
            while not self._stop.is_set():
                if not self._net_up.is_set():
                    # Local network is down: hold fire instead of logging
                    # guaranteed failures. The negative-delay resync below
                    # restores the cadence cleanly on resume.
                    while not self._stop.is_set() and not self._net_up.wait(0.5):
                        pass
                    if self._stop.is_set():
                        break
                if time.monotonic() >= next_canary:
                    self._canary_probe(sock)
                    next_canary = time.monotonic() + self.cfg.canary_interval
                self._probe(sock)
                next_t += self.cfg.interval
                delay = next_t - time.monotonic()
                if delay < 0:  # fell behind (slow answers / a pause); don't burst
                    next_t = time.monotonic()
                    delay = 0
                self._stop.wait(delay)

    def _run_icmp(self) -> None:
        # ICMP runs at twice the DNS cadence (half the interval) so reachability
        # is sampled at finer resolution than the DNS probes it backstops.
        icmp_interval = self.cfg.interval / 2.0
        next_t = time.monotonic()
        while not self._stop.is_set():
            if not self._net_up.is_set():
                # Paused with the DNS probes — ICMP loss during a local outage
                # is just as misleading.
                while not self._stop.is_set() and not self._net_up.wait(0.5):
                    pass
                if self._stop.is_set():
                    return
                next_t = time.monotonic()
            try:
                rtt, ttl = ping_once(self.host, self.cfg.timeout)
            except PingUnavailable:
                # No `ping` binary: flag the column and stop trying.
                self.stats.mark_icmp_unavailable()
                return
            self.stats.record_ping(rtt, ttl)
            next_t += icmp_interval
            delay = next_t - time.monotonic()
            if delay < 0:  # a slow ping ate into the cadence; resync, don't burst
                next_t = time.monotonic()
                delay = 0
            self._stop.wait(delay)


@dataclass(slots=True)
class TriageResult:
    """Outcome of one triage battery, run seconds after a probe failure.

    Verdicts (most specific first):

    ``transient-udp-loss``
        A fresh UDP retry of the failing query answered — a stochastic packet
        drop, not a persistent fault.
    ``udp-blocked-or-rate-limited``
        UDP stayed dead but the same query over TCP:53 answered — something in
        front of the resolver is dropping/limiting UDP specifically (policer,
        rate limiter, full socket queue).
    ``auth-domain-failure``
        This server couldn't resolve the query but *could* serve a cached name,
        and a healthy reference server couldn't resolve the query either — the
        domain's authoritative side is the problem, not the resolver.
    ``recursion-failure``
        Cached names answer but this query won't resolve here (while the
        reference could, or wasn't checked) — the resolver's recursion/upstream
        path is stuck.
    ``fleet-or-domain-outage``
        Everything failed here *and* at the reference — network-wide trouble or
        the queried domain is down everywhere.
    ``server-unresponsive``
        UDP, TCP and the cached-name canary all failed while the reference was
        fine — the resolver (or the path to it) is down outright.
    """

    server: str
    query: str
    verdict: str = ""
    retry_ok: bool | None = None
    retry_ms: float | None = None
    tcp_ok: bool | None = None
    tcp_ms: float | None = None
    cached_ok: bool | None = None
    cached_ms: float | None = None
    cached_query: str | None = None
    ref_server: str | None = None
    ref_ok: bool | None = None
    ref_ms: float | None = None


def _recv_exact(s: socket.socket, n: int) -> bytes | None:
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def _udp_once(
    host: str, port: int, qname_wire: bytes, qtype: int, timeout: float, edns_size: int
) -> float | None:
    """One UDP query on a throwaway socket; latency in ms, or None."""
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    qid = random.randrange(1 << 16)
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            t0 = time.perf_counter()
            s.send(wire.build_query(qid, qname_wire, qtype, edns_size=edns_size))
            deadline = t0 + timeout
            while True:
                data = s.recv(4096)
                parsed = wire.parse_response(data)
                if parsed is not None and parsed[0] == qid:
                    return (time.perf_counter() - t0) * 1000.0
                if time.perf_counter() >= deadline:
                    return None
                s.settimeout(max(0.0, deadline - time.perf_counter()))
    except OSError:
        return None


def _tcp_once(
    host: str, port: int, qname_wire: bytes, qtype: int, timeout: float, edns_size: int
) -> float | None:
    """The same query over TCP:53 (2-byte length framing); latency in ms, or None."""
    qid = random.randrange(1 << 16)
    packet = wire.build_query(qid, qname_wire, qtype, edns_size=edns_size)
    try:
        t0 = time.perf_counter()
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(len(packet).to_bytes(2, "big") + packet)
            hdr = _recv_exact(s, 2)
            if hdr is None:
                return None
            body = _recv_exact(s, int.from_bytes(hdr, "big"))
            if body is None:
                return None
            parsed = wire.parse_response(body)
            if parsed is not None and parsed[0] == qid:
                return (time.perf_counter() - t0) * 1000.0
            return None
    except OSError:
        return None


def run_triage(
    host: str,
    port: int,
    qname_wire: bytes,
    qtype: int,
    label: str,
    timeout: float,
    edns_size: int,
    cached: tuple[bytes, int, str] | None,
    reference: tuple[str, int] | None,
) -> TriageResult:
    """Run the cross-check battery against a server that just timed out.

    Four probes, each on its own throwaway socket: a fresh UDP retry of the
    failing query, the same query over TCP, a recently-answered (should-be-
    cached) name over UDP, and the failing query at a healthy reference server.
    The combination pins the failure to a layer — see :class:`TriageResult`.
    """
    r = TriageResult(server=f"{host}:{port}", query=label)
    ms = _udp_once(host, port, qname_wire, qtype, timeout, edns_size)
    r.retry_ok, r.retry_ms = ms is not None, ms
    ms = _tcp_once(host, port, qname_wire, qtype, timeout, edns_size)
    r.tcp_ok, r.tcp_ms = ms is not None, ms
    if cached is not None:
        c_wire, c_qtype, c_label = cached
        ms = _udp_once(host, port, c_wire, c_qtype, timeout, edns_size)
        r.cached_ok, r.cached_ms, r.cached_query = ms is not None, ms, c_label
    if reference is not None:
        ref_host, ref_port = reference
        ms = _udp_once(ref_host, ref_port, qname_wire, qtype, timeout, edns_size)
        r.ref_server, r.ref_ok, r.ref_ms = f"{ref_host}:{ref_port}", ms is not None, ms
    r.verdict = _triage_verdict(r)
    return r


def _triage_verdict(r: TriageResult) -> str:
    if r.retry_ok:
        return "transient-udp-loss"
    if r.tcp_ok:
        return "udp-blocked-or-rate-limited"
    if r.cached_ok:
        return "auth-domain-failure" if r.ref_ok is False else "recursion-failure"
    if r.ref_ok is False:
        return "fleet-or-domain-outage"
    return "server-unresponsive"


class PollManager:
    """Starts a poller thread per server and hands out KPI snapshots."""

    def __init__(self, cfg: PollConfig) -> None:
        self.cfg = cfg
        self._stop = threading.Event()
        self.log: EventLog | None = None
        self.log_error: str | None = None  # surfaced after the UI tears down
        self._sampler: threading.Thread | None = None
        self._last_triage: dict[str, float] = {}  # server -> last battery start
        # Local-network watchdog state. net_up set = network healthy; the
        # gateway watchdog clears it while the default gateway is unreachable
        # and every polling thread holds fire until it returns.
        self.net_up = threading.Event()
        self.net_up.set()
        self.gateway: str | None = None
        self.gateway_error: str | None = None
        self.net_pauses = 0  # completed + ongoing pause episodes
        self.net_paused_total = 0.0  # seconds spent paused (completed episodes)
        self._paused_since: float | None = None
        self._gw_thread: threading.Thread | None = None
        if cfg.gateway_pause:
            from .netwatch import default_gateway

            self.gateway = cfg.gateway or default_gateway()
            if self.gateway is None:
                self.gateway_error = (
                    "network watchdog disabled: could not determine the default "
                    "gateway (pass --gateway to set one explicitly)"
                )
        if cfg.log_db:
            self.log = EventLog(cfg.log_db)
        self._pollers = [
            _ServerPoller(host, port, cfg, self._stop, self.net_up)
            for host, port in (parse_server(s, cfg.port) for s in cfg.servers)
        ]
        if self.log is not None or cfg.triage:
            for p in self._pollers:
                p._on_fail = self._make_handler(p)

    def _make_handler(self, poller: _ServerPoller):
        """Bind a per-server failure callback: log the fleet's state, then
        (rate-limited) launch the triage battery on a side thread."""
        server = f"{poller.host}:{poller.port}"

        def handler(kind: str, detail: str, query: tuple[bytes, int, str] | None) -> None:
            event_id: int | None = None
            if self.log is not None:
                try:
                    event_id = self.log.log_failure(server, kind, detail, self.snapshots())
                except sqlite3.Error as exc:
                    # Don't let a logging hiccup kill polling; disable and remember.
                    self.log_error = f"event log disabled: {exc}"
                    self.log = None
            if self.cfg.triage and kind == "timeout" and query is not None:
                now = time.monotonic()
                if now - self._last_triage.get(server, -math.inf) >= self.cfg.triage_cooldown:
                    self._last_triage[server] = now
                    threading.Thread(
                        target=self._run_triage,
                        args=(poller, query, event_id),
                        name=f"triage-{poller.host}",
                        daemon=True,
                    ).start()

        return handler

    def _run_triage(self, poller: _ServerPoller, query: tuple[bytes, int, str], event_id: int | None) -> None:
        qname_wire, qtype_int, label = query
        # Reference = any *other* server currently answering; its result tells
        # isolated-to-this-resolver apart from domain-/network-wide.
        reference = next(
            (
                (p.host, p.port)
                for p in self._pollers
                if p is not poller and p.stats.up
            ),
            None,
        )
        result = run_triage(
            poller.host, poller.port, qname_wire, qtype_int, label,
            self.cfg.timeout, self.cfg.edns_size, poller.last_ok, reference,
        )
        poller.stats.set_triage(result.verdict)
        log = self.log
        if log is not None:
            try:
                log.log_triage(event_id, result)
            except sqlite3.Error as exc:
                self.log_error = f"event log disabled: {exc}"
                self.log = None

    def start(self) -> None:
        if self.gateway is not None:
            self._gw_thread = threading.Thread(
                target=self._run_gateway_watch, name="gateway-watch", daemon=True
            )
            self._gw_thread.start()
        for p in self._pollers:
            p.start()
        # Periodic KPI sampler: writes the whole fleet's snapshot to the db on a
        # fixed interval, giving a continuous latency/availability time series
        # (the failure log alone only has points at failure moments).
        if self.log is not None and self.cfg.sample_interval > 0:
            self._sampler = threading.Thread(
                target=self._run_sampler, name="sampler", daemon=True
            )
            self._sampler.start()

    def _run_gateway_watch(self) -> None:
        """Ping the default gateway; pause all probing while it is dark.

        A couple of consecutive lost echoes (``gateway_fails``) trip the pause
        so one dropped packet doesn't stall everything; a single reply resumes.
        Pause and resume are recorded as explicit ``net-down`` / ``net-up``
        marker events, so the outage window is visible in the log instead of
        masquerading as a fleet-wide DNS failure.
        """
        fails = 0
        while not self._stop.wait(self.cfg.gateway_interval):
            try:
                rtt, _ttl = ping_once(self.gateway, timeout=1.0)  # type: ignore[arg-type]
            except PingUnavailable as exc:
                self.gateway_error = f"network watchdog disabled: no ping binary ({exc})"
                self.net_up.set()
                return
            if rtt is None:
                fails += 1
                if fails >= self.cfg.gateway_fails and self.net_up.is_set():
                    self.net_up.clear()
                    self.net_pauses += 1
                    self._paused_since = time.monotonic()
                    self._log_net_event(
                        "net-down",
                        f"gateway {self.gateway} unreachable — polling paused",
                    )
            else:
                fails = 0
                if not self.net_up.is_set():
                    paused_for = time.monotonic() - (self._paused_since or time.monotonic())
                    self.net_paused_total += paused_for
                    self._paused_since = None
                    self.net_up.set()
                    self._log_net_event(
                        "net-up",
                        f"gateway {self.gateway} reachable again after "
                        f"{paused_for:.0f}s — polling resumed",
                    )

    def _log_net_event(self, kind: str, detail: str) -> None:
        if self.log is None:
            return
        try:
            self.log.log_failure(f"gateway:{self.gateway}", kind, detail, self.snapshots())
        except sqlite3.Error as exc:
            self.log_error = f"event log disabled: {exc}"
            self.log = None

    def _run_sampler(self) -> None:
        interval = self.cfg.sample_interval
        # Per-query stats change slowly (cumulative counters) and multiply
        # rows by pool size, so they're flushed about once a minute rather
        # than on every KPI tick.
        qstats_every = max(1, round(60.0 / interval))
        tick = 0
        while not self._stop.wait(interval):
            log = self.log  # may be cleared by a failed failure-log write
            if log is None:
                return
            tick += 1
            if not self.net_up.is_set():
                continue  # frozen counters during a local outage are not data
            try:
                snaps = self.snapshots()
                log.log_samples(snaps)
                if tick % qstats_every == 0:
                    log.log_query_stats(snaps)
            except sqlite3.Error as exc:
                self.log_error = f"sample log disabled: {exc}"
                return

    def stop(self) -> None:
        self._stop.set()
        self.net_up.set()  # release pollers parked in a network pause
        # Join the sampler before closing the log so it never writes to a closed
        # connection.
        if self._sampler is not None:
            self._sampler.join(timeout=self.cfg.sample_interval + 1.0)
            self._sampler = None
        if self.log is not None:
            self.log.close()
            self.log = None

    def reset(self) -> None:
        for p in self._pollers:
            p.stats.reset()

    def snapshots(self) -> list[StatsSnapshot]:
        return [p.stats.snapshot() for p in self._pollers]
