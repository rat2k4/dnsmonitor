"""Open-loop DNS load generator (the *client* part).

The generator paces sends against a wall clock, not against the rate of
incoming responses, so a slow/overloaded resolver shows up as growing latency
and timeouts rather than silently throttling the offered load (this avoids
"coordinated omission" in the latency numbers).

A single asyncio UDP socket is used. Outstanding queries are tracked by their
16-bit DNS id; responses are matched back by id to compute latency. This keeps
the hot path to roughly one ``sendto`` per query and comfortably drives several
thousand QPS from one process. For higher offered loads use ``--workers`` (see
:func:`run_parallel_load`), which splits the QPS across several processes and
aggregates the results.
"""

from __future__ import annotations

import asyncio
import math
import random
import socket
from collections import Counter
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass, field, replace

from . import wire


@dataclass(slots=True)
class LoadConfig:
    target: str
    port: int = 53
    qps: float = 100.0
    duration: float = 10.0
    qname: str = "example.com"
    # "fixed" -> same name every time (exercises the cache / throughput path).
    # "random" -> random label prefixed (forces cache misses / recursion).
    qname_strategy: str = "fixed"
    qtype: str = "A"
    timeout: float = 2.0
    # "uniform" -> perfectly even inter-send gaps (gentlest arrival pattern for
    # a given QPS). "poisson" -> exponentially distributed gaps with the same
    # mean rate: bursty like real traffic, and the standard open-loop model. A
    # resolver's request list saturates on bursts, so poisson usually finds the
    # true breaking point earlier.
    pacing: str = "uniform"
    # EDNS0 advertised UDP payload size (RFC 6891); 0 sends plain 512-byte-limit
    # queries. Without EDNS any answer over 512 bytes comes back truncated.
    edns_size: int = 1232
    # Cap on simultaneously outstanding queries. Acts as backpressure: when the
    # resolver stalls we stop piling on (and record the shortfall) instead of
    # exhausting memory or the id space.
    max_inflight: int = 20_000
    # UDP socket buffer sizes. A large receive buffer is critical at high QPS:
    # one asyncio reader can fall behind and the kernel will silently drop
    # responses (showing up as bogus client-side timeouts) if SO_RCVBUF is
    # small. The OS may clamp this (see kern.ipc.maxsockbuf on macOS/BSD).
    socket_rcvbuf: int = 16 * 1024 * 1024
    socket_sndbuf: int = 4 * 1024 * 1024


@dataclass(slots=True)
class LoadResult:
    config: LoadConfig
    sent: int = 0
    received: int = 0
    timeouts: int = 0
    dropped: int = 0  # sends skipped because max_inflight was hit
    late: int = 0  # responses that arrived after their query was reaped as a timeout
    tc: int = 0  # truncated (TC=1) responses — the full answer didn't fit in UDP
    elapsed: float = 0.0
    latencies_ms: list[float] = field(default_factory=list)
    rcodes: Counter = field(default_factory=Counter)

    # --- derived rates -------------------------------------------------
    @property
    def offered_qps(self) -> float:
        return self.config.qps

    @property
    def sent_qps(self) -> float:
        return self.sent / self.elapsed if self.elapsed else 0.0

    @property
    def answered_qps(self) -> float:
        return self.received / self.elapsed if self.elapsed else 0.0

    @property
    def timeout_rate(self) -> float:
        return self.timeouts / self.sent if self.sent else 0.0

    @property
    def drop_rate(self) -> float:
        attempted = self.sent + self.dropped
        return self.dropped / attempted if attempted else 0.0

    @property
    def servfail(self) -> int:
        return self.rcodes.get(2, 0)

    @property
    def servfail_rate(self) -> float:
        return self.servfail / self.received if self.received else 0.0

    # --- latency -------------------------------------------------------
    def percentile(self, p: float) -> float:
        return percentile(sorted(self.latencies_ms), p)

    @property
    def p50(self) -> float:
        return self.percentile(0.50)

    @property
    def p95(self) -> float:
        return self.percentile(0.95)

    @property
    def p99(self) -> float:
        return self.percentile(0.99)

    @property
    def mean_ms(self) -> float:
        return sum(self.latencies_ms) / len(self.latencies_ms) if self.latencies_ms else float("nan")


def percentile(sorted_vals: list[float], p: float) -> float:
    """Linear-interpolated percentile of an already-sorted list."""
    if not sorted_vals:
        return float("nan")
    if len(sorted_vals) == 1:
        return sorted_vals[0]
    k = (len(sorted_vals) - 1) * p
    lo = math.floor(k)
    hi = math.ceil(k)
    if lo == hi:
        return sorted_vals[int(k)]
    return sorted_vals[lo] * (hi - k) + sorted_vals[hi] * (k - lo)


class _DnsProtocol(asyncio.DatagramProtocol):
    def __init__(self, on_response):
        self._on_response = on_response

    def datagram_received(self, data: bytes, addr) -> None:  # noqa: D102
        parsed = wire.parse_response(data)
        if parsed is not None:
            self._on_response(*parsed)

    def error_received(self, exc) -> None:  # noqa: D102
        # ICMP port-unreachable etc. The owning query will simply time out.
        pass


async def run_load(cfg: LoadConfig) -> LoadResult:
    """Drive ``cfg.qps`` queries/second at ``cfg.target`` for ``cfg.duration``."""
    loop = asyncio.get_running_loop()
    result = LoadResult(config=cfg)
    qtype = wire.QTYPES.get(cfg.qtype.upper())
    if qtype is None:
        raise ValueError(f"unsupported qtype {cfg.qtype!r}")

    inflight: dict[int, float] = {}  # qid -> send time (loop clock)
    # qids reaped as timeouts, kept briefly so a straggling answer is counted as
    # "late" (resolver slow past the timeout) instead of vanishing — that's the
    # difference between an overloaded resolver and one dropping queries.
    reaped: dict[int, float] = {}  # qid -> reap time (loop clock)

    def on_response(qid: int, rcode: int, tc: bool) -> None:
        sent_at = inflight.pop(qid, None)
        if sent_at is None:
            if reaped.pop(qid, None) is not None:
                result.late += 1
            return  # unknown / duplicate
        result.latencies_ms.append((loop.time() - sent_at) * 1000.0)
        result.rcodes[rcode] += 1
        result.received += 1
        if tc:
            result.tc += 1

    transport, _ = await loop.create_datagram_endpoint(
        lambda: _DnsProtocol(on_response),
        remote_addr=(cfg.target, cfg.port),
    )
    _tune_socket(transport, cfg)

    fixed_name = wire.encode_name(cfg.qname)
    use_random = cfg.qname_strategy == "random"

    def make_packet(qid: int) -> bytes:
        if use_random:
            # A unique label per query forces a cache miss -> real recursion.
            prefix = f"{random.getrandbits(32):08x}{random.getrandbits(32):08x}"
            name = wire.encode_name(f"{prefix}.{cfg.qname}")
            return wire.build_query(qid, name, qtype, edns_size=cfg.edns_size)
        return wire.build_query(qid, fixed_name, qtype, edns_size=cfg.edns_size)

    qid_counter = random.randrange(0x10000)

    # NOTE: ids are only guaranteed unique among *inflight* queries. A reaped
    # (timed-out) query's id can be reissued while its answer is still on the
    # wire, so past ~65536/(2*timeout) QPS per process (~16k at the 2s default)
    # a late answer can be misattributed to the new query. Single-process load
    # tops out well below that today; revisit if timeout or max_inflight change.
    def next_qid() -> int | None:
        nonlocal qid_counter
        for _ in range(0x10000):
            qid_counter = (qid_counter + 1) & 0xFFFF
            if qid_counter not in inflight:
                return qid_counter
        return None  # id space exhausted (inflight is enormous)

    interval = 1.0 / cfg.qps if cfg.qps > 0 else 0.0
    poisson = cfg.pacing == "poisson"

    def gap() -> float:
        # Mean rate is cfg.qps either way; poisson draws each inter-send gap
        # from an exponential so the offered load arrives in realistic bursts.
        return random.expovariate(cfg.qps) if poisson and cfg.qps > 0 else interval

    start = loop.time()
    end = start + cfg.duration
    next_due = start
    last_sweep = start

    try:
        while True:
            now = loop.time()
            if now >= end:
                break

            # Send everything that is "due" by the wall clock.
            while next_due <= now:
                if len(inflight) >= cfg.max_inflight or (qid := next_qid()) is None:
                    # Can't accept more; count the unsent due as a drop so the
                    # offered/sent shortfall is visible.
                    result.dropped += 1
                    next_due += gap()
                    continue
                transport.sendto(make_packet(qid))
                inflight[qid] = loop.time()
                result.sent += 1
                next_due += gap()

            # Periodically reap queries older than the timeout.
            if now - last_sweep >= 0.1:
                cutoff = now - cfg.timeout
                expired = [q for q, t in inflight.items() if t < cutoff]
                for q in expired:
                    del inflight[q]
                    reaped[q] = now
                result.timeouts += len(expired)
                # Forget reaped ids after a grace period so `reaped` stays small
                # and ids naturally return to circulation.
                if reaped:
                    stale = now - 3 * cfg.timeout
                    for q in [q for q, t in reaped.items() if t < stale]:
                        del reaped[q]
                last_sweep = now

            # Sleep until the next send is due (bounded so reaping stays timely).
            await asyncio.sleep(max(0.0, min(next_due - loop.time(), 0.005)))

        # The measurement window ends here: elapsed must not include the drain
        # below, or sent/answered QPS deflate on exactly the saturated steps
        # (up to `timeout` seconds of non-sending time would leak in) and the
        # ramp misblames the client for not offering the load.
        result.elapsed = loop.time() - start

        # Drain: give outstanding queries up to `timeout` to come back.
        drain_end = loop.time() + cfg.timeout
        while inflight and loop.time() < drain_end:
            await asyncio.sleep(0.01)
        result.timeouts += len(inflight)
    finally:
        transport.close()

    return result


def run_load_sync(cfg: LoadConfig) -> LoadResult:
    """Blocking wrapper around :func:`run_load`, for use in worker processes."""
    import asyncio as _asyncio

    return _asyncio.run(run_load(cfg))


def aggregate(results: list[LoadResult], offered_qps: float) -> LoadResult:
    """Merge per-worker results into one, as if a single generator had run.

    Latency samples are concatenated so percentiles are computed over the whole
    population; counters are summed; ``elapsed`` is the longest worker (they run
    concurrently), so the reported rates reflect the combined offered load.
    """
    merged = LoadResult(config=replace(results[0].config, qps=offered_qps))
    for r in results:
        merged.sent += r.sent
        merged.received += r.received
        merged.timeouts += r.timeouts
        merged.dropped += r.dropped
        merged.late += r.late
        merged.tc += r.tc
        merged.latencies_ms.extend(r.latencies_ms)
        merged.rcodes.update(r.rcodes)
        merged.elapsed = max(merged.elapsed, r.elapsed)
    return merged


def run_parallel_load(cfg: LoadConfig, workers: int) -> LoadResult:
    """Run ``cfg.qps`` split across ``workers`` processes and aggregate."""
    if workers <= 1:
        import asyncio as _asyncio

        return _asyncio.run(run_load(cfg))
    per = replace(cfg, qps=cfg.qps / workers)
    with ProcessPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(run_load_sync, [per] * workers))
    return aggregate(results, cfg.qps)


def _tune_socket(transport, cfg: LoadConfig) -> None:
    """Enlarge the UDP buffers so the kernel doesn't drop responses at high QPS."""
    sock = transport.get_extra_info("socket")
    if sock is None:
        return
    for opt, want in ((socket.SO_RCVBUF, cfg.socket_rcvbuf), (socket.SO_SNDBUF, cfg.socket_sndbuf)):
        try:
            sock.setsockopt(socket.SOL_SOCKET, opt, want)
        except OSError:
            pass  # best-effort; OS may cap or refuse
