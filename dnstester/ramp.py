"""Stepwise QPS ramp that ties the client and the monitor together.

For each QPS step we (optionally) snapshot Unbound's stats, run the load
generator for a fixed duration, snapshot again, and record one row combining
the client-observed result with the resolver-observed delta. The first step
that trips any saturation threshold is flagged as the breaking point, but the
ramp keeps going so the full latency-vs-QPS curve is captured either way.
"""

from __future__ import annotations

import asyncio
import time
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass, field, replace

from .loadgen import LoadConfig, LoadResult, aggregate, run_load, run_load_sync
from .monitor import MonitorDelta, UnboundMonitor, compute_delta


@dataclass(slots=True)
class Thresholds:
    """A step is "saturated" once any of these is exceeded."""

    max_p99_ms: float = 100.0
    max_timeout_rate: float = 0.02
    max_servfail_rate: float = 0.05
    max_drop_rate: float = 0.02
    # Offered load is considered unmet if sent QPS falls below this fraction.
    min_sent_fraction: float = 0.95


@dataclass(slots=True)
class RampConfig:
    load: LoadConfig  # template; .qps is overridden per step
    qps_steps: list[float]
    cooldown: float = 3.0  # idle seconds between steps (let queues/cache settle)
    thresholds: Thresholds = field(default_factory=Thresholds)
    workers: int = 1  # generator processes per step; QPS is split across them


@dataclass(slots=True)
class StepResult:
    load: LoadResult
    monitor: MonitorDelta
    saturated: bool
    reasons: list[str]


def evaluate(load: LoadResult, mon: MonitorDelta, th: Thresholds) -> tuple[bool, list[str]]:
    reasons: list[str] = []
    if load.sent_qps < load.offered_qps * th.min_sent_fraction:
        reasons.append(
            f"client could not offer load (sent {load.sent_qps:.0f}/"
            f"{load.offered_qps:.0f} qps)"
        )
    if load.drop_rate > th.max_drop_rate:
        reasons.append(f"drop rate {load.drop_rate:.1%} > {th.max_drop_rate:.0%}")
    if load.timeout_rate > th.max_timeout_rate:
        reasons.append(f"timeout rate {load.timeout_rate:.1%} > {th.max_timeout_rate:.0%}")
    if load.servfail_rate > th.max_servfail_rate:
        reasons.append(f"SERVFAIL rate {load.servfail_rate:.1%} > {th.max_servfail_rate:.0%}")
    if load.latencies_ms and load.p99 > th.max_p99_ms:
        reasons.append(f"p99 {load.p99:.1f}ms > {th.max_p99_ms:.0f}ms")
    if mon.requestlist_exceeded and mon.requestlist_exceeded > 0:
        reasons.append(f"unbound dropped {mon.requestlist_exceeded:.0f} queries (requestlist exceeded)")
    return (bool(reasons), reasons)


async def run_ramp(
    cfg: RampConfig,
    monitor: UnboundMonitor | None = None,
    on_step=None,
) -> list[StepResult]:
    """Run all QPS steps in order. ``on_step(StepResult)`` is called as each
    step finishes so callers can stream results to the console."""
    results: list[StepResult] = []

    # A single pool is reused for the whole ramp when running multi-process so
    # we don't pay process-spawn cost on every step.
    pool = ProcessPoolExecutor(max_workers=cfg.workers) if cfg.workers > 1 else None
    try:
        for qps in cfg.qps_steps:
            step_load = replace(cfg.load, qps=qps)

            before = _safe_snapshot(monitor)
            t0 = time.monotonic()
            load = await _run_step_load(step_load, cfg.workers, pool)
            elapsed = time.monotonic() - t0
            after = _safe_snapshot(monitor)

            if before is not None and after is not None:
                mon = compute_delta(
                    before, after, elapsed,
                    already_reset=monitor is not None and monitor.cfg.reset_stats,
                )
            else:
                mon = MonitorDelta.empty()

            saturated, reasons = evaluate(load, mon, cfg.thresholds)
            step = StepResult(load=load, monitor=mon, saturated=saturated, reasons=reasons)
            results.append(step)
            if on_step is not None:
                on_step(step)

            if cfg.cooldown > 0 and qps != cfg.qps_steps[-1]:
                await asyncio.sleep(cfg.cooldown)
    finally:
        if pool is not None:
            pool.shutdown()

    return results


async def _run_step_load(step_load: LoadConfig, workers: int, pool) -> LoadResult:
    """Run one step's load, either in-process or fanned out across the pool."""
    if pool is None or workers <= 1:
        return await run_load(step_load)
    per = replace(step_load, qps=step_load.qps / workers)
    loop = asyncio.get_running_loop()
    futures = [loop.run_in_executor(pool, run_load_sync, per) for _ in range(workers)]
    worker_results = await asyncio.gather(*futures)
    return aggregate(list(worker_results), step_load.qps)


def first_saturated(results: list[StepResult]) -> StepResult | None:
    """First step of a *sustained* saturation, or None.

    A single saturated step surrounded by healthy ones is treated as noise (a
    GC pause, one upstream blip during recursion) — the breaking point is only
    called where saturation holds for two consecutive steps. The final step
    can't be confirmed by a successor, so it counts on its own; better to flag
    the edge of the sweep than to report a clean run that wasn't.
    """
    for i, step in enumerate(results):
        if not step.saturated:
            continue
        if i + 1 == len(results) or results[i + 1].saturated:
            return step
    return None


def _safe_snapshot(monitor: UnboundMonitor | None) -> dict[str, float] | None:
    if monitor is None:
        return None
    try:
        return monitor.snapshot()
    except Exception:  # noqa: BLE001 — monitoring is best-effort
        return None


def build_steps(start: float, stop: float, step: float) -> list[float]:
    """Inclusive arithmetic ramp from ``start`` to ``stop``."""
    if step <= 0:
        raise ValueError("step must be > 0")
    if stop < start:
        raise ValueError("stop must be >= start")
    steps: list[float] = []
    q = start
    while q <= stop + 1e-9:
        steps.append(round(q, 3))
        q += step
    return steps
