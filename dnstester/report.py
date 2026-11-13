"""Rendering of ramp results: console table, CSV and JSON."""

from __future__ import annotations

import csv
import json
import math
from typing import Iterable

from .ramp import StepResult, first_saturated

# (header, width, extractor) for the console + CSV table.
_COLUMNS = [
    ("offered", 8, lambda s: _num(s.load.offered_qps, 0)),
    ("sent", 8, lambda s: _num(s.load.sent_qps, 0)),
    ("answered", 9, lambda s: _num(s.load.answered_qps, 0)),
    ("handled", 8, lambda s: _num(s.monitor.handled_qps, 0)),
    ("p50ms", 8, lambda s: _num(s.load.p50, 1)),
    ("p95ms", 8, lambda s: _num(s.load.p95, 1)),
    ("p99ms", 8, lambda s: _num(s.load.p99, 1)),
    ("timeout%", 9, lambda s: _pct(s.load.timeout_rate)),
    ("servfail%", 10, lambda s: _pct(s.load.servfail_rate)),
    ("drop%", 7, lambda s: _pct(s.load.drop_rate)),
    ("cachehit%", 10, lambda s: _pct(s.monitor.cache_hit_ratio)),
    ("reqlist", 8, lambda s: _num(s.monitor.requestlist_max, 0)),
    ("", 4, lambda s: "SAT" if s.saturated else ""),
]


def _num(v: float, places: int) -> str:
    if v is None or (isinstance(v, float) and math.isnan(v)):
        return "-"
    return f"{v:.{places}f}"


def _pct(v: float) -> str:
    if v is None or (isinstance(v, float) and math.isnan(v)):
        return "-"
    return f"{v * 100:.1f}"


def print_table(results: Iterable[StepResult], file=None) -> None:
    results = list(results)
    header = " ".join(h.rjust(w) for h, w, _ in _COLUMNS)
    print(header, file=file)
    print("-" * len(header), file=file)
    for step in results:
        row = " ".join(extract(step).rjust(w) for _, w, extract in _COLUMNS)
        print(row, file=file)


def print_summary(results: list[StepResult], file=None) -> None:
    sat = first_saturated(results)
    print("", file=file)
    if sat is None:
        last = results[-1]
        print(
            f"No saturation across the swept range. Max offered {last.load.offered_qps:.0f} qps "
            f"sustained at p99 {_num(last.load.p99, 1)}ms — push the ramp higher to find the knee.",
            file=file,
        )
        return
    print(
        f"Breaking point at ~{sat.load.offered_qps:.0f} qps offered "
        f"(unbound handled ~{_num(sat.monitor.handled_qps, 0)} qps):",
        file=file,
    )
    for reason in sat.reasons:
        print(f"  - {reason}", file=file)

    # Best healthy step right before saturation.
    healthy = [s for s in results if not s.saturated and s.load.offered_qps < sat.load.offered_qps]
    if healthy:
        best = healthy[-1]
        print(
            f"Last healthy step: {best.load.offered_qps:.0f} qps offered, "
            f"p99 {_num(best.load.p99, 1)}ms, answered {best.load.answered_qps:.0f} qps.",
            file=file,
        )


def write_csv(results: list[StepResult], path: str) -> None:
    with open(path, "w", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow([h or "saturated" for h, _, _ in _COLUMNS])
        for step in results:
            writer.writerow([extract(step) for _, _, extract in _COLUMNS])


def write_json(results: list[StepResult], path: str) -> None:
    payload = []
    for s in results:
        l = s.load
        m = s.monitor
        payload.append(
            {
                "offered_qps": l.offered_qps,
                "sent_qps": l.sent_qps,
                "answered_qps": l.answered_qps,
                "handled_qps": m.handled_qps,
                "sent": l.sent,
                "received": l.received,
                "timeouts": l.timeouts,
                "dropped": l.dropped,
                "late": l.late,
                "truncated": l.tc,
                "timeout_rate": l.timeout_rate,
                "servfail_rate": l.servfail_rate,
                "drop_rate": l.drop_rate,
                "latency_ms": {
                    "p50": l.p50,
                    "p95": l.p95,
                    "p99": l.p99,
                    "mean": l.mean_ms,
                },
                "rcodes": dict(l.rcodes),
                "unbound": {
                    "handled_qps": m.handled_qps,
                    "cache_hit_ratio": m.cache_hit_ratio,
                    "recursion_time_avg_ms": m.recursion_time_avg_ms,
                    "requestlist_max": m.requestlist_max,
                    "requestlist_avg": m.requestlist_avg,
                    "requestlist_exceeded": m.requestlist_exceeded,
                    "requestlist_overwritten": m.requestlist_overwritten,
                    "tcp_usage": m.tcp_usage,
                },
                "saturated": s.saturated,
                "reasons": s.reasons,
            }
        )
    with open(path, "w") as fh:
        json.dump(_clean_nan(payload), fh, indent=2)


def _clean_nan(obj):
    """Recursively turn NaN floats into None so the JSON stays valid."""
    if isinstance(obj, float):
        return None if math.isnan(obj) else obj
    if isinstance(obj, dict):
        return {k: _clean_nan(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_clean_nan(v) for v in obj]
    return obj
