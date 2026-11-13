"""Unbound-side monitoring (the *server* part).

Reads Unbound's own view of the load by running ``unbound-control
stats_noreset`` on the resolver host over SSH and parsing the ``key=value``
output. ``stats_noreset`` leaves the counters intact, so we snapshot before and
after each load step and diff the cumulative counters to get per-step rates.

SSH is driven through the system ``ssh`` client (subprocess) rather than a
library, so there is nothing to install and it honours the user's existing
``~/.ssh/config``, agent and keys.
"""

from __future__ import annotations

import math
import subprocess
from dataclasses import dataclass


@dataclass(slots=True)
class MonitorConfig:
    host: str
    user: str | None = None
    port: int = 22
    identity: str | None = None  # path to private key (-i)
    control_cmd: str = "unbound-control"
    use_sudo: bool = False
    ssh_timeout: float = 10.0
    # Use the resetting ``stats`` command instead of ``stats_noreset``. With
    # resetting stats every snapshot's counters AND gauges (requestlist.max/avg,
    # recursion time) cover exactly the interval since the previous snapshot —
    # under ``stats_noreset`` the gauges are since-startup, so a request-list
    # spike in one step would smear into every later step's numbers. Turn this
    # off only if something else on the host also reads unbound's counters and
    # must not have them reset underneath it.
    reset_stats: bool = True

    @property
    def enabled(self) -> bool:
        return bool(self.host)


class UnboundMonitor:
    def __init__(self, cfg: MonitorConfig):
        self.cfg = cfg

    def _ssh_argv(self, remote_cmd: str) -> list[str]:
        argv = [
            "ssh",
            "-o", "BatchMode=yes",
            "-o", f"ConnectTimeout={int(self.cfg.ssh_timeout)}",
            "-p", str(self.cfg.port),
        ]
        if self.cfg.identity:
            argv += ["-i", self.cfg.identity]
        target = f"{self.cfg.user}@{self.cfg.host}" if self.cfg.user else self.cfg.host
        argv.append(target)
        argv.append(remote_cmd)
        return argv

    def _remote_cmd(self, subcmd: str) -> str:
        prefix = "sudo " if self.cfg.use_sudo else ""
        return f"{prefix}{self.cfg.control_cmd} {subcmd}"

    def check(self) -> str | None:
        """Return ``None`` if the resolver is reachable, else an error string."""
        try:
            out = self._run("status")
        except MonitorError as exc:
            return str(exc)
        return None if out else "empty response from unbound-control status"

    def snapshot(self) -> dict[str, float]:
        """Return the full parsed stats map (resetting or not per the config)."""
        subcmd = "stats" if self.cfg.reset_stats else "stats_noreset"
        return parse_stats(self._run(subcmd))

    def _run(self, subcmd: str) -> str:
        argv = self._ssh_argv(self._remote_cmd(subcmd))
        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=self.cfg.ssh_timeout + 5,
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            raise MonitorError(f"ssh failed: {exc}") from exc
        if proc.returncode != 0:
            raise MonitorError(
                f"`{' '.join(argv[-2:])}` exited {proc.returncode}: "
                f"{proc.stderr.strip() or proc.stdout.strip()}"
            )
        return proc.stdout


class MonitorError(RuntimeError):
    pass


def parse_stats(text: str) -> dict[str, float]:
    stats: dict[str, float] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or "=" not in line:
            continue
        key, _, val = line.partition("=")
        try:
            stats[key.strip()] = float(val.strip())
        except ValueError:
            continue
    return stats


@dataclass(slots=True)
class MonitorDelta:
    handled_qps: float
    cache_hit_ratio: float
    recursion_time_avg_ms: float
    requestlist_exceeded: float
    requestlist_overwritten: float
    requestlist_max: float
    requestlist_avg: float
    servfail_answers: float
    tcp_usage: float

    @classmethod
    def empty(cls) -> "MonitorDelta":
        nan = float("nan")
        return cls(nan, nan, nan, nan, nan, nan, nan, nan, nan)


def compute_delta(
    before: dict[str, float],
    after: dict[str, float],
    elapsed: float,
    *,
    already_reset: bool = False,
) -> MonitorDelta:
    """Per-step view from two snapshots that straddle a load step.

    With ``already_reset`` (the resetting ``stats`` command) the *before*
    snapshot zeroed the counters, so *after* holds exactly the step's counts —
    no differencing needed, and the gauges are genuinely per-step too.
    """

    def d(key: str) -> float:
        if already_reset:
            return after.get(key, float("nan"))
        if key in before and key in after:
            return after[key] - before[key]
        return float("nan")

    def g(key: str) -> float:
        return after.get(key, float("nan"))

    handled = d("total.num.queries")
    hits = d("total.num.cachehits")
    miss = d("total.num.cachemiss")
    total_cache = hits + miss
    hit_ratio = hits / total_cache if total_cache and not math.isnan(total_cache) and total_cache > 0 else float("nan")

    return MonitorDelta(
        handled_qps=handled / elapsed if elapsed and not math.isnan(handled) else float("nan"),
        cache_hit_ratio=hit_ratio,
        recursion_time_avg_ms=g("total.recursion.time.avg") * 1000.0,
        requestlist_exceeded=d("total.requestlist.exceeded"),
        requestlist_overwritten=d("total.requestlist.overwritten"),
        requestlist_max=g("total.requestlist.max"),
        requestlist_avg=g("total.requestlist.avg"),
        servfail_answers=d("num.answer.rcode.SERVFAIL"),
        tcp_usage=g("total.tcpusage"),
    )
