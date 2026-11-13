"""SQLite event log for probe failures.

When a DNS probe fails (a timeout or a socket error), we don't just want to
know *that* one server hiccuped — we want the surrounding context: what was
every other server doing at that instant? A failure on one resolver while the
others stay green points at that resolver; failures across the board point at
the network or the client. So each failure writes one ``events`` row plus a
``server_status`` row per polled server capturing its last-known state.

Opt-in: only created when the user passes a database path. Thread-safe — every
server polls on its own thread and any of them can trip a failure concurrently,
so all writes go through a single connection guarded by a lock.
"""

from __future__ import annotations

import math
import sqlite3
import threading
import time
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .poller import StatsSnapshot

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    ts             REAL NOT NULL,   -- unix epoch seconds
    iso            TEXT NOT NULL,   -- ISO-8601 UTC, for eyeballing
    trigger_server TEXT NOT NULL,
    trigger_kind   TEXT NOT NULL,   -- 'timeout' | 'error'
    trigger_detail TEXT             -- failing query, or error message
);
CREATE TABLE IF NOT EXISTS server_status (
    event_id            INTEGER NOT NULL REFERENCES events(id),
    server              TEXT NOT NULL,
    up                  INTEGER NOT NULL,
    sent                INTEGER,
    answered            INTEGER,
    timeouts            INTEGER,
    errors              INTEGER,
    availability        REAL,
    recent_availability REAL,
    last_ms             REAL,
    p95_ms              REAL,
    stability           REAL,
    last_error          TEXT,
    last_query          TEXT,
    last_error_query    TEXT,
    dns_dscp_last       INTEGER,
    dns_dscp_mode       INTEGER,
    icmp_enabled        INTEGER,
    icmp_up             INTEGER,
    icmp_success        REAL,
    icmp_last_ms        REAL,
    icmp_ttl_min        INTEGER,
    icmp_ttl_max        INTEGER,
    icmp_ttl_mode       INTEGER,
    icmp_ttl_least      INTEGER
);
CREATE INDEX IF NOT EXISTS idx_status_event ON server_status(event_id);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE TABLE IF NOT EXISTS samples (
    ts                  REAL NOT NULL,   -- unix epoch seconds
    iso                 TEXT NOT NULL,   -- ISO-8601 UTC
    server              TEXT NOT NULL,
    up                  INTEGER NOT NULL,
    sent                INTEGER,
    answered            INTEGER,
    timeouts            INTEGER,
    errors              INTEGER,
    availability        REAL,
    recent_availability REAL,
    last_ms             REAL,
    p95_ms              REAL,
    stability           REAL,
    dns_dscp_last       INTEGER,
    dns_dscp_mode       INTEGER,
    icmp_enabled        INTEGER,
    icmp_up             INTEGER,
    icmp_success        REAL,
    icmp_last_ms        REAL,
    icmp_ttl_min        INTEGER,
    icmp_ttl_max        INTEGER,
    icmp_ttl_mode       INTEGER,
    icmp_ttl_least      INTEGER
);
CREATE INDEX IF NOT EXISTS idx_samples_ts ON samples(ts);
CREATE TABLE IF NOT EXISTS triage (
    event_id     INTEGER REFERENCES events(id),  -- NULL if event logging was off
    ts           REAL NOT NULL,
    iso          TEXT NOT NULL,
    server       TEXT NOT NULL,
    query        TEXT,
    retry_ok     INTEGER,  -- fresh UDP retry of the failing query
    retry_ms     REAL,
    tcp_ok       INTEGER,  -- same query over TCP:53
    tcp_ms       REAL,
    cached_ok    INTEGER,  -- a recently-answered (should-be-cached) name
    cached_ms    REAL,
    cached_query TEXT,
    ref_server   TEXT,     -- healthy other server given the same query
    ref_ok       INTEGER,
    ref_ms       REAL,
    verdict      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_triage_ts ON triage(ts);
CREATE TABLE IF NOT EXISTS query_stats (
    ts          REAL NOT NULL,   -- unix epoch seconds
    iso         TEXT NOT NULL,
    server      TEXT NOT NULL,
    query       TEXT NOT NULL,
    sent        INTEGER,         -- cumulative since poll start / last reset
    answered    INTEGER,
    failed      INTEGER,
    mean_ms     REAL,
    stdev_ms    REAL,
    last_ttl    INTEGER,         -- min TTL of the most recent answer
    last_answer TEXT             -- rdata of the most recent answer
);
CREATE INDEX IF NOT EXISTS idx_qstats_ts ON query_stats(ts);
-- Every failure event stamped with how widespread it was at that instant:
-- 'isolated' (only the trigger down), 'partial', or 'fleet-wide' (all down).
CREATE VIEW IF NOT EXISTS events_classified AS
SELECT e.*,
       (SELECT COUNT(*) FROM server_status s WHERE s.event_id = e.id AND s.up = 0)
           AS servers_down,
       (SELECT COUNT(*) FROM server_status s WHERE s.event_id = e.id)
           AS servers_total,
       CASE
           WHEN (SELECT COUNT(*) FROM server_status s WHERE s.event_id = e.id AND s.up = 0) <= 1
               THEN 'isolated'
           WHEN (SELECT COUNT(*) FROM server_status s WHERE s.event_id = e.id AND s.up = 0)
                < (SELECT COUNT(*) FROM server_status s WHERE s.event_id = e.id)
               THEN 'partial'
           ELSE 'fleet-wide'
       END AS class
FROM events e;
"""

# Columns added after the initial schema shipped. ``CREATE TABLE IF NOT EXISTS``
# won't touch an existing table, so we ALTER in anything missing on open.
_MIGRATIONS = {
    "server_status": [
        ("icmp_ttl_min", "INTEGER"),
        ("icmp_ttl_max", "INTEGER"),
        ("icmp_ttl_mode", "INTEGER"),
        ("icmp_ttl_least", "INTEGER"),
        ("dns_dscp_last", "INTEGER"),
        ("dns_dscp_mode", "INTEGER"),
        ("raw_lost", "INTEGER"),
        ("recovered", "INTEGER"),
        ("late_answers", "INTEGER"),
        ("tc_answers", "INTEGER"),
        ("last_triage", "TEXT"),
    ],
    "samples": [
        ("icmp_ttl_min", "INTEGER"),
        ("icmp_ttl_max", "INTEGER"),
        ("icmp_ttl_mode", "INTEGER"),
        ("icmp_ttl_least", "INTEGER"),
        ("dns_dscp_last", "INTEGER"),
        ("dns_dscp_mode", "INTEGER"),
        ("raw_lost", "INTEGER"),
        ("recovered", "INTEGER"),
        ("late_answers", "INTEGER"),
        ("tc_answers", "INTEGER"),
        ("canary_sent", "INTEGER"),
        ("canary_hijacks", "INTEGER"),
    ],
}


def _num(x: float | None) -> float | None:
    """SQLite can't store NaN/inf meaningfully — fold them to NULL."""
    if x is None or math.isnan(x) or math.isinf(x):
        return None
    return x


def _ttl_cols(s: StatsSnapshot) -> tuple:
    """The ICMP TTL columns in schema order: min, max, mode, least.

    All NULL when ICMP is off or no echo has been received yet.
    """
    if not s.icmp_enabled or not s.icmp_recv:
        return (None, None, None, None)
    return (
        s.icmp_ttl_min,
        s.icmp_ttl_max,
        s.icmp_ttl_mode,
        s.icmp_ttl_least,
    )


class EventLog:
    """A SQLite sink for probe-failure events. One connection, one lock."""

    def __init__(self, path: str) -> None:
        self.path = path
        # check_same_thread=False because the failing poller thread writes
        # directly; the lock below serialises those writes.
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._lock = threading.Lock()
        self._conn.executescript(_SCHEMA)
        self._migrate()
        self._conn.commit()

    def _migrate(self) -> None:
        """Add columns introduced after a log's tables were first created."""
        for table, cols in _MIGRATIONS.items():
            existing = {
                row[1] for row in self._conn.execute(f"PRAGMA table_info({table})")
            }
            for name, decl in cols:
                if name not in existing:
                    self._conn.execute(
                        f"ALTER TABLE {table} ADD COLUMN {name} {decl}"
                    )

    def log_failure(
        self,
        trigger_server: str,
        trigger_kind: str,
        trigger_detail: str,
        snapshots: list[StatsSnapshot],
    ) -> int:
        """Record one failure event plus every server's last-known status.

        Returns the new event's row id so follow-up records (the triage
        battery) can reference it.
        """
        now = time.time()
        iso = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO events (ts, iso, trigger_server, trigger_kind, trigger_detail) "
                "VALUES (?, ?, ?, ?, ?)",
                (now, iso, trigger_server, trigger_kind, trigger_detail),
            )
            event_id = cur.lastrowid
            self._conn.executemany(
                "INSERT INTO server_status ("
                "event_id, server, up, sent, answered, timeouts, errors, "
                "availability, recent_availability, last_ms, p95_ms, stability, "
                "last_error, last_query, last_error_query, "
                "dns_dscp_last, dns_dscp_mode, "
                "icmp_enabled, icmp_up, icmp_success, icmp_last_ms, "
                "icmp_ttl_min, icmp_ttl_max, icmp_ttl_mode, icmp_ttl_least, "
                "raw_lost, recovered, late_answers, tc_answers, last_triage"
                ") VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                [
                    (
                        event_id,
                        f"{s.host}:{s.port}",
                        int(s.up),
                        s.sent,
                        s.answered,
                        s.timeouts,
                        s.errors,
                        _num(s.availability),
                        _num(s.recent_availability),
                        _num(s.last_ms),
                        _num(s.p95_ms),
                        _num(s.stability),
                        s.last_error or None,
                        s.last_query or None,
                        s.last_error_query or None,
                        s.dns_dscp_last,
                        s.dns_dscp_mode,
                        int(s.icmp_enabled),
                        int(s.icmp_up),
                        _num(s.icmp_success) if s.icmp_enabled else None,
                        _num(s.icmp_last_ms) if s.icmp_enabled else None,
                        *_ttl_cols(s),
                        s.raw_lost,
                        s.recovered,
                        s.late_answers,
                        s.tc_answers,
                        s.last_triage or None,
                    )
                    for s in snapshots
                ],
            )
            self._conn.commit()
        return int(event_id) if event_id is not None else 0

    def log_samples(self, snapshots: list[StatsSnapshot]) -> None:
        """Record one periodic per-server KPI snapshot (a continuous trace).

        Unlike :meth:`log_failure`, which only fires on a probe failure, this is
        called on a fixed interval so the ``samples`` table is an evenly-spaced
        time series of latency/availability — what you want for plotting trends.
        """
        now = time.time()
        iso = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with self._lock:
            self._conn.executemany(
                "INSERT INTO samples ("
                "ts, iso, server, up, sent, answered, timeouts, errors, "
                "availability, recent_availability, last_ms, p95_ms, stability, "
                "dns_dscp_last, dns_dscp_mode, "
                "icmp_enabled, icmp_up, icmp_success, icmp_last_ms, "
                "icmp_ttl_min, icmp_ttl_max, icmp_ttl_mode, icmp_ttl_least, "
                "raw_lost, recovered, late_answers, tc_answers, "
                "canary_sent, canary_hijacks"
                ") VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                [
                    (
                        now,
                        iso,
                        f"{s.host}:{s.port}",
                        int(s.up),
                        s.sent,
                        s.answered,
                        s.timeouts,
                        s.errors,
                        _num(s.availability),
                        _num(s.recent_availability),
                        _num(s.last_ms),
                        _num(s.p95_ms),
                        _num(s.stability),
                        s.dns_dscp_last,
                        s.dns_dscp_mode,
                        int(s.icmp_enabled),
                        int(s.icmp_up),
                        _num(s.icmp_success) if s.icmp_enabled else None,
                        _num(s.icmp_last_ms) if s.icmp_enabled else None,
                        *_ttl_cols(s),
                        s.raw_lost,
                        s.recovered,
                        s.late_answers,
                        s.tc_answers,
                        s.canary_sent,
                        s.canary_hijacks,
                    )
                    for s in snapshots
                ],
            )
            self._conn.commit()

    def log_triage(self, event_id: int | None, r) -> None:
        """Record one triage-battery result (``r`` is a poller.TriageResult)."""
        now = time.time()
        iso = datetime.now(timezone.utc).isoformat(timespec="seconds")

        def b(v: bool | None) -> int | None:
            return None if v is None else int(v)

        with self._lock:
            self._conn.execute(
                "INSERT INTO triage ("
                "event_id, ts, iso, server, query, "
                "retry_ok, retry_ms, tcp_ok, tcp_ms, "
                "cached_ok, cached_ms, cached_query, "
                "ref_server, ref_ok, ref_ms, verdict"
                ") VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    event_id,
                    now,
                    iso,
                    r.server,
                    r.query,
                    b(r.retry_ok),
                    _num(r.retry_ms),
                    b(r.tcp_ok),
                    _num(r.tcp_ms),
                    b(r.cached_ok),
                    _num(r.cached_ms),
                    r.cached_query,
                    r.ref_server,
                    b(r.ref_ok),
                    _num(r.ref_ms),
                    r.verdict,
                ),
            )
            self._conn.commit()

    def log_query_stats(self, snapshots: list[StatsSnapshot]) -> None:
        """Record each server's cumulative per-query counters.

        Gives the failure-by-(server, query) matrix its denominators — from the
        events table alone you can count failures per name but not rates.
        """
        now = time.time()
        iso = datetime.now(timezone.utc).isoformat(timespec="seconds")
        rows = [
            (
                now,
                iso,
                f"{s.host}:{s.port}",
                label,
                q_sent,
                q_ans,
                q_fail,
                _num(q_mean),
                _num(q_stdev),
                ttl,
                ans or None,
            )
            for s in snapshots
            for (label, q_sent, q_ans, q_fail, q_mean, q_stdev, ttl, ans) in s.query_stats
        ]
        if not rows:
            return
        with self._lock:
            self._conn.executemany(
                "INSERT INTO query_stats ("
                "ts, iso, server, query, sent, answered, failed, "
                "mean_ms, stdev_ms, last_ttl, last_answer"
                ") VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                rows,
            )
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()
