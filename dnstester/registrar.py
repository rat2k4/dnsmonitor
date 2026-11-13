"""Periodic registrar: record newly-added, *verified* servers and domains.

The web control panel (and a plain editor) grow two list files — ``servers.txt``
and ``dns.txt``. This watcher polls those files on an interval and, when it
finds an entry it hasn't seen, *proves it works* before writing it to the result
database:

* a new **server** is registered only once a DNS query sent straight to it gets
  a valid response (so dead IPs and typos never enter the ``servers`` table);
* a new **domain** is registered only once it resolves against an
  already-verified server (so junk names never enter the ``domains`` table).

Entries that don't verify are left out and retried on the next scan, so a server
that is merely slow to come up gets picked up automatically later. The registry
lives in the same SQLite file as the poller's failure log; the two write
different tables and each uses its own connection with a busy timeout.
"""

from __future__ import annotations

import random
import socket
import sqlite3
import time
from datetime import datetime, timezone

from . import wire
from .poller import parse_query, parse_server

_SCHEMA = """
CREATE TABLE IF NOT EXISTS servers (
    server       TEXT PRIMARY KEY,   -- "host:port"
    host         TEXT NOT NULL,
    port         INTEGER NOT NULL,
    first_seen   REAL,               -- unix epoch: first noticed in the file
    verified_ts  REAL,               -- unix epoch: first successful query
    verified_iso TEXT,
    verify_query TEXT,               -- the query that proved it works
    verify_rcode TEXT,               -- its RCODE (NOERROR / NXDOMAIN / ...)
    verify_ms    REAL                -- that query's round-trip time
);
CREATE TABLE IF NOT EXISTS domains (
    name          TEXT NOT NULL,
    qtype         TEXT NOT NULL,
    first_seen    REAL,
    verified_ts   REAL,
    verified_iso  TEXT,
    verify_server TEXT,              -- the resolver that answered it
    verify_rcode  TEXT,
    verify_ms     REAL,
    PRIMARY KEY (name, qtype)
);
"""


def query_once(
    host: str, port: int, name: str, qtype: str, timeout: float
) -> tuple[bool, float | None, str | None]:
    """Send one DNS query and wait for a matching reply.

    Returns ``(ok, rtt_ms, rcode_name)``. ``ok`` is True when the resolver
    returns a well-formed response to *our* query id — proof it is alive and
    speaking DNS — regardless of the RCODE (NXDOMAIN still means it answered).
    """
    qtype_int = wire.QTYPES.get(qtype.upper(), 1)
    qid = random.randrange(1 << 16)
    try:
        packet = wire.build_query(qid, wire.encode_name(name), qtype_int)
    except ValueError:
        return False, None, None  # unencodable name
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        t0 = time.perf_counter()
        sock.send(packet)
        deadline = t0 + timeout
        while True:  # ignore stray datagrams with a mismatched id
            data = sock.recv(4096)
            parsed = wire.parse_response(data)
            if parsed is not None and parsed[0] == qid:
                rtt = (time.perf_counter() - t0) * 1000.0
                return True, rtt, wire.RCODES.get(parsed[1], str(parsed[1]))
            if time.perf_counter() >= deadline:
                return False, None, None
            sock.settimeout(max(0.0, deadline - time.perf_counter()))
    except OSError:
        return False, None, None
    finally:
        sock.close()


def _read_list(path: str) -> list[str]:
    """Non-empty, non-comment lines of a list file (or [] if it's missing)."""
    try:
        with open(path, encoding="utf-8") as fh:
            return [ln.split("#", 1)[0].strip() for ln in fh if ln.split("#", 1)[0].strip()]
    except OSError:
        return []


class Registrar:
    """Verifies and records newly-added servers/domains into the result db."""

    def __init__(
        self,
        db_path: str,
        servers_file: str,
        qname_file: str,
        *,
        port: int = 53,
        timeout: float = 2.0,
        default_qtype: str = "A",
    ) -> None:
        self.servers_file = servers_file
        self.qname_file = qname_file
        self.port = port
        self.timeout = timeout
        self.default_qtype = default_qtype
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute("PRAGMA busy_timeout=5000")  # ride out the poller's writes
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    # -- file readers ---------------------------------------------------------

    def _file_servers(self) -> list[tuple[str, int]]:
        out = []
        for spec in _read_list(self.servers_file):
            try:
                out.append(parse_server(spec, self.port))
            except (ValueError, IndexError):
                continue  # malformed line — skip
        return out

    def _file_domains(self) -> list[tuple[str, str]]:
        return [parse_query(tok, self.default_qtype) for tok in _read_list(self.qname_file)]

    # -- one scan -------------------------------------------------------------

    def scan_once(self) -> tuple[list[str], list[str]]:
        """Verify and register any new entries. Returns (servers, domains) added."""
        now = time.time()
        known_servers = {r[0] for r in self._conn.execute("SELECT server FROM servers")}
        known_domains = {(r[0], r[1]) for r in self._conn.execute("SELECT name, qtype FROM domains")}
        file_domains = self._file_domains()

        added_servers: list[str] = []
        for host, port in self._file_servers():
            key = f"{host}:{port}"
            if key in known_servers:
                continue
            # Probe with a real domain from the pool if we have one, else a
            # well-known name — we only need *something* to ask.
            name, qtype = file_domains[0] if file_domains else ("example.com", "A")
            ok, rtt, rcode = query_once(host, port, name, qtype, self.timeout)
            if not ok:
                continue  # unverified — try again next scan
            self._conn.execute(
                "INSERT OR IGNORE INTO servers (server, host, port, first_seen, "
                "verified_ts, verified_iso, verify_query, verify_rcode, verify_ms) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (key, host, port, now, now,
                 datetime.now(timezone.utc).isoformat(timespec="seconds"),
                 f"{name} {qtype}", rcode, rtt),
            )
            known_servers.add(key)
            added_servers.append(key)

        # Domains are verified against an already-registered (verified) server.
        verified = list(self._conn.execute("SELECT host, port, server FROM servers"))
        added_domains: list[str] = []
        for name, qtype in file_domains:
            if (name, qtype) in known_domains or not verified:
                continue
            for host, port, server in verified:
                ok, rtt, rcode = query_once(host, port, name, qtype, self.timeout)
                if ok:
                    self._conn.execute(
                        "INSERT OR IGNORE INTO domains (name, qtype, first_seen, "
                        "verified_ts, verified_iso, verify_server, verify_rcode, verify_ms) "
                        "VALUES (?,?,?,?,?,?,?,?)",
                        (name, qtype, now, now,
                         datetime.now(timezone.utc).isoformat(timespec="seconds"),
                         server, rcode, rtt),
                    )
                    known_domains.add((name, qtype))
                    added_domains.append(f"{name} {qtype}")
                    break  # one good answer is enough

        if added_servers or added_domains:
            self._conn.commit()
        return added_servers, added_domains
