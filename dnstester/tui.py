"""Curses front-end for the DNS quality poller.

Renders every server as a column and every KPI as a row, so several resolvers
can be compared at a glance — all the numbers on one screen, updating live. A
per-server latency sparkline gives an immediate visual read on stability.

Keys: ``q``/Esc quit · ``r`` reset all counters · ``space`` pause/resume the
display (polling keeps running underneath) · ``h``/``?`` toggle the help screen
that explains every measured variable.
"""

from __future__ import annotations

import curses
import math
import textwrap
import time
from collections.abc import Callable

from .poller import PollConfig, PollManager, StatsSnapshot
from .wire import RCODES

_SPARK = " ▁▂▃▄▅▆▇█"  # index 0 (space) is reserved for "no data / timeout"

# Well-known DSCP code points, for annotating the raw value with its standard
# name (RFC 2474 / 2597 / 3246). Anything not listed is shown as a bare number.
_DSCP_NAMES = {
    0: "CS0", 8: "CS1", 16: "CS2", 24: "CS3", 32: "CS4", 40: "CS5", 48: "CS6",
    56: "CS7", 10: "AF11", 12: "AF12", 14: "AF13", 18: "AF21", 20: "AF22",
    22: "AF23", 26: "AF31", 28: "AF32", 30: "AF33", 34: "AF41", 36: "AF42",
    38: "AF43", 46: "EF",
}

# Color pair ids.
_C_HEAD = 1
_C_GOOD = 2
_C_WARN = 3
_C_BAD = 4
_C_DIM = 5

# Help-screen content: every measured variable, grouped to mirror the dashboard
# sections, as (section title, [(row label, explanation), ...]). Kept next to the
# rows it documents so the two stay in step.
_HELP_INTRO = (
    "Each column is one resolver; each row is a live KPI. Counters accumulate "
    "since start or the last reset (r); windowed metrics cover only the most "
    "recent probes. Colours: green = healthy, yellow = warning, red = bad."
)
_HELP: list[tuple[str, list[tuple[str, str]]]] = [
    ("Overview", [
        ("state", "Outcome of the latest probe: UP = answered, DOWN = failed, "
                  "... = nothing sent yet."),
        ("current qry", "Name and record type of the most recent probe."),
        ("stability", "0-100 heuristic dominated by recent availability (~4 "
                      "points per 1% of dropped queries), with small penalties "
                      "for tail latency (p95) and jitter. A quick 'how solid is "
                      "this resolver', not an official metric."),
        ("sent/answered", "Total DNS queries sent / how many got any response "
                          "(any rcode), on one line."),
        ("availability", "answered / sent over the whole run."),
        ("recent avail", "Availability over just the recent sliding window."),
        ("timeouts", "Probes that got no reply within the timeout (count and "
                     "rate)."),
        ("net errors", "Socket / network errors, distinct from timeouts (count "
                       "and rate)."),
        ("raw pkt loss", "Unanswered packets / packets sent, counting "
                         "retransmits. A probe retries before failing (like a "
                         "real stub resolver), so this is the wire-level drop "
                         "rate while 'timeouts' is the after-retry failure a "
                         "user would feel."),
        ("retry saves", "Probes whose first packet went unanswered but whose "
                        "retransmit got an answer — loss the retry hid."),
        ("late answers", "Answers that arrived after their probe had already "
                         "timed out, and how late the last one was. Late "
                         "answers mean the resolver is slow (overloaded); none "
                         "at all means queries are being dropped outright."),
        ("eff. qps", "Effective query rate: sent / elapsed seconds."),
    ]),
    ("Latency (DNS response time)", [
        ("min/mean/max/last", "Four values on one line (ms, 's' past 1000ms): "
                              "fastest answer / running mean / slowest answer / "
                              "most recent answered probe."),
        ("p50 / p90 / p95 / p99", "Percentiles over the recent window: half / "
                                  "90% / 95% / 99% of answers were at least this "
                                  "fast."),
        ("std dev", "Per-query standard deviation of latency, pooled across the "
                    "query pool — the resolver's own consistency, not the spread "
                    "between different pool names."),
        ("jitter", "Smoothed change between consecutive answers to the *same* "
                   "query — real resolver jitter, not pool-name differences."),
        ("ewma", "Exponentially weighted moving average — recent-weighted "
                 "latency trend."),
        ("cv", "Coefficient of variation (per-query std dev / mean) — relative "
               "consistency; >0.5 flags an erratic resolver."),
        ("recursion ovh", "Mean DNS latency minus mean ICMP RTT — the resolver's "
                          "own processing/recursion time, with network distance "
                          "subtracted out. Near zero means cache hits; large "
                          "means recursion or a busy resolver. '-' if ICMP is "
                          "off; can go slightly negative for fast local caches."),
    ]),
    ("Answers", [
        ("rcodes", "Distribution of DNS response codes (NOERROR, SERVFAIL, "
                   "NXDOMAIN, ...) with counts."),
        ("queries", "Number of distinct (name, type) pairs probed from the "
                    "pool."),
        ("inconsistent", "Distinct queries that returned more than one different "
                         "answer set during the run."),
        ("answer flaps", "Times a query's answer changed from the previous probe "
                         "— content instability."),
        ("truncated", "Answers with the TC bit set — the response didn't fit "
                      "in the advertised UDP size. A real client would retry "
                      "over TCP; lots of truncation means EDNS trouble or "
                      "middlebox interference."),
        ("canary", "NXDOMAIN-hijack check (--canary-zone): a name that cannot "
                   "exist is asked periodically; the only honest answer is "
                   "NXDOMAIN. HIJACK means the resolver returned an address "
                   "for it (NXDOMAIN rewriting)."),
        ("worst query", "The pool query with the most failed probes — with a "
                        "pool, tells you at a glance *which name* is hurting."),
        ("dscp", "DiffServ code point on the most recent answer packet (top 6 "
                 "bits of the IPv4 TOS / IPv6 Traffic Class byte); standard names "
                 "like CS0 / EF shown when known. '-' if the OS doesn't expose "
                 "it."),
    ]),
    ("ICMP ping (host reachability, independent of DNS)", [
        ("ping", "ICMP state: off = disabled, n/a = no ping binary, UP / DOWN = "
                 "last echo replied or not."),
        ("sent/recv", "ICMP echo requests sent / replies received, on one line."),
        ("ping success", "recv / sent."),
        ("ping loss", "1 - success (packet loss)."),
        ("min/mean/max/last", "ICMP round-trip times on one line (same format as "
                              "DNS latency): fastest / mean / slowest / most "
                              "recent reply."),
        ("rtt jitter", "Smoothed change between consecutive ICMP RTTs."),
        ("ttl min/max", "Smallest / largest TTL (IPv6: hop limit) seen on "
                        "received echoes, on one line."),
        ("ttl most freq", "TTL value seen on the most replies."),
        ("ttl least freq", "TTL value seen on the fewest replies. A TTL that "
                           "shifts or spreads means the route to the host "
                           "changed."),
    ]),
    ("Streaks & errors", [
        ("current", "Current run of consecutive ok or fail probes."),
        ("longest ok", "Longest run of consecutive successful probes."),
        ("longest fail", "Longest run of consecutive failed probes."),
        ("last error", "Text of the most recent error."),
        ("last err qry", "Query that triggered the most recent failure."),
        ("triage", "Verdict of the most recent triage battery, run seconds "
                   "after a timeout: transient-udp-loss, "
                   "udp-blocked-or-rate-limited, recursion-failure, "
                   "auth-domain-failure, fleet-or-domain-outage, or "
                   "server-unresponsive. Full details land in the --log-db "
                   "triage table."),
    ]),
    ("Sparklines (bottom rows)", [
        ("latency ~", "Recent DNS latency as block glyphs; blanks are "
                      "timeouts / gaps."),
        ("ping ~", "Recent ICMP RTT as block glyphs."),
    ]),
]


def _fmt_ms(v: float) -> str:
    if v is None or math.isnan(v):
        return "-"
    if v >= 1000:
        return f"{v / 1000:.2f}s"
    if v >= 100:
        return f"{v:.0f}ms"
    return f"{v:.1f}ms"


def _fmt_ms_c(v: float) -> str:
    """Compact ms (no unit, ``s`` past 1000ms) for packing several into one cell."""
    if v is None or math.isnan(v):
        return "-"
    if v >= 1000:
        return f"{v / 1000:.1f}s"
    if v >= 10:
        return f"{v:.0f}"
    return f"{v:.1f}"


def _mmml(min_v: float, mean_v: float, max_v: float, last_v: float) -> str:
    """Pack min/mean/max/last into one ``a/b/c/d`` cell (compact ms, '-' = none)."""
    return "/".join(_fmt_ms_c(v) for v in (min_v, mean_v, max_v, last_v))


def _fmt_pct(v: float) -> str:
    return "-" if v is None or math.isnan(v) else f"{v * 100:.1f}%"


def _sparkline(samples: list[float], width: int) -> str:
    """Map the last ``width`` latencies to block glyphs; gaps (NaN) -> space."""
    if width <= 0:
        return ""
    tail = samples[-width:]
    vals = [v for v in tail if not math.isnan(v)]
    if not vals:
        return " " * len(tail)
    lo, hi = min(vals), max(vals)
    span = hi - lo or 1.0
    out = []
    for v in tail:
        if math.isnan(v):
            out.append(" ")
        else:
            level = 1 + int((v - lo) / span * (len(_SPARK) - 2))
            out.append(_SPARK[min(level, len(_SPARK) - 1)])
    return "".join(out)


# Each KPI row: (label, value(snapshot)->str, color(snapshot)->pair|0).
def _rows() -> list[tuple[str, Callable[[StatsSnapshot], str], Callable[[StatsSnapshot], int]]]:
    def rcode_str(s: StatsSnapshot) -> str:
        if not s.rcodes:
            return "-"
        return " ".join(
            f"{RCODES.get(k, str(k))}:{v}" for k, v in s.rcodes.most_common()
        )

    def streak_str(s: StatsSnapshot) -> str:
        if s.cur_streak == 0:
            return "-"
        kind = "ok" if s.cur_streak > 0 else "fail"
        return f"{abs(s.cur_streak)} {kind}"

    def av_color(s: StatsSnapshot) -> int:
        if s.sent == 0:
            return _C_DIM
        if s.availability >= 0.999:
            return _C_GOOD
        if s.availability >= 0.99:
            return _C_WARN
        return _C_BAD

    def stab_color(s: StatsSnapshot) -> int:
        return _C_GOOD if s.stability >= 90 else _C_WARN if s.stability >= 70 else _C_BAD

    def _icmp_state(s: StatsSnapshot) -> str:
        if not s.icmp_enabled:
            return "off"
        if s.icmp_unavailable:
            return "n/a"
        if not s.icmp_sent:
            return "..."
        return "UP" if s.icmp_up else "DOWN"

    def _icmp_success(s: StatsSnapshot) -> str:
        if not s.icmp_enabled or not s.icmp_sent:
            return "-"
        return _fmt_pct(s.icmp_success)

    def _fmt_dscp(v) -> str:
        if v is None:
            return "-"
        name = _DSCP_NAMES.get(v)
        return f"{v} ({name})" if name else str(v)

    def _fmt_ttl(v) -> str:
        return "-" if v is None else str(v)

    def _ttl_row(get):
        return lambda s: _fmt_ttl(get(s)) if s.icmp_enabled and s.icmp_recv else "-"

    def _ttl_pair(s):
        if not (s.icmp_enabled and s.icmp_recv):
            return "-"
        return f"{_fmt_ttl(s.icmp_ttl_min)}/{_fmt_ttl(s.icmp_ttl_max)}"

    none = lambda s: 0
    return [
        ("state", lambda s: "UP" if s.up else "DOWN" if s.sent else "...",
         lambda s: _C_GOOD if s.up else _C_BAD if s.sent else _C_DIM),
        ("current qry", lambda s: s.last_query or "-", lambda s: _C_HEAD if s.last_query else _C_DIM),
        ("stability", lambda s: f"{s.stability:.0f}/100", stab_color),
        ("sent/answered", lambda s: f"{s.sent}/{s.answered}", none),
        ("availability", lambda s: _fmt_pct(s.availability), av_color),
        ("recent avail", lambda s: _fmt_pct(s.recent_availability), av_color),
        ("timeouts", lambda s: f"{s.timeouts} ({_fmt_pct(s.timeout_rate)})",
         lambda s: _C_BAD if s.timeout_rate > 0 else 0),
        ("net errors", lambda s: f"{s.errors} ({_fmt_pct(s.error_rate)})",
         lambda s: _C_BAD if s.errors else 0),
        ("raw pkt loss", lambda s: f"{s.raw_lost + s.timeouts} ({_fmt_pct(s.raw_loss_rate)})",
         lambda s: _C_BAD if s.raw_loss_rate > 0.02 else _C_WARN if s.raw_loss_rate > 0 else 0),
        ("retry saves", lambda s: str(s.recovered),
         lambda s: _C_WARN if s.recovered else 0),
        ("late answers",
         lambda s: f"{s.late_answers} (last {_fmt_ms(s.last_late_ms)})" if s.late_answers else "0",
         lambda s: _C_WARN if s.late_answers else 0),
        ("eff. qps", lambda s: f"{s.effective_qps:.2f}", none),
        ("─ latency ─", lambda s: "", lambda s: _C_DIM),
        ("min/mean/max/last",
         lambda s: _mmml(s.min_ms, s.mean_ms, s.max_ms, s.last_ms), none),
        ("p50", lambda s: _fmt_ms(s.p50_ms), none),
        ("p90", lambda s: _fmt_ms(s.p90_ms), none),
        ("p95", lambda s: _fmt_ms(s.p95_ms), none),
        ("p99", lambda s: _fmt_ms(s.p99_ms), none),
        ("std dev", lambda s: _fmt_ms(s.stdev_ms), none),
        ("jitter", lambda s: _fmt_ms(s.jitter_ms),
         lambda s: _C_WARN if s.jitter_ms > 20 else 0),
        ("ewma", lambda s: _fmt_ms(s.ewma_ms), none),
        ("cv", lambda s: f"{s.cv:.2f}", lambda s: _C_WARN if s.cv > 0.5 else 0),
        ("recursion ovh", lambda s: _fmt_ms(s.recursion_overhead_ms), none),
        ("─ answers ─", lambda s: "", lambda s: _C_DIM),
        ("rcodes", rcode_str,
         lambda s: _C_BAD if any(k != 0 for k in s.rcodes) else 0),
        ("queries", lambda s: str(s.unique_queries), none),
        ("inconsistent", lambda s: str(s.inconsistent_queries),
         lambda s: _C_WARN if s.inconsistent_queries else 0),
        ("answer flaps", lambda s: str(s.answer_flaps),
         lambda s: _C_WARN if s.answer_flaps else 0),
        ("truncated", lambda s: str(s.tc_answers),
         lambda s: _C_WARN if s.tc_answers else 0),
        ("canary",
         lambda s: (f"{s.canary_hijacks} HIJACK/{s.canary_sent}" if s.canary_hijacks
                    else f"{s.canary_last or '...'} ({s.canary_sent})") if s.canary_sent else "-",
         lambda s: _C_BAD if s.canary_hijacks else _C_DIM if not s.canary_sent else 0),
        ("worst query", lambda s: s.worst_query or "-",
         lambda s: _C_WARN if s.worst_query else _C_DIM),
        ("dscp", lambda s: _fmt_dscp(s.dns_dscp_last), none),
        ("─ icmp ─", lambda s: "", lambda s: _C_DIM),
        ("ping", _icmp_state,
         lambda s: 0 if not s.icmp_enabled or s.icmp_unavailable
         else _C_GOOD if s.icmp_up else _C_BAD if s.icmp_sent else _C_DIM),
        ("sent/recv",
         lambda s: f"{s.icmp_sent}/{s.icmp_recv}" if s.icmp_enabled else "-", none),
        ("ping success", _icmp_success,
         lambda s: 0 if not s.icmp_enabled or not s.icmp_sent
         else _C_GOOD if s.icmp_success >= 0.999
         else _C_WARN if s.icmp_success >= 0.99 else _C_BAD),
        ("ping loss", lambda s: _fmt_pct(s.icmp_loss) if s.icmp_enabled and s.icmp_sent else "-",
         lambda s: _C_BAD if s.icmp_enabled and s.icmp_loss > 0 else 0),
        ("min/mean/max/last",
         lambda s: _mmml(s.icmp_min_ms, s.icmp_mean_ms, s.icmp_max_ms, s.icmp_last_ms)
         if s.icmp_enabled else "-", none),
        ("rtt jitter", lambda s: _fmt_ms(s.icmp_jitter_ms) if s.icmp_enabled else "-",
         lambda s: _C_WARN if s.icmp_enabled and s.icmp_jitter_ms > 20 else 0),
        ("ttl min/max", _ttl_pair, none),
        ("ttl most freq", _ttl_row(lambda s: s.icmp_ttl_mode), none),
        ("ttl least freq", _ttl_row(lambda s: s.icmp_ttl_least), none),
        ("─ streaks ─", lambda s: "", lambda s: _C_DIM),
        ("current", streak_str, lambda s: 0 if s.cur_streak >= 0 else _C_BAD),
        ("longest ok", lambda s: str(s.longest_ok), none),
        ("longest fail", lambda s: str(s.longest_fail),
         lambda s: _C_WARN if s.longest_fail else 0),
        ("last error", lambda s: s.last_error or "-",
         lambda s: _C_BAD if s.last_error else 0),
        ("last err qry", lambda s: s.last_error_query or "-",
         lambda s: _C_BAD if s.last_error_query else _C_DIM),
        ("triage", lambda s: s.last_triage or "-",
         lambda s: (_C_DIM if not s.last_triage
                    else _C_WARN if s.last_triage == "transient-udp-loss" else _C_BAD)),
    ]


def _safe_add(win, y: int, x: int, text: str, attr: int = 0) -> None:
    """addstr that silently clips at the screen edge (curses raises otherwise)."""
    maxy, maxx = win.getmaxyx()
    if y < 0 or y >= maxy or x >= maxx:
        return
    win.addnstr(y, x, text, max(0, maxx - x - 1), attr)


def _help_lines(width: int) -> list[tuple[str, str, str]]:
    """Flatten the help content into ``(kind, label, text)`` lines for ``width``.

    ``kind`` selects how a line is drawn: ``head`` (section title), ``entry``
    (label + first wrapped line of its explanation), ``cont`` (wrapped
    continuation), ``dim`` (intro / blank). Wrapping is done here so the renderer
    just slices the list for scrolling.
    """
    label_w = 18
    out: list[tuple[str, str, str]] = []
    for chunk in textwrap.wrap(_HELP_INTRO, max(20, width - 2)) or [""]:
        out.append(("dim", "", chunk))
    out.append(("dim", "", ""))
    body_w = max(20, width - 2 - label_w)
    for title, entries in _HELP:
        out.append(("head", "", title))
        for label, desc in entries:
            wrapped = textwrap.wrap(desc, body_w) or [""]
            out.append(("entry", label, wrapped[0]))
            for cont in wrapped[1:]:
                out.append(("cont", "", cont))
        out.append(("dim", "", ""))
    return out


def _draw_help(win, scroll: int) -> int:
    """Render the scrollable help overlay; return the (clamped) scroll offset."""
    win.erase()
    maxy, maxx = win.getmaxyx()
    label_w = 18
    _safe_add(win, 0, 0, " Measured variables — help".ljust(maxx - 1),
              curses.color_pair(_C_HEAD) | curses.A_BOLD)

    lines = _help_lines(maxx)
    page = max(1, maxy - 3)  # rows between the title and the footer
    max_scroll = max(0, len(lines) - page)
    scroll = max(0, min(scroll, max_scroll))

    for i, (kind, label, text) in enumerate(lines[scroll : scroll + page]):
        y = 2 + i
        if kind == "head":
            _safe_add(win, y, 0, text, curses.color_pair(_C_WARN) | curses.A_BOLD)
        elif kind == "entry":
            _safe_add(win, y, 0, label.ljust(label_w),
                      curses.color_pair(_C_HEAD) | curses.A_BOLD)
            _safe_add(win, y, label_w, text)
        elif kind == "cont":
            _safe_add(win, y, label_w, text)
        else:
            _safe_add(win, y, 0, text, curses.color_pair(_C_DIM))

    more = "  (↑/↓ scroll)" if max_scroll else ""
    footer = f" [h/?/q/Esc] back{more}"
    _safe_add(win, maxy - 1, 0, footer.ljust(maxx - 1), curses.color_pair(_C_DIM))
    win.noutrefresh()
    curses.doupdate()
    return scroll


def _draw(
    win,
    snaps: list[StatsSnapshot],
    cfg: PollConfig,
    started: float,
    paused: bool,
    net_note: str | None = None,
) -> None:
    win.erase()
    maxy, maxx = win.getmaxyx()
    rows = _rows()
    label_w = 18  # widest label is the "min/mean/max/last" combined rows

    elapsed = time.monotonic() - started
    hh, rem = divmod(int(elapsed), 3600)
    mm, ss = divmod(rem, 60)
    pool = cfg.queries or [(cfg.qname, cfg.qtype)]
    if len(pool) == 1:
        query_desc = f"{pool[0][0]} {pool[0][1]}"
    else:
        query_desc = f"pool of {len(pool)} ({cfg.pool_order})"
    header = (
        f" DNS quality poller   query: {query_desc} ({cfg.qname_strategy})"
        f"   every {cfg.interval:g}s   elapsed {hh:02d}:{mm:02d}:{ss:02d}"
    )
    _safe_add(win, 0, 0, header.ljust(maxx - 1), curses.color_pair(_C_HEAD) | curses.A_BOLD)
    hint = " [q]uit  [r]eset  [space]pause  [h]elp" + ("   *PAUSED*" if paused else "")
    _safe_add(win, 1, 0, hint, curses.color_pair(_C_DIM))
    if net_note:
        _safe_add(win, 2, 0, f" ⏸ {net_note}"[: maxx - 1],
                  curses.color_pair(_C_BAD) | curses.A_BOLD)

    # Column width sized to fit all servers; clamp so labels stay readable.
    n = len(snaps)
    avail = maxx - label_w - 1
    col_w = max(12, min(22, avail // n if n else avail))

    def colx(i: int) -> int:
        return label_w + i * col_w

    top = 3
    # Server header row.
    _safe_add(win, top, 0, "server".ljust(label_w), curses.A_BOLD | curses.A_UNDERLINE)
    for i, s in enumerate(snaps):
        name = f"{s.host}:{s.port}" if s.port != 53 else s.host
        _safe_add(win, top, colx(i), name.ljust(col_w - 1)[: col_w - 1],
                  curses.A_BOLD | curses.A_UNDERLINE | curses.color_pair(_C_HEAD))

    # KPI rows.
    for r, (label, value, color) in enumerate(rows):
        y = top + 1 + r
        if y >= maxy - 2:
            break
        is_sep = label.startswith("─")
        _safe_add(win, y, 0, label.ljust(label_w),
                  curses.color_pair(_C_DIM) if is_sep else curses.A_BOLD)
        if is_sep:
            for i in range(n):
                _safe_add(win, y, colx(i), "─" * (col_w - 1), curses.color_pair(_C_DIM))
            continue
        for i, s in enumerate(snaps):
            pair = color(s)
            attr = curses.color_pair(pair) if pair else 0
            _safe_add(win, y, colx(i), value(s)[: col_w - 1], attr)

    # Sparkline rows at the bottom: DNS latency, then ICMP RTT.
    spark_y = min(top + 1 + len(rows) + 1, maxy - 2)
    if spark_y < maxy:
        _safe_add(win, spark_y, 0, "latency ~".ljust(label_w), curses.A_BOLD)
        for i, s in enumerate(snaps):
            _safe_add(win, spark_y, colx(i), _sparkline(s.recent_ms, col_w - 1),
                      curses.color_pair(_C_GOOD if s.up else _C_BAD))
    ping_y = spark_y + 1
    if ping_y < maxy and any(s.icmp_enabled for s in snaps):
        _safe_add(win, ping_y, 0, "ping ~".ljust(label_w), curses.A_BOLD)
        for i, s in enumerate(snaps):
            if s.icmp_enabled:
                _safe_add(win, ping_y, colx(i), _sparkline(s.icmp_recent_ms, col_w - 1),
                          curses.color_pair(_C_GOOD if s.icmp_up else _C_BAD))

    win.noutrefresh()
    curses.doupdate()


def _run(win, mgr: PollManager, cfg: PollConfig, refresh: float) -> None:
    curses.curs_set(0)
    win.nodelay(True)
    if curses.has_colors():
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(_C_HEAD, curses.COLOR_CYAN, -1)
        curses.init_pair(_C_GOOD, curses.COLOR_GREEN, -1)
        curses.init_pair(_C_WARN, curses.COLOR_YELLOW, -1)
        curses.init_pair(_C_BAD, curses.COLOR_RED, -1)
        curses.init_pair(_C_DIM, curses.COLOR_WHITE, -1)

    started = time.monotonic()
    paused = False
    help_mode = False
    help_scroll = 0
    while True:
        ch = win.getch()

        net_note = (
            None if mgr.net_up.is_set()
            else f"NETWORK DOWN — gateway {mgr.gateway} unreachable; polling paused"
        )

        if help_mode:
            # In the help overlay keys scroll or dismiss; polling continues.
            if ch in (ord("q"), ord("Q"), 27, ord("h"), ord("H"), ord("?")):
                help_mode = False
                _draw(win, mgr.snapshots(), cfg, started, paused, net_note)
            else:
                if ch in (curses.KEY_DOWN, ord("j")):
                    help_scroll += 1
                elif ch in (curses.KEY_UP, ord("k")):
                    help_scroll -= 1
                elif ch in (curses.KEY_NPAGE, ord(" ")):
                    help_scroll += 10
                elif ch == curses.KEY_PPAGE:
                    help_scroll -= 10
                elif ch in (curses.KEY_HOME, ord("g")):
                    help_scroll = 0
                elif ch == curses.KEY_END:
                    help_scroll = 1 << 30
                if ch != -1:  # redraw only on input to avoid flicker
                    help_scroll = _draw_help(win, help_scroll)
            time.sleep(refresh)
            continue

        if ch in (ord("q"), ord("Q"), 27):  # q / Esc
            return
        if ch in (ord("h"), ord("H"), ord("?")):
            help_mode = True
            help_scroll = _draw_help(win, 0)
            time.sleep(refresh)
            continue
        if ch in (ord("r"), ord("R")):
            mgr.reset()
            started = time.monotonic()
        elif ch == ord(" "):
            paused = not paused
        if not paused:
            _draw(win, mgr.snapshots(), cfg, started, paused, net_note)
        elif ch != -1:
            _draw(win, mgr.snapshots(), cfg, started, paused, net_note)
        time.sleep(refresh)


def run_dashboard(cfg: PollConfig, refresh: float = 0.5) -> str | None:
    """Start the pollers and run the curses dashboard until the user quits.

    Returns a warning string (e.g. an event-log failure) to print once the
    screen is restored, or ``None``.
    """
    mgr = PollManager(cfg)
    mgr.start()
    try:
        curses.wrapper(_run, mgr, cfg, refresh)
    finally:
        mgr.stop()
    warnings = [w for w in (mgr.log_error, mgr.gateway_error) if w]
    return "\n".join(warnings) or None
