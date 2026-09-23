"""Streamlit dashboard for a dnstester failure-log database.

The poller's ``--log-db`` sink writes two tables (see :mod:`dnstester.dblog`):

``events``
    one row per probe failure (a timeout or socket error), stamped with the
    triggering server and the failing query.
``server_status``
    the whole fleet's last-known state captured at the instant of each failure
    — so every event carries a snapshot of what *all* the resolvers were doing.

That second table is what makes the log worth more than a bare failure count:
a failure on one resolver while the others stay green points at that resolver;
failures across the board point at the network or the client. This dashboard
surfaces both — the headline failure counts and the fleet-wide context.

Run it with::

    streamlit run dashboard.py
    streamlit run dashboard.py -- --db /path/to/dns-failures.db

(Streamlit forwards everything after ``--`` to the script.) Streamlit and
pandas are core dependencies, so ``uv sync`` (or ``pip install -e .``) pulls
them in.
"""

from __future__ import annotations

import argparse
import os
import sqlite3

from datetime import datetime

import altair as alt
import pandas as pd
import streamlit as st

# The log stores timestamps as UTC epoch seconds; the dashboard shows everything
# in the machine's local time. tz_localize(None) drops the offset afterwards so
# the values are naive local wall-clock — which Altair/Vega render as-is (no
# further browser-side shifting) and pandas formats directly in captions.
LOCAL_TZ = datetime.now().astimezone().tzinfo


def to_local(ts_seconds: pd.Series) -> pd.Series:
    """UTC epoch seconds -> naive local-time datetimes."""
    return (
        pd.to_datetime(ts_seconds, unit="s", utc=True)
        .dt.tz_convert(LOCAL_TZ)
        .dt.tz_localize(None)
    )

# The latency-over-time chart can carry one point per server per failure event —
# well past Altair's default 5k-row guard — so lift it for this local dashboard.
alt.data_transformers.disable_max_rows()

DEFAULT_DB = "dns-failures.db"


def _db_path() -> str:
    """Resolve the database path from ``-- --db PATH`` or the default."""
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--db", default=DEFAULT_DB)
    args, _ = parser.parse_known_args()
    return args.db


# Only the columns the dashboard actually reads — selecting these instead of
# ``SELECT *`` roughly halves the server_status read and quartereds the samples
# read on a large log (the tables carry ~20 columns each, most unused here).
# TTL columns are optional: older logs predate them, so we intersect with what
# the table actually has at query time.
_EVENT_COLS = ["id", "ts", "trigger_server", "trigger_kind", "trigger_detail"]
_STATUS_COLS = [
    "event_id", "server", "up", "availability", "p95_ms", "last_ms",
    "icmp_enabled", "icmp_up", "icmp_success", "icmp_last_ms",
    "icmp_ttl_min", "icmp_ttl_max", "icmp_ttl_mode", "icmp_ttl_least",
]
_SAMPLE_COLS = ["ts", "server", "p95_ms", "last_ms"]
_TRIAGE_COLS = [
    "ts", "server", "query", "retry_ok", "retry_ms", "tcp_ok", "tcp_ms",
    "cached_ok", "cached_ms", "cached_query", "ref_server", "ref_ok", "verdict",
]
_QSTATS_COLS = [
    "ts", "server", "query", "sent", "answered", "failed",
    "mean_ms", "last_ttl", "last_answer",
]

# Cache-reload granularity in seconds: the log's mtime is bucketed to this so a
# continuously-written log doesn't force a full reload on every Streamlit rerun.
_RELOAD_BUCKET_S = 5.0

# Max points *per server* in the latency-over-time chart. Altair embeds the data
# inline in the Vega spec, so an un-thinned multi-hour trace ships megabytes of
# JSON to the browser and renders sluggishly. Above this we time-bucket each
# server's series; below it (e.g. after narrowing the time slider) the raw
# samples pass through untouched, so zooming in restores full resolution.
_LATENCY_MAX_POINTS = 400


def downsample_series(long: pd.DataFrame, max_points: int = _LATENCY_MAX_POINTS) -> pd.DataFrame:
    """Thin a ``time``/``server``/``value`` long frame to ~``max_points`` per server.

    Each server's series is resampled into equal time buckets (median per bucket,
    which is robust to outliers) only when it exceeds ``max_points``; smaller
    series are returned as-is so short windows keep every sample. Empty buckets
    are dropped so gaps in the data stay gaps rather than becoming zero-rows.
    """
    if long.empty or long.groupby("server").size().max() <= max_points:
        return long
    span = (long["time"].max() - long["time"].min()).total_seconds()
    bucket = pd.to_timedelta(max(span / max_points, 1.0), unit="s")
    return (
        long.set_index("time")
        .groupby("server")
        .resample(bucket)["value"]
        .median()
        .reset_index()
        .dropna(subset=["value"])
    )


def _existing_cols(conn: sqlite3.Connection, table: str, wanted: list[str]) -> list[str]:
    """Return the subset of ``wanted`` that ``table`` actually has, in order.

    Empty when the table is absent (``PRAGMA table_info`` yields nothing), which
    lets callers treat a missing table the same as one with no usable columns.
    """
    have = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
    return [c for c in wanted if c in have]


@st.cache_data(show_spinner=False)
def load_tables(
    path: str, mtime: float
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Read the log tables into DataFrames:
    (events, server_status, samples, triage, query_stats).

    ``mtime`` is a cache-key only (not used in the body): the caller passes the
    log's modification time bucketed to ``_RELOAD_BUCKET_S`` so the cache
    invalidates when the file changes, but at most once per bucket rather than on
    every individual append. The ``samples`` table is the periodic KPI trace
    (poll --sample-interval); it may be absent on older logs, in which case an
    empty frame is returned.

    Reads only the columns rendered below rather than ``SELECT *``, and skips the
    ``ORDER BY`` (downstream sorts/filters in pandas and Altair) — both noticeably
    cut load time on large logs, which matters because this re-runs every time
    the poller appends to the file.
    """
    del mtime  # cache-key only
    # Read-only URI so we never touch the log being analysed.
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        ev_cols = _existing_cols(conn, "events", _EVENT_COLS)
        events = pd.read_sql_query(f"SELECT {', '.join(ev_cols)} FROM events", conn)
        st_cols = _existing_cols(conn, "server_status", _STATUS_COLS)
        status = pd.read_sql_query(f"SELECT {', '.join(st_cols)} FROM server_status", conn)
        sa_cols = _existing_cols(conn, "samples", _SAMPLE_COLS)
        samples = (
            pd.read_sql_query(f"SELECT {', '.join(sa_cols)} FROM samples", conn)
            if sa_cols else pd.DataFrame()  # table absent on pre-sampling logs
        )
        tr_cols = _existing_cols(conn, "triage", _TRIAGE_COLS)
        triage = (
            pd.read_sql_query(f"SELECT {', '.join(tr_cols)} FROM triage", conn)
            if tr_cols else pd.DataFrame()  # table absent on older logs
        )
        qs_cols = _existing_cols(conn, "query_stats", _QSTATS_COLS)
        qstats = (
            pd.read_sql_query(f"SELECT {', '.join(qs_cols)} FROM query_stats", conn)
            if qs_cols else pd.DataFrame()
        )
    finally:
        conn.close()

    if not events.empty:
        # ``ts`` is unix epoch seconds (UTC); show it in local time.
        events["time"] = to_local(events["ts"])
    if not samples.empty:
        samples["time"] = to_local(samples["ts"])
    if not triage.empty:
        triage["time"] = to_local(triage["ts"])
    if not qstats.empty:
        qstats["time"] = to_local(qstats["ts"])
    return events, status, samples, triage, qstats


def toggle_bar(
    wide: pd.DataFrame,
    *,
    cat_type: str,
    value_title: str,
    cat_title: str | None = None,
    horizontal: bool = False,
    stack: bool = False,
    height: int = 300,
) -> alt.Chart:
    """Build a multi-series bar chart whose legend toggles series visibility.

    ``wide`` is index = category (x for vertical, y for horizontal), columns =
    series. Clicking a series' legend swatch filters that dataset out (so a
    stacked chart re-stacks to close the gap) and clicking again restores it —
    an interaction Streamlit's native charts don't offer, so these go through
    Altair.
    """
    cat = wide.index.name or "category"
    long = wide.reset_index().melt(id_vars=cat, var_name="series", value_name="value")
    domain = list(wide.columns)  # pin the colour scale so the legend keeps every

    # empty=False so that with nothing clicked the selection matches nothing and
    # `~picked` lets every row through; clicking a legend entry adds that series
    # to the selection, and the `~picked` filter then drops its rows. The colour
    # scale's explicit `domain` keeps the filtered-out series in the legend, so
    # it stays clickable to bring the dataset back.
    #
    # toggle="true" (the Vega expression, not the bool True) makes *every* plain
    # click flip membership; the bool default maps to "event.shiftKey", where a
    # plain click only ever re-selects the same item and never clears it.
    picked = alt.selection_point(
        fields=["series"], bind="legend", toggle="true", empty=False
    )

    cat_enc = alt.X if not horizontal else alt.Y
    val_enc = alt.Y if not horizontal else alt.X
    enc = {
        cat_enc.__name__.lower(): cat_enc(f"{cat}:{cat_type}", title=cat_title),
        val_enc.__name__.lower(): val_enc(
            "value:Q", title=value_title, stack="zero" if stack else None
        ),
        "color": alt.Color("series:N", title=None, scale=alt.Scale(domain=domain)),
        "tooltip": [cat, "series", alt.Tooltip("value:Q", format=".2f", title=value_title)],
    }
    if not stack:  # group the bars side-by-side rather than overlapping them
        if horizontal:
            enc["yOffset"] = alt.YOffset("series:N")
        else:
            enc["xOffset"] = alt.XOffset("series:N")

    return (
        alt.Chart(long)
        .mark_bar()
        .encode(**enc)
        .transform_filter(~picked)
        .add_params(picked)
        .properties(height=height)
    )


def latency_lines(long: pd.DataFrame, value_title: str, height: int = 340) -> alt.Chart:
    """Line+point chart of one metric per server over time, legend-toggleable.

    ``long`` columns: ``time`` (datetime), ``server``, ``value``. Clicking a
    server in the legend hides its line (click again to restore). Unlike the bar
    charts this drives visibility through an *opacity* rule rather than a data
    filter: a filter can't coexist with the scales-bound zoom from
    ``.interactive()`` (the two selections clash), whereas opacity does, and it
    keeps the y-axis steady when a line is hidden instead of rescaling.
    """
    domain = sorted(long["server"].unique())
    picked = alt.selection_point(fields=["server"], bind="legend", toggle="true", empty=False)
    # empty=False: with nothing clicked the predicate matches nothing, so every
    # line takes the `.otherwise` (visible) branch; clicking a legend entry adds
    # that server to the selection, flipping just its line to opacity 0.
    opacity = alt.when(picked).then(alt.value(0.0)).otherwise(alt.value(0.85))
    return (
        alt.Chart(long)
        .mark_line(point=alt.OverlayMarkDef(size=18, filled=True), strokeWidth=1.4)
        .encode(
            x=alt.X("time:T", title=None),
            y=alt.Y("value:Q", title=value_title),
            color=alt.Color("server:N", title=None, scale=alt.Scale(domain=domain)),
            opacity=opacity,
            tooltip=[
                alt.Tooltip("time:T", title="time", format="%Y-%m-%d %H:%M:%S"),
                "server",
                alt.Tooltip("value:Q", title=value_title, format=".1f"),
            ],
        )
        .add_params(picked)
        .properties(height=height)
        .interactive()  # scroll/drag to zoom and pan the time axis
    )


def main() -> None:
    st.set_page_config(page_title="DNS Failure Dashboard", page_icon="📡", layout="wide")
    st.title("📡 DNS Failure-Log Dashboard")

    path = st.sidebar.text_input("Database path", value=_db_path())
    if not os.path.exists(path):
        st.error(f"Database not found: `{path}`")
        st.stop()

    # Quantise the file mtime that keys the cache: while the poller is actively
    # appending, mtime changes on every write, which would otherwise reload the
    # whole log on every rerun. Bucketing to _RELOAD_BUCKET_S caps reloads to at
    # most one per bucket — a few seconds of staleness for far less re-reading.
    cache_key = os.path.getmtime(path) // _RELOAD_BUCKET_S
    events, status, samples, triage, qstats = load_tables(path, cache_key)
    # net-down / net-up rows are watchdog markers ("the box's own network was
    # out, polling paused"), not resolver failures — keep them out of every
    # failure statistic but surface the outage windows separately.
    if not events.empty:
        is_net = events["trigger_kind"].str.startswith("net-")
        net_events = events[is_net]
        events = events[~is_net]
    else:
        net_events = events
    if events.empty:
        st.warning("No failure events logged yet — the database is empty.")
        st.stop()

    servers = sorted(status["server"].unique())

    # --- sidebar filters -----------------------------------------------------
    st.sidebar.header("Filters")
    chosen = st.sidebar.multiselect(
        "Triggering server", servers, default=servers,
        help="Limit the view to failures triggered by these resolvers.",
    )
    tmin = events["time"].min().to_pydatetime()
    tmax = events["time"].max().to_pydatetime()
    if tmin < tmax:
        start, end = st.sidebar.slider(
            "Time range", min_value=tmin, max_value=tmax, value=(tmin, tmax),
            format="HH:mm",
        )
    else:
        start, end = tmin, tmax

    fev = events[
        events["trigger_server"].isin(chosen)
        & events["time"].between(pd.Timestamp(start), pd.Timestamp(end))
    ]
    if fev.empty:
        st.warning("No events match the current filters.")
        st.stop()
    fstatus = status[status["event_id"].isin(fev["id"])]

    # --- headline metrics ----------------------------------------------------
    span = fev["time"].max() - fev["time"].min()
    minutes = max(span.total_seconds() / 60, 1)
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Failure events", f"{len(fev):,}")
    c2.metric("Resolvers monitored", len(servers))
    c3.metric("Distinct failing queries", fev["trigger_detail"].nunique())
    c4.metric("Failures / min", f"{len(fev) / minutes:.1f}")
    st.caption(
        f"Window: {fev['time'].min():%Y-%m-%d %H:%M} → {fev['time'].max():%Y-%m-%d %H:%M} local "
        f"({span})"
    )
    if not net_events.empty:
        pauses = net_events[net_events["trigger_kind"] == "net-down"]
        st.info(
            f"⏸ {len(pauses)} local-network outage(s) detected during this log "
            "(default gateway unreachable). Polling was paused, so those windows "
            "contain no probe data and are excluded from the failure statistics. "
            "Details in the raw events under trigger_kind net-down / net-up."
        )

    # --- failures over time --------------------------------------------------
    st.subheader("Failures over time")
    freq = st.radio(
        "Bucket", ["1min", "5min", "15min", "1h"], index=1, horizontal=True,
        label_visibility="collapsed",
    )
    by_time = (
        fev.set_index("time")
        .groupby([pd.Grouper(freq=freq), "trigger_server"])
        .size()
        .unstack(fill_value=0)
    )
    st.caption("Tip: click a resolver in the legend to hide it; click again to bring it back.")
    st.altair_chart(
        toggle_bar(
            by_time, cat_type="T", value_title="failures",
            cat_title=None, stack=True, height=320,
        ),
        use_container_width=True,
    )

    # --- time-of-day pattern ---------------------------------------------------
    st.subheader("When do failures happen? (hour × resolver)")
    st.caption(
        "Failures bucketed by local hour of day. A band across every resolver "
        "at the same hours points at congestion or the network; a band on one "
        "resolver is that resolver's own problem."
    )
    heat = (
        fev.assign(hour=fev["time"].dt.hour)
        .groupby(["hour", "trigger_server"])
        .size()
        .reset_index(name="failures")
    )
    st.altair_chart(
        alt.Chart(heat)
        .mark_rect()
        .encode(
            x=alt.X("hour:O", title="hour of day (local)"),
            y=alt.Y("trigger_server:N", title=None),
            color=alt.Color("failures:Q", scale=alt.Scale(scheme="reds"), title="failures"),
            tooltip=["hour", "trigger_server", "failures"],
        )
        .properties(height=max(120, 24 * heat["trigger_server"].nunique())),
        use_container_width=True,
    )

    # --- latency over time ---------------------------------------------------
    # Prefer the periodic 'samples' trace (evenly spaced, every server always
    # present); fall back to failure-moment snapshots for pre-sampling logs.
    st.subheader("Latency per server over time")
    use_samples = not samples.empty
    if use_samples:
        st.caption(
            "Continuous trace from the periodic KPI sampler (`poll "
            "--sample-interval`). Click a server in the legend to toggle it; "
            "scroll/drag to zoom."
        )
    else:
        st.caption(
            "Sampled at every failure event (no periodic `samples` table in this "
            "log — run the poller with `--sample-interval` for a continuous "
            "trace). Click a server in the legend to toggle it; scroll/drag to zoom."
        )
    metric = st.radio(
        "Latency metric", ["p95_ms", "last_ms"], index=0, horizontal=True,
        format_func=lambda m: {"p95_ms": "p95 (recent window)", "last_ms": "last probe RTT"}[m],
        label_visibility="collapsed",
    )
    if use_samples:
        lat = samples[
            samples["server"].isin(chosen)
            & samples["time"].between(pd.Timestamp(start), pd.Timestamp(end))
        ][["time", "server", metric]]
    else:
        lat = (
            fstatus.merge(fev[["id", "time"]], left_on="event_id", right_on="id")
            [["time", "server", metric]]
        )
    lat = lat.rename(columns={metric: "value"}).dropna(subset=["value"])
    if lat.empty:
        st.info("No latency samples for the current filters.")
    else:
        raw_points = len(lat)
        lat = downsample_series(lat)
        st.altair_chart(
            latency_lines(lat, value_title=f"{metric.replace('_ms', '')} latency (ms)"),
            use_container_width=True,
        )
        if len(lat) < raw_points:
            st.caption(
                f"Showing {len(lat):,} of {raw_points:,} samples (time-bucketed "
                "median per server for responsiveness — narrow the time range to "
                "see every sample)."
            )

    # --- per-server breakdowns ----------------------------------------------
    left, right = st.columns(2)
    with left:
        st.subheader("Failures by triggering resolver")
        by_server = fev["trigger_server"].value_counts()
        st.bar_chart(by_server, height=300, horizontal=True)
    with right:
        st.subheader("Most-failed queries")
        top_q = fev["trigger_detail"].value_counts().head(15)
        st.bar_chart(top_q, height=300, horizontal=True)

    # --- isolated vs. fleet-wide --------------------------------------------
    st.subheader("Was each failure isolated or fleet-wide?")
    st.caption(
        "For every failure we recorded how many resolvers were up at that instant. "
        "Most resolvers up → an isolated hiccup on one server; many down → a "
        "network- or client-side problem hitting the whole fleet."
    )
    fleet = (
        fstatus.groupby("event_id")
        .agg(up=("up", "sum"), total=("up", "size"))
        .assign(label=lambda d: d["up"].astype(str) + " / " + d["total"].astype(str) + " up")
    )
    fleet["down"] = fleet["total"] - fleet["up"]
    fleet["class"] = "partial"
    fleet.loc[fleet["down"] <= 1, "class"] = "isolated"
    fleet.loc[fleet["down"] >= fleet["total"], "class"] = "fleet-wide"
    k1, k2, k3 = st.columns(3)
    k1.metric("Isolated (1 resolver down)", f"{(fleet['class'] == 'isolated').sum():,}")
    k2.metric("Partial (some down)", f"{(fleet['class'] == 'partial').sum():,}")
    k3.metric("Fleet-wide (all down)", f"{(fleet['class'] == 'fleet-wide').sum():,}")
    dist = fleet["label"].value_counts().sort_index()
    st.bar_chart(dist, height=260)

    # --- triage verdicts -------------------------------------------------------
    st.subheader("Triage verdicts — what each failure actually was")
    if triage.empty:
        st.info(
            "No triage batteries in this log. The poller runs them automatically "
            "on timeouts (rate-limited per server) unless `--no-triage` was set; "
            "older logs predate the feature."
        )
    else:
        ftr = triage[
            triage["server"].isin(chosen)
            & triage["time"].between(pd.Timestamp(start), pd.Timestamp(end))
        ]
        if ftr.empty:
            st.info("No triage batteries match the current filters.")
        else:
            st.caption(
                "Seconds after a probe exhausted its retries, the server was "
                "cross-checked: a fresh UDP retry, the same query over TCP, a "
                "should-be-cached name, and the query at a healthy reference "
                "server. **transient-udp-loss** = a stochastic drop; "
                "**udp-blocked-or-rate-limited** = TCP answered while UDP stayed "
                "dead (policer); **recursion-failure** = cached names fine, this "
                "query stuck; **auth-domain-failure** = no resolver could answer "
                "it; **server-unresponsive** = everything at that box failed."
            )
            wide = ftr.groupby(["server", "verdict"]).size().unstack(fill_value=0)
            wide.index.name = "server"
            st.altair_chart(
                toggle_bar(
                    wide, cat_type="N", value_title="batteries",
                    horizontal=True, stack=True, height=max(160, 34 * len(wide)),
                ),
                use_container_width=True,
            )
            with st.expander(f"Raw triage batteries ({len(ftr):,})"):
                cols = [c for c in (
                    "time", "server", "query", "verdict", "retry_ok", "tcp_ok",
                    "cached_ok", "cached_query", "ref_server", "ref_ok",
                ) if c in ftr.columns]
                raw_tr = ftr[cols].sort_values("time", ascending=False).copy()
                raw_tr["time"] = raw_tr["time"].dt.strftime("%Y-%m-%d %H:%M:%S")
                st.dataframe(raw_tr, use_container_width=True, hide_index=True)

    # --- per-query failure rates ----------------------------------------------
    st.subheader("Failure rate by (resolver, query)")
    if qstats.empty:
        st.info(
            "No `query_stats` in this log — the poller writes them about once a "
            "minute when `--log-db` is on (newer builds only)."
        )
    else:
        # The counters are cumulative: the latest row per (server, query) is the
        # whole run's tally.
        latest = (
            qstats.sort_values("ts").groupby(["server", "query"]).last().reset_index()
        )
        latest = latest[latest["server"].isin(chosen) & (latest["sent"] > 0)]
        if latest.empty:
            st.info("No per-query counters for the selected servers.")
        else:
            latest["fail %"] = (100 * latest["failed"] / latest["sent"]).round(2)
            show_cols = [c for c in (
                "server", "query", "sent", "answered", "failed", "fail %",
                "mean_ms", "last_ttl", "last_answer",
            ) if c in latest.columns]
            st.caption(
                "Cumulative per-query counters (latest snapshot). Sort by "
                "**fail %** to see which name hurts on which resolver; "
                "`last_ttl` counting down between runs means cache hits, and "
                "`last_answer` makes flaps inspectable."
            )
            st.dataframe(
                latest[show_cols].sort_values("fail %", ascending=False),
                use_container_width=True, hide_index=True,
                column_config={
                    "fail %": st.column_config.ProgressColumn(
                        "fail %", min_value=0, max_value=100, format="%.1f%%"
                    ),
                    "mean_ms": st.column_config.NumberColumn("mean (ms)", format="%.1f"),
                },
            )

    # --- per-resolver health (snapshots at failure moments) ------------------
    st.subheader("Resolver health at failure moments")
    st.caption(
        "Averaged across the fleet snapshots captured at each failure in the "
        "current window — not a continuous uptime measure, but a read on how "
        "each resolver looked whenever *something* went wrong."
    )
    health = (
        fstatus.groupby("server")
        .agg(
            snapshots=("up", "size"),
            pct_up=("up", lambda s: 100 * s.mean()),
            avg_availability=("availability", "mean"),
            avg_p95_ms=("p95_ms", "mean"),
            avg_last_ms=("last_ms", "mean"),
            pct_icmp_up=("icmp_up", lambda s: 100 * s.mean()),
            avg_icmp_ms=("icmp_last_ms", "mean"),
        )
        .round(2)
        .sort_values("pct_up")
    )
    # Recursion overhead: resolver processing/recursion time with network
    # distance removed (avg DNS RTT minus avg ICMP RTT). Mirrors the TUI
    # 'recursion ovh' row, approximated from the stored last-RTT columns; NaN
    # where ICMP was disabled. Near 0 = cache hits, large = recursion/busy box.
    health["avg_recursion_ms"] = (health["avg_last_ms"] - health["avg_icmp_ms"]).round(2)
    st.dataframe(
        health,
        use_container_width=True,
        column_config={
            "pct_up": st.column_config.ProgressColumn(
                "DNS up %", min_value=0, max_value=100, format="%.0f%%"
            ),
            "pct_icmp_up": st.column_config.ProgressColumn(
                "ICMP up %", min_value=0, max_value=100, format="%.0f%%"
            ),
            "avg_p95_ms": st.column_config.NumberColumn("Avg DNS p95 (ms)", format="%.1f"),
            "avg_last_ms": st.column_config.NumberColumn("Avg DNS last (ms)", format="%.1f"),
            "avg_icmp_ms": st.column_config.NumberColumn("Avg ICMP RTT (ms)", format="%.1f"),
            "avg_recursion_ms": st.column_config.NumberColumn(
                "Avg recursion overhead (ms)", format="%.1f",
                help="Avg DNS RTT minus avg ICMP RTT — resolver processing with "
                     "network distance removed. Near 0 = served from cache; "
                     "large = recursion or a busy resolver; can be slightly "
                     "negative for fast local caches.",
            ),
        },
    )

    # --- network reachability vs DNS (ICMP) ----------------------------------
    icmp = fstatus[fstatus["icmp_enabled"] == 1]
    if not icmp.empty:
        st.subheader("Network reachability vs DNS (ICMP ping)")
        st.caption(
            "ICMP pings the resolver's host independently of DNS. If a box keeps "
            "answering pings while its DNS service times out, the failure is the "
            "resolver overloading — not the network or the host going down."
        )

        # Headline: across the snapshots captured at failures, how often was the
        # host reachable (ICMP up) even though DNS was down?
        dns_down = icmp[icmp["up"] == 0]
        reachable = (
            100 * dns_down["icmp_up"].mean() if not dns_down.empty else float("nan")
        )
        m1, m2, m3 = st.columns(3)
        m1.metric("Snapshots with DNS down", f"{len(dns_down):,}")
        m2.metric(
            "…yet host still pinging",
            "—" if dns_down.empty else f"{reachable:.0f}%",
            help="DNS-down snapshots where ICMP still replied → reachable but not resolving.",
        )
        m3.metric("Avg ICMP packet loss", f"{100 * (1 - icmp['icmp_success'].mean()):.2f}%")

        ci, cj = st.columns(2)
        with ci:
            st.caption("Reachability per resolver — DNS up % vs ICMP up % (click legend to toggle)")
            reach = pd.DataFrame({
                "DNS up %": 100 * icmp.groupby("server")["up"].mean(),
                "ICMP up %": 100 * icmp.groupby("server")["icmp_up"].mean(),
            })
            st.altair_chart(
                toggle_bar(reach, cat_type="N", value_title="%", horizontal=True, height=300),
                use_container_width=True,
            )
        with cj:
            st.caption("Latency per resolver — DNS p95 vs ICMP RTT, ms (click legend to toggle)")
            lat = pd.DataFrame({
                "DNS p95 (ms)": icmp.groupby("server")["p95_ms"].mean(),
                "ICMP RTT (ms)": icmp.groupby("server")["icmp_last_ms"].mean(),
            })
            st.altair_chart(
                toggle_bar(lat, cat_type="N", value_title="ms", horizontal=True, height=300),
                use_container_width=True,
            )

        # Recursion overhead = what the resolver adds on top of raw network RTT
        # (avg DNS RTT minus avg ICMP RTT). Isolates resolver processing from
        # distance: near zero / negative means answers come from cache, large
        # means real recursion or a busy resolver.
        overhead = (
            icmp.groupby("server")["last_ms"].mean()
            - icmp.groupby("server")["icmp_last_ms"].mean()
        ).dropna().sort_values().rename("recursion overhead (ms)")
        if not overhead.empty:
            st.caption(
                "Recursion overhead per resolver — avg DNS RTT minus avg ICMP "
                "RTT (resolver processing with network distance removed; lower / "
                "negative = more cache-served, higher = recursion or a busy box)."
            )
            st.bar_chart(overhead, height=300, horizontal=True)

        # ICMP reply TTL per resolver. The columns are cumulative over the run,
        # so we take each server's latest snapshot for the full-run picture.
        # A shifting TTL means the hop count to the resolver changed (a route
        # change); a wide min↔max spread means it kept changing.
        ttl_cols = [
            "icmp_ttl_min", "icmp_ttl_max", "icmp_ttl_mode", "icmp_ttl_least",
        ]
        if all(c in icmp.columns for c in ttl_cols) and icmp["icmp_ttl_max"].notna().any():
            st.caption(
                "ICMP reply TTL per resolver (hop limit of received echoes). A "
                "changing TTL points at a route change between you and the box."
            )
            latest = icmp.sort_values("event_id").groupby("server").last()
            ttl_tbl = pd.DataFrame({
                "Min TTL": latest["icmp_ttl_min"],
                "Max TTL": latest["icmp_ttl_max"],
                "Most frequent TTL": latest["icmp_ttl_mode"],
                "Least frequent TTL": latest["icmp_ttl_least"],
            }).dropna(how="all")
            st.dataframe(
                ttl_tbl,
                use_container_width=True,
                column_config={
                    "Min TTL": st.column_config.NumberColumn(format="%.0f"),
                    "Max TTL": st.column_config.NumberColumn(format="%.0f"),
                    "Most frequent TTL": st.column_config.NumberColumn(format="%.0f"),
                    "Least frequent TTL": st.column_config.NumberColumn(format="%.0f"),
                },
            )
    else:
        st.info("No ICMP probe data in this log (ping was disabled when polling).")

    # --- raw event browser ---------------------------------------------------
    with st.expander(f"Raw events ({len(fev):,})"):
        raw = fev[["time", "trigger_server", "trigger_kind", "trigger_detail"]].copy()
        raw["time"] = raw["time"].dt.strftime("%Y-%m-%d %H:%M:%S")
        st.dataframe(
            raw.rename(columns={"time": "time (local)"}),
            use_container_width=True, hide_index=True,
        )


if __name__ == "__main__":
    main()
