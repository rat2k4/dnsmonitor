"""Command-line interface for DNStester.

Subcommands::

    ramp     stepwise QPS ramp with optional Unbound monitoring (the main one)
    client   one-shot load run at a single QPS
    monitor  print one unbound-control stats delta over an interval
    poll     live curses dashboard of response-quality KPIs for one or more
             DNS servers (latency, jitter, availability, RCODEs, ...)
    profile  one-shot capability & hygiene audit of a resolver (transports,
             DNSSEC, middleboxes, identity, NXDOMAIN honesty, ...)
    compare  ask every resolver the same questions and group the answers —
             outliers and disagreements stand out
    export   dump a poll --log-db failure database to CSV or XLSX
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from . import __version__, report
from .loadgen import LoadConfig, run_parallel_load
from .monitor import MonitorConfig, MonitorError, UnboundMonitor, compute_delta
from .ramp import RampConfig, Thresholds, build_steps, run_ramp


def _add_target_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--target", required=True, help="resolver IP/host to query")
    p.add_argument("--port", type=int, default=53, help="resolver UDP port (default 53)")
    p.add_argument("--qname", default="example.com", help="name to query (default example.com)")
    p.add_argument(
        "--qname-strategy",
        choices=("fixed", "random"),
        default="fixed",
        help="fixed: same name (cache/throughput path); random: unique label per "
        "query to force cache misses / recursion (default fixed)",
    )
    p.add_argument("--qtype", default="A", help="query type (A, AAAA, NS, ...; default A)")
    p.add_argument("--timeout", type=float, default=2.0, help="per-query timeout seconds (default 2)")
    p.add_argument("--max-inflight", type=int, default=20_000, help="cap on outstanding queries")
    p.add_argument(
        "--pacing", choices=("uniform", "poisson"), default="uniform",
        help="inter-send gaps: uniform (perfectly even, gentlest possible "
        "arrival pattern) or poisson (exponential gaps, same mean rate — "
        "bursty like real traffic; usually finds the breaking point earlier)",
    )
    p.add_argument(
        "--edns-size", type=int, default=1232, metavar="BYTES",
        help="EDNS0 advertised UDP payload size (default 1232); 0 sends plain "
        "queries limited to 512-byte answers. Truncated (TC) responses are "
        "counted either way",
    )
    p.add_argument(
        "--workers",
        type=int,
        default=1,
        help="generator processes; the target QPS is split evenly across them "
        "(default 1). Use this to get past a single process's send/recv ceiling.",
    )


def _add_monitor_args(p: argparse.ArgumentParser) -> None:
    g = p.add_argument_group("unbound monitor (over SSH, optional)")
    g.add_argument("--ssh-host", help="host running unbound; enables monitoring")
    g.add_argument("--ssh-user", help="SSH user")
    g.add_argument("--ssh-port", type=int, default=22, help="SSH port (default 22)")
    g.add_argument("--ssh-key", help="path to SSH private key (-i)")
    g.add_argument("--unbound-control", default="unbound-control", help="remote unbound-control path")
    g.add_argument("--sudo", action="store_true", help="run unbound-control via sudo on the host")
    g.add_argument(
        "--no-stats-reset", action="store_true",
        help="read counters with 'stats_noreset' instead of the resetting "
        "'stats'. Resetting (the default) makes every snapshot — including "
        "gauges like requestlist.max and recursion time — cover exactly one "
        "step; use this flag only if something else on the host also consumes "
        "unbound's counters",
    )


def _monitor_from_args(args) -> UnboundMonitor | None:
    if not getattr(args, "ssh_host", None):
        return None
    cfg = MonitorConfig(
        host=args.ssh_host,
        user=args.ssh_user,
        port=args.ssh_port,
        identity=args.ssh_key,
        control_cmd=args.unbound_control,
        use_sudo=args.sudo,
        reset_stats=not args.no_stats_reset,
    )
    return UnboundMonitor(cfg)


def _load_from_args(args, qps: float) -> LoadConfig:
    return LoadConfig(
        target=args.target,
        port=args.port,
        qps=qps,
        duration=args.duration,
        qname=args.qname,
        qname_strategy=args.qname_strategy,
        qtype=args.qtype,
        timeout=args.timeout,
        max_inflight=args.max_inflight,
        pacing=args.pacing,
        edns_size=args.edns_size,
    )


def cmd_ramp(args) -> int:
    if args.qps_list:
        steps = [float(x) for x in args.qps_list.split(",") if x.strip()]
    else:
        steps = build_steps(args.qps_start, args.qps_stop, args.qps_step)
    if not steps:
        print("no QPS steps to run", file=sys.stderr)
        return 2

    monitor = _monitor_from_args(args)
    if monitor is not None:
        err = monitor.check()
        if err is not None:
            print(f"warning: unbound monitor unreachable, continuing client-only: {err}", file=sys.stderr)
            monitor = None
        else:
            print(f"monitoring unbound on {args.ssh_host} via unbound-control", file=sys.stderr)

    template = _load_from_args(args, steps[0])
    cfg = RampConfig(
        load=template,
        qps_steps=steps,
        cooldown=args.cooldown,
        workers=args.workers,
        thresholds=Thresholds(
            max_p99_ms=args.max_p99_ms,
            max_timeout_rate=args.max_timeout_rate,
            max_servfail_rate=args.max_servfail_rate,
        ),
    )

    print(
        f"ramping {steps[0]:.0f}->{steps[-1]:.0f} qps in {len(steps)} steps, "
        f"{args.duration:.0f}s each, querying {args.qname} ({args.qname_strategy}) at "
        f"{args.target}:{args.port}\n",
        file=sys.stderr,
    )

    printed_header = {"done": False}

    def on_step(step):
        if not printed_header["done"]:
            report.print_table([step])
            printed_header["done"] = True
        else:
            # Re-render just this row by printing the table for a single step
            # without the header.
            from .report import _COLUMNS  # local import keeps module surface small

            print(" ".join(extract(step).rjust(w) for _, w, extract in _COLUMNS))

    results = asyncio.run(run_ramp(cfg, monitor=monitor, on_step=on_step))

    report.print_summary(results)
    if args.csv:
        report.write_csv(results, args.csv)
        print(f"\nwrote {args.csv}", file=sys.stderr)
    if args.json:
        report.write_json(results, args.json)
        print(f"wrote {args.json}", file=sys.stderr)
    return 0


def cmd_client(args) -> int:
    cfg = _load_from_args(args, args.qps)
    result = run_parallel_load(cfg, args.workers)
    if args.workers > 1:
        print(f"workers     : {args.workers} ({args.qps / args.workers:.0f} qps each)")
    print(f"offered     : {result.offered_qps:.0f} qps")
    print(f"sent        : {result.sent} ({result.sent_qps:.0f} qps)")
    print(f"answered    : {result.received} ({result.answered_qps:.0f} qps)")
    print(f"timeouts    : {result.timeouts} ({result.timeout_rate:.1%})")
    print(f"dropped     : {result.dropped} ({result.drop_rate:.1%})")
    print(f"late        : {result.late} (answers after the timeout)")
    print(f"truncated   : {result.tc} (TC=1 responses)")
    print(f"latency ms  : p50={result.p50:.1f} p95={result.p95:.1f} p99={result.p99:.1f} mean={result.mean_ms:.1f}")
    from .wire import RCODES

    rc = ", ".join(f"{RCODES.get(k, k)}={v}" for k, v in sorted(result.rcodes.items()))
    print(f"rcodes      : {rc or '-'}")
    return 0


def cmd_monitor(args) -> int:
    monitor = _monitor_from_args(args)
    if monitor is None:
        print("--ssh-host is required for the monitor subcommand", file=sys.stderr)
        return 2
    err = monitor.check()
    if err is not None:
        print(f"unbound unreachable: {err}", file=sys.stderr)
        return 1
    try:
        before = monitor.snapshot()
        import time

        time.sleep(args.interval)
        after = monitor.snapshot()
    except MonitorError as exc:
        print(f"monitor error: {exc}", file=sys.stderr)
        return 1
    delta = compute_delta(
        before, after, args.interval, already_reset=monitor.cfg.reset_stats
    )
    print(f"over {args.interval:.0f}s:")
    print(f"  handled            : {delta.handled_qps:.0f} qps")
    print(f"  cache hit ratio    : {delta.cache_hit_ratio:.1%}")
    print(f"  recursion time avg : {delta.recursion_time_avg_ms:.1f} ms")
    print(f"  requestlist max/avg: {delta.requestlist_max:.0f} / {delta.requestlist_avg:.1f}")
    print(f"  requestlist exceeded: {delta.requestlist_exceeded:.0f}")
    print(f"  tcp usage          : {delta.tcp_usage:.0f}")
    return 0


def _servers_from_args(args) -> list[str] | None:
    """Servers from positional args, falling back to --servers-file.

    Returns None (after printing the reason) when none can be found.
    """
    servers = [s for s in (args.servers or []) if s.strip()]
    if not servers and args.servers_file:
        try:
            with open(args.servers_file, encoding="utf-8") as fh:
                servers = [
                    line for raw in fh
                    if (line := raw.split("#", 1)[0].strip())
                ]
        except OSError as exc:
            print(f"cannot read --servers-file: {exc}", file=sys.stderr)
            return None
    if not servers:
        print(
            "no DNS servers: pass them as arguments or list them in "
            f"{args.servers_file}",
            file=sys.stderr,
        )
        return None
    return servers


def cmd_poll(args) -> int:
    from .poller import PollConfig, load_queries
    from .tui import run_dashboard

    servers = _servers_from_args(args)
    if servers is None:
        return 2
    names = [t for raw in (args.qnames or []) for t in raw.split(",")]
    try:
        queries = load_queries(names, args.qname_file, args.qname, args.qtype)
    except OSError as exc:
        print(f"cannot read --qname-file: {exc}", file=sys.stderr)
        return 2
    cfg = PollConfig(
        servers=servers,
        port=args.port,
        qname=args.qname,
        qname_strategy=args.qname_strategy,
        qtype=args.qtype,
        interval=args.interval,
        timeout=args.timeout,
        queries=queries,
        pool_order=args.pool_order,
        icmp=not args.no_icmp,
        log_db=args.log_db,
        sample_interval=args.sample_interval,
        retries=args.retries,
        edns_size=args.edns_size,
        canary_zone=args.canary_zone,
        canary_interval=args.canary_interval,
        triage=not args.no_triage,
        triage_cooldown=args.triage_cooldown,
        gateway_pause=not args.no_gateway_pause,
        gateway=args.gateway,
        gateway_interval=args.gateway_interval,
    )
    if args.log_db:
        print(f"logging probe failures to {args.log_db}", file=sys.stderr)
        if args.sample_interval > 0:
            print(
                f"sampling fleet KPIs every {args.sample_interval:g}s to {args.log_db}",
                file=sys.stderr,
            )
    if args.headless:
        return _run_poll_headless(cfg, args.refresh)
    try:
        warning = run_dashboard(cfg, refresh=args.refresh)
    except KeyboardInterrupt:
        warning = None
    if warning:
        print(warning, file=sys.stderr)
    return 0


def _run_poll_headless(cfg, refresh: float) -> int:
    """Run the pollers without the curses UI, for unattended/background use.

    Drives :class:`PollManager` directly (the curses dashboard is only a viewer)
    and prints a compact status line on an interval, so the run is observable in
    a log file. Stops cleanly on SIGINT/SIGTERM so a supervisor — e.g. the web
    control panel — can terminate it and let the SQLite log flush.
    """
    import signal
    import threading
    import time
    from datetime import datetime, timezone

    from .poller import PollManager

    stop = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    signal.signal(signal.SIGTERM, lambda *_: stop.set())

    mgr = PollManager(cfg)
    mgr.start()
    print(
        f"polling {len(cfg.servers)} server(s) headless, "
        f"{len(cfg.queries or [])} quer(y/ies) in the pool; send SIGTERM to stop",
        flush=True,
    )
    if mgr.gateway is not None:
        print(f"network watchdog: pausing whenever gateway {mgr.gateway} is unreachable", flush=True)
    elif mgr.gateway_error:
        print(mgr.gateway_error, file=sys.stderr, flush=True)
    period = max(refresh, 2.0)  # don't spam the log; one status line every ~2s+
    was_paused = False
    try:
        while not stop.wait(period):
            paused = not mgr.net_up.is_set()
            iso = datetime.now(timezone.utc).isoformat(timespec="seconds")
            if paused != was_paused:
                print(
                    f"{iso}  {'PAUSED — gateway ' + str(mgr.gateway) + ' unreachable' if paused else 'RESUMED — gateway reachable again'}",
                    flush=True,
                )
                was_paused = paused
            if paused:
                continue  # counters are frozen; a status line would just repeat
            snaps = mgr.snapshots()
            up = sum(1 for s in snaps if s.up)
            parts = []
            for s in snaps:
                avail = s.recent_availability
                shown = f"{avail:.0%}" if avail == avail else "--"  # NaN guard
                parts.append(f"{s.host}:{s.port}={shown}")
            print(f"{iso}  up {up}/{len(snaps)}  " + " ".join(parts), flush=True)
    finally:
        mgr.stop()
    if mgr.log_error:
        print(mgr.log_error, file=sys.stderr)
    print("stopped", flush=True)
    return 0


def cmd_register(args) -> int:
    import signal
    import threading
    from datetime import datetime

    from .registrar import Registrar

    reg = Registrar(
        db_path=args.log_db,
        servers_file=args.servers_file,
        qname_file=args.qname_file,
        port=args.port,
        timeout=args.timeout,
    )
    stop = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    print(
        f"registrar watching {args.servers_file} and {args.qname_file} "
        f"every {args.interval:g}s -> {args.log_db}; send SIGTERM to stop",
        flush=True,
    )
    try:
        first = True
        # Scan immediately, then every --interval seconds.
        while first or not stop.wait(args.interval):
            first = False
            try:
                servers, domains = reg.scan_once()
            except Exception as exc:  # never let one bad scan kill the watcher
                print(f"scan error: {exc}", file=sys.stderr, flush=True)
                continue
            if servers or domains:
                iso = datetime.now().strftime("%H:%M:%S")
                if servers:
                    print(f"{iso}  + server(s): {', '.join(servers)}", flush=True)
                if domains:
                    print(f"{iso}  + domain(s): {', '.join(domains)}", flush=True)
    finally:
        reg.close()
    print("stopped", flush=True)
    return 0


def cmd_profile(args) -> int:
    from .audit import print_profile, profile_server
    from .poller import parse_server

    servers = _servers_from_args(args)
    if servers is None:
        return 2
    all_results = {}
    for spec in servers:
        host, port = parse_server(spec, args.port)
        label = f"{host}:{port}"
        print(f"profiling {label} ...", file=sys.stderr)
        checks = profile_server(
            host, port,
            timeout=args.timeout,
            edns_size=args.edns_size,
            hijack_zone=args.hijack_zone,
            offline=args.offline,
            oarc=args.oarc,
        )
        print_profile(label, checks)
        all_results[label] = [
            {"check": k, "value": v, "level": lvl} for k, v, lvl in checks
        ]
    if args.json:
        import json

        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(all_results, fh, indent=2)
        print(f"\nwrote {args.json}", file=sys.stderr)
    return 0


def cmd_compare(args) -> int:
    from .compare import print_compare, run_compare, to_jsonable
    from .poller import load_queries

    servers = _servers_from_args(args)
    if servers is None:
        return 2
    names = [t for raw in (args.qnames or []) for t in raw.split(",")]
    try:
        queries = load_queries(names, args.qname_file, args.qname, args.qtype)
    except OSError as exc:
        print(f"cannot read --qname-file: {exc}", file=sys.stderr)
        return 2
    results = run_compare(
        servers, args.port, queries, timeout=args.timeout, edns_size=args.edns_size
    )
    print_compare(results, total_servers=len(servers))
    if args.json:
        import json

        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(to_jsonable(results), fh, indent=2)
        print(f"\nwrote {args.json}", file=sys.stderr)
    # Exit 1 when any query produced an outlier or timeout, so scripts can alert.
    troubled = any(
        e["timeouts"] or any(len(g["servers"]) == 1 for g in e["groups"][1:])
        for e in results
    )
    return 1 if troubled else 0


def cmd_export(args) -> int:
    from .export import ExportError, export, infer_format

    try:
        fmt = infer_format(args.output, args.format)
        written = export(args.db, args.output, fmt, table=args.table)
    except ExportError as exc:
        print(f"export failed: {exc}", file=sys.stderr)
        return 2
    for path in written:
        print(f"wrote {path}", file=sys.stderr)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dnstester", description="Unbound scalability tester")
    parser.add_argument("--version", action="version", version=f"dnstester {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    # ramp
    p_ramp = sub.add_parser("ramp", help="stepwise QPS ramp (main command)")
    _add_target_args(p_ramp)
    p_ramp.add_argument("--duration", type=float, default=15.0, help="seconds per step (default 15)")
    p_ramp.add_argument("--cooldown", type=float, default=3.0, help="idle seconds between steps (default 3)")
    p_ramp.add_argument("--qps-start", type=float, default=100.0, help="first step QPS (default 100)")
    p_ramp.add_argument("--qps-stop", type=float, default=2000.0, help="last step QPS (default 2000)")
    p_ramp.add_argument("--qps-step", type=float, default=250.0, help="QPS increment (default 250)")
    p_ramp.add_argument("--qps-list", help="explicit comma-separated QPS steps, overrides start/stop/step")
    p_ramp.add_argument("--max-p99-ms", type=float, default=100.0, help="p99 latency saturation threshold")
    p_ramp.add_argument("--max-timeout-rate", type=float, default=0.02, help="timeout-rate saturation threshold")
    p_ramp.add_argument("--max-servfail-rate", type=float, default=0.05, help="SERVFAIL-rate saturation threshold")
    p_ramp.add_argument("--csv", help="write results to this CSV path")
    p_ramp.add_argument("--json", help="write results to this JSON path")
    _add_monitor_args(p_ramp)
    p_ramp.set_defaults(func=cmd_ramp)

    # client
    p_client = sub.add_parser("client", help="single load run at one QPS")
    _add_target_args(p_client)
    p_client.add_argument("--qps", type=float, default=100.0, help="target QPS (default 100)")
    p_client.add_argument("--duration", type=float, default=10.0, help="seconds (default 10)")
    p_client.set_defaults(func=cmd_client)

    # monitor
    p_mon = sub.add_parser("monitor", help="print one unbound-control stats delta")
    p_mon.add_argument("--interval", type=float, default=5.0, help="seconds between snapshots (default 5)")
    _add_monitor_args(p_mon)
    p_mon.set_defaults(func=cmd_monitor)

    # poll
    p_poll = sub.add_parser(
        "poll", help="live curses dashboard of DNS response-quality KPIs for several servers"
    )
    p_poll.add_argument(
        "servers",
        nargs="*",
        help="DNS servers to profile (host, host:port, or [v6]:port); if omitted, "
        "they're read from --servers-file",
    )
    p_poll.add_argument(
        "--servers-file", default="servers.txt", metavar="PATH",
        help="file of DNS servers, one per line (used when none are passed as "
        "arguments; '#' comments and blank lines ignored; default servers.txt)",
    )
    p_poll.add_argument("--port", type=int, default=53, help="default UDP port for servers (default 53)")
    p_poll.add_argument(
        "--qname", default="example.com",
        help="single name to query when no pool is given (default example.com)",
    )
    p_poll.add_argument(
        "--qnames", action="append", metavar="NAME[:QTYPE],...",
        help="query pool: comma-separated names, each optionally 'name:QTYPE' "
        "(e.g. example.com,cloudflare.com:AAAA,a.root-servers.net:NS). "
        "Repeatable; combines with --qname-file. Probes rotate through the pool.",
    )
    p_poll.add_argument(
        "--qname-file", metavar="PATH",
        help="file with one query per line ('name' or 'name:QTYPE'); "
        "blank lines and '#' comments ignored. Adds to the pool.",
    )
    p_poll.add_argument(
        "--pool-order", choices=("roundrobin", "random"), default="roundrobin",
        help="how each server walks the query pool (default roundrobin)",
    )
    p_poll.add_argument(
        "--qname-strategy",
        choices=("fixed", "random"),
        default="fixed",
        help="fixed: ask the pool names as-is (measures cache/serving path); "
        "random: prepend a unique label to force cache misses / recursion "
        "(default fixed)",
    )
    p_poll.add_argument("--qtype", default="A", help="default query type for pool entries without one (default A)")
    p_poll.add_argument(
        "--no-icmp", action="store_true",
        help="disable the ICMP ping side-channel (by default each server is also "
        "pinged once per interval for reachability / RTT)",
    )
    p_poll.add_argument(
        "--log-db", metavar="PATH",
        help="log every DNS probe failure to this SQLite file, capturing the "
        "last-known status of all polled servers at the moment of failure",
    )
    p_poll.add_argument(
        "--sample-interval", type=float, default=5.0, metavar="SECONDS",
        help="with --log-db, also write a periodic snapshot of every server's "
        "KPIs to a 'samples' table this often, for a continuous latency/"
        "availability trace (default 5; 0 disables)",
    )
    p_poll.add_argument("--interval", type=float, default=1.0, help="seconds between probes per server (default 1)")
    p_poll.add_argument("--timeout", type=float, default=2.0, help="per-probe timeout seconds (default 2)")
    p_poll.add_argument(
        "--retries", type=int, default=1, metavar="N",
        help="retransmits before a probe counts as failed (default 1, like a "
        "real stub resolver). The KPIs then separate raw packet loss from "
        "effective, after-retry failure. 0 restores single-shot probes",
    )
    p_poll.add_argument(
        "--edns-size", type=int, default=1232, metavar="BYTES",
        help="EDNS0 advertised UDP size on probes (default 1232); 0 sends "
        "plain 512-byte-limit queries. Truncated answers are counted either way",
    )
    p_poll.add_argument(
        "--canary-zone", metavar="ZONE",
        help="enable the NXDOMAIN-hijack canary: periodically ask each server "
        "for a random label under this zone (e.g. 'cl'), which cannot exist. "
        "Any answer other than NXDOMAIN is flagged; an address back means the "
        "resolver rewrites NXDOMAIN. Use a zone without a wildcard record",
    )
    p_poll.add_argument(
        "--canary-interval", type=float, default=60.0, metavar="SECONDS",
        help="seconds between canary probes per server (default 60)",
    )
    p_poll.add_argument(
        "--no-triage", action="store_true",
        help="disable the triage battery (by default, when a probe exhausts "
        "its retries, the server is cross-checked from a side thread — UDP "
        "retry, TCP, a cached name, and a reference server — and the failure "
        "is classified; verdicts show in the dashboard and, with --log-db, "
        "land in the 'triage' table)",
    )
    p_poll.add_argument(
        "--triage-cooldown", type=float, default=30.0, metavar="SECONDS",
        help="minimum seconds between triage batteries per server (default 30)",
    )
    p_poll.add_argument(
        "--gateway", metavar="IP",
        help="network-watchdog target (default: the autodetected default "
        "gateway). While this address doesn't answer pings, all probing is "
        "paused — a box with its own network down would otherwise log every "
        "resolver as failed",
    )
    p_poll.add_argument(
        "--gateway-interval", type=float, default=2.0, metavar="SECONDS",
        help="seconds between gateway watchdog pings (default 2; two "
        "consecutive losses pause, one reply resumes)",
    )
    p_poll.add_argument(
        "--no-gateway-pause", action="store_true",
        help="disable the network watchdog (keep probing even when the "
        "default gateway is unreachable)",
    )
    p_poll.add_argument("--refresh", type=float, default=0.5, help="screen refresh seconds (default 0.5)")
    p_poll.add_argument(
        "--headless", action="store_true",
        help="run without the curses dashboard (for background/unattended use): "
        "poll on the configured interval, logging failures to --log-db and "
        "printing a periodic status line until SIGINT/SIGTERM",
    )
    p_poll.set_defaults(func=cmd_poll)

    # profile
    p_prof = sub.add_parser(
        "profile",
        help="one-shot capability & hygiene audit of one or more resolvers "
        "(transports, DNSSEC validation, middlebox detection, identity, "
        "NXDOMAIN honesty, rebind filtering, QNAME minimisation, ...)",
    )
    p_prof.add_argument(
        "servers", nargs="*",
        help="resolvers to audit (host, host:port, or [v6]:port); if omitted, "
        "read from --servers-file",
    )
    p_prof.add_argument(
        "--servers-file", default="servers.txt", metavar="PATH",
        help="fallback server list, one per line (default servers.txt)",
    )
    p_prof.add_argument("--port", type=int, default=53, help="default port (default 53)")
    p_prof.add_argument("--timeout", type=float, default=2.0, help="per-check timeout seconds (default 2)")
    p_prof.add_argument("--edns-size", type=int, default=1232, metavar="BYTES",
                        help="EDNS0 UDP size for checks that use EDNS (default 1232)")
    p_prof.add_argument(
        "--hijack-zone", default="com", metavar="ZONE",
        help="zone for the NXDOMAIN-honesty check (a random label under it must "
        "not exist; default com — pick any zone without a wildcard)",
    )
    p_prof.add_argument(
        "--offline", action="store_true",
        help="skip checks that rely on third-party test services "
        "(dnssec-failed.org, whoami.akamai.net, Google, internet.nl, nip.io)",
    )
    p_prof.add_argument(
        "--oarc", action="store_true",
        help="also run DNS-OARC's source-port / transaction-id randomness "
        "raters (porttest / txidtest.dns-oarc.net; adds ~10-20s per server)",
    )
    p_prof.add_argument("--json", metavar="PATH", help="also write results as JSON")
    p_prof.set_defaults(func=cmd_profile)

    # compare
    p_cmp = sub.add_parser(
        "compare",
        help="ask every resolver the same questions simultaneously and group "
        "the answers — outliers, disagreements and timeouts stand out",
    )
    p_cmp.add_argument(
        "servers", nargs="*",
        help="resolvers to compare; if omitted, read from --servers-file",
    )
    p_cmp.add_argument(
        "--servers-file", default="servers.txt", metavar="PATH",
        help="fallback server list (default servers.txt)",
    )
    p_cmp.add_argument("--port", type=int, default=53, help="default port (default 53)")
    p_cmp.add_argument("--qname", default="example.com",
                       help="single name when no pool is given (default example.com)")
    p_cmp.add_argument(
        "--qnames", action="append", metavar="NAME[:QTYPE],...",
        help="comma-separated query pool (same format as poll); repeatable",
    )
    p_cmp.add_argument(
        "--qname-file", default=None, metavar="PATH",
        help="file with one query per line (e.g. dns.txt)",
    )
    p_cmp.add_argument("--qtype", default="A", help="default record type (default A)")
    p_cmp.add_argument("--timeout", type=float, default=2.0, help="per-query timeout seconds (default 2)")
    p_cmp.add_argument("--edns-size", type=int, default=1232, metavar="BYTES",
                       help="EDNS0 UDP size (default 1232)")
    p_cmp.add_argument("--json", metavar="PATH", help="also write results as JSON")
    p_cmp.set_defaults(func=cmd_compare)

    # register
    p_reg = sub.add_parser(
        "register",
        help="periodically watch the server/domain list files and record newly "
        "added entries to the result db once they pass a verifying DNS query",
    )
    p_reg.add_argument(
        "--servers-file", default="servers.txt", metavar="PATH",
        help="file of DNS servers to watch, one per line (default servers.txt)",
    )
    p_reg.add_argument(
        "--qname-file", default="dns.txt", metavar="PATH",
        help="file of domains to watch, one per line (default dns.txt)",
    )
    p_reg.add_argument(
        "--log-db", default="dns-failures.db", metavar="PATH",
        help="result database to register verified servers/domains into "
        "(default dns-failures.db)",
    )
    p_reg.add_argument("--port", type=int, default=53, help="default server port (default 53)")
    p_reg.add_argument("--interval", type=float, default=5.0, help="seconds between file scans (default 5)")
    p_reg.add_argument("--timeout", type=float, default=2.0, help="verifying-query timeout seconds (default 2)")
    p_reg.set_defaults(func=cmd_register)

    # export
    p_exp = sub.add_parser(
        "export", help="dump a poll --log-db failure database to CSV or XLSX"
    )
    p_exp.add_argument("db", help="SQLite database written by 'poll --log-db'")
    p_exp.add_argument(
        "-o", "--output", required=True, metavar="PATH",
        help="output file; format inferred from .csv / .xlsx unless --format given",
    )
    p_exp.add_argument(
        "--format", choices=("csv", "xlsx"), default=None,
        help="output format (default: inferred from the output extension)",
    )
    p_exp.add_argument(
        "--table",
        choices=("joined", "events", "server_status", "samples", "triage",
                 "query_stats", "all"),
        default="joined",
        help="which table to export. 'joined' (default) is each per-server "
        "snapshot stamped with its failure event; 'triage' is the failure-"
        "classification batteries; 'query_stats' the per-(server, query) "
        "counters; 'all' exports every table present (separate sheets in "
        "XLSX, separate files in CSV)",
    )
    p_exp.set_defaults(func=cmd_export)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
