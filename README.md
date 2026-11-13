# DNStester

A scalability test harness for the [Unbound](https://nlnetlabs.nl/projects/unbound/)
DNS resolver. It has two cooperating parts:

- **Client** — an *open-loop* DNS load generator. It paces queries against a
  wall clock at a precise target QPS, regardless of how fast responses come
  back, so an overloaded resolver shows up as rising latency / timeouts instead
  of the load silently throttling itself (this avoids *coordinated omission* in
  the latency numbers).
- **Monitor** — reads Unbound's own view of the load by running
  `unbound-control stats_noreset` on the resolver host over SSH and parsing the
  counters (queries handled, cache hit ratio, recursion time, request-list
  saturation).

A **ramp** orchestrator drives the client through a series of increasing QPS
steps, snapshots the monitor around each step, records the full latency-vs-QPS
curve, and flags the saturation / breaking point.

The command-line tools are pure stdlib; the monitor shells out to your system
`ssh` (honouring `~/.ssh/config`, agent and keys). Only the optional web
dashboard (`dashboard.py`) needs third-party packages: Streamlit and pandas.
Requires Python 3.14+.

## Quick start

### 1. Clone and install

You need Python 3.14+ and [uv](https://docs.astral.sh/uv/). Plain `pip`
works too.

```bash
git clone https://github.com/rat2k4/dnsmonitor.git
cd dnsmonitor

uv sync                          # creates .venv and installs dependencies
source .venv/bin/activate        # or prefix each command with `uv run`

# Without uv:
#   python3.14 -m venv .venv && source .venv/bin/activate && pip install -e .

python main.py --help            # list every subcommand
```

### 2. Pick your servers and domains

```bash
cp servers.example.txt servers.txt    # resolvers to test; add your own here
```

`servers.txt` (resolvers to test) and `dns.txt` (domains to query) are read by
`poll`, `profile`, `compare` and `register` whenever you don't pass servers on
the command line. Each file starts with a comment block describing its format.

`servers.txt` is git-ignored, so your ISP or internal resolvers stay on your
machine. `servers.example.txt` is the committed template with public resolvers
only (Cloudflare, Google).

To push the project to a remote host with rsync, do the same with the deploy
script and set your destination in it:

```bash
cp deploy.example.sh deploy.sh        # edit DEST; deploy.sh is git-ignored
./deploy.sh -n                        # dry run
```

### 3. Run each command

The examples use public resolvers (`1.1.1.1`, `8.8.8.8`). `ramp`, `client` and
`monitor` are load and stats tools for a resolver **you control**: point
`--target` / `--ssh-host` at your own Unbound host (`10.0.0.5` below is a
placeholder). Don't load-test public resolvers.

```bash
# ramp: stepwise QPS ramp against your resolver, with Unbound stats over SSH
python main.py ramp --target 10.0.0.5 \
    --qps-start 100 --qps-stop 3000 --qps-step 250 --duration 15 \
    --ssh-host 10.0.0.5 --ssh-user admin --sudo \
    --csv results.csv --json results.json

# client: a single load run at a fixed QPS (quick sanity check)
python main.py client --target 10.0.0.5 --qps 500 --duration 10

# monitor: one unbound-control stats delta over 10 s, no load applied
python main.py monitor --ssh-host 10.0.0.5 --ssh-user admin --sudo --interval 10

# poll: live terminal dashboard of response quality (q to quit);
# --log-db records every failure to SQLite for export/dashboard
python main.py poll 1.1.1.1 8.8.8.8 --qname-file dns.txt --log-db dns-failures.db

# profile: one-shot capability and hygiene audit of each resolver
python main.py profile 1.1.1.1 8.8.8.8

# compare: send the same queries to every resolver and diff the answers
python main.py compare 1.1.1.1 8.8.8.8 --qnames example.com,example.com:AAAA

# register: watch servers.txt / dns.txt and record new entries once verified
python main.py register --log-db dns-failures.db

# export: dump the poll failure database to Excel or CSV
python main.py export dns-failures.db -o failures.xlsx
```

With no servers on the command line, `poll`, `profile` and `compare` read
`servers.txt`. For example, `python main.py poll --qname-file dns.txt` polls
every resolver in the file.

### 4. Web dashboard

```bash
streamlit run dashboard.py                              # opens http://localhost:8501
streamlit run dashboard.py -- --db /path/to/dns-failures.db
```

The dashboard charts the `--log-db` failure database. Its **Control** page
edits `servers.txt` / `dns.txt` and starts or stops `poll` and `register` in
the background, so you don't need the CLI.

### More `ramp` details

If `--ssh-host` is omitted (or the host is unreachable) the ramp still runs
client-side only; the Unbound columns just show `-`. See
[Subcommands](#subcommands) below for every option.

## Subcommands

### `ramp` (main command)

Stepwise QPS ramp. Prints a live table and a summary identifying the breaking
point. Key options:

| Option | Meaning |
| --- | --- |
| `--target` / `--port` | Resolver to query (UDP, default port 53). |
| `--qps-start/-stop/-step` | Arithmetic ramp, or use `--qps-list 100,500,1000,...`. |
| `--duration` | Seconds of load per step (default 15). |
| `--cooldown` | Idle seconds between steps so queues/cache settle (default 3). |
| `--qname` / `--qname-strategy` | What to ask. `fixed` reuses one name (cache/throughput path); `random` prepends a unique label per query to force cache misses and real recursion (see the warning under *Interpreting results*). |
| `--qtype` | A, AAAA, HTTPS, NS, ... (default A). |
| `--pacing` | `uniform` (default) sends at perfectly even intervals — the gentlest arrival pattern possible for a given QPS. `poisson` draws exponential inter-send gaps with the same mean rate: bursty like real traffic, and usually finds the breaking point earlier (the request list saturates on bursts). |
| `--edns-size` | EDNS0 advertised UDP payload size (default 1232). `0` sends plain queries, limiting answers to 512 bytes; truncated (TC=1) responses are counted either way and reported as `truncated`. |
| `--max-p99-ms`, `--max-timeout-rate`, `--max-servfail-rate` | Saturation thresholds. |
| `--ssh-host/-user/-port/-key`, `--unbound-control`, `--sudo` | Monitor over SSH. |
| `--csv`, `--json` | Write machine-readable results. |

A step is flagged **saturated** when any of these trips:

- the client cannot offer the requested load (sent QPS < 95% of offered, or drop rate high),
- timeout rate > `--max-timeout-rate`,
- SERVFAIL rate > `--max-servfail-rate`,
- p99 latency > `--max-p99-ms`,
- Unbound reports `requestlist.exceeded` (it dropped queries internally).

A single saturated step surrounded by healthy ones is treated as noise; the
reported breaking point is the first of **two consecutive** saturated steps
(or a saturated final step).

By default the monitor uses the resetting `unbound-control stats`, so every
per-step column — including gauges like `reqlist` max/avg and recursion time —
covers exactly that step. Pass `--no-stats-reset` to fall back to
`stats_noreset` if something else on the host also consumes Unbound's counters
(the gauges then read since-startup, and a spike smears into later steps).

### `client`

One-shot load run at a single QPS — handy for sanity checks.

```bash
python main.py client --target 10.0.0.5 --qps 500 --duration 10
```

### `monitor`

Print one `unbound-control` stats delta over an interval (no load applied):

```bash
python main.py monitor --ssh-host 10.0.0.5 --ssh-user admin --sudo --interval 10
```

### `poll`

A live **curses dashboard** that profiles the *response quality and stability*
of one or more DNS servers at once. Unlike `ramp` (which pushes a resolver to
its breaking point), `poll` sends a slow, steady stream of probes — the kind of
thing you leave running to characterise a server or compare several side by
side. Each server is a column; every statistical KPI is a row, so the whole
picture is on one screen.

```bash
# Compare three public resolvers, one probe each per second.
python main.py poll 1.1.1.1 8.8.8.8 9.9.9.9

# Non-standard port, force real recursion (cache-miss path), AAAA, faster cadence.
python main.py poll 10.0.0.5:5353 '[2606:4700:4700::1111]:53' \
    --qname example.com --qname-strategy random --qtype AAAA --interval 0.5
```

**Query pool.** Instead of hammering a single name, give the poller a *pool* of
queries to rotate through — more representative of real traffic, and it
exercises more of the resolver. Each pool entry is a name, optionally with its
own record type as `name:QTYPE`:

```bash
# Inline pool (comma-separated; --qnames is also repeatable).
python main.py poll 1.1.1.1 8.8.8.8 \
    --qnames example.com,cloudflare.com:AAAA,a.root-servers.net:NS,wikipedia.org

# Or load the pool from a file (one 'name' or 'name:QTYPE' per line,
# '#' comments and blank lines ignored), and visit it in random order.
python main.py poll 1.1.1.1 8.8.8.8 --qname-file domains.txt --pool-order random
```

Each server walks the pool independently (`--pool-order roundrobin` for even
coverage, or `random`). `--qtype` sets the default record type for entries that
don't specify one; `--qname-strategy random` still composes, prepending a unique
label to whichever pool name is chosen to force cache misses. Answer-consistency
is tracked **per query**, so the `inconsistent` / `answer flaps` KPIs only flag a
name that gives *differing answers to the same question* — not the normal
variation between different pool names.

Keys: `q`/Esc quit · `r` reset all counters · `space` pause/resume the display
(polling continues underneath).

**Retries — raw loss vs. effective failure.** Each probe retransmits once
(`--retries`, default 1) before it counts as failed, mirroring what a real stub
resolver does. The KPIs then separate the two numbers that matter for
different audiences: `raw pkt loss` (unanswered packets / packets sent,
counting retransmits — the wire-level drop rate you take to the ISP) and
`timeouts` (failures *after* the retry — what a user actually feels). `retry
saves` counts probes rescued by the retransmit; `late answers` counts answers
that straggled in after their probe had already timed out — late answers mean
the resolver is slow (overloaded), none at all means queries are dropped
outright. Probes carry EDNS0 (`--edns-size`, default 1232) and truncated
answers are counted in `truncated`.

**Triage battery.** When a probe exhausts its retries, the failing server is
cross-checked from a side thread within seconds (rate-limited by
`--triage-cooldown`, default 30s; disable with `--no-triage`): a fresh UDP
retry of the failing query, the same query over **TCP:53**, a recently-answered
*should-be-cached* name, and the same query at a healthy reference server. The
combination pins the failure to a layer and the verdict shows in the `triage`
row (and, with `--log-db`, lands in the `triage` table):

| verdict | meaning |
| --- | --- |
| `transient-udp-loss` | the retry answered — a stochastic packet drop |
| `udp-blocked-or-rate-limited` | TCP answered while UDP stayed dead — a policer / rate limiter / full socket queue in front of the resolver |
| `recursion-failure` | cached names answer but this query won't resolve here — recursion/upstream path stuck |
| `auth-domain-failure` | the reference server can't resolve it either — the domain's authoritative side is the problem |
| `fleet-or-domain-outage` | everything failed here *and* at the reference |
| `server-unresponsive` | UDP, TCP and cached-name all dead while the reference was fine |

**Network watchdog (automatic pause).** If the box running the tests loses its
*own* network, every DNS probe fails no matter how healthy the resolvers are —
and a long unattended run would log thousands of bogus "fleet-wide" failures.
The poller therefore autodetects the default gateway (`route`/`/proc/net/route`)
and pings it every `--gateway-interval` seconds (default 2). Two consecutive
lost echoes pause **all** probing — DNS, ICMP, canary, and the KPI sampler —
and a single reply resumes it; the cadence restarts cleanly with no catch-up
burst. Pauses are visible everywhere: a red banner in the dashboard, `PAUSED`/
`RESUMED` lines in headless mode, and explicit `net-down` / `net-up` marker
events in the log (which the web dashboard excludes from failure statistics
and reports as outage windows instead). Override the target with
`--gateway IP` (any always-on box on your LAN works) or disable with
`--no-gateway-pause`.

**NXDOMAIN-hijack canary.** `--canary-zone cl` (any zone without a wildcard)
periodically asks each server for a random label under that zone, which cannot
exist. The only honest answer is NXDOMAIN — an address back means the resolver
rewrites NXDOMAIN (ad/search hijacking) and the `canary` row flags `HIJACK`.
The canary also doubles as a forced-recursion health probe, and stays out of
the regular latency/availability KPIs.

**Failure logging (SQLite).** Pass `--log-db PATH` to record every DNS probe
failure (timeout or socket error) to a SQLite database. Each failure writes one
`events` row (when, which server, what kind, the failing query / error) plus a
`server_status` row for **every** polled server capturing its last-known state
at that instant — so a logged failure tells you whether it was isolated to one
resolver or fleet-wide:

```bash
python main.py poll 1.1.1.1 8.8.8.8 9.9.9.9 --log-db dns-failures.db
```

```sql
-- failures per server
SELECT trigger_server, trigger_kind, COUNT(*)
FROM events GROUP BY 1, 2;

-- the whole fleet's state at the moment of each failure
SELECT e.iso, e.trigger_server, s.server, s.up, s.availability, s.last_error
FROM events e JOIN server_status s ON s.event_id = e.id
ORDER BY e.id;
```

Logging is opt-in (no `--log-db`, no database) and off the hot path — writes
happen only on failure, serialised through one connection, and a write error
disables logging rather than disrupting the poll. (ICMP losses don't trigger an
event — they're frequently just a firewall — but each server's ICMP state *is*
recorded in the snapshot.)

Alongside `events` / `server_status` the log also carries:

- `samples` — the periodic fleet-wide KPI trace (`--sample-interval`), now
  including raw loss / retry / late-answer / truncation / canary counters;
- `triage` — one row per triage battery with every probe outcome and the
  verdict;
- `query_stats` — cumulative per-`(server, query)` counters flushed about once
  a minute: sent/answered/failed, latency mean/stdev, plus the most recent
  answer's rdata and minimum TTL (a TTL counting down between probes proves the
  answer came from cache). This gives the failure-by-query matrix real
  denominators — "tigo.cl fails 12% of the time on resolver X", not just a
  raw failure count;
- `events_classified` — a view stamping every event `isolated` / `partial` /
  `fleet-wide` from the number of servers down at that instant.

### `profile`

A one-shot **capability & hygiene audit** of one or more resolvers — twenty
pointed questions instead of a stream of probes:

```bash
python main.py profile 1.1.1.1 8.8.8.8         # or read servers.txt
python main.py profile --hijack-zone cl --json audit.json
python main.py profile --oarc                          # add spoofability raters
```

Checks per server:

- **Transports** — UDP, TCP (RFC 7766 mandates it), and DNS-over-TLS on 853.
- **EDNS0** — OPT echoed back, or stripped by a middlebox.
- **DNSSEC** — three angles: RRSIGs returned under the DO bit, the AD bit on a
  signed domain, and the decisive one: the intentionally-broken
  `dnssec-failed.org` must SERVFAIL on a validating resolver; an address back
  means the resolver protects nobody.
- **0x20 case echo** — a mixed-case query must come back byte-identical;
  rewriting means a middlebox is normalising your DNS.
- **Cache snooping** — an `RD=0` query shows whether outsiders can read the
  cache.
- **ANY handling** — minimal HINFO (RFC 8482) / refused / full amplification
  fodder.
- **NXDOMAIN honesty** — a random label under `--hijack-zone` must be NXDOMAIN
  (plus the negative-cache TTL from the SOA).
- **Identity** — `id.server` / `version.bind` (CHAOS) and NSID (RFC 5001):
  which anycast instance is actually answering you.
- **Egress & privacy** — `whoami.akamai.net` and Google's
  `o-o.myaddr.l.google.com` reveal the address the resolver recurses from
  (single box vs. farm) and whether your subnet is forwarded upstream via ECS.
- **QNAME minimisation** (RFC 7816) via `qnamemin-test.internet.nl`.
- **Rebind filtering** — a private address via `nip.io`: filtered or passed.
- **Spoofability** (`--oarc`, slow) — DNS-OARC's `porttest` / `txidtest` grade
  the resolver's source-port and TXID randomness GOOD/FAIR/POOR.

Checks that depend on third-party test services are skipped with `--offline`.

### `compare`

Ask **every resolver the same questions simultaneously** and cluster the
answers — the direct test for tampering, stale caches, or a broken forwarder:

```bash
python main.py compare --qname-file dns.txt            # servers from servers.txt
python main.py compare 1.1.1.1 8.8.8.8 --qnames example.com,emol.com:A
```

Answers are grouped by *overlap*, not exact equality: CDN names hand out
rotating subsets of one address pool, so honest resolvers rarely match
byte-for-byte but always intersect — a cluster shows as `N agree` (identical)
or `N overlap` (rotating pool). An answer sharing *nothing* with the rest is
flagged `OUTLIER`; judge it by what it returns (a private IP, an ad portal, or
the ISP's own webserver is a conviction; a plausible CDN address in another
region is not). Exits non-zero when any outlier or timeout was seen, so it
drops straight into a cron alert.

### `export`

Dump a `--log-db` failure database to a spreadsheet for analysis — **CSV** or
**XLSX** (real Excel-readable `.xlsx`, written with nothing but the standard
library, so still no third-party deps):

```bash
# Headline view: every per-server snapshot stamped with its failure event.
python main.py export dns-failures.db -o failures.xlsx

# Plain CSV (format inferred from the extension; or force it with --format).
python main.py export dns-failures.db -o failures.csv

# All three tables — separate sheets in XLSX, separate files in CSV.
python main.py export dns-failures.db -o failures.xlsx --table all
```

`--table` picks what to export:

- `joined` (default) — each `server_status` row with its triggering event's
  timestamp / trigger columns prepended: "the fleet's state at the moment of
  each failure" in one flat sheet.
- `events` — the raw failure events.
- `server_status` — the raw per-server snapshots.
- `samples` — the periodic KPI trace.
- `triage` — the failure-classification batteries.
- `query_stats` — the per-(server, query) counters.
- `all` — every table present in the log (one sheet per table in XLSX; one
  suffixed `.csv` file per table in CSV, since a CSV holds one table). Tables
  a given log predates are skipped.

The database is opened read-only, so exporting never touches the log you're
analysing.

**KPIs shown per server:**

- **State / availability** — UP/DOWN, the *current query* in flight, queries
  sent/answered, all-time and recent-window availability %, timeout rate,
  network-error rate, effective QPS, and a 0–100 *stability index* (a documented
  heuristic combining recent availability with tail-latency and jitter penalties).
- **Latency (ms)** — last, min, mean, p50/p90/p95/p99 (over the recent window),
  max, standard deviation, RFC 3550-style smoothed **jitter**, an EWMA, and the
  **coefficient of variation** (stdev/mean — a scale-free stability number).
- **Answers** — RCODE breakdown (NOERROR/SERVFAIL/NXDOMAIN/…), the number of
  distinct *queries* probed, plus *inconsistent* and *answer-flap* counters: a
  TTL-independent signature of the answer section is compared across probes of
  the **same** question, so a name that flaps or is inconsistently
  load-balanced stands out (without false-flagging the normal variation between
  different pool names).
- **ICMP / ping** — alongside the DNS probe, each server is also pinged once
  per interval (via the system `ping`, no root needed) on its own thread, so you
  get a reachability/RTT *side-channel*: ping state, sent/received, **success**
  and **loss** rate, and RTT last/min/mean/max/jitter. Comparing this against
  the DNS columns separates "the box is unreachable" from "the resolver is slow
  or dropping queries" (ICMP is often firewalled even where DNS answers — that
  shows as `ping loss` while DNS stays green). Disable with `--no-icmp`.
- **Streaks** — current up/down streak, longest healthy and longest failing
  runs, the last error seen, and the *query that last errored* (handy with a
  pool — it tells you which name is failing).

Per-server **sparklines** at the bottom (DNS `latency ~` and ICMP `ping ~`) give
an instant visual read on stability (gaps mark timeouts / lost echoes).
Everything is pure stdlib — `curses`, one UDP socket per server for DNS, and a
shell-out to `ping` for ICMP, each paced on its own thread against a wall clock
so a slow server (or a blocked ping) never delays the others' cadence.

## Output columns

`offered` / `sent` / `answered` are QPS the test *asked for*, *managed to
send*, and *got answers for*. `handled` is what Unbound itself counted. When
`sent` drops below `offered`, or `answered` below `sent`, the resolver (or the
network/client) is the bottleneck. `reqlist` is Unbound's max request-list
length during the step — a key recursion-saturation signal.

## Prerequisites on the Unbound host

The monitor needs `unbound-control` working over SSH. On the resolver host
ensure remote control is enabled in `unbound.conf`:

```
remote-control:
    control-enable: yes
```

then `unbound-control-setup` (once) and confirm `unbound-control status`
returns. Use `--sudo` if `unbound-control` requires root.

## Interpreting results / tuning Unbound

The `random` strategy stresses recursion; `fixed` stresses the cache and raw
packet throughput.

> **Warning — `random` against a real domain is a random-subdomain NXDOMAIN
> flood.** Every `<random>.example.com` recursion lands on the domain's real
> authoritative servers, so the latency you measure depends on infrastructure
> you don't control (and looks like an attack to its operators). Worse, RFC
> 8198 aggressive NSEC caching can let the resolver answer many of those names
> from the negative cache — quietly defeating the "force recursion" intent.
> For controlled results point `--qname` at a wildcard zone on an authoritative
> server you run in the lab (a second Unbound with a `local-zone` works fine).

If you saturate on recursion (high recursion time, rising
`reqlist`), the relevant Unbound knobs are `num-threads`,
`num-queries-per-thread`, `outgoing-range`, and `so-rcvbuf`/`so-sndbuf`. For
raw throughput, `num-threads`, `so-reuseport: yes` and `msg-cache-size` /
`rrset-cache-size` matter most.

## Scaling the load generator

A single Python process tops out around 10–15k QPS — one asyncio thread doing
both sends and receives becomes the ceiling long before a tuned Unbound does.
If you see high client-side timeouts while Unbound's own `requestlist.exceeded`
stays at 0, you are measuring the generator, not the resolver.

Two levers:

- **`--workers N`** (on both `client` and `ramp`) forks N generator processes
  and splits the target QPS across them, then aggregates the results into one
  report. Start with `--workers` ≈ number of CPU cores:

  ```bash
  python main.py ramp --target 10.0.0.5 --qps-start 5000 --qps-stop 60000 \
      --qps-step 5000 --duration 15 --workers 8 \
      --ssh-host 10.0.0.5 --ssh-user root --sudo \
      --unbound-control "unbound-control -c /var/unbound/unbound.conf"
  ```

- **UDP socket buffers.** The generator already requests a large `SO_RCVBUF`
  (16 MB) to stop the kernel silently dropping responses, but the OS caps it.
  On macOS/BSD raise the cap first:

  ```bash
  sudo sysctl -w kern.ipc.maxsockbuf=33554432   # 32 MB
  ```

  On Linux: `sudo sysctl -w net.core.rmem_max=33554432`.

For loads beyond what one machine can generate, run `client`/`ramp` on several
machines against the same target and sum the results.
```
