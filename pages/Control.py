"""Control panel: manage the resolver/domain lists and run the poller.

A thin web front-end over the ``dnstester poll --headless`` command. It edits
two plain-text files — ``servers.txt`` (the resolvers to probe) and ``dns.txt``
(the query pool, passed as ``--qname-file``) — then launches the poller as a
background subprocess that logs failures to ``dns-failures.db`` (``--log-db``).
Those two paths are the defaults here; the Dashboard page reads the same db.

The run is a detached child process, not a thread, so it survives Streamlit's
script reruns and a browser reload: its PID and output live in small dotfiles
(``.poll.pid`` / ``.poll.log``) that this page reads back to show status and
offer a Stop button. Stopping sends SIGTERM, which the headless runner handles
by flushing the SQLite log and exiting.
"""

from __future__ import annotations

import ipaddress
import os
import re
import signal
import subprocess
import sys
from pathlib import Path

import streamlit as st

# Anchor every path to the repo root (this file lives in pages/), so the app
# behaves the same regardless of the directory Streamlit was launched from.
ROOT = Path(__file__).resolve().parent.parent
MAIN_PY = ROOT / "main.py"               # the CLI entry we launch
SERVERS_FILE = ROOT / "servers.txt"
QNAME_FILE = ROOT / "dns.txt"            # --qname-file default

# Comment blocks written at the top of each file on save (keep in sync with
# the committed servers.txt / dns.txt).
SERVERS_HEADER = "# servers.txt — DNS resolvers to test, one per line.\n#\n# Read by:  python main.py poll | profile | compare | register   (--servers-file)\n#           and the web Control page, which rewrites this file on save.\n#\n# Accepted forms (literal IP addresses only, no hostnames):\n#   8.8.8.8                  IPv4, port 53\n#   8.8.8.8:5353             IPv4 with port\n#   2606:4700:4700::1111     IPv6, port 53\n#   [2606:4700:4700::1111]:53  IPv6 with port (brackets required)\n# Blank lines and anything after '#' are ignored.\n#\n# Keep only public resolvers in the committed copy. Add ISP or internal\n# resolvers locally and do not commit them.\n\n"
QNAME_HEADER = "# dns.txt — query pool: the domains each resolver is asked for, one per line.\n#\n# Read by:  python main.py poll | compare | register   (--qname-file)\n#           and the web Control page, which rewrites this file on save.\n#\n# Accepted forms:\n#   example.com              queried with the default type (--qtype, default A)\n#   example.com:AAAA         explicit record type (A, AAAA, MX, NS, TXT, ...)\n# Blank lines and anything after '#' are ignored.\n\n"
LOG_DB = ROOT / "dns-failures.db"        # --log-db default
PID_FILE = ROOT / ".poll.pid"
RUN_LOG = ROOT / ".poll.log"
REG_PID_FILE = ROOT / ".register.pid"
REG_LOG = ROOT / ".register.log"


def read_lines(path: Path) -> list[str]:
    """Non-empty, non-comment lines from a list file (order preserved)."""
    if not path.exists():
        return []
    out = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            out.append(line)
    return out


def write_list(path: Path, header: str, items: list[str]) -> None:
    """Persist a cleaned list, keeping a short comment header."""
    seen, clean = set(), []
    for it in items:
        it = it.strip()
        if it and it not in seen:        # drop blanks and dupes
            seen.add(it)
            clean.append(it)
    path.write_text(header + "\n".join(clean) + "\n", encoding="utf-8")


# A DNS name: dot-separated labels of letters/digits/hyphen (and a leading
# underscore for service names like _dmarc), each starting/ending alphanumeric.
_LABEL = r"[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9])?"
_DOMAIN_RE = re.compile(rf"^(?=.{{1,253}}$){_LABEL}(?:\.{_LABEL})*\.?$")
_QTYPE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9]*$")


def validate_server(entry: str) -> tuple[bool, str]:
    """Accept only a literal IP address, optionally with a port.

    Forms: ``ip``, ``ip:port``, or ``[v6]:port``. Returns ``(ok, normalized)``
    on success or ``(False, reason)`` so the caller can show what's wrong —
    keeping ``servers.txt`` free of hostnames, typos, and junk.
    """
    s = entry.strip()
    host, port = s, None
    if s.startswith("["):                       # [v6] or [v6]:port
        host, sep, rest = s[1:].partition("]")
        if not sep:
            return False, "missing closing ']'"
        if rest:
            if not rest.startswith(":"):
                return False, "expected ':port' after ']'"
            port = rest[1:]
    elif s.count(":") == 1:                      # ipv4:port (a bare v6 has 2+)
        host, _, port = s.partition(":")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False, f"not a valid IP address: {host!r}"
    if port is not None and (not port.isdigit() or not 1 <= int(port) <= 65535):
        return False, f"invalid port: {port!r}"
    return True, s


def validate_domain(entry: str) -> tuple[bool, str]:
    """Accept a clean DNS name, optionally suffixed ``:QTYPE`` (e.g. A, AAAA)."""
    s = entry.strip()
    name, sep, qtype = s.partition(":")
    if sep and not _QTYPE_RE.match(qtype):
        return False, f"invalid query type: {qtype!r}"
    if not _DOMAIN_RE.match(name.strip()):
        return False, f"invalid characters in domain name: {name.strip()!r}"
    return True, s


def save_validated(path: Path, header: str, raw_text: str, validator, name: str) -> bool:
    """Validate every non-blank line, then save — or report bad lines and abort."""
    items, errors = [], []
    for line in raw_text.splitlines():
        s = line.split("#", 1)[0].strip()
        if not s:
            continue
        ok, res = validator(s)
        (items if ok else errors).append(res if ok else f"`{s}` — {res}")
    if errors:
        st.error("Nothing saved — fix these lines first:\n" + "\n".join(f"- {e}" for e in errors))
        return False
    write_list(path, header, items)
    st.success(f"Saved {name}")
    return True


# Command-line matchers identifying each background child of ours. The poll
# command carries "--headless"; the registrar carries the "register" subcommand.
# Neither matches the other, so the two are tracked independently.
def _is_poll(cmd: str) -> bool:
    return str(MAIN_PY) in cmd and "--headless" in cmd


def _is_register(cmd: str) -> bool:
    return str(MAIN_PY) in cmd and "register" in cmd.split()


def _process_cmd(pid: int) -> str | None:
    """The command line of a PID, or None if no such process exists."""
    try:
        r = subprocess.run(
            ["ps", "-p", str(pid), "-o", "command="],
            capture_output=True, text=True, timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return r.stdout.strip() or None


def _scan_for(matches) -> int | None:
    """Scan the whole process table for a process whose command ``matches``.

    Independent of any pid file, so an orphaned run (pid file deleted, or one
    started straight from a terminal) is still found — that's what stops us
    launching a duplicate.
    """
    try:
        out = subprocess.run(
            ["ps", "-ax", "-o", "pid=,command="],
            capture_output=True, text=True, timeout=5,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    for line in out.splitlines():
        pid_str, _, cmd = line.strip().partition(" ")
        if pid_str.isdigit() and matches(cmd):
            return int(pid_str)
    return None


def running_pid(pid_file: Path, matches) -> int | None:
    """Authoritative check for one of our background children — verified vs the OS.

    Prefers the pid file (cheap) but confirms that PID *actually* matches, to
    guard against a recycled PID pointing at some unrelated process. Falls back
    to a full process-table scan so an orphaned run is still detected and never
    double-started. Returns the live PID or None.
    """
    if pid_file.exists():
        try:
            pid = int(pid_file.read_text().strip())
        except (ValueError, OSError):
            pid = None
        if pid is not None:
            cmd = _process_cmd(pid)
            if cmd and matches(cmd):
                return pid
    found = _scan_for(matches)
    if found:
        pid_file.write_text(str(found))   # adopt the orphan so Stop can reach it
        return found
    pid_file.unlink(missing_ok=True)      # nothing running — clear any stale file
    return None


def terminate(pid_file: Path, matches) -> None:
    """SIGTERM the tracked process (if any) and clear its pid file."""
    pid = running_pid(pid_file, matches)
    if pid:
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass
    pid_file.unlink(missing_ok=True)


def poll_pid() -> int | None:
    return running_pid(PID_FILE, _is_poll)


def reg_pid() -> int | None:
    return running_pid(REG_PID_FILE, _is_register)


def start_poll(servers: list[str], interval: float, qname_strategy: str, icmp: bool) -> str | None:
    """Launch the headless poller as a background process. Returns an error str."""
    if poll_pid():
        return "A poll is already running."
    if not servers:
        return "Add at least one DNS server first."
    if not read_lines(QNAME_FILE):
        return "Add at least one domain first."

    # Guard the command line: only feed the poller validated IPs / domains.
    bad_s = [s for s in servers if not validate_server(s)[0]]
    if bad_s:
        return "Invalid server(s) in servers.txt: " + ", ".join(bad_s)
    bad_d = [d for d in read_lines(QNAME_FILE) if not validate_domain(d)[0]]
    if bad_d:
        return "Invalid domain(s) in dns.txt: " + ", ".join(bad_d)

    cmd = [
        sys.executable, str(MAIN_PY), "poll", *servers,
        "--qname-file", str(QNAME_FILE),
        "--log-db", str(LOG_DB),
        "--interval", str(interval),
        "--qname-strategy", qname_strategy,
        "--headless",
    ]
    if not icmp:
        cmd.append("--no-icmp")

    log = open(RUN_LOG, "w")  # noqa: SIM115 — handed to the child, closed on exit
    proc = subprocess.Popen(
        cmd, cwd=str(ROOT), stdout=log, stderr=subprocess.STDOUT,
        start_new_session=True,  # detach from Streamlit's process group
    )
    PID_FILE.write_text(str(proc.pid))
    return None


def stop_poll() -> None:
    terminate(PID_FILE, _is_poll)


def start_register(interval: float) -> str | None:
    """Launch the periodic registrar as a background process. Returns an error str."""
    if reg_pid():
        return "The registrar is already running."
    cmd = [
        sys.executable, str(MAIN_PY), "register",
        "--servers-file", str(SERVERS_FILE),
        "--qname-file", str(QNAME_FILE),
        "--log-db", str(LOG_DB),
        "--interval", str(interval),
    ]
    log = open(REG_LOG, "w")  # noqa: SIM115 — handed to the child, closed on exit
    proc = subprocess.Popen(
        cmd, cwd=str(ROOT), stdout=log, stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    REG_PID_FILE.write_text(str(proc.pid))
    return None


def stop_register() -> None:
    terminate(REG_PID_FILE, _is_register)


# --- page ---------------------------------------------------------------------

st.set_page_config(page_title="DNStester Control", page_icon="🎛️", layout="wide")
st.title("🎛️ DNStester Control Panel")
st.caption(
    "Manage the resolvers and domains, then run the poller. Failures are logged "
    f"to `{LOG_DB.name}` — view them on the **Dashboard** page."
)

servers = read_lines(SERVERS_FILE)
domains = read_lines(QNAME_FILE)

col_s, col_d = st.columns(2)

with col_s:
    st.subheader("DNS servers")
    st.caption("One resolver per line — `host`, `host:port`, or `[v6]:port`.")
    servers_text = st.text_area(
        "servers", value="\n".join(servers), height=220, label_visibility="collapsed",
    )
    if st.button("💾 Save servers", use_container_width=True):
        if save_validated(
            SERVERS_FILE,
            SERVERS_HEADER,
            servers_text, validate_server, "servers.txt",
        ):
            st.rerun()

with col_d:
    st.subheader("Domains (query pool)")
    st.caption("One name per line — optionally `name:QTYPE` (e.g. `example.com:AAAA`).")
    domains_text = st.text_area(
        "domains", value="\n".join(domains), height=220, label_visibility="collapsed",
    )
    if st.button("💾 Save domains", use_container_width=True):
        if save_validated(
            QNAME_FILE,
            QNAME_HEADER,
            domains_text, validate_domain, "dns.txt",
        ):
            st.rerun()

st.divider()
st.subheader("Run the poller")

pid = poll_pid()
c1, c2, c3 = st.columns(3)
interval = c1.number_input("Probe interval (s)", min_value=0.1, value=1.0, step=0.1)
strategy = c2.selectbox(
    "Query strategy", ["fixed", "random"],
    help="fixed: ask the names as-is (cache/serving path); "
    "random: prepend a unique label to force cache misses / recursion.",
)
icmp = c3.checkbox("ICMP ping side-channel", value=True)

st.caption(
    f"Command: `dnstester poll {' '.join(servers) or '<servers>'} "
    f"--qname-file {QNAME_FILE.name} --log-db {LOG_DB.name} --headless`"
)

run_col, stop_col, _ = st.columns([1, 1, 4])
if pid:
    stop_col.button(
        "⏹️ Stop", type="primary", use_container_width=True,
        on_click=lambda: (stop_poll(), st.toast("Stopping…")),
    )
    run_col.success(f"Running (PID {pid})")
else:
    if run_col.button("▶️ Start", type="primary", use_container_width=True):
        err = start_poll(servers, interval, strategy, icmp)
        if err:
            st.error(err)
        else:
            st.toast("Poller started")
            st.rerun()

st.divider()
st.subheader("Auto-register new servers & domains")
st.caption(
    "A background watcher that scans `servers.txt` / `dns.txt` on an interval "
    "and records any newly-added entry to the result db — but only after it "
    "passes a verifying DNS query (new servers probed directly; new domains "
    "resolved against an already-verified server)."
)

rpid = reg_pid()
reg_interval = st.number_input(
    "Scan interval (s)", min_value=1.0, value=5.0, step=1.0, key="reg_interval"
)
st.caption(
    f"Command: `dnstester register --servers-file {SERVERS_FILE.name} "
    f"--qname-file {QNAME_FILE.name} --log-db {LOG_DB.name}`"
)
rrun_col, rstop_col, _ = st.columns([1, 1, 4])
if rpid:
    rstop_col.button(
        "⏹️ Stop registrar", type="primary", use_container_width=True,
        on_click=lambda: (stop_register(), st.toast("Stopping registrar…")),
    )
    rrun_col.success(f"Running (PID {rpid})")
else:
    if rrun_col.button("▶️ Start registrar", use_container_width=True):
        err = start_register(reg_interval)
        if err:
            st.error(err)
        else:
            st.toast("Registrar started")
            st.rerun()

# Live log tails. While either child is running the fragment re-runs every 2s on
# its own (run_every) without rerunning the whole page; otherwise it runs once.
@st.fragment(run_every=2 if (pid or rpid) else None)
def run_output() -> None:
    poll_alive, reg_alive = poll_pid(), reg_pid()
    for title, log_path, was_running, is_running in (
        ("Poller output", RUN_LOG, pid, poll_alive),
        ("Registrar output", REG_LOG, rpid, reg_alive),
    ):
        label = f"🟢 {title} (live)" if is_running else title
        with st.expander(label, expanded=bool(was_running)):
            if log_path.exists():
                tail = log_path.read_text(encoding="utf-8", errors="replace").splitlines()[-25:]
                st.code("\n".join(tail) or "(no output yet)", language="text")
            else:
                st.caption("Not run yet.")
    # If a child exited on its own, refresh the whole page so its controls flip
    # back to "Start" and the auto-refresh timer can wind down.
    if (pid and not poll_alive) or (rpid and not reg_alive):
        st.rerun()


run_output()
