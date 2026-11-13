"""One-shot resolver capability & hygiene audit (the *profile* subcommand).

Where *poll* watches quality over time, this asks a resolver twenty pointed
one-off questions and prints a scorecard: which transports it speaks, whether
it validates DNSSEC, whether anything between you and it rewrites packets,
who it actually is (anycast instance / egress), and how honest its answers
are. Every check is a plain DNS query built with :mod:`dnstester.wire` —
pure stdlib, DoT included via :mod:`ssl`.

Some checks lean on well-known public test services (marked *external*; skip
them with ``--offline``):

- ``dnssec-failed.org`` — Comcast's intentionally-broken DNSSEC zone: a
  validating resolver must SERVFAIL it, a non-validating one hands back an
  address.
- ``whoami.akamai.net`` / ``o-o.myaddr.l.google.com`` — echo the address the
  resolver used to reach Akamai / Google (the *egress*), and Google also
  reveals whether your subnet was forwarded upstream via EDNS Client Subnet.
- ``qnamemin-test.internet.nl`` — reports whether the resolver minimises
  QNAMEs (RFC 7816) instead of leaking full names to the roots.
- ``porttest.dns-oarc.net`` / ``txidtest.dns-oarc.net`` — DNS-OARC's
  spoofability raters: they watch the queries the resolver sends them and
  grade its source-port and transaction-id randomness (GOOD / FAIR / POOR).
- ``nip.io`` — resolves ``a.b.c.d.nip.io`` to ``a.b.c.d``; asking for a
  private address through it reveals whether the resolver filters RFC 1918
  answers (DNS-rebind protection).
"""

from __future__ import annotations

import random
import socket
import ssl
import string
import time

from . import wire

# Levels for console colouring / JSON.
OK, WARN, BAD, INFO = "ok", "warn", "bad", "info"

_SIGNED_NAME = "cloudflare.com"  # long-standing DNSSEC-signed zone
_BOGUS_NAME = "dnssec-failed.org"  # intentionally broken DNSSEC (Comcast)
_CACHED_NAME = "example.com"  # near-certain to be cacheable anywhere


# --- low-level exchanges -----------------------------------------------------


def _udp(host: str, port: int, packet: bytes, qid: int, timeout: float) -> bytes | None:
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            t0 = time.perf_counter()
            s.send(packet)
            deadline = t0 + timeout
            while True:
                data = s.recv(65535)
                parsed = wire.parse_response(data)
                if parsed is not None and parsed[0] == qid:
                    return data
                if time.perf_counter() >= deadline:
                    return None
                s.settimeout(max(0.0, deadline - time.perf_counter()))
    except OSError:
        return None


def _recv_exact(s: socket.socket, n: int) -> bytes | None:
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def _framed(sock: socket.socket, packet: bytes, qid: int) -> bytes | None:
    """Send/receive one query over an already-connected stream socket."""
    sock.sendall(len(packet).to_bytes(2, "big") + packet)
    hdr = _recv_exact(sock, 2)
    if hdr is None:
        return None
    body = _recv_exact(sock, int.from_bytes(hdr, "big"))
    if body is None:
        return None
    parsed = wire.parse_response(body)
    return body if parsed is not None and parsed[0] == qid else None


def _tcp(host: str, port: int, packet: bytes, qid: int, timeout: float) -> bytes | None:
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            return _framed(s, packet, qid)
    except OSError:
        return None


def _dot(host: str, packet: bytes, qid: int, timeout: float) -> bytes | None:
    """DNS over TLS on port 853 (RFC 7858). Certificate is not verified —
    this is a capability probe, not a trust decision."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, 853), timeout=timeout) as raw:
            raw.settimeout(timeout)
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                return _framed(s, packet, qid)
    except (OSError, ssl.SSLError):
        return None


def _ask(
    host: str,
    port: int,
    name: str,
    qtype: str,
    timeout: float,
    edns_size: int = 1232,
    *,
    transport: str = "udp",
    qclass: int = 1,
    rd: bool = True,
    dnssec_ok: bool = False,
    nsid: bool = False,
) -> tuple[bytes | None, float]:
    """One question, one answer: ``(raw_response | None, elapsed_ms)``."""
    qid = random.randrange(1 << 16)
    packet = wire.build_query(
        qid, wire.encode_name(name), wire.QTYPES.get(qtype.upper(), 1), edns_size,
        qclass=qclass, rd=rd, dnssec_ok=dnssec_ok, nsid=nsid,
    )
    t0 = time.perf_counter()
    if transport == "tcp":
        data = _tcp(host, port, packet, qid, timeout)
    elif transport == "dot":
        data = _dot(host, packet, qid, timeout)
    else:
        data = _udp(host, port, packet, qid, timeout)
    return data, (time.perf_counter() - t0) * 1000.0


def _rcode(data: bytes) -> int:
    return wire.parse_response(data)[1]  # type: ignore[index]


def _txt(data: bytes | None) -> str:
    if data is None:
        return ""
    details = wire.answer_details(data)
    return details[1] if details else ""


# --- the checks ----------------------------------------------------------------

Check = tuple[str, str, str]  # (key, value, level)


def profile_server(
    host: str,
    port: int,
    timeout: float = 2.0,
    edns_size: int = 1232,
    hijack_zone: str = "com",
    offline: bool = False,
    oarc: bool = False,
) -> list[Check]:
    """Run every check against one resolver, returning ordered results.

    ``offline`` skips checks that depend on third-party test services;
    ``oarc`` additionally enables the (slow) DNS-OARC randomness raters.
    """
    out: list[Check] = []
    add = out.append

    # -- transport ------------------------------------------------------------
    udp_resp, udp_ms = _ask(host, port, _CACHED_NAME, "A", timeout, edns_size)
    if udp_resp is None:
        add(("udp", "NO ANSWER — nothing else can be tested", BAD))
        return out
    flags = wire.response_flags(udp_resp) or {}
    add(("udp", f"yes, {udp_ms:.1f}ms, {wire.RCODES.get(_rcode(udp_resp), '?')}", OK))
    add(("recursion (RA)", "yes" if flags.get("ra") else "NO — not a recursive resolver for us",
         OK if flags.get("ra") else BAD))

    tcp_resp, tcp_ms = _ask(host, port, _CACHED_NAME, "A", timeout, edns_size, transport="tcp")
    add(("tcp", f"yes, {tcp_ms:.1f}ms" if tcp_resp else "NO — RFC 7766 requires it; big answers will fail",
         OK if tcp_resp else BAD))

    dot_resp, dot_ms = _ask(host, port, _CACHED_NAME, "A", timeout + 1, edns_size, transport="dot")
    add(("dns-over-tls :853", f"yes, {dot_ms:.1f}ms" if dot_resp else "no", OK if dot_resp else INFO))

    # -- EDNS / identity --------------------------------------------------------
    nsid_resp, _ = _ask(host, port, _CACHED_NAME, "A", timeout, edns_size, nsid=True)
    if nsid_resp is not None:
        has_opt = any(
            rrtype == 41
            for _s, rrtype, _c, _t, _o, _l in wire._iter_records(nsid_resp, "additional")
        )
        add(("edns0", "yes (OPT echoed)" if has_opt else "NO — OPT stripped (old server or middlebox)",
             OK if has_opt else WARN))
        nsid = wire.opt_nsid(nsid_resp)
        add(("nsid", nsid or "-", INFO))
    else:
        add(("edns0", "no answer to EDNS query — possible EDNS-hostile middlebox", WARN))

    for label, names in (("id.server", ("id.server", "hostname.bind")),
                         ("version", ("version.server", "version.bind"))):
        value = ""
        for n in names:
            r, _ = _ask(host, port, n, "TXT", timeout, 0, qclass=3)
            value = _txt(r)
            if value:
                break
        add((label, value or "-", INFO))

    # -- DNSSEC -----------------------------------------------------------------
    do_resp, _ = _ask(host, port, _SIGNED_NAME, "A", timeout, edns_size, dnssec_ok=True)
    if do_resp is not None:
        types = wire.answer_rrtypes(do_resp)
        rrsig = 46 in types
        ad = (wire.response_flags(do_resp) or {}).get("ad", False)
        add(("dnssec rrsig", "returned with DO" if rrsig else "not returned", OK if rrsig else WARN))
        add(("dnssec ad bit", "set (validates + trusts path)" if ad else "not set", OK if ad else INFO))
    else:
        add(("dnssec rrsig", "no answer to DO query", WARN))
    if not offline:
        bogus, _ = _ask(host, port, _BOGUS_NAME, "A", timeout + 2, edns_size)
        if bogus is None:
            add(("dnssec validation", "unknown (no answer for bogus domain)", INFO))
        elif _rcode(bogus) == 2:
            add(("dnssec validation", f"yes — bogus {_BOGUS_NAME} -> SERVFAIL", OK))
        elif wire.answer_rrtypes(bogus):
            add(("dnssec validation", f"NO — bogus {_BOGUS_NAME} accepted (returned an address)", BAD))
        else:
            add(("dnssec validation", f"unclear ({wire.RCODES.get(_rcode(bogus), '?')}, empty)", INFO))

    # -- packet integrity / hygiene ----------------------------------------------
    rand = "".join(random.choice(string.ascii_lowercase) for _ in range(10))
    mixed = "".join(c.upper() if i % 2 else c for i, c in enumerate(rand)) + ".ExAmPlE.CoM"
    qid = random.randrange(1 << 16)
    mixed_wire = wire.encode_name(mixed)
    echo = _udp(host, port, wire.build_query(qid, mixed_wire, 1, edns_size), qid, timeout)
    if echo is None:
        add(("0x20 case echo", "no answer", INFO))
    else:
        preserved = wire.question_bytes(echo) == mixed_wire
        add(("0x20 case echo", "preserved" if preserved
             else "REWRITTEN — a middlebox is normalising your queries", OK if preserved else BAD))

    rd0, _ = _ask(host, port, _CACHED_NAME, "A", timeout, edns_size, rd=False)
    if rd0 is None:
        add(("rd=0 (cache snoop)", "no answer", INFO))
    elif _rcode(rd0) == 5:
        add(("rd=0 (cache snoop)", "REFUSED (snooping blocked)", OK))
    elif wire.answer_rrtypes(rd0):
        add(("rd=0 (cache snoop)", "answers from cache (cache is publicly snoopable)", WARN))
    else:
        add(("rd=0 (cache snoop)", "empty answer", OK))

    any_resp, _ = _ask(host, port, _SIGNED_NAME, "ANY", timeout, edns_size)
    if any_resp is None:
        add(("any query", "no answer", INFO))
    else:
        types = wire.answer_rrtypes(any_resp)
        rc = _rcode(any_resp)
        if types == {13}:
            add(("any query", "minimal HINFO (RFC 8482)", OK))
        elif rc in (4, 5):  # NOTIMP / REFUSED — ANY sensibly disabled
            add(("any query", f"{wire.RCODES.get(rc)} (ANY disabled)", OK))
        elif types:
            add(("any query", f"{len(types)} rrtype(s) returned (amplification-friendly)", WARN))
        else:
            add(("any query", "empty answer", INFO))

    hijack_name = f"dnstester-{random.getrandbits(48):012x}.{hijack_zone}"
    hj, _ = _ask(host, port, hijack_name, "A", timeout + 2, edns_size)
    if hj is None:
        add(("nxdomain honesty", "no answer", INFO))
    elif _rcode(hj) == 3:
        neg = wire.soa_min_ttl(hj)
        add(("nxdomain honesty", "honest NXDOMAIN", OK))
        add(("negative-cache ttl", f"{neg}s" if neg is not None else "-", INFO))
    elif wire.answer_rrtypes(hj):
        add(("nxdomain honesty", f"HIJACKED — {_txt(hj)} returned for a nonexistent name", BAD))
    else:
        add(("nxdomain honesty", f"{wire.RCODES.get(_rcode(hj), '?')} (empty)", INFO))

    # -- external observers ------------------------------------------------------
    if not offline:
        egress, _ = _ask(host, port, "whoami.akamai.net", "A", timeout + 2, edns_size)
        add(("egress ip (akamai)", _txt(egress) or "-", INFO))

        gtxt = _txt(_ask(host, port, "o-o.myaddr.l.google.com", "TXT", timeout + 2, edns_size)[0])
        if gtxt:
            ecs = "edns0-client-subnet" in gtxt
            add(("egress (google)", gtxt, INFO))
            add(("ecs forwarded", "yes — your subnet is sent upstream" if ecs else "no", INFO))
        else:
            add(("egress (google)", "-", INFO))

        qmin = _txt(_ask(host, port, "a.b.qnamemin-test.internet.nl", "TXT", timeout + 2, edns_size)[0])
        if "HOORAY" in qmin:
            add(("qname minimisation", "yes (RFC 7816)", OK))
        elif qmin:
            add(("qname minimisation", "NO — full names leak toward the roots", WARN))
        else:
            add(("qname minimisation", "unknown", INFO))

        rebind, _ = _ask(host, port, "10.13.37.1.nip.io", "A", timeout + 2, edns_size)
        if rebind is None:
            add(("rebind filtering", "unknown (no answer)", INFO))
        else:
            details = wire.answer_details(rebind)
            got_private = details is not None and "10.13.37.1" in details[1]
            add(("rebind filtering", "none — private addresses pass through" if got_private
                 else "filters private answers (rebind protection)",
                 INFO if got_private else OK))

    if oarc and not offline:
        for label, name in (("source-port randomness", "porttest.dns-oarc.net"),
                            ("txid randomness", "txidtest.dns-oarc.net")):
            txt = _txt(_ask(host, port, name, "TXT", 10.0, edns_size)[0])
            level = OK if "GOOD" in txt else BAD if "POOR" in txt else WARN if "FAIR" in txt else INFO
            add((label, txt or "unknown (service unreachable through this resolver)", level))

    return out


_MARK = {OK: "+", WARN: "~", BAD: "!", INFO: " "}


def print_profile(server: str, checks: list[Check], file=None) -> None:
    print(f"\n== {server} " + "=" * max(0, 58 - len(server)), file=file)
    for key, value, level in checks:
        print(f" {_MARK[level]} {key:<22} {value}", file=file)
