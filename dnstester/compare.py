"""Cross-resolver answer comparison (the *compare* subcommand).

Ask every server the same questions at the same moment and group the answers:
servers that agree cluster together, and a resolver returning something
different from everyone else sticks out immediately — the direct test for
tampering, stale caches, or a misconfigured forwarder. Timeouts are their own
group, so "who couldn't answer at all" is part of the same picture.

Caveat printed with the output: CDN-backed names can legitimately differ per
resolver (each resolver may be steered to a different PoP), so an outlier
*answer set* is a lead, not a conviction — the giveaway is an outlier that is
not a plausible CDN address (a private IP, an ad-server, the ISP's own web
portal) or one that flaps between probes (the poller's `answer flaps` KPI).
"""

from __future__ import annotations

import random
import time
from concurrent.futures import ThreadPoolExecutor

from . import wire
from .audit import _udp
from .poller import parse_server


def _query_one(
    host: str, port: int, name: str, qtype: str, timeout: float, edns_size: int
) -> dict:
    """One server × one query -> outcome dict. Retries once, like a stub."""
    qtype_int = wire.QTYPES.get(qtype.upper(), 1)
    qname_wire = wire.encode_name(name)
    for _attempt in range(2):
        qid = random.randrange(1 << 16)
        packet = wire.build_query(qid, qname_wire, qtype_int, edns_size)
        t0 = time.perf_counter()
        data = _udp(host, port, packet, qid, timeout)
        if data is not None:
            ms = (time.perf_counter() - t0) * 1000.0
            rcode = wire.parse_response(data)[1]  # type: ignore[index]
            sig = wire.answer_signature(data)
            details = wire.answer_details(data)
            ttl, text = details if details is not None else (None, "")
            return {
                "server": f"{host}:{port}",
                "ok": True,
                "rcode": wire.RCODES.get(rcode, str(rcode)),
                "sig": sig,
                "ttl": ttl,
                "answer": text,
                "ms": round(ms, 1),
            }
    return {"server": f"{host}:{port}", "ok": False}


def run_compare(
    servers: list[str],
    port: int,
    queries: list[tuple[str, str]],
    timeout: float = 2.0,
    edns_size: int = 1232,
) -> list[dict]:
    """For each query, every server's answer grouped by (rcode, answer set).

    Servers are asked in parallel per query so the snapshots are simultaneous —
    sequential queries would let short-TTL CDN rotation masquerade as
    disagreement.
    """
    parsed = [parse_server(s, port) for s in servers]
    results: list[dict] = []
    with ThreadPoolExecutor(max_workers=max(1, len(parsed))) as pool:
        for name, qtype in queries:
            outcomes = list(
                pool.map(
                    lambda hp: _query_one(hp[0], hp[1], name, qtype, timeout, edns_size),
                    parsed,
                )
            )
            answered = [o for o in outcomes if o["ok"]]
            timeouts = [o["server"] for o in outcomes if not o["ok"]]
            results.append({
                "query": f"{name} {qtype}",
                "groups": _cluster(answered),
                "timeouts": timeouts,
            })
    return results


def _cluster(answered: list[dict]) -> list[dict]:
    """Group answers by *overlap*, not exact equality.

    Load-balanced / CDN names hand out rotating subsets of one address pool,
    so two honest resolvers rarely return byte-identical sets — but their sets
    intersect. Union-find on "shares at least one record (same rcode)" keeps
    a rotating pool in one cluster while a genuinely foreign answer (a hijack
    portal, a stale forwarder) shares nothing and stays an outlier.
    """
    n = len(answered)
    parent = list(range(n))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    for i in range(n):
        for j in range(i + 1, n):
            a, b = answered[i], answered[j]
            if a["rcode"] != b["rcode"]:
                continue
            sa, sb = a["sig"] or frozenset(), b["sig"] or frozenset()
            same_empty = not sa and not sb  # e.g. both NXDOMAIN / both NODATA
            if same_empty or (sa & sb):
                parent[find(i)] = find(j)

    clusters: dict[int, dict] = {}
    for idx, o in enumerate(answered):
        g = clusters.setdefault(
            find(idx),
            {"servers": [], "rcode": o["rcode"], "answer": o["answer"],
             "identical": True, "first_sig": o["sig"], "ttls": [], "ms": []},
        )
        g["servers"].append(o["server"])
        if o["sig"] != g["first_sig"]:
            g["identical"] = False
        if o["ttl"] is not None:
            g["ttls"].append(o["ttl"])
        g["ms"].append(o["ms"])
    for g in clusters.values():
        del g["first_sig"]
    return sorted(clusters.values(), key=lambda g: -len(g["servers"]))


def print_compare(results: list[dict], total_servers: int, file=None) -> None:
    print(
        "Answer agreement across resolvers (note: CDN-backed names can "
        "legitimately differ per resolver — judge outliers by *what* they "
        "return, not just that they differ):",
        file=file,
    )
    for entry in results:
        print(f"\n{entry['query']}", file=file)
        multi = sum(1 for g in entry["groups"] if len(g["servers"]) > 1)
        for g in entry["groups"]:
            n = len(g["servers"])
            if n > 1:
                mark = " "
                tag = f"{n} agree " if g["identical"] else f"{n} overlap"
            elif len(entry["groups"]) == 1:
                mark, tag = " ", "1 server"
            else:
                mark, tag = "!", "OUTLIER "
            ttls = g["ttls"]
            ttl_s = (
                f"ttl {min(ttls)}" if ttls and min(ttls) == max(ttls)
                else f"ttl {min(ttls)}-{max(ttls)}" if ttls else "no answer data"
            )
            answer = g["answer"] or f"(empty {g['rcode']})"
            note = "" if g["identical"] or n == 1 else " (rotating pool — sets differ but share records)"
            print(f" {mark} {tag} {', '.join(g['servers'])}", file=file)
            print(f"           -> {answer}  [{g['rcode']}, {ttl_s}]{note}", file=file)
        for s in entry["timeouts"]:
            print(f" ! TIMEOUT  {s}", file=file)


def to_jsonable(results: list[dict]) -> list[dict]:
    """Strip the unserialisable signature sets for --json output."""
    out = []
    for entry in results:
        out.append({
            "query": entry["query"],
            "timeouts": entry["timeouts"],
            "groups": [
                {k: v for k, v in g.items() if k != "sig"} for g in entry["groups"]
            ],
        })
    return out
