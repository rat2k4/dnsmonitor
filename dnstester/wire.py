"""Minimal DNS wire-format helpers.

Just enough of RFC 1035 to build an A/AAAA/whatever query and read the ID and
RCODE back out of a response. Kept dependency-free and allocation-light because
this runs on the hot path of the load generator.
"""

from __future__ import annotations

import socket
import struct

# QTYPE values we care about; extend as needed.
QTYPES: dict[str, int] = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
    "SOA": 6,
    "PTR": 12,
    "MX": 15,
    "TXT": 16,
    "AAAA": 28,
    "SRV": 33,
    "SVCB": 64,
    "HTTPS": 65,
    "ANY": 255,
}

# RCODE names for the low nibble of the response flags.
RCODES: dict[int, str] = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}

_FLAGS_RD = 0x0100  # standard query, recursion desired


def encode_name(name: str) -> bytes:
    """Encode a domain name into DNS label format (no compression)."""
    out = bytearray()
    for label in name.rstrip(".").split("."):
        if not label:
            continue
        raw = label.encode("idna") if not label.isascii() else label.encode("ascii")
        if len(raw) > 63:
            raise ValueError(f"label too long: {label!r}")
        out.append(len(raw))
        out.extend(raw)
    out.append(0)
    return bytes(out)


def build_query(
    qid: int,
    qname_wire: bytes,
    qtype: int,
    edns_size: int = 0,
    *,
    qclass: int = 1,
    rd: bool = True,
    dnssec_ok: bool = False,
    nsid: bool = False,
) -> bytes:
    """Assemble a query packet from a pre-encoded name and a query id.

    ``qname_wire`` is the output of :func:`encode_name` so callers can encode a
    fixed name once and reuse it across millions of packets.

    ``edns_size`` > 0 appends an EDNS0 OPT pseudo-record (RFC 6891) advertising
    that UDP payload size. Without EDNS a response is limited to 512 bytes and
    anything larger comes back truncated; 1232 is the common modern default.

    The keyword extras exist for the audit checks: ``qclass=3`` asks CHAOS
    (id.server / version.bind), ``rd=False`` probes cache-snooping policy,
    ``dnssec_ok`` sets the DO bit (top bit of the OPT TTL field) so a
    validating resolver returns RRSIGs and the AD bit, and ``nsid`` attaches an
    empty NSID option (RFC 5001) asking the server to identify itself.
    """
    flags = _FLAGS_RD if rd else 0
    arcount = 1 if edns_size else 0
    header = struct.pack("!HHHHHH", qid & 0xFFFF, flags, 1, 0, 0, arcount)
    packet = header + qname_wire + struct.pack("!HH", qtype, qclass)
    if edns_size:
        # OPT RR: root name, type 41, class = requestor's UDP size; the TTL
        # field is [ext-rcode(8) | version(8) | flags(16)] and DO is the top
        # bit of the flags half (RFC 6891 §6.1.4).
        opt_ttl = 0x8000 if dnssec_ok else 0
        rdata = struct.pack("!HH", 3, 0) if nsid else b""
        packet += b"\x00" + struct.pack("!HHIH", 41, edns_size, opt_ttl, len(rdata)) + rdata
    return packet


def parse_response(data: bytes) -> tuple[int, int, bool] | None:
    """Return ``(qid, rcode, truncated)`` from a response, or ``None`` if too short."""
    if len(data) < 4:
        return None
    qid = (data[0] << 8) | data[1]
    rcode = data[3] & 0x0F
    truncated = bool(data[2] & 0x02)  # TC bit: the full answer didn't fit
    return qid, rcode, truncated


def _skip_name(data: bytes, off: int) -> int:
    """Advance ``off`` past a (possibly compressed) domain name. RFC 1035 §4.1.4."""
    n = len(data)
    while off < n:
        length = data[off]
        if length == 0:
            return off + 1
        if length & 0xC0 == 0xC0:  # compression pointer: 2 bytes, name ends here
            return off + 2
        off += 1 + length
    return off


def answer_signature(data: bytes) -> frozenset[tuple[int, bytes]] | None:
    """Return a TTL-independent signature of a response's answer section.

    The signature is the set of ``(rrtype, rdata)`` pairs in the answer section,
    deliberately ignoring TTLs and record ordering so that the *content* of the
    answer can be compared across probes. Two probes that resolve to the same
    addresses produce the same signature; a server that is flapping or
    inconsistently load-balancing produces different signatures over time.

    Returns ``None`` if the message is malformed/truncated (so callers can tell
    "couldn't read it" apart from "empty answer", which is an empty frozenset).
    """
    if len(data) < 12:
        return None
    qdcount = (data[4] << 8) | data[5]
    ancount = (data[6] << 8) | data[7]
    off = 12
    try:
        for _ in range(qdcount):  # skip questions: name + qtype(2) + qclass(2)
            off = _skip_name(data, off) + 4
        records: list[tuple[int, bytes]] = []
        for _ in range(ancount):
            off = _skip_name(data, off)
            rrtype = (data[off] << 8) | data[off + 1]
            rdlength = (data[off + 8] << 8) | data[off + 9]
            rdata_start = off + 10
            rdata = bytes(data[rdata_start : rdata_start + rdlength])
            if len(rdata) != rdlength:
                return None  # truncated rdata
            records.append((rrtype, rdata))
            off = rdata_start + rdlength
    except IndexError:
        return None
    return frozenset(records)


def _read_name(data: bytes, off: int, depth: int = 0) -> tuple[str, int]:
    """Decode a (possibly compressed) name for display. Returns ``(text, next_off)``.

    ``next_off`` is the offset after the name *at the original position* (a
    compression pointer consumes 2 bytes regardless of where it points).
    ``depth`` guards against pointer loops in hostile/corrupt messages.
    """
    labels: list[str] = []
    n = len(data)
    while off < n:
        length = data[off]
        if length == 0:
            return ".".join(labels) or ".", off + 1
        if length & 0xC0 == 0xC0:  # compression pointer
            if depth > 8 or off + 1 >= n:
                return ".".join(labels), off + 2
            target = ((length & 0x3F) << 8) | data[off + 1]
            suffix, _ = _read_name(data, target, depth + 1)
            labels.append(suffix)
            return ".".join(labels), off + 2
        labels.append(data[off + 1 : off + 1 + length].decode("ascii", "replace"))
        off += 1 + length
    return ".".join(labels), off


def _render_rdata(rrtype: int, rdata: bytes, data: bytes, rdata_off: int) -> str:
    """Human-readable rdata for the common types; hex for everything else."""
    try:
        if rrtype == 1 and len(rdata) == 4:  # A
            return socket.inet_ntop(socket.AF_INET, rdata)
        if rrtype == 28 and len(rdata) == 16:  # AAAA
            return socket.inet_ntop(socket.AF_INET6, rdata)
        if rrtype in (2, 5, 12):  # NS / CNAME / PTR: a single name
            return _read_name(data, rdata_off)[0]
        if rrtype == 15 and len(rdata) > 2:  # MX: preference + name
            pref = (rdata[0] << 8) | rdata[1]
            return f"{pref} {_read_name(data, rdata_off + 2)[0]}"
        if rrtype == 16:  # TXT: length-prefixed strings
            parts, i = [], 0
            while i < len(rdata):
                ln = rdata[i]
                parts.append(rdata[i + 1 : i + 1 + ln].decode("ascii", "replace"))
                i += 1 + ln
            return " ".join(parts)
    except (OSError, IndexError, ValueError):
        pass
    return rdata.hex() if len(rdata) <= 16 else f"{rdata[:16].hex()}…({len(rdata)}B)"


def answer_details(data: bytes) -> tuple[int | None, str] | None:
    """Return ``(min_ttl, "rdata, rdata, ...")`` for a response's answer section.

    The TTL is the smallest across the answer records — on a repeated query it
    counting down between probes is direct evidence the answer came from cache,
    while snapping back to its ceiling means a fresh recursion. The rdata string
    makes answer flaps inspectable (CDN rotation vs. something being rewritten).

    Returns ``None`` for a malformed/truncated message; ``(None, "")`` for an
    empty answer section (e.g. NXDOMAIN).
    """
    if len(data) < 12:
        return None
    qdcount = (data[4] << 8) | data[5]
    ancount = (data[6] << 8) | data[7]
    off = 12
    min_ttl: int | None = None
    parts: list[str] = []
    try:
        for _ in range(qdcount):
            off = _skip_name(data, off) + 4
        for _ in range(ancount):
            off = _skip_name(data, off)
            rrtype = (data[off] << 8) | data[off + 1]
            ttl = (data[off + 4] << 24) | (data[off + 5] << 16) | (data[off + 6] << 8) | data[off + 7]
            rdlength = (data[off + 8] << 8) | data[off + 9]
            rdata_start = off + 10
            rdata = bytes(data[rdata_start : rdata_start + rdlength])
            if len(rdata) != rdlength:
                return None
            if rrtype != 41:  # OPT is metadata, not an answer
                min_ttl = ttl if min_ttl is None else min(min_ttl, ttl)
                parts.append(_render_rdata(rrtype, rdata, data, rdata_start))
            off = rdata_start + rdlength
    except IndexError:
        return None
    return min_ttl, ", ".join(parts)


def response_flags(data: bytes) -> dict[str, bool] | None:
    """Header flag bits that matter for diagnosis: qr/tc/rd/ra/ad/cd."""
    if len(data) < 4:
        return None
    hi, lo = data[2], data[3]
    return {
        "qr": bool(hi & 0x80),
        "tc": bool(hi & 0x02),
        "rd": bool(hi & 0x01),
        "ra": bool(lo & 0x80),
        "ad": bool(lo & 0x20),  # answer validated by a DNSSEC-aware resolver
        "cd": bool(lo & 0x10),
    }


def question_bytes(data: bytes) -> bytes | None:
    """Raw qname bytes of the first question, exactly as the server echoed them.

    Question names are never compressed, so this is a straight scan to the root
    label. Comparing it byte-for-byte against the sent name detects middleboxes
    that rewrite the question (they typically normalise the 0x20 mixed case).
    """
    if len(data) < 13 or ((data[4] << 8) | data[5]) < 1:
        return None
    off = 12
    n = len(data)
    while off < n:
        length = data[off]
        if length == 0:
            return bytes(data[12 : off + 1])
        if length & 0xC0:
            return None  # compressed/invalid in a question — bail out
        off += 1 + length
    return None


def _iter_records(data: bytes, *sections: str):
    """Yield ``(section, rrtype, rrclass, ttl, rdata_off, rdlength)`` for the
    requested sections ('answer', 'authority', 'additional')."""
    if len(data) < 12:
        return
    counts = {
        "answer": (data[6] << 8) | data[7],
        "authority": (data[8] << 8) | data[9],
        "additional": (data[10] << 8) | data[11],
    }
    off = 12
    try:
        for _ in range((data[4] << 8) | data[5]):  # questions
            off = _skip_name(data, off) + 4
        for section in ("answer", "authority", "additional"):
            for _ in range(counts[section]):
                off = _skip_name(data, off)
                rrtype = (data[off] << 8) | data[off + 1]
                rrclass = (data[off + 2] << 8) | data[off + 3]
                ttl = int.from_bytes(data[off + 4 : off + 8], "big")
                rdlength = (data[off + 8] << 8) | data[off + 9]
                rdata_off = off + 10
                if rdata_off + rdlength > len(data):
                    return
                if section in sections:
                    yield section, rrtype, rrclass, ttl, rdata_off, rdlength
                off = rdata_off + rdlength
    except IndexError:
        return


def opt_nsid(data: bytes) -> str | None:
    """The NSID (RFC 5001) string from the response's OPT record, if present."""
    for _sec, rrtype, _cls, _ttl, rd_off, rd_len in _iter_records(data, "additional"):
        if rrtype != 41:
            continue
        off, end = rd_off, rd_off + rd_len
        while off + 4 <= end:
            code = (data[off] << 8) | data[off + 1]
            olen = (data[off + 2] << 8) | data[off + 3]
            val = data[off + 4 : off + 4 + olen]
            if code == 3:
                try:
                    return val.decode("ascii")
                except UnicodeDecodeError:
                    return val.hex()
            off += 4 + olen
    return None


def soa_min_ttl(data: bytes) -> int | None:
    """Effective negative-caching TTL from the authority SOA (RFC 2308):
    min(SOA record TTL, SOA minimum field). None if no SOA present."""
    for _sec, rrtype, _cls, ttl, rd_off, rd_len in _iter_records(data, "authority"):
        if rrtype != 6 or rd_len < 20:
            continue
        off = _skip_name(data, rd_off)  # mname
        off = _skip_name(data, off)  # rname
        if off + 20 > rd_off + rd_len:
            continue
        minimum = int.from_bytes(data[off + 16 : off + 20], "big")
        return min(ttl, minimum)
    return None


def answer_rrtypes(data: bytes) -> set[int]:
    """The set of record types in the answer section (for ANY / RRSIG checks)."""
    return {rrtype for _s, rrtype, _c, _t, _o, _l in _iter_records(data, "answer")}
