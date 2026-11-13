"""Export a poller failure-log database (see :mod:`dnstester.dblog`) to CSV or XLSX.

The ``poll --log-db`` sink writes two tables: ``events`` (one row per probe
failure) and ``server_status`` (the whole fleet's last-known state captured at
each failure). This module reads them back out for analysis in a spreadsheet.

Three logical tables can be exported:

``events``
    the raw failure events.
``server_status``
    the raw per-server snapshots.
``joined``
    a denormalised view — every ``server_status`` row with its triggering
    event's timestamp / trigger columns prepended, i.e. "the fleet's state at
    the moment of each failure" in one flat sheet. This is usually the one you
    want.

Output format is chosen by ``--format`` or inferred from the output extension
(``.csv`` -> csv, ``.xlsx``/``.xls`` -> xlsx). XLSX is written with nothing but
the standard library: an ``.xlsx`` file is a zip of XML parts, which we build
directly with :mod:`zipfile`, so the project stays dependency-free. For CSV,
where one file holds one table, exporting several tables writes one ``.csv``
per table next to the chosen path (``out_events.csv``, ``out_status.csv``, ...).
"""

from __future__ import annotations

import csv
import os
import sqlite3
import zipfile
from xml.sax.saxutils import escape

# The logical tables we can export, mapped to the SQL that produces them. The
# 'joined' view is the headline: each fleet snapshot stamped with its event.
_QUERIES: dict[str, str] = {
    "events": "SELECT * FROM events ORDER BY id",
    "server_status": (
        "SELECT * FROM server_status ORDER BY event_id, server"
    ),
    "joined": (
        "SELECT e.id AS event_id, e.ts, e.iso, "
        "e.trigger_server, e.trigger_kind, e.trigger_detail, "
        "s.server, s.up, s.sent, s.answered, s.timeouts, s.errors, "
        "s.availability, s.recent_availability, s.last_ms, s.p95_ms, "
        "s.stability, s.last_error, s.last_query, s.last_error_query, "
        "s.icmp_enabled, s.icmp_up, s.icmp_success, s.icmp_last_ms "
        "FROM events e JOIN server_status s ON s.event_id = e.id "
        "ORDER BY e.id, s.server"
    ),
    "samples": "SELECT * FROM samples ORDER BY ts, server",
    "triage": "SELECT * FROM triage ORDER BY ts",
    "query_stats": "SELECT * FROM query_stats ORDER BY ts, server, query",
}

# Short suffixes used when one CSV-per-table is written from a single path.
_CSV_SUFFIX = {
    "events": "events",
    "server_status": "status",
    "joined": "joined",
    "samples": "samples",
    "triage": "triage",
    "query_stats": "queries",
}


class ExportError(Exception):
    """Raised for user-facing problems (missing db, unknown table, ...)."""


def _fetch(conn: sqlite3.Connection, table: str) -> tuple[list[str], list[tuple]]:
    """Run a logical table's query, returning (column_names, rows)."""
    sql = _QUERIES.get(table)
    if sql is None:
        raise ExportError(f"unknown table {table!r}")
    try:
        cur = conn.execute(sql)
    except sqlite3.OperationalError as exc:
        # Most likely the db wasn't produced by --log-db, so the table is absent.
        raise ExportError(f"cannot read table {table!r}: {exc}") from exc
    cols = [d[0] for d in cur.description]
    return cols, cur.fetchall()


# --- CSV ---------------------------------------------------------------------


def _write_csv(path: str, cols: list[str], rows: list[tuple]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(cols)
        w.writerows(rows)


# --- XLSX (stdlib-only minimal writer) --------------------------------------
#
# An .xlsx is an OPC zip package. We emit the minimal set of parts Excel /
# LibreOffice / Numbers need: content-types, the root relationship, a workbook
# listing the sheets, the workbook relationships, and one worksheet part per
# table. Cell values are written inline (no shared-strings table) which keeps
# the writer to a single pass and a few dozen lines.

_CONTENT_TYPES_HEAD = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
    '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
    '<Default Extension="xml" ContentType="application/xml"/>'
    '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
)
_ROOT_RELS = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
    '</Relationships>'
)


def _col_ref(idx: int) -> str:
    """0-based column index -> spreadsheet letters (0->A, 26->AA)."""
    s = ""
    idx += 1
    while idx:
        idx, rem = divmod(idx - 1, 26)
        s = chr(65 + rem) + s
    return s


def _safe_sheet_name(name: str, used: set[str]) -> str:
    """Excel sheet names: <=31 chars, none of []:*?/\\, and unique."""
    clean = "".join("_" if c in r"[]:*?/\\" else c for c in name)[:31] or "Sheet"
    base, n = clean, 1
    while clean in used:
        suffix = f"_{n}"
        clean = base[: 31 - len(suffix)] + suffix
        n += 1
    used.add(clean)
    return clean


def _cell(ref: str, value) -> str:
    if value is None or value == "":
        return f'<c r="{ref}"/>'
    if isinstance(value, bool):  # bool before int — bool is a subclass of int
        return f'<c r="{ref}"><v>{int(value)}</v></c>'
    if isinstance(value, (int, float)):
        return f'<c r="{ref}"><v>{value}</v></c>'
    text = escape(str(value))
    return f'<c r="{ref}" t="inlineStr"><is><t xml:space="preserve">{text}</t></is></c>'


def _sheet_xml(cols: list[str], rows: list[tuple]) -> str:
    parts = [
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">',
        "<sheetData>",
    ]
    parts.append('<row r="1">')
    parts.extend(_cell(f"{_col_ref(i)}1", c) for i, c in enumerate(cols))
    parts.append("</row>")
    for r, row in enumerate(rows, start=2):
        parts.append(f'<row r="{r}">')
        parts.extend(_cell(f"{_col_ref(i)}{r}", v) for i, v in enumerate(row))
        parts.append("</row>")
    parts.append("</sheetData></worksheet>")
    return "".join(parts)


def _write_xlsx(path: str, sheets: list[tuple[str, list[str], list[tuple]]]) -> None:
    """sheets: list of (sheet_name, columns, rows)."""
    used: set[str] = set()
    named = [(_safe_sheet_name(name, used), cols, rows) for name, cols, rows in sheets]

    content_types = [_CONTENT_TYPES_HEAD]
    wb_sheets = []
    wb_rels = []
    for i, (name, _cols, _rows) in enumerate(named, start=1):
        content_types.append(
            f'<Override PartName="/xl/worksheets/sheet{i}.xml" '
            'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        )
        wb_sheets.append(f'<sheet name="{escape(name)}" sheetId="{i}" r:id="rId{i}"/>')
        wb_rels.append(
            f'<Relationship Id="rId{i}" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
            f'Target="worksheets/sheet{i}.xml"/>'
        )
    content_types.append("</Types>")

    workbook = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        "<sheets>" + "".join(wb_sheets) + "</sheets></workbook>"
    )
    workbook_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        + "".join(wb_rels)
        + "</Relationships>"
    )

    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", "".join(content_types))
        z.writestr("_rels/.rels", _ROOT_RELS)
        z.writestr("xl/workbook.xml", workbook)
        z.writestr("xl/_rels/workbook.xml.rels", workbook_rels)
        for i, (_name, cols, rows) in enumerate(named, start=1):
            z.writestr(f"xl/worksheets/sheet{i}.xml", _sheet_xml(cols, rows))


# --- orchestration -----------------------------------------------------------


def infer_format(out_path: str, explicit: str | None) -> str:
    if explicit:
        return explicit
    ext = os.path.splitext(out_path)[1].lower()
    if ext in (".xlsx", ".xls"):
        return "xlsx"
    if ext == ".csv":
        return "csv"
    raise ExportError(
        f"cannot infer format from {out_path!r}; pass --format csv|xlsx"
    )


def _resolve_tables(table: str) -> list[str]:
    if table == "all":
        return ["joined", "events", "server_status", "samples", "triage", "query_stats"]
    if table not in _QUERIES:
        raise ExportError(
            f"unknown table {table!r}; choose from "
            f"{', '.join(_QUERIES)} or 'all'"
        )
    return [table]


def export(db_path: str, out_path: str, fmt: str, table: str = "joined") -> list[str]:
    """Export `table` from `db_path` to `out_path` in `fmt`. Returns files written."""
    if not os.path.exists(db_path):
        raise ExportError(f"database not found: {db_path}")
    tables = _resolve_tables(table)

    # Read-only connection so we never mutate the log being analysed.
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        if table == "all":
            # Older logs predate some tables (samples/triage/query_stats):
            # export what exists rather than failing the whole run.
            fetched = []
            for t in tables:
                try:
                    fetched.append((t, *_fetch(conn, t)))
                except ExportError:
                    continue
            if not fetched:
                raise ExportError("no exportable tables found in this database")
        else:
            fetched = [(t, *_fetch(conn, t)) for t in tables]
    finally:
        conn.close()

    if fmt == "xlsx":
        _write_xlsx(out_path, [(t, cols, rows) for t, cols, rows in fetched])
        return [out_path]

    if fmt == "csv":
        if len(fetched) == 1:
            t, cols, rows = fetched[0]
            _write_csv(out_path, cols, rows)
            return [out_path]
        # Several tables, one CSV each: insert the suffix before the extension.
        stem, ext = os.path.splitext(out_path)
        ext = ext or ".csv"
        written = []
        for t, cols, rows in fetched:
            p = f"{stem}_{_CSV_SUFFIX.get(t, t)}{ext}"
            _write_csv(p, cols, rows)
            written.append(p)
        return written

    raise ExportError(f"unknown format {fmt!r}")
