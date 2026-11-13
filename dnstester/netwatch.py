"""Local-network awareness for the poller.

If the box running the tests loses its own network — default gateway gone —
every DNS probe is doomed regardless of how healthy the resolvers are. Logging
those failures would poison the statistics ("all servers down for 10 minutes"
when it was the local Wi-Fi), so the poll manager watches the default gateway
and pauses all probing while it is unreachable.

This module only knows how to *find* the gateway, cross-platform and stdlib
only; the watchdog loop itself lives in :class:`dnstester.poller.PollManager`.
"""

from __future__ import annotations

import socket
import struct
import subprocess


def default_gateway() -> str | None:
    """Best-effort default-gateway address for this host, or None.

    Tries, in order: ``/proc/net/route`` (Linux, no subprocess), ``route -n
    get default`` (macOS/BSD), ``ip route show default`` (Linux without
    procfs access). IPv4 only — the watchdog just needs *something* on the
    local segment to ping.
    """
    try:
        with open("/proc/net/route", encoding="ascii") as fh:
            for line in list(fh)[1:]:
                fields = line.split()
                # default route (dest 0.0.0.0) with the gateway flag set
                if len(fields) >= 4 and fields[1] == "00000000" and int(fields[3], 16) & 0x2:
                    return socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))
    except (OSError, ValueError):
        pass
    for argv, marker in (
        (["route", "-n", "get", "default"], "gateway:"),
        (["ip", "route", "show", "default"], "via"),
    ):
        try:
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=3)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if proc.returncode != 0:
            continue
        if marker == "gateway:":
            for line in proc.stdout.splitlines():
                line = line.strip()
                if line.startswith(marker):
                    return line.split(":", 1)[1].strip() or None
        else:
            parts = proc.stdout.split()
            if marker in parts and parts.index(marker) + 1 < len(parts):
                return parts[parts.index(marker) + 1]
    return None
