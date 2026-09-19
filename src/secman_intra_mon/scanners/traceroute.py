"""traceroute adapter — finds routers between us and discovered hosts.

Hop addresses that are not part of the target's own subnet reveal router
interfaces; each router interface implies an adjacent subnet the discovery
engine can iterate into.
"""

from __future__ import annotations

import ipaddress
import re

from .base import run_tool

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
TRACE_TIMEOUT = 60


def trace_hops(target: str, max_hops: int = 8, timeout: int = TRACE_TIMEOUT) -> list[str]:
    """Return the ordered hop addresses on the path to target (best effort)."""
    argv = [
        "traceroute",
        "-n",
        "-q",
        "1",
        "-w",
        "2",
        "-m",
        str(max_hops),
        target,
    ]
    proc = run_tool(argv, timeout)
    if proc.returncode != 0:
        return []
    hops: list[str] = []
    for line in proc.stdout.splitlines():
        for candidate in _IP_RE.findall(line):
            try:
                ipaddress.ip_address(candidate)
            except ValueError:
                continue
            if candidate != target and candidate not in hops:
                hops.append(candidate)
    return hops
