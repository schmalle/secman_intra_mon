"""arp-scan adapter — layer-2 discovery on directly connected segments.

Requires root (raw Ethernet frames) and layer-2 adjacency: it cannot work
across routers or inside a bridged Docker network.
"""

from __future__ import annotations

import ipaddress
import re

from ..models import DiscoveredHost
from ..scope import IpNetwork
from .base import ScannerError, run_tool

_LINE_RE = re.compile(r"^(\S+)\t([0-9a-fA-F:]{17})\t?(.*)$")
DUP_MARKER = "(DUP:"


def arp_sweep(
    network: IpNetwork, interface: str | None = None, timeout: int | None = None
) -> list[DiscoveredHost]:
    if timeout is None:
        timeout = min(120 + network.num_addresses // 10, 900)
    argv = ["arp-scan"]
    if interface:
        argv += ["--interface", interface]
    argv += ["--retry", "2", str(network)]
    proc = run_tool(argv, timeout)
    if proc.returncode != 0:
        raise ScannerError(f"arp-scan failed: {proc.stderr.strip()[:300]}")

    hosts: dict[str, DiscoveredHost] = {}
    for line in proc.stdout.splitlines():
        if DUP_MARKER in line:
            line = line.split(DUP_MARKER)[0].rstrip()
        match = _LINE_RE.match(line.strip())
        if not match:
            continue
        ip, mac, vendor = match.groups()
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue
        hosts[ip] = DiscoveredHost(
            ip=ip,
            mac=mac.upper(),
            mac_vendor=vendor.strip() or None,
            discovered_via="arp-scan",
        )
    return list(hosts.values())
