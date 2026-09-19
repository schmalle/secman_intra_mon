"""fping adapter — fast ICMP sweep for host discovery."""

from __future__ import annotations

import ipaddress

from ..models import DiscoveredHost
from ..scope import IpNetwork
from .base import ScannerError, run_tool


def ping_sweep(network: IpNetwork, timeout: int | None = None) -> list[DiscoveredHost]:
    """Return hosts answering ICMP. Non-alive addresses are not reported (-a)."""
    if timeout is None:
        timeout = min(60 + network.num_addresses // 5, 900)
    argv = ["fping", "-a", "-q", "-r", "1", "-g", str(network)]
    proc = run_tool(argv, timeout)
    # fping exits 1 when no host answered — that is a valid empty result.
    if proc.returncode not in (0, 1):
        raise ScannerError(f"fping failed: {proc.stderr.strip()[:300]}")
    hosts: list[DiscoveredHost] = []
    for line in proc.stdout.splitlines():
        candidate = line.strip()
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue
        hosts.append(DiscoveredHost(ip=candidate, discovered_via="fping"))
    return hosts
