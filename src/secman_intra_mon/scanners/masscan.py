"""masscan adapter — optional fast port discovery.

masscan finds open ports quickly; results are then handed to nmap `-sV` for
verification and service detail (see discovery engine, profile "masscan").
Requires root and a rate limit — the default rate is deliberately moderate
for intranet use.
"""

from __future__ import annotations

from ..models import DiscoveredHost
from ..scope import IpNetwork
from .base import ScannerError, run_tool
from .nmap import parse_nmap_xml

DEFAULT_RATE = 1000  # packets/second; intranet-friendly
DEFAULT_PORTS = "1-10000"


def port_sweep(
    network: IpNetwork,
    ports: str = DEFAULT_PORTS,
    rate: int = DEFAULT_RATE,
    timeout: int | None = None,
) -> tuple[list[DiscoveredHost], str]:
    """Discover open ports on a network. Returns (hosts, raw_xml)."""
    if timeout is None:
        timeout = min(300 + network.num_addresses // 2, 3600)
    argv = [
        "masscan",
        str(network),
        "-p",
        ports,
        "--rate",
        str(rate),
        "--open-only",
        "-oX",
        "-",
    ]
    proc = run_tool(argv, timeout)
    if proc.returncode != 0:
        raise ScannerError(f"masscan failed: {proc.stderr.strip()[:300]}")
    return parse_nmap_xml(proc.stdout), proc.stdout
