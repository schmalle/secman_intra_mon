"""nmap adapter — the primary scanner.

Runs nmap with XML to stdout (`-oX -`) and parses the result. The XML is
produced by our own nmap invocation; stdlib ElementTree (no DTD/external
entities) is used for parsing.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET

from ..models import DiscoveredHost, DiscoveredPort
from .base import ScannerError, run_tool

#: scan profile -> nmap port-selection arguments
PROFILES: dict[str, list[str]] = {
    "fast": ["--top-ports", "100"],
    "default": ["--top-ports", "1000"],
    "full": ["-p-"],
}

DISCOVERY_TIMEOUT = 900
SERVICE_SCAN_TIMEOUT = 5400


def host_discovery(
    targets: list[str], arp: bool, timeout: int = DISCOVERY_TIMEOUT
) -> tuple[list[DiscoveredHost], str]:
    """Ping-sweep style discovery. Returns (hosts, raw_xml)."""
    argv = ["nmap", "-sn", "-n", "-T4", "--max-retries", "2"]
    if arp:
        argv.append("-PR")
    argv += ["-oX", "-", *targets]
    proc = run_tool(argv, timeout)
    if proc.returncode != 0:
        raise ScannerError(f"nmap host discovery failed: {proc.stderr.strip()[:300]}")
    return parse_nmap_xml(proc.stdout), proc.stdout


def service_scan(
    targets: list[str],
    profile: str = "default",
    os_scan: bool = False,
    ports: str | None = None,
    timeout: int = SERVICE_SCAN_TIMEOUT,
) -> tuple[list[DiscoveredHost], str]:
    """Service/version scan of live hosts. Returns (hosts, raw_xml)."""
    argv = ["nmap", "-sV", "--version-intensity", "4", "-n", "-T4"]
    if ports:
        argv += ["-p", ports]
    else:
        argv += PROFILES.get(profile, PROFILES["default"])
    if os_scan:
        argv.append("-O")
    argv += ["--host-timeout", "300s", "-oX", "-", *targets]
    proc = run_tool(argv, timeout)
    if proc.returncode != 0:
        raise ScannerError(f"nmap service scan failed: {proc.stderr.strip()[:300]}")
    return parse_nmap_xml(proc.stdout), proc.stdout


def parse_nmap_xml(xml_text: str) -> list[DiscoveredHost]:
    """Parse nmap `-oX` output (also accepts masscan `-oX`, a compatible subset)."""
    try:
        root = ET.fromstring(xml_text.strip())
    except ET.ParseError as exc:
        raise ScannerError(f"failed to parse scanner XML output: {exc}") from exc
    if root.tag != "nmaprun":
        raise ScannerError(f"unexpected XML root element {root.tag!r} (expected 'nmaprun')")

    hosts: list[DiscoveredHost] = []
    for host_el in root.iter("host"):
        status_el = host_el.find("status")
        if status_el is None or status_el.get("state") != "up":
            continue

        ip: str | None = None
        mac: str | None = None
        mac_vendor: str | None = None
        for addr_el in host_el.findall("address"):
            addrtype = addr_el.get("addrtype", "")
            if addrtype in ("ipv4", "ipv6") and ip is None:
                ip = addr_el.get("addr")
            elif addrtype == "mac":
                mac = addr_el.get("addr")
                mac_vendor = addr_el.get("vendor")
        if ip is None:
            continue

        hostname: str | None = None
        hostnames_el = host_el.find("hostnames")
        if hostnames_el is not None:
            for hn_el in hostnames_el.findall("hostname"):
                name = hn_el.get("name")
                if name:
                    hostname = name
                    if hn_el.get("type") == "PTR":
                        break

        ports: list[DiscoveredPort] = []
        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") not in ("open", "filtered"):
                    continue
                service_el = port_el.find("service")
                ports.append(
                    DiscoveredPort(
                        port=int(port_el.get("portid", "0")),
                        protocol=port_el.get("protocol", "tcp"),
                        state=state_el.get("state", "open"),
                        service=service_el.get("name", "") if service_el is not None else "",
                        product=service_el.get("product", "") if service_el is not None else "",
                        version=service_el.get("version", "") if service_el is not None else "",
                    )
                )

        os_guess: str | None = None
        os_el = host_el.find("os")
        if os_el is not None:
            match_el = os_el.find("osmatch")
            if match_el is not None:
                os_guess = match_el.get("name")

        hosts.append(
            DiscoveredHost(
                ip=ip,
                mac=mac,
                mac_vendor=mac_vendor,
                hostname=hostname,
                os_guess=os_guess,
                ports=ports,
            )
        )
    return hosts
