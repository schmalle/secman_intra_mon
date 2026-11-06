"""Deterministic, local asset classification.

The classifier deliberately uses only scanner observations.  It is available
without an LLM and provides a conservative network-device/server distinction;
``unknown`` is preferable to inventing a confident type from weak evidence.
"""

from __future__ import annotations

from dataclasses import dataclass

from .models import DiscoveredHost

NETWORK_SERVICES = {
    "bgp",
    "bootpc",
    "bootps",
    "domain",
    "ike",
    "isakmp",
    "netconf-ssh",
    "rip",
    "snmp",
    "snmptrap",
}
NETWORK_PORTS = {53, 67, 68, 161, 162, 179, 500, 520, 830}
SERVER_SERVICES = {
    "ftp",
    "http",
    "https",
    "imap",
    "ldap",
    "microsoft-ds",
    "ms-sql-s",
    "mysql",
    "nfs",
    "pop3",
    "postgresql",
    "smtp",
    "ssh",
}
SERVER_PORTS = {21, 22, 25, 80, 110, 143, 389, 443, 445, 2049, 3306, 3389, 5432, 8080, 8443}
NETWORK_HINTS = (
    "cisco",
    "juniper",
    "router",
    "switch",
    "firewall",
    "fortinet",
    "aruba",
    "mikrotik",
    "ubiquiti",
    "palo alto",
)
ENDPOINT_HINTS = ("android", "iphone", "ipad", "workstation", "windows 10", "windows 11", "mac os")


@dataclass(frozen=True)
class AssetClassification:
    kind: str
    confidence: str
    evidence: tuple[str, ...]


def classify_host(host: DiscoveredHost) -> AssetClassification:
    """Classify a host as network device, server, endpoint, or unknown."""
    text = " ".join(
        part.lower() for part in (host.mac_vendor or "", host.hostname or "", host.os_guess or "") if part
    )
    services = {port.service.lower() for port in host.open_ports if port.service}
    ports = {port.port for port in host.open_ports}
    network_evidence = sorted(services & NETWORK_SERVICES)
    network_ports = sorted(ports & NETWORK_PORTS)
    network_hint = next((hint for hint in NETWORK_HINTS if hint in text), None)
    if network_hint or network_evidence or network_ports:
        evidence = [*(f"service:{item}" for item in network_evidence)]
        evidence.extend(f"port:{item}" for item in network_ports)
        if network_hint:
            evidence.append(f"identity:{network_hint}")
        confidence = "high" if network_hint and (network_evidence or network_ports) else "medium"
        return AssetClassification("network_device", confidence, tuple(evidence))

    endpoint_hint = next((hint for hint in ENDPOINT_HINTS if hint in text), None)
    server_evidence = sorted(services & SERVER_SERVICES)
    server_ports = sorted(ports & SERVER_PORTS)
    if endpoint_hint and len(server_ports) <= 1:
        return AssetClassification("endpoint", "medium", (f"identity:{endpoint_hint}",))
    if server_evidence or len(server_ports) >= 2:
        evidence = [*(f"service:{item}" for item in server_evidence)]
        evidence.extend(f"port:{item}" for item in server_ports)
        return AssetClassification("server", "medium", tuple(evidence))
    return AssetClassification("unknown", "low", ())
