"""Shared data model for discovery results.

These dataclasses are the currency between scanner adapters, the discovery
engine, storage, terminal output and the secman client.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class DiscoveredPort:
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: str = ""
    product: str = ""
    version: str = ""

    def label(self) -> str:
        name = self.service or "unknown"
        detail = " ".join(part for part in (self.product, self.version) if part)
        return f"{name} ({detail})" if detail else name


@dataclass
class DiscoveredHost:
    ip: str
    status: str = "up"
    mac: str | None = None
    mac_vendor: str | None = None
    hostname: str | None = None
    os_guess: str | None = None
    discovered_via: str = ""
    ports: list[DiscoveredPort] = field(default_factory=list)

    @property
    def open_ports(self) -> list[DiscoveredPort]:
        return [p for p in self.ports if p.state == "open"]

    def display_name(self) -> str:
        return self.hostname or self.ip

    @property
    def asset_kind(self) -> str:
        """Best-effort local classification; never requires data egress."""
        from .classification import classify_host

        return classify_host(self).kind


@dataclass
class Enrichment:
    """LLM classification of one asset (persisted in asset_enrichment)."""

    device_type: str = ""
    role: str = ""
    criticality: str = ""  # low | medium | high
    confidence: float = 0.0
    rationale: str = ""


@dataclass
class Finding:
    """One LLM-recorded exposure observation on an asset."""

    severity: str  # info | low | medium | high
    title: str
    detail: str = ""


@dataclass
class NetworkSeed:
    cidr: str
    discovered_via: str  # "manual" | "interface" | "route" | "traceroute"
    depth: int = 0


@dataclass
class NetworkResult:
    """Outcome of processing one network seed."""

    seed: NetworkSeed
    hosts: list[DiscoveredHost] = field(default_factory=list)
    discovery_tool: str = ""
    error: str | None = None

    @property
    def live_hosts(self) -> list[DiscoveredHost]:
        return [h for h in self.hosts if h.status == "up"]
