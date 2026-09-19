"""Scope guard — the safety boundary of the tool.

Only private/link-local/loopback ranges are in scope by default. Public
ranges require an explicit opt-in, and an operator-provided exclude list is
always honored. Every scan target and every network enqueued by the
iterative engine passes through this guard.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

IpNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
IpAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

#: Ranges considered "internal" and scannable without extra opt-in.
PRIVATE_NETWORKS: list[IpNetwork] = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),  # link-local
    ipaddress.ip_network("100.64.0.0/10"),  # carrier-grade NAT / RFC 6598
    ipaddress.ip_network("127.0.0.0/8"),  # loopback
    ipaddress.ip_network("fc00::/7"),  # IPv6 ULA
    ipaddress.ip_network("fe80::/10"),  # IPv6 link-local
    ipaddress.ip_network("::1/128"),
]

#: Hard upper bound for a single discovery target unless --allow-large is given.
DEFAULT_MAX_ADDRESSES = 4096


class ScopeError(Exception):
    pass


def parse_network(value: str) -> IpNetwork:
    try:
        return ipaddress.ip_network(value.strip(), strict=False)
    except ValueError as exc:
        raise ScopeError(f"invalid network: {value!r}") from exc


@dataclass
class ScopeGuard:
    allow_public: bool = False
    excludes: list[IpNetwork] = field(default_factory=list)
    max_addresses: int = DEFAULT_MAX_ADDRESSES
    allow_large: bool = False

    def assess(self, network: IpNetwork) -> tuple[bool, str]:
        """Return (allowed, reason) for a candidate network."""
        if not self.allow_public and not self._is_private(network):
            return False, "public range (use --allow-public to override)"
        for excluded in self.excludes:
            if network.overlaps(excluded):
                return False, f"overlaps excluded range {excluded}"
        if (
            not self.allow_large
            and network.num_addresses > self.max_addresses
            and network.prefixlen not in (0,)
        ):
            return False, (
                f"too large ({network.num_addresses} addresses, limit "
                f"{self.max_addresses}; use --allow-large to override)"
            )
        return True, "in scope"

    def check(self, network: IpNetwork) -> None:
        allowed, reason = self.assess(network)
        if not allowed:
            raise ScopeError(f"{network}: {reason}")

    def ip_allowed(self, ip: IpAddress) -> bool:
        if not self.allow_public and not any(ip in net for net in PRIVATE_NETWORKS):
            return False
        return not any(ip in net for net in self.excludes)

    def filter_networks(self, networks: list[IpNetwork]) -> list[IpNetwork]:
        return [net for net in networks if self.assess(net)[0]]

    @staticmethod
    def _is_private(network: IpNetwork) -> bool:
        # matching versions make subnet_of type-safe for the network unions
        return any(
            network.version == priv.version and network.subnet_of(priv)  # type: ignore[arg-type]
            for priv in PRIVATE_NETWORKS
        )
