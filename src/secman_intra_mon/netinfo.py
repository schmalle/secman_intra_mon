"""Local network topology: interfaces, subnets, routes, gateways.

Linux-first via iproute2 JSON output (`ip -j addr` / `ip -j route`), with a
psutil fallback so the tool also works on macOS dev hosts. These functions
only read local state — they send no packets.
"""

from __future__ import annotations

import ipaddress
import json
import shutil
import subprocess
from dataclasses import dataclass

import psutil

from .scope import IpNetwork

_IP_TIMEOUT = 10


@dataclass
class LocalInterface:
    name: str
    ip: str
    prefixlen: int
    network: IpNetwork


@dataclass
class LocalTopology:
    interfaces: list[LocalInterface]
    gateways: list[str]
    routed_networks: list[IpNetwork]  # non-default routes beyond directly connected

    @property
    def subnets(self) -> list[IpNetwork]:
        return [iface.network for iface in self.interfaces]

    def is_directly_connected(self, network: IpNetwork) -> bool:
        return any(network == iface.network for iface in self.interfaces)


def get_topology() -> LocalTopology:
    if shutil.which("ip"):
        try:
            return _topology_from_iproute2()
        except (subprocess.SubprocessError, OSError, json.JSONDecodeError, KeyError):
            pass
    return _topology_from_psutil()


def _run_ip(args: list[str]) -> list[dict[str, object]]:
    proc = subprocess.run(
        ["ip", "-j", *args],
        capture_output=True,
        text=True,
        timeout=_IP_TIMEOUT,
        check=True,
    )
    data = json.loads(proc.stdout)
    return data if isinstance(data, list) else [data]


def _topology_from_iproute2() -> LocalTopology:
    interfaces: list[LocalInterface] = []
    for link in _run_ip(["addr", "show"]):
        ifname = str(link.get("ifname", ""))
        if ifname == "lo":
            continue
        addr_info = link.get("addr_info", [])
        if not isinstance(addr_info, list):
            continue
        for addr in addr_info:
            if not isinstance(addr, dict) or addr.get("family") != "inet":
                continue
            local = str(addr.get("local", ""))
            prefixlen = int(str(addr.get("prefixlen", "0")))
            if not local:
                continue
            network = ipaddress.ip_network(f"{local}/{prefixlen}", strict=False)
            interfaces.append(LocalInterface(name=ifname, ip=local, prefixlen=prefixlen, network=network))

    gateways: list[str] = []
    routed: list[IpNetwork] = []
    for route in _run_ip(["route", "show"]):
        dst = str(route.get("dst", "default"))
        gateway = route.get("gateway")
        if dst == "default":
            if gateway:
                gateways.append(str(gateway))
            continue
        # Non-default route. Directly connected subnets appear here too
        # (without gateway); those are covered by the interface list.
        if gateway:
            try:
                routed.append(ipaddress.ip_network(dst, strict=False))
            except ValueError:
                continue
    return LocalTopology(interfaces=interfaces, gateways=gateways, routed_networks=routed)


def _topology_from_psutil() -> LocalTopology:
    interfaces: list[LocalInterface] = []
    stats = psutil.net_if_stats()
    for name, addrs in psutil.net_if_addrs().items():
        if name == "lo0" or name.startswith("lo"):
            continue
        if name in stats and not stats[name].isup:
            continue
        for addr in addrs:
            if addr.family.name != "AF_INET" or not addr.netmask:
                continue
            if addr.address.startswith("127."):
                continue
            network = ipaddress.ip_network(f"{addr.address}/{addr.netmask}", strict=False)
            interfaces.append(
                LocalInterface(
                    name=name,
                    ip=addr.address,
                    prefixlen=network.prefixlen,
                    network=network,
                )
            )
    return LocalTopology(interfaces=interfaces, gateways=[], routed_networks=[])
