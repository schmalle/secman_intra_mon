"""Iterative discovery engine.

Breadth-first iteration over networks:

  seed (own interfaces, routes, --network)
    -> host discovery (arp-scan | fping | nmap -sn)
    -> service scan (nmap -sV, optionally via masscan pre-scan)
    -> expansion (traceroute hops reveal router interfaces => adjacent subnets)
    -> next depth

Every candidate network passes the scope guard. Iteration is bounded by
--max-depth; expansion can only ever reach networks this host has routes to.
"""

from __future__ import annotations

import ipaddress
import socket
from collections import deque
from collections.abc import Iterator
from dataclasses import dataclass, field

from .models import DiscoveredHost, NetworkResult, NetworkSeed
from .netinfo import LocalTopology
from .scanners import arpscan, base, fping, masscan, nmap, traceroute
from .scope import IpNetwork, ScopeGuard, parse_network

#: how many hosts per network get a traceroute for expansion
TRACE_SAMPLE_SIZE = 8
#: cap for reverse-DNS lookups per network
DNS_LOOKUP_CAP = 64


@dataclass
class DiscoveryOptions:
    networks: list[str] = field(default_factory=list)
    max_depth: int = 2
    profile: str = "default"
    os_scan: bool = False
    dry_run: bool = False
    expand: bool = True
    resolve_dns: bool = True
    masscan_rate: int = masscan.DEFAULT_RATE


@dataclass
class DiscoveryPlanEntry:
    seed: NetworkSeed
    allowed: bool
    reason: str


@dataclass
class DiscoveryRun:
    """State and results of one iterative discovery run."""

    options: DiscoveryOptions
    guard: ScopeGuard
    topology: LocalTopology
    tools: dict[str, base.ToolStatus]
    planned: list[DiscoveryPlanEntry] = field(default_factory=list)
    results: list[NetworkResult] = field(default_factory=list)
    nmap_xml_documents: list[str] = field(default_factory=list)
    visited: set[str] = field(default_factory=set)

    @property
    def all_hosts(self) -> list[DiscoveredHost]:
        """Hosts merged across networks (a host can appear in several passes)."""
        merged: dict[str, DiscoveredHost] = {}
        for result in self.results:
            for host in result.live_hosts:
                if host.ip in merged:
                    existing = merged[host.ip]
                    known = {(p.port, p.protocol) for p in existing.ports}
                    existing.ports.extend(p for p in host.ports if (p.port, p.protocol) not in known)
                    for attr in ("mac", "mac_vendor", "hostname", "os_guess"):
                        if not getattr(existing, attr) and getattr(host, attr):
                            setattr(existing, attr, getattr(host, attr))
                else:
                    merged[host.ip] = host
        return list(merged.values())


def create_run(
    options: DiscoveryOptions,
    guard: ScopeGuard,
    topology: LocalTopology,
    tools: dict[str, base.ToolStatus] | None = None,
) -> DiscoveryRun:
    return DiscoveryRun(options=options, guard=guard, topology=topology, tools=tools or base.detect_tools())


def build_plan(run: DiscoveryRun) -> list[DiscoveryPlanEntry]:
    """Seed networks only — no packets sent. Backs --dry-run and run seeding."""
    plan: list[DiscoveryPlanEntry] = []
    for seed in _seed_networks(run.options, run.topology):
        allowed, reason = run.guard.assess(parse_network(seed.cidr))
        plan.append(DiscoveryPlanEntry(seed=seed, allowed=allowed, reason=reason))
    return plan


def run_discovery(run: DiscoveryRun) -> Iterator[NetworkResult]:
    """Execute the iterative discovery, yielding one result per network."""
    queue: deque[NetworkSeed] = deque()

    for entry in build_plan(run):
        run.planned.append(entry)
        if entry.allowed:
            queue.append(entry.seed)

    while queue:
        seed = queue.popleft()
        network = parse_network(seed.cidr)
        key = str(network)
        if key in run.visited:
            continue
        run.visited.add(key)
        allowed, reason = run.guard.assess(network)
        if not allowed:
            run.results.append(NetworkResult(seed=seed, error=f"out of scope: {reason}"))
            continue

        if run.options.dry_run:
            run.results.append(NetworkResult(seed=seed, discovery_tool="dry-run"))
            continue

        result = _process_network(network, seed, run)
        run.results.append(result)
        yield result

        if run.options.expand and seed.depth < run.options.max_depth:
            for new_seed in _expand(result, run):
                if str(parse_network(new_seed.cidr)) not in run.visited:
                    queue.append(new_seed)


def _seed_networks(options: DiscoveryOptions, topology: LocalTopology) -> list[NetworkSeed]:
    seeds: list[NetworkSeed] = []
    seen: set[str] = set()

    def add(cidr: str, via: str) -> None:
        network = parse_network(cidr)
        key = str(network)
        # Skip tiny point-to-point seeds unless the operator asked for them.
        if key in seen or (network.prefixlen >= 31 and via != "manual"):
            return
        seen.add(key)
        seeds.append(NetworkSeed(cidr=key, discovered_via=via, depth=0))

    for cidr in options.networks:
        add(cidr, "manual")
    if not options.networks:
        for subnet in topology.subnets:
            add(str(subnet), "interface")
        for routed in topology.routed_networks:
            add(str(routed), "route")
    return seeds


def _process_network(
    network: IpNetwork,
    seed: NetworkSeed,
    run: DiscoveryRun,
    profile: str | None = None,
) -> NetworkResult:
    profile = profile or run.options.profile
    result = NetworkResult(seed=seed)

    hosts, tool = _discover_hosts(network, run)
    result.discovery_tool = tool
    hosts = [h for h in hosts if run.guard.ip_allowed(ipaddress.ip_address(h.ip))]
    result.hosts = hosts

    for host in hosts:
        host.discovered_via = host.discovered_via or tool

    if run.options.resolve_dns:
        _enrich_dns(hosts)

    if profile == "masscan":
        _scan_services_masscan(network, result, run)
    elif hosts:
        _scan_services_nmap(hosts, run, profile)

    return result


def _discover_hosts(network: IpNetwork, run: DiscoveryRun) -> tuple[list[DiscoveredHost], str]:
    """Pick the best available discovery tool for this network."""
    tools = run.tools
    l2_adjacent = run.topology.is_directly_connected(network)
    can_raw = base.has_net_raw()

    arp_status = tools.get("arp-scan")
    if l2_adjacent and can_raw and arp_status and arp_status.available:
        interface = _interface_for(network, run.topology)
        try:
            return arpscan.arp_sweep(network, interface=interface), "arp-scan"
        except base.ScannerError:
            pass  # fall through to nmap -PR / fping

    fping_status = tools.get("fping")
    if fping_status and fping_status.available:
        try:
            return fping.ping_sweep(network), "fping"
        except base.ScannerError:
            pass

    base.require_tool(tools, "nmap")
    use_arp = l2_adjacent and can_raw
    hosts, _xml = nmap.host_discovery([str(network)], arp=use_arp)
    tool = "nmap-pr" if use_arp else "nmap-sn"
    for host in hosts:
        host.discovered_via = tool
    return hosts, tool


def _scan_services_nmap(hosts: list[DiscoveredHost], run: DiscoveryRun, profile: str | None = None) -> None:
    """Classic profile: nmap -sV over the live hosts, merged in place."""
    base.require_tool(run.tools, "nmap")
    ips = [h.ip for h in hosts]
    scanned, xml_doc = nmap.service_scan(
        ips, profile=profile or run.options.profile, os_scan=run.options.os_scan
    )
    run.nmap_xml_documents.append(xml_doc)
    scanned_by_ip = {h.ip: h for h in scanned}
    for host in hosts:
        _merge_scan_detail(host, scanned_by_ip.get(host.ip))


def _scan_services_masscan(network: IpNetwork, result: NetworkResult, run: DiscoveryRun) -> None:
    """masscan profile: masscan finds open ports network-wide, nmap verifies.

    Hosts that never answered the discovery phase but show open ports are
    added as additional assets. nmap -sV runs per distinct port-set so
    service detail stays accurate.
    """
    if not base.has_net_raw():
        raise base.ScannerError("profile 'masscan' requires root / CAP_NET_RAW")
    base.require_tool(run.tools, "masscan")
    base.require_tool(run.tools, "nmap")

    open_hosts, _masscan_xml = masscan.port_sweep(network, rate=run.options.masscan_rate)
    ports_by_ip: dict[str, tuple[int, ...]] = {}
    for host in open_hosts:
        ports = tuple(sorted({p.port for p in host.open_ports}))
        if ports:
            ports_by_ip[host.ip] = ports

    hosts_by_ip = {h.ip: h for h in result.hosts}
    for ip in ports_by_ip:
        if ip not in hosts_by_ip and run.guard.ip_allowed(ipaddress.ip_address(ip)):
            new_host = DiscoveredHost(ip=ip, discovered_via="masscan")
            result.hosts.append(new_host)
            hosts_by_ip[ip] = new_host
            if run.options.resolve_dns:
                _enrich_dns([new_host])

    # Group hosts by identical port sets to minimize nmap invocations.
    groups: dict[tuple[int, ...], list[str]] = {}
    for ip, ports in ports_by_ip.items():
        groups.setdefault(ports, []).append(ip)

    for ports, ips in groups.items():
        port_arg = ",".join(str(p) for p in ports)
        detailed, xml_doc = nmap.service_scan(ips, ports=port_arg, os_scan=run.options.os_scan)
        run.nmap_xml_documents.append(xml_doc)
        detailed_by_ip = {h.ip: h for h in detailed}
        for ip in ips:
            existing = hosts_by_ip.get(ip)
            if existing is not None:
                _merge_scan_detail(existing, detailed_by_ip.get(ip))


def _merge_scan_detail(host: DiscoveredHost, detail: DiscoveredHost | None) -> None:
    if detail is None:
        return
    host.ports = detail.ports
    host.os_guess = detail.os_guess or host.os_guess
    host.hostname = host.hostname or detail.hostname
    host.mac = host.mac or detail.mac
    host.mac_vendor = host.mac_vendor or detail.mac_vendor


def _expand(result: NetworkResult, run: DiscoveryRun) -> list[NetworkSeed]:
    """Traceroute to a sample of hosts; router hops imply adjacent subnets."""
    tools = run.tools
    traceroute_status = tools.get("traceroute")
    if traceroute_status is None or not traceroute_status.available:
        return []
    network = parse_network(result.seed.cidr)
    sample = _trace_sample(result.live_hosts, run.topology)
    candidates: dict[str, NetworkSeed] = {}
    for ip in sample:
        for seed in _candidates_from_hops(
            traceroute.trace_hops(ip), network, result.seed.depth + 1, run.guard, run.visited
        ):
            candidates.setdefault(seed.cidr, seed)
    return list(candidates.values())


def _candidates_from_hops(
    hops: list[str],
    network: IpNetwork,
    depth: int,
    guard: ScopeGuard,
    visited: set[str],
) -> list[NetworkSeed]:
    """Turn traceroute hops into candidate seeds: every hop outside the
    current network is a router interface; its /24 becomes a candidate."""
    candidates: dict[str, NetworkSeed] = {}
    for hop in hops:
        hop_addr = ipaddress.ip_address(hop)
        if not guard.ip_allowed(hop_addr) or hop_addr.is_loopback:
            continue
        if hop_addr in network:
            continue
        candidate = ipaddress.ip_network(f"{hop}/24", strict=False)
        allowed, _reason = guard.assess(candidate)
        if not allowed:
            continue
        key = str(candidate)
        if key not in visited and key not in candidates:
            candidates[key] = NetworkSeed(
                cidr=key,
                discovered_via=f"traceroute via {hop}",
                depth=depth,
            )
    return list(candidates.values())


def _trace_sample(hosts: list[DiscoveredHost], topology: LocalTopology) -> list[str]:
    """Gateways first, then a spread of hosts — routers are the interesting targets."""
    sample: list[str] = []
    host_ips = {h.ip for h in hosts}
    for gateway in topology.gateways:
        if gateway in host_ips:
            sample.append(gateway)
    for host in hosts:
        if host.ip not in sample:
            sample.append(host.ip)
        if len(sample) >= TRACE_SAMPLE_SIZE:
            break
    return sample[:TRACE_SAMPLE_SIZE]


def _enrich_dns(hosts: list[DiscoveredHost]) -> None:
    lookups = 0
    for host in hosts:
        if host.hostname or lookups >= DNS_LOOKUP_CAP:
            continue
        lookups += 1
        try:
            host.hostname = socket.gethostbyaddr(host.ip)[0]
        except OSError:
            continue


def _interface_for(network: IpNetwork, topology: LocalTopology) -> str | None:
    for iface in topology.interfaces:
        if iface.network == network:
            return iface.name
    return None
