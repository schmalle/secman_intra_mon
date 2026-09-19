"""Terminal rendering (rich) and JSON output."""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any

from rich.console import Console
from rich.table import Table

from .discovery import DiscoveryPlanEntry, DiscoveryRun
from .models import DiscoveredHost, NetworkResult
from .scanners.base import ToolStatus

console = Console()
err_console = Console(stderr=True)


def info(message: str) -> None:
    console.print(f"[blue]·[/blue] {message}")


def warn(message: str) -> None:
    err_console.print(f"[yellow]![/yellow] {message}")


def error(message: str) -> None:
    err_console.print(f"[red]✗[/red] {message}")


def success(message: str) -> None:
    console.print(f"[green]✓[/green] {message}")


def print_json(payload: Any) -> None:
    console.print(json.dumps(payload, indent=2, default=str))


# -- capabilities ------------------------------------------------------------


def print_capabilities(tools: dict[str, ToolStatus], is_root: bool, has_net_raw: bool) -> None:
    table = Table(title="Scanner capabilities")
    table.add_column("Tool")
    table.add_column("Available")
    table.add_column("Version", overflow="fold")
    table.add_column("Needs root/NET_RAW")
    for status in tools.values():
        table.add_row(
            status.name,
            "[green]yes[/green]" if status.available else "[red]no[/red]",
            status.version or "—",
            "yes" if status.needs_root else "no",
        )
    console.print(table)
    privilege = "root" if is_root else ("CAP_NET_RAW" if has_net_raw else "unprivileged")
    console.print(f"Privilege level: [bold]{privilege}[/bold]")
    if not has_net_raw:
        warn(
            "no root/CAP_NET_RAW — ARP discovery, OS detection (-O) and masscan "
            "are disabled; falling back to ICMP/TCP discovery"
        )


# -- discovery ----------------------------------------------------------------


def print_plan(plan: list[DiscoveryPlanEntry]) -> None:
    table = Table(title="Discovery plan (no packets sent)")
    table.add_column("Network")
    table.add_column("Source")
    table.add_column("Depth", justify="right")
    table.add_column("Status")
    table.add_column("Reason", overflow="fold")
    for entry in plan:
        allowed = entry.allowed
        table.add_row(
            entry.seed.cidr,
            entry.seed.discovered_via,
            str(entry.seed.depth),
            "[green]in scope[/green]" if allowed else "[red]skipped[/red]",
            entry.reason,
        )
    console.print(table)


def print_network_result(result: NetworkResult, show_hosts: bool = True) -> None:
    seed = result.seed
    if result.error:
        warn(f"{seed.cidr} (depth {seed.depth}, {seed.discovered_via}): {result.error}")
        return
    live = result.live_hosts
    console.print(
        f"\n[bold cyan]{seed.cidr}[/bold cyan] "
        f"(depth {seed.depth}, via {seed.discovered_via}, discovery: {result.discovery_tool}) "
        f"— {len(live)} live host(s)"
    )
    if show_hosts and live:
        console.print(hosts_table(live))


def hosts_table(hosts: list[DiscoveredHost]) -> Table:
    table = Table(show_lines=False)
    table.add_column("IP")
    table.add_column("Hostname", overflow="fold")
    table.add_column("MAC / Vendor", overflow="fold")
    table.add_column("OS guess", overflow="fold")
    table.add_column("Open ports", overflow="fold")
    for host in sorted(hosts, key=_ip_sort_key):
        mac = host.mac or ""
        if host.mac_vendor:
            mac = f"{mac} ({host.mac_vendor})" if mac else host.mac_vendor
        ports = ", ".join(f"{p.port}/{p.service or '?'}" for p in host.open_ports) or "—"
        table.add_row(
            host.ip,
            host.hostname or "—",
            mac or "—",
            host.os_guess or "—",
            ports,
        )
    return table


def print_run_summary(run: DiscoveryRun) -> None:
    hosts = run.all_hosts
    open_ports = sum(len(h.open_ports) for h in hosts)
    errored = [r for r in run.results if r.error]
    console.print("\n[bold]Discovery summary[/bold]")
    console.print(f"  networks visited : {len(run.visited)}")
    console.print(f"  live hosts       : {len(hosts)}")
    console.print(f"  open ports       : {open_ports}")
    if errored:
        console.print(f"  networks skipped : {len(errored)} (out of scope or failed)")


def run_to_dict(run: DiscoveryRun) -> dict[str, Any]:
    return {
        "networks": [
            {
                "cidr": r.seed.cidr,
                "depth": r.seed.depth,
                "discovered_via": r.seed.discovered_via,
                "discovery_tool": r.discovery_tool,
                "error": r.error,
                "hosts": [asdict(h) for h in r.live_hosts],
            }
            for r in run.results
        ],
        "summary": {
            "networks_visited": len(run.visited),
            "live_hosts": len(run.all_hosts),
            "open_ports": sum(len(h.open_ports) for h in run.all_hosts),
        },
    }


# -- persisted data -----------------------------------------------------------


def print_assets(assets: list[dict[str, Any]]) -> None:
    table = Table(title=f"Persisted assets ({len(assets)})")
    table.add_column("IP")
    table.add_column("Hostname", overflow="fold")
    table.add_column("MAC / Vendor", overflow="fold")
    table.add_column("OS guess", overflow="fold")
    table.add_column("Network")
    table.add_column("Open ports", overflow="fold")
    table.add_column("Last run", justify="right")
    for asset in assets:
        mac = asset["mac"] or ""
        if asset["mac_vendor"]:
            mac = f"{mac} ({asset['mac_vendor']})" if mac else asset["mac_vendor"]
        open_ports = [p for p in asset["ports"] if p["state"] == "open"]
        ports = ", ".join(f"{p['port']}/{p['service'] or '?'}" for p in open_ports) or "—"
        table.add_row(
            asset["ip"],
            asset["hostname"] or "—",
            mac or "—",
            asset["os_guess"] or "—",
            asset["network_cidr"] or "—",
            ports,
            str(asset["last_seen_run_id"]),
        )
    console.print(table)


def print_asset_detail(asset: dict[str, Any]) -> None:
    console.print(f"[bold cyan]{asset['ip']}[/bold cyan] {asset['hostname'] or ''}")
    for key in ("mac", "mac_vendor", "os_guess", "discovered_via", "network_cidr"):
        if asset.get(key):
            console.print(f"  {key.replace('_', ' '):<15}: {asset[key]}")
    console.print(
        f"  first seen run : {asset['first_seen_run_id']}   last seen run: {asset['last_seen_run_id']}"
    )
    if asset["ports"]:
        table = Table(title="Ports")
        table.add_column("Port", justify="right")
        table.add_column("Proto")
        table.add_column("State")
        table.add_column("Service", overflow="fold")
        for port in asset["ports"]:
            service = port["service"] or "unknown"
            detail = " ".join(p for p in (port["product"], port["version"]) if p)
            table.add_row(
                str(port["port"]),
                port["protocol"],
                port["state"],
                f"{service} ({detail})" if detail else service,
            )
        console.print(table)


def print_networks(networks: list[dict[str, Any]]) -> None:
    table = Table(title=f"Discovered networks ({len(networks)})")
    table.add_column("CIDR")
    table.add_column("Source", overflow="fold")
    table.add_column("Depth", justify="right")
    table.add_column("First run", justify="right")
    table.add_column("Last run", justify="right")
    for net in networks:
        table.add_row(
            net["cidr"],
            net["discovered_via"],
            str(net["depth"]),
            str(net["first_seen_run_id"]),
            str(net["last_seen_run_id"]),
        )
    console.print(table)


def print_runs(runs: list[dict[str, Any]]) -> None:
    table = Table(title=f"Scan runs ({len(runs)})")
    table.add_column("ID", justify="right")
    table.add_column("Started")
    table.add_column("Finished")
    table.add_column("Command", overflow="fold")
    for run in runs:
        table.add_row(
            str(run["id"]),
            str(run["started_at"]),
            str(run["finished_at"] or "running"),
            run["command"],
        )
    console.print(table)


def _ip_sort_key(host: DiscoveredHost) -> tuple[int, ...]:
    try:
        return tuple(int(part) for part in host.ip.split("."))
    except ValueError:
        return (0,)
