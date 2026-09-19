"""secman-intra-mon command line interface."""

from __future__ import annotations

import ipaddress
import os
import socket
import sys
from typing import Annotated, Any, NoReturn

import typer

from . import __version__
from .config import ConfigError, DbConfig, SecmanConfig
from .discovery import (
    DiscoveryOptions,
    build_plan,
    create_run,
    run_discovery,
)
from .models import DiscoveredHost, DiscoveredPort
from .netinfo import get_topology
from .output import (
    console,
    error,
    info,
    print_asset_detail,
    print_assets,
    print_capabilities,
    print_json,
    print_network_result,
    print_networks,
    print_plan,
    print_run_summary,
    print_runs,
    run_to_dict,
    success,
    warn,
)
from .scanners import base
from .scanners.base import ScannerError
from .scope import ScopeError, ScopeGuard, parse_network
from .secman import SecmanClient, SecmanError, push_hosts
from .storage import Storage, StorageError

app = typer.Typer(
    name="secman-intra-mon",
    help=("Iterative intranet asset discovery for secman. Only scan networks you are authorized to assess."),
    no_args_is_help=True,
    add_completion=False,
)
assets_app = typer.Typer(no_args_is_help=True, help="Show persisted assets.")
networks_app = typer.Typer(no_args_is_help=True, help="Show discovered networks.")
db_app = typer.Typer(no_args_is_help=True, help="Database administration.")
app.add_typer(assets_app, name="assets")
app.add_typer(networks_app, name="networks")
app.add_typer(db_app, name="db")

PROFILES = ("fast", "default", "full", "masscan")


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"secman-intra-mon {__version__}")
        raise typer.Exit()


@app.callback()
def _callback(
    version: Annotated[bool, typer.Option("--version", callback=_version_callback, is_eager=True)] = False,
) -> None:
    pass


def _fail(message: str) -> NoReturn:
    error(message)
    raise typer.Exit(1)


def _guard(allow_public: bool, excludes: list[str] | None, allow_large: bool) -> ScopeGuard:
    try:
        return ScopeGuard(
            allow_public=allow_public,
            excludes=[parse_network(e) for e in (excludes or [])],
            allow_large=allow_large,
        )
    except ScopeError as exc:
        _fail(f"invalid --exclude value: {exc}")


def _storage_or_fail() -> Storage:
    try:
        db_config = DbConfig.from_env()
    except ConfigError as exc:
        _fail(str(exc))
    if db_config is None:
        _fail(
            "database not configured — set SECMAN_INTRA_MON_DB_USER and "
            "SECMAN_INTRA_MON_DB_PASSWORD (see .env.example)"
        )
    storage = Storage(db_config)
    try:
        storage.connect()
    except StorageError as exc:
        _fail(str(exc))
    return storage


def _secman_client_or_fail() -> SecmanClient:
    try:
        secman_config = SecmanConfig.from_env()
    except ConfigError as exc:
        _fail(str(exc))
    if secman_config is None:
        _fail("secman not configured — set SECMAN_URL and credentials (see .env.example)")
    return SecmanClient(secman_config)


def _asset_owner(config_username: str | None) -> str:
    return os.environ.get("SECMAN_ASSET_OWNER") or config_username or "secman_intra_mon"


def _login_and_check_roles(client: SecmanClient) -> None:
    roles = client.login()
    if roles and "ADMIN" not in roles:
        warn(
            f"secman account roles {roles} do not include ADMIN — "
            "asset import and nmap upload will be rejected"
        )


# -- discover ------------------------------------------------------------------


@app.command()
def discover(
    networks: Annotated[
        list[str] | None,
        typer.Option("--network", "-n", help="CIDR to scan (repeatable). Default: auto-detect."),
    ] = None,
    max_depth: Annotated[int, typer.Option("--max-depth", help="Iteration depth for network expansion.")] = 2,
    profile: Annotated[
        str, typer.Option("--profile", help="Scan profile: fast | default | full | masscan.")
    ] = "default",
    os_scan: Annotated[bool, typer.Option("--os-scan", help="nmap OS detection (-O, needs root).")] = False,
    exclude: Annotated[
        list[str] | None, typer.Option("--exclude", help="CIDR to never scan (repeatable).")
    ] = None,
    allow_public: Annotated[
        bool, typer.Option("--allow-public", help="Allow public (non-RFC1918) ranges.")
    ] = False,
    allow_large: Annotated[
        bool, typer.Option("--allow-large", help="Allow networks larger than /20.")
    ] = False,
    no_expand: Annotated[
        bool, typer.Option("--no-expand", help="Do not iterate into adjacent networks.")
    ] = False,
    no_dns: Annotated[bool, typer.Option("--no-dns", help="Skip reverse-DNS enrichment.")] = False,
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Print the plan, send no packets.")] = False,
    store_db: Annotated[bool, typer.Option("--store-db", help="Persist results into MariaDB.")] = False,
    upload_secman: Annotated[
        bool, typer.Option("--upload-secman", help="Push results to the secman backend.")
    ] = False,
    masscan_rate: Annotated[
        int, typer.Option("--masscan-rate", help="masscan packets/second (profile masscan).")
    ] = 1000,
    json_output: Annotated[bool, typer.Option("--json", help="Machine-readable JSON output.")] = False,
) -> None:
    """Iteratively discover assets, starting from this host's own networks."""
    if profile not in PROFILES:
        _fail(f"unknown profile {profile!r} (choose from {', '.join(PROFILES)})")
    guard = _guard(allow_public, exclude, allow_large)
    options = DiscoveryOptions(
        networks=networks or [],
        max_depth=max_depth,
        profile=profile,
        os_scan=os_scan,
        dry_run=dry_run,
        expand=not no_expand,
        resolve_dns=not no_dns,
        masscan_rate=masscan_rate,
    )
    topology = get_topology()
    run = create_run(options, guard, topology)

    if dry_run:
        plan = build_plan(run)
        if json_output:
            print_json(
                [
                    {
                        "cidr": e.seed.cidr,
                        "via": e.seed.discovered_via,
                        "allowed": e.allowed,
                        "reason": e.reason,
                    }
                    for e in plan
                ]
            )
        else:
            print_plan(plan)
            if not any(e.allowed for e in plan):
                warn("no in-scope networks — pass --network or adjust scope options")
        return

    storage: Storage | None = None
    run_id: int | None = None
    if store_db:
        storage = _storage_or_fail()
        run_id = storage.create_run(
            command=" ".join(sys.argv),
            params={
                "networks": networks or [],
                "max_depth": max_depth,
                "profile": profile,
                "os_scan": os_scan,
                "exclude": exclude or [],
            },
            tools=run.tools,
        )

    try:
        for result in run_discovery(run):
            if not json_output:
                print_network_result(result)
            if storage is not None and run_id is not None and result.error is None:
                storage.upsert_network(run_id, result.seed)
                for host in result.live_hosts:
                    storage.upsert_host(run_id, host, result.seed.cidr)
    except ScannerError as exc:
        if storage is not None and run_id is not None:
            storage.finish_run(run_id)
        _fail(str(exc))

    if storage is not None and run_id is not None:
        storage.finish_run(run_id)
        storage.close()

    if json_output:
        print_json(run_to_dict(run))
    else:
        print_run_summary(run)
        if storage is not None:
            success(f"run {run_id} persisted")

    if upload_secman:
        _upload_run_to_secman(run.all_hosts, run.nmap_xml_documents)


def _upload_run_to_secman(hosts: list[DiscoveredHost], xml_documents: list[str]) -> None:
    client = _secman_client_or_fail()
    try:
        _login_and_check_roles(client)
        owner = _asset_owner(client.username)
        summary = push_hosts(client, hosts, owner, xml_documents)
        success(
            f"secman: {summary.assets_created} asset(s) created, "
            f"{summary.assets_updated} updated, {summary.xml_uploads} nmap XML upload(s)"
        )
        for err in summary.errors:
            warn(f"secman: {err}")
    except SecmanError as exc:
        _fail(str(exc))
    finally:
        client.close()


# -- scan ------------------------------------------------------------------------


@app.command()
def scan(
    targets: Annotated[list[str], typer.Argument(help="IPs, CIDRs or hostnames to service-scan.")],
    profile: Annotated[str, typer.Option("--profile", help="fast | default | full.")] = "default",
    ports: Annotated[
        str | None, typer.Option("--ports", "-p", help="nmap port spec, e.g. 22,80,443.")
    ] = None,
    os_scan: Annotated[bool, typer.Option("--os-scan", help="nmap OS detection (-O).")] = False,
    exclude: Annotated[
        list[str] | None, typer.Option("--exclude", help="CIDR to never scan (repeatable).")
    ] = None,
    allow_public: Annotated[
        bool, typer.Option("--allow-public", help="Allow public (non-RFC1918) ranges.")
    ] = False,
    allow_large: Annotated[
        bool, typer.Option("--allow-large", help="Allow networks larger than /20.")
    ] = False,
    store_db: Annotated[bool, typer.Option("--store-db", help="Persist results into MariaDB.")] = False,
    json_output: Annotated[bool, typer.Option("--json", help="JSON output.")] = False,
) -> None:
    """Direct nmap service scan of the given targets."""
    from .scanners import nmap as nmap_scanner

    guard = _guard(allow_public, exclude, allow_large)
    checked = [_checked_target(t, guard) for t in targets]

    tools = base.detect_tools()
    try:
        base.require_tool(tools, "nmap")
        hosts, _xml = nmap_scanner.service_scan(
            checked,
            profile=profile if profile in PROFILES else "default",
            ports=ports,
            os_scan=os_scan,
        )
    except ScannerError as exc:
        _fail(str(exc))

    for host in hosts:
        host.discovered_via = "scan"

    if json_output:
        print_json([_host_to_dict(h) for h in hosts])
    else:
        from .output import hosts_table

        console.print(hosts_table(hosts))

    if store_db:
        storage = _storage_or_fail()
        run_id = storage.create_run(
            command=" ".join(sys.argv),
            params={"targets": targets, "profile": profile, "ports": ports},
            tools=tools,
        )
        for host in hosts:
            storage.upsert_host(run_id, host, _network_label_for(host.ip))
        storage.finish_run(run_id)
        storage.close()
        if not json_output:
            success(f"run {run_id} persisted")


def _checked_target(target: str, guard: ScopeGuard) -> str:
    try:
        network = parse_network(target)
    except ScopeError:
        # maybe a hostname — resolve, then scope-check the address
        try:
            resolved = socket.gethostbyname(target)
        except OSError:
            _fail(f"invalid target (not an IP, CIDR or resolvable hostname): {target!r}")
        if not guard.ip_allowed(ipaddress.ip_address(resolved)):
            _fail(f"{target!r} resolves to {resolved} which is out of scope")
        return target
    allowed, reason = guard.assess(network)
    if not allowed:
        _fail(f"target {target!r} rejected by scope guard: {reason}")
    return target


def _network_label_for(ip: str) -> str:
    try:
        return str(ipaddress.ip_network(f"{ip}/24", strict=False))
    except ValueError:
        return ""


def _host_to_dict(host: DiscoveredHost) -> dict[str, Any]:
    from dataclasses import asdict

    return asdict(host)


# -- capabilities ----------------------------------------------------------------


@app.command()
def capabilities() -> None:
    """Show detected scanner tools and privilege level."""
    tools = base.detect_tools()
    print_capabilities(tools, base.is_root(), base.has_net_raw())


# -- db --------------------------------------------------------------------------


@db_app.command("init")
def db_init() -> None:
    """Create the database (if needed) and apply migrations."""
    try:
        db_config = DbConfig.from_env()
    except ConfigError as exc:
        _fail(str(exc))
    if db_config is None:
        _fail(
            "database not configured — set SECMAN_INTRA_MON_DB_USER and "
            "SECMAN_INTRA_MON_DB_PASSWORD (see .env.example)"
        )
    # connect without pre-selecting the schema: init is what creates it
    storage = Storage(db_config)
    try:
        storage.ensure_database()
        applied = storage.apply_migrations()
        if applied:
            success(f"applied migration(s): {', '.join(applied)}")
        else:
            info("schema already up to date")
    except StorageError as exc:
        _fail(str(exc))
    finally:
        storage.close()


# -- assets / networks / runs ----------------------------------------------------


@assets_app.command("list")
def assets_list(
    network: Annotated[
        str | None, typer.Option("--network", "-n", help="Only assets inside this CIDR.")
    ] = None,
    run_id: Annotated[int | None, typer.Option("--run-id", help="Only assets last seen in this run.")] = None,
    json_output: Annotated[bool, typer.Option("--json", help="JSON output.")] = False,
) -> None:
    """List persisted assets."""
    storage = _storage_or_fail()
    try:
        assets = storage.list_assets(run_id=run_id)
    finally:
        storage.close()
    if network:
        try:
            net = parse_network(network)
        except ScopeError as exc:
            _fail(str(exc))
        assets = [a for a in assets if ipaddress.ip_address(a["ip"]) in net]
    if json_output:
        print_json(assets)
    else:
        print_assets(assets)


@assets_app.command("show")
def assets_show(
    ip: Annotated[str, typer.Argument(help="Asset IP address.")],
    json_output: Annotated[bool, typer.Option("--json", help="JSON output.")] = False,
) -> None:
    """Show one persisted asset with its ports."""
    storage = _storage_or_fail()
    try:
        asset = storage.get_asset(ip)
    finally:
        storage.close()
    if asset is None:
        _fail(f"no persisted asset with IP {ip}")
    if json_output:
        print_json(asset)
    else:
        print_asset_detail(asset)


@networks_app.command("list")
def networks_list(
    json_output: Annotated[bool, typer.Option("--json", help="JSON output.")] = False,
) -> None:
    """List discovered networks."""
    storage = _storage_or_fail()
    try:
        networks = storage.list_networks()
    finally:
        storage.close()
    if json_output:
        print_json(networks)
    else:
        print_networks(networks)


@app.command()
def runs(
    limit: Annotated[int, typer.Option("--limit", help="How many runs to show.")] = 20,
    json_output: Annotated[bool, typer.Option("--json", help="JSON output.")] = False,
) -> None:
    """List past scan runs."""
    storage = _storage_or_fail()
    try:
        rows = storage.list_runs(limit=limit)
    finally:
        storage.close()
    if json_output:
        print_json(rows)
    else:
        print_runs(rows)


# -- secman-push -------------------------------------------------------------------


@app.command("secman-push")
def secman_push(
    run_id: Annotated[int | None, typer.Option("--run-id", help="Run to push (default: latest).")] = None,
) -> None:
    """Push persisted assets of a run to the secman backend."""
    storage = _storage_or_fail()
    try:
        effective_run_id = run_id if run_id is not None else storage.latest_run_id()
        if effective_run_id is None:
            _fail("no scan runs in the database yet")
        rows = storage.list_assets(run_id=effective_run_id)
    finally:
        storage.close()
    if not rows:
        _fail(f"no assets recorded for run {effective_run_id}")

    hosts = [_row_to_host(row) for row in rows]
    client = _secman_client_or_fail()
    try:
        _login_and_check_roles(client)
        owner = _asset_owner(client.username)
        summary = push_hosts(client, hosts, owner, xml_documents=None)
        success(
            f"secman: {summary.assets_created} asset(s) created, "
            f"{summary.assets_updated} updated (run {effective_run_id})"
        )
        for err in summary.errors:
            warn(f"secman: {err}")
        info("note: port-level records are uploaded via nmap XML only during 'discover --upload-secman'")
    except SecmanError as exc:
        _fail(str(exc))
    finally:
        client.close()


def _row_to_host(row: dict[str, Any]) -> DiscoveredHost:
    return DiscoveredHost(
        ip=row["ip"],
        mac=row["mac"],
        mac_vendor=row["mac_vendor"],
        hostname=row["hostname"],
        os_guess=row["os_guess"],
        discovered_via=row["discovered_via"],
        ports=[
            DiscoveredPort(
                port=p["port"],
                protocol=p["protocol"],
                state=p["state"],
                service=p["service"],
                product=p["product"],
                version=p["version"],
            )
            for p in row["ports"]
        ],
    )


def main() -> None:
    app()


if __name__ == "__main__":
    main()
