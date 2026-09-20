"""secman-intra-mon command line interface."""

from __future__ import annotations

import ipaddress
import os
import socket
import sys
from collections.abc import Callable
from typing import Annotated, Any, NoReturn

import pymysql
import typer

from . import __version__
from .agent import AgentBudgets, AgentRunner
from .ask import AskError, generate_sql
from .config import ConfigError, DbConfig, LlmConfig, SecmanConfig
from .discovery import (
    DiscoveryOptions,
    build_plan,
    create_run,
    run_discovery,
)
from .enrich import SEVERITIES, ClassifiedAsset, classify_assets
from .llm import LlmClient, LlmError
from .models import DiscoveredHost, DiscoveredPort, Enrichment
from .netinfo import get_topology
from .output import (
    console,
    err_console,
    error,
    info,
    print_asset_detail,
    print_assets,
    print_capabilities,
    print_diff_report,
    print_enrichments,
    print_findings,
    print_json,
    print_narrative,
    print_network_result,
    print_networks,
    print_plan,
    print_rows,
    print_run_overview,
    print_run_summary,
    print_runs,
    run_to_dict,
    success,
    warn,
)
from .report import diff_payload, run_payload, summarize_diff, summarize_run
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
findings_app = typer.Typer(no_args_is_help=True, help="Show recorded LLM findings.")
app.add_typer(assets_app, name="assets")
app.add_typer(networks_app, name="networks")
app.add_typer(db_app, name="db")
app.add_typer(findings_app, name="findings")

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


def _llm_client_or_fail() -> LlmClient:
    try:
        llm_config = LlmConfig.from_env()
    except ConfigError as exc:
        _fail(str(exc))
    if llm_config is None:
        _fail(
            "LLM features are not configured — set OPENROUTER_API_KEY "
            "(and optionally SECMAN_INTRA_MON_LLM_MODEL; see .env.example)"
        )
    return LlmClient(llm_config)


def _llm_client_or_none() -> LlmClient | None:
    try:
        llm_config = LlmConfig.from_env()
    except ConfigError as exc:
        warn(str(exc))
        return None
    return LlmClient(llm_config) if llm_config else None


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
        bool,
        typer.Option(
            "--upload-secman",
            help="Explicitly push and flag actively discovered assets in secman (off by default).",
        ),
    ] = False,
    masscan_rate: Annotated[
        int, typer.Option("--masscan-rate", help="masscan packets/second (profile masscan).")
    ] = 1000,
    agentic: Annotated[
        bool,
        typer.Option("--agentic", help="Let the LLM planner drive discovery (needs OPENROUTER_API_KEY)."),
    ] = False,
    yes: Annotated[
        bool, typer.Option("--yes", help="Agentic mode: execute actions without per-action confirmation.")
    ] = False,
    agent_max_actions: Annotated[
        int, typer.Option("--agent-max-actions", help="Agentic mode: hard cap on planner actions.")
    ] = 30,
    agent_max_networks: Annotated[
        int, typer.Option("--agent-max-networks", help="Agentic mode: hard cap on networks scanned.")
    ] = 10,
    enrich: Annotated[
        bool, typer.Option("--enrich", help="LLM-classify discovered assets after the run.")
    ] = False,
    no_redact: Annotated[
        bool,
        typer.Option("--no-redact", help="Send real IPs to the LLM (default: pseudonymized)."),
    ] = False,
    json_output: Annotated[bool, typer.Option("--json", help="Machine-readable JSON output.")] = False,
) -> None:
    """Iteratively discover assets, starting from this host's own networks."""
    if profile not in PROFILES:
        _fail(f"unknown profile {profile!r} (choose from {', '.join(PROFILES)})")
    if agentic and dry_run:
        _fail("--agentic cannot be combined with --dry-run")
    if dry_run and (store_db or upload_secman or enrich):
        _fail("--dry-run cannot be combined with --store-db, --upload-secman, or --enrich")
    if max_depth < 0:
        _fail("--max-depth must be zero or greater")
    if masscan_rate <= 0:
        _fail("--masscan-rate must be greater than zero")
    if agent_max_actions <= 0 or agent_max_networks <= 0:
        _fail("agent budgets must be greater than zero")
    if agentic and not yes and not sys.stdin.isatty():
        _fail("--agentic needs an interactive terminal for action approval, or pass --yes")
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
                "agentic": agentic,
            },
            tools=run.tools,
        )

    llm: LlmClient | None = None
    runner: AgentRunner | None = None
    try:
        if agentic:
            llm = _llm_client_or_fail()
            try:
                base.require_tool(run.tools, "nmap")
            except ScannerError as exc:
                _fail(str(exc))
            if not json_output:
                print_plan(run.planned if run.planned else build_plan(run))
            runner = AgentRunner(
                run,
                llm,
                AgentBudgets(max_actions=agent_max_actions, max_networks=agent_max_networks),
                approve=_make_approver(yes, json_output),
                on_event=_agent_event_sink(json_output),
            )
            results_iter = runner.execute()
        else:
            results_iter = run_discovery(run)
        for result in results_iter:
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
        if runner is not None:
            storage.append_run_params(
                run_id, {"agent_audit": runner.audit, "agent_stop_reason": runner.stop_reason}
            )

    enrichments = _maybe_enrich(enrich, run.all_hosts, storage, no_redact, llm)

    if storage is not None:
        storage.close()
    if llm is not None:
        llm.close()

    if json_output:
        print_json(run_to_dict(run))
    else:
        print_run_summary(run)
        if storage is not None:
            success(f"run {run_id} persisted")

    if upload_secman:
        _upload_run_to_secman(run.all_hosts, run.nmap_xml_documents, enrichments)


def _make_approver(yes: bool, json_output: bool) -> Callable[[str], bool]:
    if yes:
        return lambda _desc: True
    target = err_console if json_output else console

    def approve(description: str) -> bool:
        target.print(f"[bold yellow]agent proposes:[/bold yellow] {description}")
        reply = target.input("Execute? [Y/n] ").strip().lower()
        return reply in ("", "y", "yes")

    return approve


def _agent_event_sink(json_output: bool) -> Callable[[str], None]:
    target = err_console if json_output else console
    return lambda message: target.print(f"[dim]agent ·[/dim] {message}")


def _maybe_enrich(
    enrich: bool,
    hosts: list[DiscoveredHost],
    storage: Storage | None,
    no_redact: bool,
    llm: LlmClient | None,
) -> dict[str, Enrichment] | None:
    """Classify hosts after a discover run; persist when storage is available."""
    if not enrich or not hosts:
        return None
    client = llm
    own_client = False
    if client is None:
        client = _llm_client_or_none()
        own_client = client is not None
    if client is None:
        warn("--enrich skipped: OPENROUTER_API_KEY is not set")
        return None
    try:
        result = classify_assets(client, hosts, redact=not no_redact)
        for err in result.errors:
            warn(f"enrich: {err}")
        if storage is not None:
            for classified in result.assets.values():
                storage.upsert_enrichment(classified.ip, classified.enrichment, client.model)
                storage.replace_findings(classified.ip, classified.findings, client.model)
        findings_total = sum(len(c.findings) for c in result.assets.values())
        success(f"enriched {len(result.assets)} asset(s), recorded {findings_total} finding(s)")
        return {ip: c.enrichment for ip, c in result.assets.items()}
    finally:
        if own_client:
            client.close()


def _upload_run_to_secman(
    hosts: list[DiscoveredHost],
    xml_documents: list[str],
    enrichments: dict[str, Enrichment] | None = None,
) -> None:
    client = _secman_client_or_fail()
    try:
        _login_and_check_roles(client)
        owner = _asset_owner(client.username)
        summary = push_hosts(client, hosts, owner, xml_documents, enrichments)
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

    if profile not in ("fast", "default", "full"):
        _fail("unknown scan profile (choose from fast, default, full)")
    guard = _guard(allow_public, exclude, allow_large)
    checked = [_checked_target(t, guard) for t in targets]

    tools = base.detect_tools()
    try:
        base.require_tool(tools, "nmap")
        hosts, _xml = nmap_scanner.service_scan(
            checked,
            profile=profile,
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
        # Pin the checked address. Passing the hostname onward would allow a
        # later DNS answer (or another address in the RRset) to bypass scope.
        return resolved
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

    return {**asdict(host), "asset_kind": host.asset_kind}


# -- capabilities ----------------------------------------------------------------


@app.command()
def capabilities() -> None:
    """Show detected scanner tools and privilege level."""
    tools = base.detect_tools()
    print_capabilities(tools, base.is_root(), base.has_net_raw())
    try:
        llm_config = LlmConfig.from_env()
    except ConfigError as exc:
        warn(str(exc))
        return
    if llm_config is None:
        info("LLM: not configured — set OPENROUTER_API_KEY for report / enrich / ask / discover --agentic")
    else:
        info(
            f"LLM: model {llm_config.model}, planner {llm_config.planner_model}, "
            f"endpoint {llm_config.base_url}"
        )


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
    enrich: Annotated[
        bool, typer.Option("--enrich", help="LLM-classify the run's assets before pushing.")
    ] = False,
    no_redact: Annotated[
        bool, typer.Option("--no-redact", help="Send real IPs to the LLM (default: pseudonymized).")
    ] = False,
) -> None:
    """Push persisted assets of a run to the secman backend."""
    storage = _storage_or_fail()
    try:
        effective_run_id = run_id if run_id is not None else storage.latest_run_id()
        if effective_run_id is None:
            _fail("no scan runs in the database yet")
        rows = storage.list_assets(run_id=effective_run_id)
        if not rows:
            _fail(f"no assets recorded for run {effective_run_id}")
        hosts = [_row_to_host(row) for row in rows]
        if enrich:
            _classify_and_store(hosts, storage, no_redact)
        enrichments = _stored_enrichments_or_warn(storage, effective_run_id)
    finally:
        storage.close()

    client = _secman_client_or_fail()
    try:
        _login_and_check_roles(client)
        owner = _asset_owner(client.username)
        summary = push_hosts(client, hosts, owner, xml_documents=None, enrichments=enrichments)
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


def _classify_and_store(hosts: list[DiscoveredHost], storage: Storage, no_redact: bool) -> None:
    client = _llm_client_or_none()
    if client is None:
        warn("--enrich skipped: OPENROUTER_API_KEY is not set — pushing without enrichment")
        return
    try:
        result = classify_assets(client, hosts, redact=not no_redact)
        for err in result.errors:
            warn(f"enrich: {err}")
        for classified in result.assets.values():
            storage.upsert_enrichment(classified.ip, classified.enrichment, client.model)
            storage.replace_findings(classified.ip, classified.findings, client.model)
        success(f"enriched {len(result.assets)} asset(s)")
    finally:
        client.close()


def _stored_enrichments_or_warn(storage: Storage, run_id: int) -> dict[str, Enrichment] | None:
    """Load stored classifications for the push; None when migration 002 is missing."""
    try:
        enrichments = storage.get_enrichments(run_id)
    except (pymysql.MySQLError, StorageError):
        warn("enrichment table missing — run 'secman-intra-mon db init' to enable enrichment tags")
        return None
    return enrichments or None


# -- report ---------------------------------------------------------------------


@app.command()
def report(
    run_id: Annotated[
        int | None, typer.Option("--run-id", help="Run to summarize (default: latest).")
    ] = None,
    from_run: Annotated[int | None, typer.Option("--from", help="Diff mode: older run id.")] = None,
    to_run: Annotated[
        int | None, typer.Option("--to", help="Diff mode: newer run id (default: latest).")
    ] = None,
    json_output: Annotated[bool, typer.Option("--json", help="JSON output.")] = False,
) -> None:
    """Summarize a persisted run, or diff two runs; LLM narrative when configured."""
    if run_id is not None and from_run is not None:
        _fail("--run-id and --from are mutually exclusive")
    if to_run is not None and from_run is None:
        _fail("--to requires --from")
    storage = _storage_or_fail()
    try:
        if from_run is not None:
            effective_to = to_run if to_run is not None else storage.latest_run_id()
            if effective_to is None:
                _fail("no scan runs in the database yet")
            if from_run >= effective_to:
                _fail(f"--from must be older than --to (got {from_run} -> {effective_to})")
            payload = diff_payload(storage, from_run, effective_to)
            if payload is None:
                _fail(f"unknown run id (--from {from_run} or --to {effective_to})")
            _emit_report(storage, payload, from_run=from_run, to_run=effective_to, json_output=json_output)
        else:
            effective_run = run_id if run_id is not None else storage.latest_run_id()
            if effective_run is None:
                _fail("no scan runs in the database yet")
            payload = run_payload(storage, effective_run)
            if payload is None:
                _fail(f"no scan run with id {effective_run}")
            _emit_report(storage, payload, run_id=effective_run, json_output=json_output)
    finally:
        storage.close()


def _emit_report(
    storage: Storage,
    payload: dict[str, Any],
    *,
    run_id: int | None = None,
    from_run: int | None = None,
    to_run: int | None = None,
    json_output: bool,
) -> None:
    llm = _llm_client_or_none()
    narrative: str | None = None
    if llm is not None:
        try:
            narrative = summarize_diff(llm, payload) if from_run is not None else summarize_run(llm, payload)
        except LlmError as exc:
            warn(f"LLM narrative failed, showing raw data: {exc}")
        finally:
            llm.close()
    if json_output:
        print_json({**payload, "narrative": narrative})
        return
    if narrative:
        print_narrative(narrative)
        return
    if llm is None:
        info("no OPENROUTER_API_KEY — showing raw data (set it for an LLM narrative)")
    if from_run is not None and to_run is not None:
        print_diff_report(storage.diff_assets(from_run, to_run), from_run, to_run)
    else:
        assert run_id is not None
        run_row = storage.get_run(run_id)
        assert run_row is not None
        networks = [n["cidr"] for n in storage.list_networks() if n["last_seen_run_id"] == run_id]
        assets = storage.list_assets(run_id=run_id)
        print_run_overview(run_row, networks, len(assets))
        print_assets(assets)


# -- enrich / findings ------------------------------------------------------------


@app.command()
def enrich(
    run_id: Annotated[int | None, typer.Option("--run-id", help="Run to classify (default: latest).")] = None,
    no_redact: Annotated[
        bool, typer.Option("--no-redact", help="Send real IPs to the LLM (default: pseudonymized).")
    ] = False,
    json_output: Annotated[bool, typer.Option("--json", help="JSON output.")] = False,
) -> None:
    """LLM-classify persisted assets and record exposure findings."""
    client = _llm_client_or_fail()
    storage = _storage_or_fail()
    try:
        effective_run = run_id if run_id is not None else storage.latest_run_id()
        if effective_run is None:
            _fail("no scan runs in the database yet")
        assets = storage.list_assets(run_id=effective_run)
        if not assets:
            _fail(f"no assets recorded for run {effective_run}")
        result = classify_assets(client, assets, redact=not no_redact)
        for err in result.errors:
            warn(f"enrich: {err}")
        if not result.assets:
            _fail("classification produced no results")
        try:
            for classified in result.assets.values():
                storage.upsert_enrichment(classified.ip, classified.enrichment, client.model)
                storage.replace_findings(classified.ip, classified.findings, client.model)
        except pymysql.MySQLError as exc:
            _fail(f"enrichment tables missing — run 'secman-intra-mon db init' ({exc})")
    finally:
        storage.close()
        client.close()
    findings_total = sum(len(c.findings) for c in result.assets.values())
    if json_output:
        print_json(
            {
                "run_id": effective_run,
                "assets": [_classified_to_dict(c) for c in result.assets.values()],
                "errors": result.errors,
            }
        )
    else:
        print_enrichments([_classified_to_dict(c) for c in result.assets.values()])
        success(
            f"run {effective_run}: {len(result.assets)} asset(s) classified, "
            f"{findings_total} finding(s) recorded"
        )


def _classified_to_dict(classified: ClassifiedAsset) -> dict[str, Any]:
    return {
        "ip": classified.ip,
        "device_type": classified.enrichment.device_type,
        "role": classified.enrichment.role,
        "criticality": classified.enrichment.criticality,
        "confidence": classified.enrichment.confidence,
        "rationale": classified.enrichment.rationale,
        "findings": [
            {"severity": f.severity, "title": f.title, "detail": f.detail} for f in classified.findings
        ],
    }


@findings_app.command("list")
def findings_list(
    severity: Annotated[
        str | None, typer.Option("--severity", help="Filter: info | low | medium | high.")
    ] = None,
    json_output: Annotated[bool, typer.Option("--json", help="JSON output.")] = False,
) -> None:
    """List recorded exposure findings."""
    if severity is not None and severity not in SEVERITIES:
        _fail(f"unknown severity {severity!r} (choose from {', '.join(SEVERITIES)})")
    storage = _storage_or_fail()
    try:
        rows = storage.list_findings(severity=severity)
    except pymysql.MySQLError as exc:
        _fail(f"findings table missing — run 'secman-intra-mon db init' ({exc})")
    finally:
        storage.close()
    if json_output:
        print_json(rows)
    else:
        print_findings(rows)


# -- ask -------------------------------------------------------------------------


@app.command()
def ask(
    question: Annotated[str, typer.Argument(help="Natural-language question over the scan database.")],
    json_output: Annotated[bool, typer.Option("--json", help="JSON output.")] = False,
) -> None:
    """Answer a question with one read-only SQL query against the scan database."""
    client = _llm_client_or_fail()
    storage = _storage_or_fail()
    try:
        try:
            answer = generate_sql(client, question)
        except (AskError, LlmError) as exc:
            _fail(str(exc))
        try:
            rows = storage.run_readonly_query(answer["sql"])
        except pymysql.MySQLError as exc:
            _fail(f"query failed: {exc}\ngenerated SQL was: {answer['sql']}")
    finally:
        storage.close()
        client.close()
    if json_output:
        print_json(
            {"question": question, "sql": answer["sql"], "explanation": answer["explanation"], "rows": rows}
        )
    else:
        info(f"SQL: {answer['sql']}")
        if answer["explanation"]:
            info(answer["explanation"])
        print_rows(rows, title="Answer")


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
