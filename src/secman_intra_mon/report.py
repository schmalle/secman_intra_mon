"""Run summaries and run-to-run diffs, with optional LLM narratives.

The deterministic payload is always computed from the persisted scan data;
when an LLM is configured it adds a natural-language reading on top. Without
an API key the report command prints the raw payload tables instead.
"""

from __future__ import annotations

import json
from typing import Any

from .llm import LlmClient
from .storage import Storage

#: caps keep the LLM payload bounded on large networks
REPORT_MAX_ASSETS = 400
REPORT_MAX_PORTS_PER_ASSET = 40
DIFF_MAX_ROWS = 200

RUN_SYSTEM_PROMPT = """\
You are a network security analyst writing for the OWNER of an authorized
internal network scan. Summarize the scan-run data as concise markdown with
the sections: Overview, Notable assets, Potential concerns.

Rules: use only facts present in the JSON data — never invent hosts, CVEs or
severity ratings. Reference assets by their IP address exactly. Keep it under
300 words. "Potential concerns" lists only exposure that is visible in the
data (legacy protocols, broad port exposure, unexpected services); write
"nothing stands out" when appropriate."""

DIFF_SYSTEM_PROMPT = """\
You are a network security analyst writing for the OWNER of an authorized
internal network scan. Summarize the CHANGE between two scan runs as concise
markdown with the sections: What appeared, What disappeared, Assessment.

Rules: use only facts present in the JSON data — never invent hosts or
events. Reference assets by their IP address exactly. Keep it under 300
words. In Assessment, call out security-relevant change first (new exposed
services, vanished hosts), then routine churn; an empty diff is a valid
result — say so plainly."""


def run_payload(storage: Storage, run_id: int) -> dict[str, Any] | None:
    """Compact JSON payload describing one run; None when the run is unknown."""
    run = storage.get_run(run_id)
    if run is None:
        return None
    assets = storage.list_assets(run_id=run_id)
    networks = [n for n in storage.list_networks() if n["last_seen_run_id"] == run_id]
    truncated = len(assets) > REPORT_MAX_ASSETS
    return {
        "mode": "run",
        "run": {
            "id": run["id"],
            "started_at": str(run["started_at"]),
            "finished_at": str(run["finished_at"] or "running"),
            "command": run["command"],
        },
        "networks": [n["cidr"] for n in networks],
        "asset_count": len(assets),
        "assets": [_compact_asset(a) for a in assets[:REPORT_MAX_ASSETS]],
        "truncated": truncated,
    }


def diff_payload(storage: Storage, from_run: int, to_run: int) -> dict[str, Any] | None:
    """Compact JSON payload of the change between two runs; None on unknown runs."""
    older = storage.get_run(from_run)
    newer = storage.get_run(to_run)
    if older is None or newer is None:
        return None
    diff = storage.diff_assets(from_run, to_run)
    truncated = any(len(rows) > DIFF_MAX_ROWS for rows in diff.values())
    return {
        "mode": "diff",
        "from_run": {"id": older["id"], "started_at": str(older["started_at"])},
        "to_run": {"id": newer["id"], "started_at": str(newer["started_at"])},
        "appeared_assets": [_compact_asset(a) for a in diff["appeared_assets"][:DIFF_MAX_ROWS]],
        "disappeared_assets": [_compact_asset(a) for a in diff["disappeared_assets"][:DIFF_MAX_ROWS]],
        "appeared_ports": diff["appeared_ports"][:DIFF_MAX_ROWS],
        "disappeared_ports": diff["disappeared_ports"][:DIFF_MAX_ROWS],
        "counts": {key: len(rows) for key, rows in diff.items()},
        "truncated": truncated,
    }


def summarize_run(client: LlmClient, payload: dict[str, Any]) -> str:
    return client.chat_text(RUN_SYSTEM_PROMPT, json.dumps(payload, default=str))


def summarize_diff(client: LlmClient, payload: dict[str, Any]) -> str:
    return client.chat_text(DIFF_SYSTEM_PROMPT, json.dumps(payload, default=str))


def _compact_asset(asset: dict[str, Any]) -> dict[str, Any]:
    open_ports = [p for p in asset["ports"] if p["state"] == "open"][:REPORT_MAX_PORTS_PER_ASSET]
    return {
        "ip": asset["ip"],
        "hostname": asset["hostname"],
        "mac_vendor": asset["mac_vendor"],
        "os_guess": asset["os_guess"],
        "network_cidr": asset["network_cidr"],
        "open_ports": [
            {
                "port": p["port"],
                "protocol": p["protocol"],
                "service": p["service"],
                "product": p["product"],
                "version": p["version"],
            }
            for p in open_ports
        ],
    }
