"""LLM asset classification and exposure findings.

Batches persisted (or freshly discovered) assets through the LLM to infer
device type, role and criticality, and to record exposure findings (legacy
protocols, broad port exposure, ...). Results are validated and clamped here
before they are persisted or pushed to secman — model output is never
trusted blindly.

IP addresses are pseudonymized per batch by default (classification does not
need them); hostnames, MAC vendors and service detail still leave the host —
see docs/SAFETY.md (data egress). Disable with --no-redact.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from .llm import LlmClient, LlmError
from .models import DiscoveredHost, Enrichment, Finding

#: assets per LLM call — classification quality degrades on huge batches
BATCH_SIZE = 15

SEVERITIES = ("info", "low", "medium", "high")
CRITICALITIES = ("low", "medium", "high")

CLASSIFY_SYSTEM_PROMPT = """\
You classify assets from an AUTHORIZED internal network scan for the network
owner. For each input asset produce one object with:

- ref: the input "ref", unchanged
- device_type: one short class, e.g. router, switch, firewall, printer,
  server-linux, server-windows, hypervisor, nas, workstation, iot,
  voip-phone, camera, unknown
- asset_role: one line, e.g. "Likely the LAN gateway / firewall"
- criticality: low | medium | high (business impact if compromised or down)
- confidence: 0..1
- rationale: one line naming the evidence you used
- findings: a list of {"severity": "info|low|medium|high", "title": short,
  "detail": one line} — only EXPOSURE visible in the data: legacy protocols
  (telnet, ftp, smbv1), databases on user segments, admin interfaces on
  printers/IoT, end-of-life service versions, unusually broad port exposure.
  Empty list when nothing stands out.

Use only facts present in the input; never invent CVEs or details. Reply
with one JSON object {"assets": [...]} and nothing else."""


@dataclass
class ClassifiedAsset:
    ip: str
    enrichment: Enrichment
    findings: list[Finding] = field(default_factory=list)


@dataclass
class ClassificationResult:
    assets: dict[str, ClassifiedAsset] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


def classify_assets(
    client: LlmClient,
    assets: Sequence[dict[str, Any] | DiscoveredHost],
    *,
    redact: bool = True,
    batch_size: int = BATCH_SIZE,
) -> ClassificationResult:
    """Classify assets in batches. Batch failures are collected, not raised."""
    result = ClassificationResult()
    normalized = [_normalize(asset) for asset in assets]
    for start in range(0, len(normalized), batch_size):
        batch = normalized[start : start + batch_size]
        payload: list[dict[str, Any]] = []
        ref_to_ip: dict[str, str] = {}
        for index, asset in enumerate(batch):
            ref = f"h{index:03d}" if redact else str(asset["ip"])
            ref_to_ip[ref] = str(asset["ip"])
            payload.append({"ref": ref, **_without_ip(asset)})
        try:
            reply = client.chat_json(CLASSIFY_SYSTEM_PROMPT, json.dumps(payload), max_tokens=3000)
        except LlmError as exc:
            result.errors.append(f"batch starting at {start + 1}: {exc}")
            continue
        _parse_batch(reply, ref_to_ip, result)
    return result


def _parse_batch(reply: Any, ref_to_ip: dict[str, str], result: ClassificationResult) -> None:
    entries = reply.get("assets") if isinstance(reply, dict) else None
    if not isinstance(entries, list):
        result.errors.append("LLM reply has no 'assets' list")
        return
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        ip = ref_to_ip.get(str(entry.get("ref", "")))
        if ip is None:
            continue  # unknown or hallucinated ref — skip
        enrichment = Enrichment(
            device_type=str(entry.get("device_type") or "")[:64],
            role=str(entry.get("asset_role") or "")[:255],
            criticality=_clamped_choice(entry.get("criticality"), CRITICALITIES),
            confidence=_clamped_confidence(entry.get("confidence")),
            rationale=str(entry.get("rationale") or ""),
        )
        findings = [
            Finding(
                severity=_clamped_choice(raw.get("severity"), SEVERITIES) or "info",
                title=str(raw.get("title") or "")[:255],
                detail=str(raw.get("detail") or ""),
            )
            for raw in (entry.get("findings") or [])
            if isinstance(raw, dict) and raw.get("title")
        ]
        result.assets[ip] = ClassifiedAsset(ip=ip, enrichment=enrichment, findings=findings)


def _normalize(asset: dict[str, Any] | DiscoveredHost) -> dict[str, Any]:
    if isinstance(asset, DiscoveredHost):
        ports = [
            {"port": p.port, "service": p.service, "product": p.product, "version": p.version}
            for p in asset.open_ports
        ]
        return {
            "ip": asset.ip,
            "hostname": asset.hostname,
            "mac_vendor": asset.mac_vendor,
            "os_guess": asset.os_guess,
            "open_ports": ports,
        }
    ports = [
        {"port": p["port"], "service": p["service"], "product": p["product"], "version": p["version"]}
        for p in asset["ports"]
        if p["state"] == "open"
    ]
    return {
        "ip": asset["ip"],
        "hostname": asset["hostname"],
        "mac_vendor": asset["mac_vendor"],
        "os_guess": asset["os_guess"],
        "open_ports": ports,
    }


def _without_ip(normalized: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in normalized.items() if key != "ip"}


def _clamped_choice(value: Any, choices: tuple[str, ...]) -> str:
    text = str(value or "").strip().lower()
    return text if text in choices else ""


def _clamped_confidence(value: Any) -> float:
    try:
        confidence = float(value)
    except (TypeError, ValueError):
        return 0.0
    return min(max(confidence, 0.0), 1.0)
