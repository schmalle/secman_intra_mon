"""Optional secman backend integration (Phase 1 — no backend change needed).

Flow: POST /api/auth/login (JWT arrives as `secman_auth` cookie, also usable
as Bearer) -> PUT /api/assets/import per discovered asset (idempotent upsert,
tags merged additively) -> POST /api/scan/upload-nmap for the raw nmap XML
(creates Scan/ScanResult/ScanPort rows and links ports to assets in secman).

Contract verified against src/backendng (AssetController.importAsset,
ScanController.uploadNmapScan, AuthController.login). If endpoints change,
re-verify path / method / request fields / response fields / roles.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import httpx

from .config import SecmanConfig
from .models import DiscoveredHost, Enrichment

USER_AGENT = "secman-intra-mon/0.1"
LOGIN_PATH = "/api/auth/login"
IMPORT_ASSET_PATH = "/api/assets/import"
UPLOAD_NMAP_PATH = "/api/scan/upload-nmap"


class SecmanError(Exception):
    pass


@dataclass
class PushSummary:
    assets_created: int = 0
    assets_updated: int = 0
    xml_uploads: int = 0
    errors: list[str] = field(default_factory=list)


class SecmanClient:
    def __init__(self, config: SecmanConfig, timeout: float = 30.0):
        self._config = config
        self._client = httpx.Client(
            base_url=config.base_url,
            timeout=timeout,
            headers={"User-Agent": USER_AGENT},
        )
        if config.token:
            self._client.headers["Authorization"] = f"Bearer {config.token}"

    @property
    def username(self) -> str | None:
        return self._config.username

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> SecmanClient:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # -- auth ----------------------------------------------------------------

    def login(self) -> list[str]:
        """Authenticate with username/password; returns the user's roles."""
        if self._config.token:
            return []  # token auth: roles unknown, validated on first request
        try:
            response = self._client.post(
                LOGIN_PATH,
                json={
                    "username": self._config.username,
                    "password": self._config.password,
                },
            )
        except httpx.HTTPError as exc:
            raise SecmanError(f"cannot reach secman at {self._config.base_url}: {exc}") from exc
        if response.status_code == 401:
            raise SecmanError("secman login failed: invalid credentials")
        if response.status_code != 200:
            raise SecmanError(f"secman login failed: HTTP {response.status_code} {response.text[:200]}")
        jwt = response.cookies.get("secman_auth")
        if not jwt:
            raise SecmanError("secman login succeeded but no secman_auth cookie was returned")
        self._client.headers["Authorization"] = f"Bearer {jwt}"
        roles = response.json().get("roles", [])
        if not isinstance(roles, list):
            roles = []
        return [str(role) for role in roles]

    # -- ingestion -----------------------------------------------------------

    def push_asset(self, host: DiscoveredHost, owner: str, enrichment: Enrichment | None = None) -> bool:
        """Idempotent upsert of one asset. Returns True when newly created."""
        description = f"Discovered by secman_intra_mon ({host.discovered_via or 'scan'})"
        if enrichment and enrichment.role:
            description += f" — {enrichment.role}"
        body: dict[str, Any] = {
            "name": host.display_name(),
            "type": "Network Host",
            "owner": owner,
            "ip": host.ip,
            "networkZone": "INTERNAL",
            "description": description,
            "tags": self._asset_tags(host, enrichment),
        }
        response = self._request("PUT", IMPORT_ASSET_PATH, json=body)
        payload = response.json()
        return bool(payload.get("created", False))

    def upload_nmap_xml(self, xml_text: str, filename: str) -> dict[str, Any]:
        """Upload raw `nmap -oX` output; returns secman's ScanSummaryDTO."""
        response = self._request(
            "POST",
            UPLOAD_NMAP_PATH,
            files={"file": (filename, xml_text, "application/xml")},
        )
        return dict(response.json())

    # -- helpers -------------------------------------------------------------

    def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        try:
            response = self._client.request(method, path, **kwargs)
        except httpx.HTTPError as exc:
            raise SecmanError(f"secman request {method} {path} failed: {exc}") from exc
        if response.status_code in (401, 403):
            raise SecmanError(
                f"secman rejected {method} {path} (HTTP {response.status_code}) — "
                "the account needs the ADMIN role for asset import and nmap upload"
            )
        if response.status_code >= 400:
            raise SecmanError(
                f"secman {method} {path} failed: HTTP {response.status_code} {response.text[:300]}"
            )
        return response

    @staticmethod
    def _asset_tags(host: DiscoveredHost, enrichment: Enrichment | None = None) -> dict[str, str]:
        classification = host.asset_kind
        tags: dict[str, str] = {
            "source": "secman-intra-mon",
            "active_discovery": "true",
            "discovered_via": host.discovered_via or "scan",
            "asset_kind": classification,
            "classification_method": "local-heuristic",
        }
        if host.mac:
            tags["mac"] = host.mac
        if host.mac_vendor:
            tags["mac_vendor"] = host.mac_vendor
        if host.os_guess:
            tags["os_guess"] = host.os_guess
        if host.open_ports:
            tags["open_ports"] = ",".join(
                f"{p.port}/{p.protocol}" for p in sorted(host.open_ports, key=lambda p: p.port)
            )
        if enrichment:
            if enrichment.device_type:
                tags["device_type"] = enrichment.device_type
            if enrichment.criticality:
                tags["criticality"] = enrichment.criticality
        return tags


def push_hosts(
    client: SecmanClient,
    hosts: list[DiscoveredHost],
    owner: str,
    xml_documents: list[str] | None = None,
    enrichments: dict[str, Enrichment] | None = None,
) -> PushSummary:
    """Push all discovered assets, then upload nmap XML. Never raises on
    individual asset failures — errors are collected into the summary."""
    summary = PushSummary()
    for host in hosts:
        try:
            if client.push_asset(host, owner, (enrichments or {}).get(host.ip)):
                summary.assets_created += 1
            else:
                summary.assets_updated += 1
        except (SecmanError, ValueError) as exc:
            summary.errors.append(f"{host.ip}: {exc}")
    for index, xml_text in enumerate(xml_documents or [], start=1):
        try:
            client.upload_nmap_xml(xml_text, f"intra-mon-scan-{index}.xml")
            summary.xml_uploads += 1
        except SecmanError as exc:
            summary.errors.append(f"nmap xml upload {index}: {exc}")
    return summary
