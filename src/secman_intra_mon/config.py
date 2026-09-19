"""Environment-only configuration.

Credentials and connection settings come exclusively from environment
variables (convention shared with the other secman extensions) — never from
CLI arguments, so they do not leak into shell history or scan output.
"""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass
from urllib.parse import urlparse

DB_ENV_PREFIX = "SECMAN_INTRA_MON_DB_"
LLM_ENV_PREFIX = "SECMAN_INTRA_MON_LLM_"
DEFAULT_LLM_BASE_URL = "https://openrouter.ai/api/v1"
DEFAULT_LLM_MODEL = "openai/gpt-4o-mini"


class ConfigError(Exception):
    pass


@dataclass
class DbConfig:
    host: str
    port: int
    name: str
    user: str
    password: str

    @classmethod
    def from_env(cls) -> DbConfig | None:
        """Return the DB config, or None when persistence is not configured."""
        user = os.environ.get(DB_ENV_PREFIX + "USER", "")
        password = os.environ.get(DB_ENV_PREFIX + "PASSWORD", "")
        if not user or not password:
            return None
        try:
            port = int(os.environ.get(DB_ENV_PREFIX + "PORT", "3306"))
        except ValueError as exc:
            raise ConfigError(f"{DB_ENV_PREFIX}PORT is not a number") from exc
        return cls(
            host=os.environ.get(DB_ENV_PREFIX + "HOST", "127.0.0.1"),
            port=port,
            name=os.environ.get(DB_ENV_PREFIX + "NAME", "secman_intra_mon"),
            user=user,
            password=password,
        )


@dataclass
class SecmanConfig:
    base_url: str
    token: str | None
    username: str | None
    password: str | None

    @classmethod
    def from_env(cls) -> SecmanConfig | None:
        """Return the secman connection config, or None when not configured."""
        raw_url = os.environ.get("SECMAN_URL", "").strip()
        if not raw_url:
            return None
        base_url = validate_base_url(raw_url)
        token = os.environ.get("SECMAN_TOKEN") or None
        username = os.environ.get("SECMAN_USERNAME") or None
        password = os.environ.get("SECMAN_PASSWORD") or None
        if not token and not (username and password):
            raise ConfigError(
                "SECMAN_URL is set but no credentials: provide SECMAN_TOKEN or "
                "SECMAN_USERNAME + SECMAN_PASSWORD"
            )
        return cls(base_url=base_url, token=token, username=username, password=password)


@dataclass
class LlmConfig:
    """Connection settings for the optional LLM features (OpenRouter or any
    OpenAI-compatible endpoint). Absent an API key, all LLM features are off."""

    api_key: str
    model: str
    planner_model: str
    base_url: str
    timeout: float

    @classmethod
    def from_env(cls) -> LlmConfig | None:
        """Return the LLM config, or None when OPENROUTER_API_KEY is not set."""
        api_key = os.environ.get("OPENROUTER_API_KEY", "").strip()
        if not api_key:
            return None
        model = os.environ.get(LLM_ENV_PREFIX + "MODEL", "").strip() or DEFAULT_LLM_MODEL
        planner_model = os.environ.get(LLM_ENV_PREFIX + "PLANNER_MODEL", "").strip() or model
        raw_base_url = os.environ.get(LLM_ENV_PREFIX + "BASE_URL", "").strip() or DEFAULT_LLM_BASE_URL
        base_url = validate_llm_base_url(raw_base_url)
        try:
            timeout = float(os.environ.get(LLM_ENV_PREFIX + "TIMEOUT", "60"))
        except ValueError as exc:
            raise ConfigError(f"{LLM_ENV_PREFIX}TIMEOUT is not a number") from exc
        if timeout <= 0:
            raise ConfigError(f"{LLM_ENV_PREFIX}TIMEOUT must be positive")
        return cls(
            api_key=api_key,
            model=model,
            planner_model=planner_model,
            base_url=base_url,
            timeout=timeout,
        )


def validate_base_url(raw: str, env_var: str = "SECMAN_URL") -> str:
    """HTTPS-only origin; plain HTTP is tolerated for localhost development."""
    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ConfigError(f"{env_var} must be an http(s) origin, got: {raw!r}")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ConfigError(f"{env_var} must not contain credentials, query or fragment")
    if parsed.scheme == "http" and not _is_localhost(parsed.hostname):
        raise ConfigError(f"{env_var} must use https; plain http is only allowed for localhost targets")
    origin = f"{parsed.scheme}://{parsed.hostname}"
    if parsed.port:
        origin += f":{parsed.port}"
    return origin.rstrip("/")


def validate_llm_base_url(raw: str) -> str:
    """Like validate_base_url, but keeps the path (API prefix such as /api/v1)."""
    env_var = LLM_ENV_PREFIX + "BASE_URL"
    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ConfigError(f"{env_var} must be an http(s) origin, got: {raw!r}")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ConfigError(f"{env_var} must not contain credentials, query or fragment")
    if parsed.scheme == "http" and not _is_localhost(parsed.hostname):
        raise ConfigError(f"{env_var} must use https; plain http is only allowed for localhost targets")
    base = f"{parsed.scheme}://{parsed.hostname}"
    if parsed.port:
        base += f":{parsed.port}"
    return (base + parsed.path).rstrip("/")


def _is_localhost(hostname: str) -> bool:
    if hostname in ("localhost", "host.docker.internal"):
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False
