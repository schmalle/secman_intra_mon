"""LLM client for the optional AI features (report, enrich, ask, --agentic).

Talks to OpenRouter (https://openrouter.ai) or any OpenAI-compatible chat
completions endpoint (self-hosted included) via plain httpx — no extra SDK.
The API key comes from the environment only (OPENROUTER_API_KEY) and is sent
nowhere but the configured endpoint; it is never logged or persisted.

All LLM use is additive: without a key every feature degrades to the
deterministic behavior. Scan data sent to the endpoint is sensitive — see
docs/SAFETY.md (data egress).
"""

from __future__ import annotations

import json
from typing import Any

import httpx

from .config import LlmConfig

USER_AGENT = "secman-intra-mon/0.1"


class LlmError(Exception):
    pass


class LlmClient:
    def __init__(self, config: LlmConfig):
        self._config = config
        self._client = httpx.Client(
            base_url=config.base_url,
            timeout=config.timeout,
            headers={
                "Authorization": f"Bearer {config.api_key}",
                "User-Agent": USER_AGENT,
                "X-Title": "secman-intra-mon",
            },
        )

    @property
    def model(self) -> str:
        return self._config.model

    @property
    def planner_model(self) -> str:
        return self._config.planner_model

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> LlmClient:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # -- completions ---------------------------------------------------------

    def chat_text(
        self,
        system: str,
        user: str,
        *,
        model: str | None = None,
        max_tokens: int = 2000,
    ) -> str:
        """Free-form completion; returns the assistant message text."""
        messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]
        return self._complete(messages, model or self._config.model, max_tokens, json_mode=False)

    def chat_json(
        self,
        system: str,
        user: str,
        *,
        model: str | None = None,
        max_tokens: int = 2000,
    ) -> Any:
        """Completion parsed as JSON. Retries once with a repair nudge when the
        model replies with malformed JSON."""
        messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]
        text = self._complete(messages, model or self._config.model, max_tokens, json_mode=True)
        try:
            return _parse_json(text)
        except LlmError:
            messages.append({"role": "assistant", "content": text})
            messages.append(
                {
                    "role": "user",
                    "content": "Your reply was not valid JSON. Reply with the JSON object only, no prose.",
                }
            )
            retry = self._complete(messages, model or self._config.model, max_tokens, json_mode=True)
            return _parse_json(retry)

    def _complete(self, messages: list[dict[str, str]], model: str, max_tokens: int, json_mode: bool) -> str:
        body: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": 0.2,
        }
        if json_mode:
            body["response_format"] = {"type": "json_object"}
        try:
            response = self._client.post("/chat/completions", json=body)
        except httpx.HTTPError as exc:
            raise LlmError(f"LLM request failed: {exc}") from exc
        if response.status_code == 401:
            raise LlmError("LLM endpoint rejected the API key (HTTP 401) — check OPENROUTER_API_KEY")
        if response.status_code != 200:
            raise LlmError(f"LLM endpoint returned HTTP {response.status_code}: {response.text[:300]}")
        try:
            payload = response.json()
            return str(payload["choices"][0]["message"]["content"])
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            raise LlmError(f"unexpected LLM response shape: {response.text[:300]}") from exc


def _parse_json(text: str) -> Any:
    """Parse a model reply as JSON, tolerating markdown code fences."""
    cleaned = text.strip()
    if cleaned.startswith("```"):
        lines = cleaned.splitlines()
        # drop the opening fence (``` or ```json) and a closing fence if present
        lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        cleaned = "\n".join(lines).strip()
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError as exc:
        raise LlmError(f"LLM reply is not valid JSON: {cleaned[:200]}") from exc
