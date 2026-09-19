"""Natural-language queries over the persisted scan database.

The LLM translates a question into one SELECT statement against the schema
below; the statement is then validated (single statement, SELECT/WITH only,
no write keywords, bounded LIMIT) and executed in a read-only transaction
that is always rolled back. Keep SCHEMA_PROMPT in sync with migrations/.
"""

from __future__ import annotations

import re

from .llm import LlmClient

#: hard row cap applied when the model forgets a LIMIT
MAX_ROWS = 200

SCHEMA_PROMPT = """\
Database secman_intra_mon (MariaDB), schema:

- scan_runs(id, started_at, finished_at, command, params_json, tool_versions_json)
- networks(id, cidr UNIQUE, discovered_via, depth, first_seen_run_id, last_seen_run_id)
- assets(id, ip UNIQUE, mac, mac_vendor, hostname, os_guess, discovered_via,
  network_cidr, first_seen_run_id, last_seen_run_id, created_at, updated_at)
- ports(id, asset_id -> assets.id, port, protocol, state, service, product,
  version, first_seen_run_id, last_seen_run_id)
- asset_enrichment(asset_id -> assets.id, device_type, asset_role,
  criticality, confidence, rationale, model, classified_at)
- findings(id, asset_id -> assets.id, severity, title, detail, model, created_at)

A row's first_seen_run_id / last_seen_run_id hold the scan_runs.id of the
first / last run that observed it, so "seen in run N" means
first_seen_run_id <= N AND last_seen_run_id >= N."""

SQL_SYSTEM_PROMPT = (
    SCHEMA_PROMPT
    + """

Translate the user's question into ONE read-only SQL query. Rules: a single
SELECT (CTEs allowed); never any write or DDL; always include a LIMIT of at
most 200; join ports/assets/asset_enrichment/findings as needed; prefer
concrete columns over SELECT *. Reply with one JSON object
{"sql": "...", "explanation": "one short sentence"} and nothing else.
If the question cannot be answered from this schema, reply
{"sql": "", "explanation": "why not"}."""
)

_FORBIDDEN_RE = re.compile(
    r"\b(insert|update|delete|drop|alter|create|truncate|replace|grant|revoke|rename|"
    r"lock|unlock|call|exec|execute|handler|load|outfile|infile|dumpfile|set|use|"
    r"describe|desc|show|explain)\b",
    re.IGNORECASE,
)


class AskError(Exception):
    pass


def generate_sql(client: LlmClient, question: str) -> dict[str, str]:
    """Ask the LLM for a query; returns {"sql", "explanation"}."""
    reply = client.chat_json(SQL_SYSTEM_PROMPT, question, max_tokens=1000)
    if not isinstance(reply, dict):
        raise AskError("LLM did not return a query object")
    sql = str(reply.get("sql") or "").strip()
    explanation = str(reply.get("explanation") or "").strip()
    if not sql:
        raise AskError(explanation or "the question cannot be answered from the scan database")
    return {"sql": validate_sql(sql), "explanation": explanation}


def validate_sql(sql: str) -> str:
    """Accept exactly one SELECT/WITH statement; append a LIMIT when missing."""
    cleaned = sql.strip().strip("`").strip()
    if not cleaned:
        raise AskError("empty query")
    if ";" in cleaned[:-1] or cleaned.count(";") > 1:
        raise AskError("only a single statement is allowed")
    cleaned = cleaned.rstrip(";").strip()
    first_word = cleaned.split(None, 1)[0].lower() if cleaned.split(None, 1) else ""
    if first_word not in ("select", "with"):
        raise AskError("only SELECT queries are allowed")
    forbidden = _FORBIDDEN_RE.search(cleaned)
    if forbidden:
        raise AskError(f"query contains forbidden keyword {forbidden.group(0)!r}")
    if not re.search(r"\blimit\b", cleaned, re.IGNORECASE):
        cleaned = f"{cleaned} LIMIT {MAX_ROWS}"
    return cleaned
