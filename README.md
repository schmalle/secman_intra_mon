# secman_intra_mon — iterative intranet asset discovery

`secman-intra-mon` discovers the assets reachable from the host it runs on and
feeds them into [secman](https://github.com/schmalle/secman), the security
requirement, vulnerability, and risk management platform. Starting from the
host's own IP networks it finds live hosts, port-scans them with nmap, and then
iterates into adjacent networks revealed by traceroute — breadth-first, bounded
by `--max-depth`.

Results print as rich terminal tables or JSON, persist into a local MariaDB for
history, and can optionally be pushed to a secman backend (idempotent asset
upserts plus raw nmap XML uploads). A Dockerfile provides a Linux runtime with
all scanner tools included.

> **AUTHORIZATION WARNING** — scan only networks you own or have explicit
> written permission to assess. This is an *active* scanner: it sends ARP,
> ICMP, TCP, and UDP probes. Unauthorized scanning may be illegal in your
> jurisdiction and it will be noticed — expect IDS/IPS alerts, firewall logs,
> and helpdesk tickets. The built-in scope guard (private ranges only, explicit
> opt-ins for anything else) is a safety net, not a permission slip.
> See [Safety and authorization](docs/SAFETY.md).

## Five-minute quickstart

Prerequisites: Python 3.12 or newer,
[`uv`](https://docs.astral.sh/uv/getting-started/installation/), and `nmap` in
PATH (`apt install nmap` / `brew install nmap`). For ARP discovery and the
masscan profile you additionally need root (or `CAP_NET_RAW`) plus, optionally,
`arp-scan`, `fping`, `masscan`, and `traceroute`. No scanner binaries at hand?
Use the [Docker image](docs/DOCKER.md), which ships all of them.

```bash
git clone <repository-url> secman_intra_mon
cd secman_intra_mon
./scripts/setup.sh                        # uv sync --locked --all-groups

uv run secman-intra-mon capabilities      # which tools and privileges do we have?
uv run secman-intra-mon discover --dry-run   # the plan — no packets sent

sudo -E uv run secman-intra-mon discover --network 192.168.1.0/24
```

Replace `192.168.1.0/24` with your own subnet. Without `--network`, the seed
networks come from the host's interfaces and routing table. `sudo -E` preserves
your environment; elevated privileges are only needed for ARP discovery, OS
detection (`--os-scan`), and the `masscan` profile — plain nmap-based discovery
runs unprivileged.

To keep history across runs, point the tool at a MariaDB and persist the run:

```bash
export SECMAN_INTRA_MON_DB_USER=intra_mon
export SECMAN_INTRA_MON_DB_PASSWORD='load-from-your-secret-manager'

uv run secman-intra-mon db init
sudo -E uv run secman-intra-mon discover --network 192.168.1.0/24 --store-db
uv run secman-intra-mon assets list
```

No MariaDB server at hand? `docker compose up -d db` starts a local one — see
[Optional MariaDB history](#optional-mariadb-history). You can also
`source .venv/bin/activate` and call `secman-intra-mon` directly instead of
going through `uv run`.

## Common examples

```bash
# Preview exactly what would be scanned — no packets are sent
uv run secman-intra-mon discover --dry-run

# Discover the host's own networks, quick top-100-port profile, no expansion
sudo -E uv run secman-intra-mon discover --profile fast --no-expand

# One specific network, excluding a sensitive segment
sudo -E uv run secman-intra-mon discover -n 10.10.0.0/22 --exclude 10.10.1.0/24

# Large flat network at speed: masscan finds open ports, nmap -sV verifies them
sudo -E uv run secman-intra-mon discover -n 10.0.0.0/16 \
  --profile masscan --allow-large --masscan-rate 2000

# Service-scan known hosts directly (no discovery phase, no expansion)
uv run secman-intra-mon scan 192.168.1.1 192.168.1.23 -p 22,80,443

# Full port scan plus OS fingerprinting of one host (needs root)
sudo -E uv run secman-intra-mon scan 10.20.30.40 --profile full --os-scan

# Machine-readable output for scripting
uv run secman-intra-mon discover --json | jq '.summary'

# Persist, then browse history
sudo -E uv run secman-intra-mon discover --store-db
uv run secman-intra-mon runs --limit 5
uv run secman-intra-mon assets show 192.168.1.23
```

## Command reference

| Command | Purpose | Key options |
| --- | --- | --- |
| `discover` | Iterative BFS discovery, seeded from this host's networks | `--network/-n` (repeatable), `--max-depth` (default 2), `--profile fast\|default\|full\|masscan`, `--os-scan`, `--exclude` (repeatable), `--allow-public`, `--allow-large`, `--no-expand`, `--no-dns`, `--dry-run`, `--store-db`, `--upload-secman`, `--masscan-rate` (default 1000), `--agentic` (+`--yes`, `--agent-max-actions`, `--agent-max-networks`), `--enrich` (+`--no-redact`), `--json` |
| `scan` | Direct nmap service scan of the given targets | targets (IPs, CIDRs, hostnames), `--profile fast\|default\|full`, `--ports/-p`, `--os-scan`, `--exclude`, `--allow-public`, `--allow-large`, `--store-db`, `--json` |
| `capabilities` | Show detected scanner tools, privileges and LLM status | — |
| `db init` | Create the database (if needed) and apply migrations | — |
| `assets list` | List persisted assets | `--network/-n`, `--run-id`, `--json` |
| `assets show <ip>` | Show one persisted asset with its ports | `--json` |
| `networks list` | List discovered networks | `--json` |
| `runs` | List past scan runs | `--limit` (default 20), `--json` |
| `secman-push` | Push the persisted assets of a run to secman | `--run-id` (default: latest run), `--enrich`, `--no-redact` |
| `report` | Summarize a run, or diff two runs (LLM narrative when configured) | `--run-id`, `--from`/`--to`, `--json` |
| `enrich` | LLM-classify persisted assets, record exposure findings | `--run-id`, `--no-redact`, `--json` |
| `findings list` | List recorded exposure findings | `--severity`, `--json` |
| `ask` | Answer a question with one read-only SQL query over the scan DB | `--json` |

Every command supports `--help`; the app supports `--version`.

Scan profiles select the port coverage of the nmap `-sV` service scan:

| Profile | Ports scanned | Notes |
| --- | --- | --- |
| `fast` | top 100 | quick sweep of the most common services |
| `default` | top 1000 | good everyday coverage |
| `full` | all 65535 (`-p-`) | thorough, slow; use for single segments or hosts |
| `masscan` | masscan pre-scan of ports 1–10000, then nmap `-sV` verification | needs root/`CAP_NET_RAW`; fastest on large ranges; tune with `--masscan-rate` (packets/second, default 1000) |

## Configuration

Configuration comes from environment variables only — credentials are never
accepted as CLI arguments, so they cannot leak into shell history, scan output,
or the database. Copy `.env.example` to `.env`, fill it in, and export it:

```bash
cp .env.example .env
${EDITOR:-vi} .env
set -a; . ./.env; set +a
```

| Variable | Default | Purpose |
| --- | --- | --- |
| `SECMAN_INTRA_MON_DB_HOST` | `127.0.0.1` | MariaDB host |
| `SECMAN_INTRA_MON_DB_PORT` | `3306` | MariaDB port |
| `SECMAN_INTRA_MON_DB_NAME` | `secman_intra_mon` | MariaDB database name |
| `SECMAN_INTRA_MON_DB_USER` | — | DB user; persistence is enabled only when both USER and PASSWORD are set |
| `SECMAN_INTRA_MON_DB_PASSWORD` | — | DB password |
| `SECMAN_URL` | — | secman origin; HTTPS required, plain HTTP only for localhost |
| `SECMAN_USERNAME` / `SECMAN_PASSWORD` | — | secman login (dedicated ADMIN-role service account) |
| `SECMAN_TOKEN` | — | existing secman JWT, alternative to username/password |
| `SECMAN_ASSET_OWNER` | `SECMAN_USERNAME` | owner written onto imported secman assets |
| `OPENROUTER_API_KEY` | — | OpenRouter key; enables the LLM features when set |
| `SECMAN_INTRA_MON_LLM_MODEL` | `openai/gpt-4o-mini` | model for reports, classification and NL2SQL |
| `SECMAN_INTRA_MON_LLM_PLANNER_MODEL` | `SECMAN_INTRA_MON_LLM_MODEL` | model for the agentic discovery planner |
| `SECMAN_INTRA_MON_LLM_BASE_URL` | `https://openrouter.ai/api/v1` | OpenAI-compatible endpoint (self-hosted allowed; HTTPS required outside localhost) |
| `SECMAN_INTRA_MON_LLM_TIMEOUT` | `60` | LLM request timeout in seconds |

Values may be `pass://` references (for example
`pass://secman/intra-mon-db-password`) resolved through your secret-manager
wrapper — the same convention as the other secman extensions; resolved secrets
stay in the process environment.

## Optional MariaDB history

MariaDB is contacted only for `db init`, `assets`, `networks`, `runs`,
`secman-push`, or a `discover`/`scan` with `--store-db`. Any reachable MariaDB
server works — configure it via the `SECMAN_INTRA_MON_DB_*` variables above,
then initialize the schema:

```bash
uv run secman-intra-mon db init
```

For a self-contained local setup, the compose file runs MariaDB 11.4 alongside
the containerized scanner:

```bash
export SECMAN_INTRA_MON_DB_PASSWORD='load-from-your-secret-manager'
docker compose up -d db
docker compose run --rm app db init
docker compose run --rm app discover --store-db
docker compose run --rm app assets list
```

See [Docker](docs/DOCKER.md) for the full walkthrough, and
[Architecture](docs/ARCHITECTURE.md) for the schema and upsert semantics.

## Optional secman upload

With `SECMAN_URL` and credentials set, a discovery run can push its results
straight into secman:

```bash
export SECMAN_URL=https://secman.example.invalid
export SECMAN_USERNAME=intra-mon-service
export SECMAN_PASSWORD='load-from-your-secret-manager'

sudo -E uv run secman-intra-mon discover --store-db --upload-secman
uv run secman-intra-mon secman-push --run-id 3   # re-push a persisted run later
```

The account needs the ADMIN role — asset import and nmap upload are ADMIN
endpoints; use a dedicated service account. Upload creates/updates `Network
Host` assets (upsert by name) and submits the raw nmap XML so secman builds
port-level records. See [secman integration](docs/SECMAN.md) for details and
troubleshooting.

## Optional LLM features (OpenRouter)

With `OPENROUTER_API_KEY` set, four AI features become available on top of the
deterministic pipeline — all of them additive, all of them off without a key:

```bash
uv run secman-intra-mon report --run-id 3          # narrative summary of a run
uv run secman-intra-mon report --from 2 --to 3     # what changed between runs?
uv run secman-intra-mon enrich --run-id 3          # classify assets, record findings
uv run secman-intra-mon findings list --severity high
uv run secman-intra-mon ask "which hosts appeared in the last run with SMB open?"
sudo -E uv run secman-intra-mon discover --agentic   # the LLM plans the iteration
```

- **`report`** turns run data or a run-to-run diff into an analyst-style
  narrative. Without an LLM key it prints the raw tables instead.
- **`enrich`** classifies assets (device type, role, criticality) and records
  exposure findings (legacy protocols, broad port exposure, ...) into the
  `asset_enrichment` and `findings` tables (run `db init` to apply migration
  002). Classifications flow into secman as `device_type`/`criticality` tags
  on the next `secman-push` (or immediately via `secman-push --enrich` /
  `discover --enrich`). IPs are pseudonymized before they leave the host
  (`--no-redact` disables that).
- **`ask`** translates a question into a single read-only SELECT (validated,
  LIMIT-capped, executed in a transaction that is always rolled back).
- **`discover --agentic`** replaces the fixed BFS with an observe → plan →
  act loop: the planner proposes one action per step from a closed vocabulary
  (`scan_network`, `trace_host`, `note`, `stop`). Every proposal is validated
  against the same scope guard, depth limits and hard budgets
  (`--agent-max-actions`, `--agent-max-networks`) — the model can narrow the
  plan, never widen it, and it never constructs commands. Each packet-sending
  action needs operator confirmation unless `--yes` is given, and every
  proposal and verdict is written to an audit log persisted in the run's
  `params_json`.

Data egress: LLM requests carry scan results (topology, hosts, services) to
the configured endpoint. Read [docs/SAFETY.md](docs/SAFETY.md) before
enabling, and consider `SECMAN_INTRA_MON_LLM_BASE_URL` pointing at a
self-hosted OpenAI-compatible gateway to keep the data on-prem.

## Development

Python 3.12+, managed with uv. Lint/typecheck/build gate before every commit:

```bash
./scripts/verify.sh   # uv lock --check, ruff check, ruff format --check, mypy, uv build
```

Agent-authored commits go to the `dev` branch (never the default branch
directly) and follow Conventional Commits — see `AGENTS.md`.

```
src/secman_intra_mon/
  cli.py            commands (typer)
  discovery.py      iterative BFS engine
  agent.py          agentic planner loop (discover --agentic)
  llm.py            OpenRouter / OpenAI-compatible client (httpx)
  report.py         run summaries and diffs (LLM narratives)
  enrich.py         LLM asset classification + findings
  ask.py            natural-language to read-only SQL
  netinfo.py        local interfaces/routes (ip -j, psutil fallback)
  scope.py          scope guard — the safety boundary
  scanners/         nmap, masscan, fping, arp-scan, traceroute adapters
  storage.py        MariaDB persistence (pymysql)
  migrations/       SQL schema, applied by `db init`
  secman.py         secman REST client
  output.py         rich tables / JSON
  config.py         environment-only configuration
  models.py         shared dataclasses
scripts/            setup.sh, verify.sh
docs/               ARCHITECTURE, SCANNERS, DOCKER, SECMAN, SAFETY
Dockerfile          Linux runtime with all scanner tools
docker-compose.yml  scanner app + MariaDB 11.4
```

## Documentation

- [Architecture and data model](docs/ARCHITECTURE.md)
- [Scanner tools and privileges](docs/SCANNERS.md)
- [Docker and docker compose](docs/DOCKER.md)
- [secman integration](docs/SECMAN.md)
- [Safety and authorization](docs/SAFETY.md)

## Limitations

- Discovery can only ever reach networks the scanning host has routes to — not
  behind NAT, not into unreachable VLANs or firewalled segments; expansion
  candidates are always `/24` guesses around observed router interfaces,
  depth-limited by `--max-depth`.
- The pipeline is IPv4-oriented: interface/route seeding and traceroute
  expansion handle IPv4 only. IPv6 ULA/link-local ranges pass the scope guard
  but are not exercised by the automated pipeline.
- Hosts that answer neither ARP nor ICMP are invisible to classic discovery;
  only the `masscan` profile still finds them via their open ports.
- ARP discovery, OS detection (`--os-scan`), and the `masscan` profile require
  root or `CAP_NET_RAW`; without them the tool degrades to fping/nmap `-sn`
  discovery and nmap service scans (see [Scanners](docs/SCANNERS.md)).
- macOS/Windows development hosts: no iproute2, so topology falls back to
  psutil (interfaces only, no gateway routes), and Docker host networking does
  not expose the LAN — use `--network` explicitly there.
- secman upload requires an ADMIN-role account and pushes assets plus raw nmap
  XML only; port-level records exist in secman only for runs uploaded while the
  XML was still in memory (`discover --upload-secman`).
- LLM features need network access to the configured endpoint and send it scan
  data (pseudonymized for `enrich`, real addresses for the agentic planner).
  Classification and findings are model output: treat them as hints for an
  analyst, not as verified facts. The agentic planner is additionally bounded
  by the scope guard, depth and the action/network budgets — but its plan
  quality depends entirely on the configured model.
