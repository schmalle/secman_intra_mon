# Safety and authorization

## Authorization and the law

`secman-intra-mon` is an **active network scanner**. It sends ARP requests,
ICMP echo, TCP SYN/connect probes, and UDP traceroute packets, and it
fingerprint-services whatever answers. Run it only against networks you own or
hold **explicit written permission** to assess. In many jurisdictions
unauthorized scanning is a criminal offense; in all organizations it trips
alarms. Get the permission in writing, agree on scope and timing, and inform
your network/security operations team before the first run.

## Scope guard

The scope guard (`src/secman_intra_mon/scope.py`) is the tool's safety
boundary. Every scan target, every discovered host IP, every traceroute hop,
and every network the iterative engine enqueues passes through it.

**Allowed by default** (no flags needed):

- RFC1918 private ranges: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
- Link-local `169.254.0.0/16`, carrier-grade NAT `100.64.0.0/10`, loopback `127.0.0.0/8`
- IPv6 ULA `fc00::/7`, IPv6 link-local `fe80::/10`, `::1/128`

**Overrides and limits:**

| Flag | Effect | Use when |
| --- | --- | --- |
| `--allow-public` | permits public (non-private) ranges | you are authorized to scan address space outside RFC1918 — rare |
| `--exclude <cidr>` (repeatable) | never scans anything overlapping the CIDR | always; carve out fragile OT/ICS segments, printers, or the CEO's laptop |
| `--allow-large` | permits networks above 4096 addresses (larger than /20) | you verified the range and the load is acceptable |

`--exclude` is honored at every stage — seed assessment, per-network
processing, per-host filtering, and expansion candidates. The size limit
applies per network; `discover` without `--network` still only seeds from what
the host itself is attached or routed to. `--dry-run` shows the exact plan
with guard verdicts before a single packet is sent — use it whenever you
change scope flags.

## Operational impact

Active scanning is detectable and can be disruptive:

- **IDS/IPS and firewalls will alert.** Port scans across thousands of
  addresses are textbook detection material. Whitelist the scanner host
  deliberately, not silently, and expect SOC questions anyway.
- **Rate and profile control the load.** `--profile fast` probes the top 100
  ports per host, `default` the top 1000, and `full` all 65535 — a
  hundred-fold difference in packets and time. The `masscan` profile adds a
  network-wide pre-scan at `--masscan-rate` packets/second (default 1000,
  deliberately moderate); raising it can saturate links or crash cheap
  routers. Prefer several `fast` runs over one `full` run on production
  segments.
- **OS detection (`--os-scan`) and ARP discovery are the noisiest modes** and
  need root — another reason they are opt-in.
- Scan windows matter: run against office segments outside business hours and
  against production systems only in agreed maintenance windows.
- Reverse-DNS enrichment queries your resolvers (max 64 lookups per network);
  `--no-dns` silences that if DNS traffic itself is sensitive.

## Credential hygiene

- Credentials come from **environment variables only** — never CLI arguments,
  so they cannot leak into shell history, `ps` output, the persisted
  `scan_runs.command`, or scan output.
- `.env.example` documents the `pass://` reference convention: store the real
  secret in your password manager, keep only the reference in `.env`, and let
  your wrapper resolve it into the process environment.
- `SECMAN_URL` is validated: HTTPS required (plain HTTP only for localhost),
  and URLs containing credentials, query, or fragments are rejected.
- The secman account must be a **dedicated ADMIN-role service account** — see
  [SECMAN.md](SECMAN.md). The DB account should own only the
  `secman_intra_mon` schema. Never reuse personal credentials.
- `.env` is excluded by both `.gitignore` and `.dockerignore` — keep it that
  way.

## Data sensitivity

Scan results are a map of your internal network: live hosts, IP/MAC addresses,
open ports, service versions, OS guesses, and how subnets interconnect. Treat
them accordingly:

- Restrict the MariaDB account and host; the compose file publishes
  `127.0.0.1:3306` only — do not re-publish it to the LAN.
- Backups of the database are topology exports; encrypt and retain them like
  other security data. `docker compose down -v` destroys the local history.
- JSON output (`--json`) and terminal output contain the same sensitive data —
  mind where you pipe or paste them.
- The secman backend receives the same information via `--upload-secman`;
  confirm its access control and retention before pushing.

## Responsible defaults summary

| Aspect | Default | Override |
| --- | --- | --- |
| Scope | private/link-local/loopback ranges only | `--allow-public` |
| Denylist | none, but always honored when given | `--exclude` (repeatable) |
| Network size | max 4096 addresses per network | `--allow-large` |
| Iteration depth | 2 | `--max-depth` |
| Expansion | on, traceroute-sampled (8 hosts, 8 hops) | `--no-expand` |
| Port coverage | top 1000 (`--profile default`) | `--profile fast` / `full` / `masscan` |
| masscan rate | 1000 packets/second | `--masscan-rate` |
| Reverse DNS | on, max 64 lookups/network | `--no-dns` |
| OS detection | off (needs root) | `--os-scan` |
| Packets before consent | none — `--dry-run` shows the plan first | — |
| Credentials | environment only, never CLI/output/DB | — |
| Persistence | off unless DB is configured | `--store-db` |
| secman upload | off | `--upload-secman` / `secman-push` |
