# Architecture

`secman-intra-mon` is a small pipeline: a typer CLI drives an iterative
discovery engine, which orchestrates external scanner binaries through thin
adapters; results flow into terminal/JSON output, MariaDB storage, and an
optional secman REST push.

```
                 ┌───────────┐
                 │  cli.py   │  commands, flag wiring, scope-guard construction
                 └─────┬─────┘
                       │
               ┌───────▼────────┐      ┌────────────┐
               │  discovery.py  │─────▶│  scope.py  │  every candidate network and
               │  BFS engine    │      │  guard     │  every discovered IP passes here
               └──┬────┬─────┬──┘      └────────────┘
                  │    │     │
        ┌─────────▼┐ ┌─▼─────▼─────┐ ┌▼───────────┐
        │ netinfo  │ │ scanners/   │ │ output.py  │  rich tables / JSON
        │ topology │ │ adapters    │ ├────────────┤
        └──────────┘ └─────────────┘ │ storage.py │──▶ MariaDB (pymysql)
                                     │ secman.py  │──▶ secman REST (httpx)
                                     └────────────┘
```

`models.py` holds the shared dataclasses (`DiscoveredHost`, `DiscoveredPort`,
`NetworkSeed`, `NetworkResult`) that are the currency between all stages.

## The iterative discovery algorithm

The engine (`discovery.py`) is a breadth-first traversal over networks, bounded
by `--max-depth` (default 2) and gated by the scope guard at every step.

**1. Seed.** Seeds come from `--network/-n` options (`manual`), or — when none
are given — from the host itself: every interface subnet (`ip -j addr`,
`netinfo.py`, with a psutil fallback for macOS dev hosts) and every non-default
route with a gateway (`ip -j route`). Interface/route seeds with a prefix
longer than /31 are skipped as point-to-point noise; manual seeds are always
kept. Reading topology sends no packets. `--dry-run` stops here and prints the
plan with the guard verdict per seed.

**2. Per-network processing.** Each dequeued network is scope-checked again,
then processed in three phases:

- **Host discovery** — pick the best available tool (details in
  [SCANNERS.md](SCANNERS.md)):
  `arp-scan` when the network is directly connected (L2-adjacent) and we hold
  `CAP_NET_RAW`, else `fping`, else `nmap -sn` (with `-PR` when L2-adjacent
  and raw-capable). Discovered hosts are filtered through the guard's per-IP
  check, so an exclude list is honored even when a scanner reports extra
  addresses.
- **Service scan** — classic profiles (`fast`/`default`/`full`) run one
  `nmap -sV` over the live hosts; the raw `-oX` XML is kept in memory for the
  optional secman upload. The `masscan` profile instead sweeps the whole
  network with masscan (default ports 1–10000, `--masscan-rate` pps), adds
  hosts that answered with open ports but never showed up in discovery, then
  groups hosts by identical port-set and runs one `nmap -sV` verification per
  group — service detail stays accurate while nmap invocations stay few.
- **Reverse-DNS enrichment** — best-effort `PTR` lookup per host that does not
  already carry a name, capped at 64 lookups per network (`--no-dns`
  disables).

**3. Expansion.** If expansion is enabled (`--no-expand` disables) and the
network was processed below `--max-depth`, up to 8 live hosts are sampled —
known gateways first, then a spread of hosts — and tracerouted
(`-n -q1 -w2 -m8`). Every hop address that lies *outside* the current network
is a router interface; its `/24` becomes a candidate seed at depth+1
(`discovered_via` = `traceroute via <hop>`), queued only if it passes the
scope guard and was not already visited.

### What expansion can and cannot find

Expansion only ever reaches networks the scanning host can already route to —
traceroute just makes the routing visible. It cannot cross NAT boundaries,
enter VLANs the host has no route to, or survive paths where filters drop the
probes. Candidate networks are always `/24` guesses around observed router
interfaces: a router's `10.30.4.1` yields `10.30.4.0/24` regardless of the
real subnet size. Hops inside the current network, loopbacks, out-of-scope
addresses, and already-visited networks are ignored. Depth is counted per seed
and hard-bounded, so iteration always terminates.

## Data model (MariaDB)

Applied by `db init` from `migrations/001_initial.sql`; a
`schema_migrations` table tracks applied versions.

| Table | Purpose | Key columns |
| --- | --- | --- |
| `scan_runs` | one row per persisted run | `id`, `started_at`, `finished_at`, `command`, `params_json`, `tool_versions_json` |
| `networks` | every network ever processed | `cidr` UNIQUE, `discovered_via`, `depth`, `first_seen_run_id`, `last_seen_run_id` |
| `assets` | one row per discovered IP | `ip` UNIQUE, `mac`, `mac_vendor`, `hostname`, `os_guess`, `discovered_via`, `network_cidr`, `first_seen_run_id`, `last_seen_run_id` |
| `ports` | one row per open/filtered port per asset | UNIQUE (`asset_id`, `port`, `protocol`), `state`, `service`, `product`, `version`, `first_seen_run_id`, `last_seen_run_id`; FK to `assets` with `ON DELETE CASCADE` |

**Upsert and idempotency semantics.** Writes are `INSERT ... ON DUPLICATE KEY
UPDATE` against the natural keys (`assets.ip`, `ports(asset_id, port,
protocol)`, `networks.cidr`). Re-running a scan therefore updates history in
place instead of duplicating rows: `last_seen_run_id` always advances to the
current run, while `first_seen_run_id` keeps the run that first observed the
row. Nullable attributes (`mac`, `mac_vendor`, `hostname`, `os_guess`) are
updated with `COALESCE(new, existing)` — a later run that learns nothing new
never erases previously known detail. Port rows refresh `state`, `service`,
`product`, and `version` on every sighting. Ports that vanish are not deleted;
their `last_seen_run_id` simply stops advancing, so staleness is queryable.

## Tool selection per phase

| Phase | Preferred | Fallback | Last resort |
| --- | --- | --- | --- |
| Host discovery (L2-adjacent, raw-capable) | `arp-scan` | `fping` | `nmap -sn -PR` |
| Host discovery (routed) | `fping` | `nmap -sn` | — |
| Service scan | `nmap -sV` | — | — |
| Port pre-scan (`masscan` profile) | `masscan` | nmap `-sV` verification per port-set group | — |
| Expansion | `traceroute` | no expansion when missing | — |

nmap is the only hard requirement: every profile ends in an `nmap -sV` service
scan, and nmap is also the final host-discovery fallback. Everything else
degrades gracefully — see [SCANNERS.md](SCANNERS.md) for privileges and
detection.

## Security design

- **Scope guard** (`scope.py`): RFC1918, link-local, CGNAT, loopback, IPv6
  ULA/link-local are in scope by default; public ranges need `--allow-public`;
  networks above 4096 addresses need `--allow-large`; `--exclude` ranges are
  always honored. Every scan target, every discovered host IP, every
  traceroute hop, and every enqueued network passes through it.
- **Credentials from the environment only** (`config.py`): nothing secret is
  accepted on the command line, logged, or written to the database.
  `SECMAN_URL` is validated to be an HTTPS origin (plain HTTP only for
  localhost) with no embedded credentials.
- **Subprocess discipline** (`scanners/base.py`): scanners run as argument
  lists with `shell=False` and mandatory timeouts.
- **XML parsing**: nmap/masscan write `-oX` XML to stdout of our own
  invocations; parsing uses stdlib `xml.etree.ElementTree` — no DTDs, no
  external entities.
- **Storage**: parameterized queries only (pymysql `%s` placeholders);
  passwords never appear in `scan_runs.command` because they cannot be CLI
  arguments.
