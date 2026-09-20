# secman integration

`secman-intra-mon` can push discovery results into a
[secman](https://github.com/schmalle/secman) backend. This document describes
**Phase 1**, which is implemented and works against a stock secman deployment,
and sketches **Phase 2**, a proposal that requires a coordinated backend
change and is *not* implemented.

## Phase 1 — implemented

Phase 1 reuses secman's existing REST endpoints; no backend change is needed:

| Endpoint | Method | Role | Used for |
| --- | --- | --- | --- |
| `/api/auth/login` | POST | — | username/password login, JWT arrives as the `secman_auth` HttpOnly cookie |
| `/api/assets/import` | PUT | ADMIN | idempotent asset upsert (one call per discovered host) |
| `/api/scan/upload-nmap` | POST | ADMIN | raw nmap `-oX` upload (one call per scanned network) |

### Prerequisites

Create a **dedicated service account** in secman (for example
`intra-mon-service`) and grant it the **ADMIN** role. Both ingestion endpoints
are ADMIN-only; the CLI warns after login when the account's roles do not
include ADMIN, and the backend rejects the calls with 401/403 otherwise.

Least privilege matters here: this account's credentials live in the scanner's
environment and can create and modify *any* asset in secman. Use a unique,
strong password, store it via your secret manager (`pass://` references are
supported), and rotate it like any other automation credential.

### Environment setup

```bash
export SECMAN_URL=https://secman.example.invalid   # https required
export SECMAN_USERNAME=intra-mon-service
export SECMAN_PASSWORD='load-from-your-secret-manager'
# optional: owner label written onto imported assets (default: SECMAN_USERNAME)
export SECMAN_ASSET_OWNER="Security Team"
```

`SECMAN_URL` must be an HTTPS origin without credentials, query, or fragment;
plain HTTP is accepted only for localhost development (`localhost`,
`host.docker.internal`, loopback addresses).

**Token alternative:** instead of username/password, export an existing JWT as
`SECMAN_TOKEN` (sent as `Authorization: Bearer`). The token skips the login
call, so roles are unknown until the first request — a non-ADMIN token fails
on the first import call. Tokens have a limited lifetime (about 8 h), which
makes them handy for one-off manual pushes.

### `discover --upload-secman` flow

```bash
sudo -E uv run secman-intra-mon discover --store-db --upload-secman
```

After the discovery finishes, the push runs in three steps:

1. **Login** — `POST /api/auth/login` with `{username, password}`; the JWT from
   the `secman_auth` cookie is reused as a Bearer token for the rest of the
   session. Skipped entirely when `SECMAN_TOKEN` is set.
2. **Asset import** — one `PUT /api/assets/import` per discovered host:
   `name` (hostname or IP), `type` = `Network Host`, `owner`, `ip`,
   `networkZone` = `INTERNAL`, a description noting the discovery method, and
   tags: `source=secman-intra-mon`, `active_discovery=true`, `asset_kind`,
   `classification_method=local-heuristic`, `discovered_via`, `mac`,
   `mac_vendor`, `os_guess`, and `open_ports`
   (e.g. `22/tcp,443/tcp`). Secman upserts by name, so re-runs update the same
   asset instead of duplicating it; tags merge additively.
3. **nmap XML upload** — each network's raw nmap `-oX` document (kept in memory
   during the run) is submitted to `POST /api/scan/upload-nmap` as multipart
   field `file`. Secman parses the genuine nmap output into
   Scan/ScanResult/ScanPort rows and links the ports to the matching assets.

The push is **best-effort per asset**: a single failing host or XML document is
collected into the summary and reported as a warning; it does not abort the
remaining uploads.

No discovery command uploads implicitly. The operator must spell
`--upload-secman`, or later run the equally explicit `secman-push` command.
The source/active-discovery tags make imported observations distinguishable
from manually maintained assets. Classification is deterministic and local:
network protocol ports/services and network-vendor/OS hints identify network
devices; common hosted services identify servers; workstation/mobile OS hints
identify endpoints; insufficient evidence remains `unknown`. Treat it as a
triage hint, not an inventory authority.

### `secman-push` — re-pushing a persisted run

```bash
uv run secman-intra-mon runs                 # find the run id
uv run secman-intra-mon secman-push --run-id 3   # default: latest run
```

This pushes the assets recorded in MariaDB for the given run — useful when the
backend was down during the live scan. **Assets only, no port records:** the
nmap XML exists only in memory during a live `discover` run and is never stored
in the database, so a later re-push has nothing genuine to submit to
`/api/scan/upload-nmap`. Reconstructed XML would not be nmap's real output, so
the command deliberately skips it and prints a note. For port-level records in
secman, run with `--upload-secman` live (or re-run the scan).

### What lands in secman

- **Assets** — upserted `Network Host` entries in network zone `INTERNAL`,
  owned by `SECMAN_ASSET_OWNER`, carrying the discovery tags above.
- **Scans** — per uploaded network, a Scan with ScanResults and ScanPorts built
  by secman's own nmap parser, linked to the imported assets. Closed/filtered
  nuance, service names, products, and versions all come from secman's parser,
  not from this client.

### Troubleshooting

| Symptom | Likely cause / fix |
| --- | --- |
| `secman login failed: invalid credentials` (401) | wrong `SECMAN_USERNAME`/`SECMAN_PASSWORD`, or the password rotated |
| `no secman_auth cookie was returned` | the backend is not secman, or auth is configured differently |
| `rejected ... (HTTP 401/403)` on import/upload | the account lacks the ADMIN role — both endpoints require it |
| `SECMAN_URL must use https` | plain HTTP URL for a non-localhost host; use HTTPS or a tunnel |
| `cannot reach secman at ...` | URL, DNS, or TLS issue; check `curl -v $SECMAN_URL` from the same host |
| partial push warnings | per-asset failures are listed in the summary; fix and re-run `secman-push` |

## Phase 2 — proposal (not implemented)

Phase 1 imports assets and ports but creates no first-class *run* object in
secman, so discovery history, run-scoped diffing, and scanner lifecycle
management live only in the local MariaDB.

The proposal is to adopt secman's integration-run contract
(`/api/integrations/v1/runs`, the same channel `secman_web_check` uses) for
intranet discovery:

- Add an `INTRA_DISCOVERY` source to `IntegrationRunValidator.SOURCES` in the
  main secman repository so the backend accepts this result class natively.
- Submit each discovery run as one integration run with a deterministic
  `runKey` (derived from the scope parameters), so re-scans update the same
  logical run instead of accumulating duplicates.

This is a coordinated backend change: the secman repo must ship the new source
value before this client can send it, and the client's payload mapping
(assets, ports, networks → integration-run DTOs) needs to be verified against
that contract. Until then, Phase 1 remains the supported integration path.
