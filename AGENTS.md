# AGENTS.md — secman_intra_mon

Iterative intranet asset discovery extension for [secman](https://github.com/schmalle/secman).
Independent client repository of the secman backend: own release cycle, gitignored by the
parent repo, nothing in the parent build touches this directory.

## Git workflow

- Agent-authored commits go to the **`dev` branch**, never to the default branch directly.
  Open a PR from `dev` for review.
- Commits follow **Conventional Commits**: `type(scope): description`
  (e.g. `feat(discovery): add traceroute expansion`, `fix(secman): send tags as map`).

## Toolchain

- Python >= 3.12, managed with **uv** (`uv sync`, `uv run secman-intra-mon ...`).
- Lint/typecheck/build gate before every commit: `scripts/verify.sh`
  (`uv lock --check`, `ruff check`, `ruff format --check`, `mypy`, `uv build`).
- Runtime scanner binaries (nmap required; masscan, fping, arp-scan, traceroute optional)
  are external tools wrapped by `src/secman_intra_mon/scanners/`, never bundled.

## Security boundaries (hard rules)

- This is an **active network scanner**. It must only ever run against networks the
  operator is authorized to assess. Keep the authorization warning in the README.
- The scope guard in `src/secman_intra_mon/scope.py` (private ranges by default,
  `--allow-public` opt-in, `--exclude` denylist) is a safety feature: do not weaken it,
  and route every scan target and every enqueued network through it.
- Credentials come from the **environment only** (`SECMAN_USERNAME`/`SECMAN_PASSWORD` or
  `SECMAN_TOKEN`, DB via `SECMAN_INTRA_MON_DB_*`). Never accept credentials via CLI
  arguments, never log them, never write them into scan output or the database.
- Scanner XML is parsed from stdout of self-invoked nmap/masscan processes; keep XML
  parsing DTD-free (`xml.etree.ElementTree` defaults, no external entities).
- subprocess calls: argument lists only, `shell=False`, timeouts mandatory.

## Secman backend contract

Integration uses REST (`POST /api/auth/login`, `PUT /api/assets/import`,
`POST /api/scan/upload-nmap`). Backend changes break clients silently — when touching
`src/secman_intra_mon/secman.py`, verify all five dimensions against the backend source
(`src/backendng` in the secman repo): path, HTTP method, request field names, response
fields read, `@Secured` roles / required headers. Do not trust endpoint lists in docs;
re-grep the extension for `/api/` usage.

## Layout

```
src/secman_intra_mon/   package (cli, config, netinfo, scope, discovery, storage,
                        output, secman, models, scanners/, migrations/)
scripts/                setup.sh, verify.sh
docs/                   ARCHITECTURE, SCANNERS, DOCKER, SECMAN, SAFETY
Dockerfile              Linux runtime (scanner binaries included)
docker-compose.yml      app + MariaDB 11.4 for local use
```
