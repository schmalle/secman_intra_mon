# Docker

The Dockerfile builds a self-contained Linux runtime on `python:3.12-slim`
with every supported scanner binary installed (`nmap`, `masscan`, `fping`,
`arp-scan`, `traceroute`, plus `iproute2`, `dnsutils`, `iputils-ping`) and the
project synced with `uv sync --locked --no-dev`. The image's entrypoint is the
CLI itself, so every argument after the image name is a `secman-intra-mon`
argument.

## Build

```bash
docker build -t secman-intra-mon .
```

## Run modes

### Full layer-2 mode (recommended, Linux only)

```bash
docker run --rm --network host --user root --cap-drop ALL \
  --cap-add NET_RAW --cap-add NET_ADMIN \
  secman-intra-mon capabilities

docker run --rm --network host --user root --cap-drop ALL \
  --cap-add NET_RAW --cap-add NET_ADMIN \
  secman-intra-mon discover --dry-run
```

Host networking puts the container on the real LAN. The explicit root user is
needed because several packaged scanner binaries check their effective UID in
addition to opening raw sockets; `--cap-drop ALL` and the two added capabilities
constrain it to networking operations. Everything works in this mode: interface/route seeding
sees the host's topology, ARP discovery runs on connected segments, masscan and
`--os-scan` are usable, and traceroute expansion observes real paths.

### Degraded bridge mode

```bash
docker run --rm secman-intra-mon discover --network 192.168.1.0/24 --no-expand
```

With the default bridge network and no extra capabilities the container sits
behind Docker NAT on its own bridge segment. Consequences:

- **Auto-seeding is useless** — interfaces and routes are the container's, not
  the LAN's. Always pass `--network` (and `--no-expand`, or expansion will
  chase NAT paths) in this mode.
- **ARP discovery cannot work** — the target LAN is not layer-2 adjacent to the
  container. Discovery falls back to `fping`/`nmap -sn`.
- **masscan and `--os-scan` are unavailable** — both need raw sockets
  (`CAP_NET_RAW`, dropped by default).
- nmap `-sV` service scans and reverse DNS work fine, so bridge mode is still
  useful for quick targeted service scans.

You can grant raw sockets without host networking (`--cap-add NET_RAW`), but
ARP discovery still only sees the bridge segment — full fidelity requires host
networking, which Docker provides on Linux only. On macOS/Windows, Docker's
"host networking" does not expose the LAN; run natively with uv instead.

## docker compose (app + MariaDB)

`docker-compose.yml` wires the scanner to a dedicated MariaDB 11.4 with a
healthcheck-gated startup order and a persisted volume. The app service already
uses host networking and both capabilities:

```bash
export SECMAN_INTRA_MON_DB_PASSWORD='load-from-your-secret-manager'

docker compose up -d db                          # MariaDB on 127.0.0.1:3306
docker compose run --rm app db init              # create schema + migrations
docker compose run --rm app discover --store-db  # scan, seeded from the host's networks
docker compose run --rm app assets list          # browse persisted results
```

Notes:

- MariaDB publishes on `127.0.0.1:3306` only — reachable from the host and from
  the host-networked app, not exposed to the LAN. Protect the database anyway:
  scan results reveal your network topology (see [SAFETY.md](SAFETY.md)).
- The database/user/password come from `MARIADB_DATABASE` / `MARIADB_USER` /
  `SECMAN_INTRA_MON_DB_PASSWORD`; the root password is randomized.
- Data survives container removal in the `db_data` volume
  (`docker compose down -v` deletes it).
- Compose host networking is Linux-only, for the same reason as above.

## Environment variables

The compose `app` service passes the standard variables through from your
shell; for plain `docker run`, pass them with `-e` or `--env-file`:

```bash
docker run --rm --network host --user root --cap-drop ALL \
  --cap-add NET_RAW --cap-add NET_ADMIN \
  --env-file .env \
  secman-intra-mon discover --store-db --upload-secman
```

| Variable | Needed for |
| --- | --- |
| `SECMAN_INTRA_MON_DB_HOST` / `_PORT` / `_NAME` | DB connection (defaults: `127.0.0.1:3306/secman_intra_mon`) |
| `SECMAN_INTRA_MON_DB_USER` / `_PASSWORD` | enables persistence (both required) |
| `SECMAN_URL`, `SECMAN_USERNAME` / `SECMAN_PASSWORD` or `SECMAN_TOKEN` | `--upload-secman` / `secman-push` |
| `SECMAN_ASSET_OWNER` | optional owner label for imported secman assets |

Remember that `.env` contains secrets — keep it out of images and git (the
repo's `.dockerignore`/`.gitignore` already exclude it).

## Container privilege model

The image defaults to `intramon` (uid 10001), which is suitable for `--help`,
capability inspection, direct TCP service scans, and degraded discovery.
Full ARP/masscan/OS fidelity requires the explicit root invocation shown above:
Debian's scanner executables may reject a non-root euid even if Docker grants
raw-socket capabilities. Compose makes that choice explicitly and drops every
capability except `NET_RAW` and `NET_ADMIN`. This is still a privileged network
position: do not add `--privileged`, do not mount the Docker socket, and use a
dedicated scanning host where possible.
