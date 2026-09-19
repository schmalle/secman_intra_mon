"""MariaDB persistence (pymysql).

Scan results are upserted incrementally: assets keyed by IP, ports keyed by
(asset, port, protocol), every row carries first/last-seen run IDs so history
accumulates across runs instead of being overwritten.

Migrations ship inside the package (`secman_intra_mon.migrations`) so the
installed wheel and the Docker image can both apply them.
"""

from __future__ import annotations

import json
from importlib import resources
from typing import Any

import pymysql
import pymysql.cursors

from .config import DbConfig
from .models import DiscoveredHost, DiscoveredPort, NetworkSeed
from .scanners.base import ToolStatus

MIGRATIONS_PACKAGE = "secman_intra_mon.migrations"


class StorageError(Exception):
    pass


class Storage:
    def __init__(self, config: DbConfig):
        self._config = config
        self._conn: pymysql.connections.Connection[Any] | None = None

    # -- lifecycle ---------------------------------------------------------

    def connect(self, database: bool = True) -> None:
        kwargs: dict[str, Any] = dict(
            host=self._config.host,
            port=self._config.port,
            user=self._config.user,
            password=self._config.password,
            charset="utf8mb4",
            cursorclass=pymysql.cursors.DictCursor,
            autocommit=False,
        )
        if database:
            kwargs["database"] = self._config.name
        try:
            self._conn = pymysql.connect(**kwargs)
        except pymysql.MySQLError as exc:
            raise StorageError(
                f"cannot connect to MariaDB at {self._config.host}:{self._config.port} "
                f"({exc}) — is it running? See docs/DOCKER.md for the compose setup."
            ) from exc

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> Storage:
        self.connect()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def _connection(self) -> pymysql.connections.Connection[Any]:
        if self._conn is None:
            self.connect()
        assert self._conn is not None
        return self._conn

    # -- migrations --------------------------------------------------------

    def ensure_database(self) -> None:
        """Create the database when missing (connects without a schema first)."""
        self.connect(database=False)
        try:
            with self._connection().cursor() as cur:
                cur.execute(f"CREATE DATABASE IF NOT EXISTS `{self._config.name}` CHARACTER SET utf8mb4")
            self._connection().commit()
        finally:
            self.close()
        self.connect()

    def apply_migrations(self) -> list[str]:
        """Apply pending migrations; returns the versions applied now."""
        migration_files = sorted(
            entry.name
            for entry in resources.files(MIGRATIONS_PACKAGE).iterdir()
            if entry.name.endswith(".sql")
        )
        conn = self._connection()
        with conn.cursor() as cur:
            cur.execute(
                "CREATE TABLE IF NOT EXISTS schema_migrations ("
                "version VARCHAR(64) PRIMARY KEY, "
                "applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)"
            )
            cur.execute("SELECT version FROM schema_migrations")
            applied = {row["version"] for row in cur.fetchall()}

            newly_applied: list[str] = []
            for filename in migration_files:
                version = filename.removesuffix(".sql")
                if version in applied:
                    continue
                sql_text = resources.files(MIGRATIONS_PACKAGE).joinpath(filename).read_text()
                for chunk in sql_text.split(";\n"):
                    lines = [line for line in chunk.splitlines() if not line.strip().startswith("--")]
                    statement = "\n".join(lines).strip()
                    if statement:
                        cur.execute(statement)
                cur.execute("INSERT INTO schema_migrations (version) VALUES (%s)", (version,))
                newly_applied.append(version)
        conn.commit()
        return newly_applied

    # -- runs ----------------------------------------------------------------

    def create_run(self, command: str, params: dict[str, Any], tools: dict[str, ToolStatus]) -> int:
        tool_versions = {name: status.version for name, status in tools.items() if status.available}
        with self._connection().cursor() as cur:
            cur.execute(
                "INSERT INTO scan_runs (command, params_json, tool_versions_json) VALUES (%s, %s, %s)",
                (command[:512], json.dumps(params), json.dumps(tool_versions)),
            )
            run_id = int(cur.lastrowid or 0)
        self._connection().commit()
        return run_id

    def finish_run(self, run_id: int) -> None:
        with self._connection().cursor() as cur:
            cur.execute(
                "UPDATE scan_runs SET finished_at = CURRENT_TIMESTAMP WHERE id = %s",
                (run_id,),
            )
        self._connection().commit()

    # -- upserts -------------------------------------------------------------

    def upsert_network(self, run_id: int, seed: NetworkSeed) -> None:
        with self._connection().cursor() as cur:
            cur.execute(
                "INSERT INTO networks (cidr, discovered_via, depth,"
                " first_seen_run_id, last_seen_run_id)"
                " VALUES (%s, %s, %s, %s, %s)"
                " ON DUPLICATE KEY UPDATE"
                " last_seen_run_id = VALUES(last_seen_run_id),"
                " discovered_via = VALUES(discovered_via),"
                " depth = VALUES(depth)",
                (seed.cidr, seed.discovered_via[:128], seed.depth, run_id, run_id),
            )
        self._connection().commit()

    def upsert_host(self, run_id: int, host: DiscoveredHost, network_cidr: str) -> int:
        """Upsert one asset and its ports; returns the asset id."""
        conn = self._connection()
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO assets (ip, mac, mac_vendor, hostname, os_guess,"
                " discovered_via, network_cidr, first_seen_run_id, last_seen_run_id)"
                " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)"
                " ON DUPLICATE KEY UPDATE"
                " last_seen_run_id = VALUES(last_seen_run_id),"
                " mac = COALESCE(VALUES(mac), mac),"
                " mac_vendor = COALESCE(VALUES(mac_vendor), mac_vendor),"
                " hostname = COALESCE(VALUES(hostname), hostname),"
                " os_guess = COALESCE(VALUES(os_guess), os_guess),"
                " discovered_via = IF(VALUES(discovered_via) <> '',"
                " VALUES(discovered_via), discovered_via)",
                (
                    host.ip,
                    host.mac,
                    host.mac_vendor,
                    host.hostname,
                    host.os_guess,
                    host.discovered_via[:32],
                    network_cidr,
                    run_id,
                    run_id,
                ),
            )
            cur.execute("SELECT id FROM assets WHERE ip = %s", (host.ip,))
            row = cur.fetchone()
            if row is None:
                raise StorageError(f"failed to upsert asset {host.ip}")
            asset_id = int(row["id"])
            for port in host.ports:
                self._upsert_port(cur, run_id, asset_id, port)
        conn.commit()
        return asset_id

    @staticmethod
    def _upsert_port(cur: Any, run_id: int, asset_id: int, port: DiscoveredPort) -> None:
        cur.execute(
            "INSERT INTO ports (asset_id, port, protocol, state, service, product,"
            " version, first_seen_run_id, last_seen_run_id)"
            " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)"
            " ON DUPLICATE KEY UPDATE"
            " last_seen_run_id = VALUES(last_seen_run_id),"
            " state = VALUES(state),"
            " service = VALUES(service),"
            " product = VALUES(product),"
            " version = VALUES(version)",
            (
                asset_id,
                port.port,
                port.protocol,
                port.state,
                port.service,
                port.product,
                port.version,
                run_id,
                run_id,
            ),
        )

    # -- queries -------------------------------------------------------------

    def list_assets(self, run_id: int | None = None) -> list[dict[str, Any]]:
        sql = (
            "SELECT a.id, a.ip, a.mac, a.mac_vendor, a.hostname, a.os_guess,"
            " a.discovered_via, a.network_cidr, a.first_seen_run_id,"
            " a.last_seen_run_id, p.port, p.protocol, p.state, p.service,"
            " p.product, p.version"
            " FROM assets a LEFT JOIN ports p ON p.asset_id = a.id"
        )
        params: tuple[Any, ...] = ()
        if run_id is not None:
            sql += " WHERE a.last_seen_run_id = %s"
            params = (run_id,)
        sql += " ORDER BY LENGTH(a.ip), a.ip, p.port"
        with self._connection().cursor() as cur:
            cur.execute(sql, params)
            return _group_assets(cur.fetchall())

    def get_asset(self, ip: str) -> dict[str, Any] | None:
        with self._connection().cursor() as cur:
            cur.execute(
                "SELECT a.id, a.ip, a.mac, a.mac_vendor, a.hostname, a.os_guess,"
                " a.discovered_via, a.network_cidr, a.first_seen_run_id,"
                " a.last_seen_run_id, p.port, p.protocol, p.state, p.service,"
                " p.product, p.version"
                " FROM assets a LEFT JOIN ports p ON p.asset_id = a.id"
                " WHERE a.ip = %s ORDER BY p.port",
                (ip,),
            )
            assets = _group_assets(cur.fetchall())
            return assets[0] if assets else None

    def list_networks(self) -> list[dict[str, Any]]:
        with self._connection().cursor() as cur:
            cur.execute(
                "SELECT cidr, discovered_via, depth, first_seen_run_id,"
                " last_seen_run_id FROM networks ORDER BY cidr"
            )
            return list(cur.fetchall())

    def list_runs(self, limit: int = 20) -> list[dict[str, Any]]:
        with self._connection().cursor() as cur:
            cur.execute(
                "SELECT id, started_at, finished_at, command FROM scan_runs ORDER BY id DESC LIMIT %s",
                (limit,),
            )
            return list(cur.fetchall())

    def latest_run_id(self) -> int | None:
        with self._connection().cursor() as cur:
            cur.execute("SELECT MAX(id) AS max_id FROM scan_runs")
            row = cur.fetchone()
            return int(row["max_id"]) if row and row["max_id"] is not None else None


def _group_assets(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Collapse the asset×port join into one dict per asset with a ports list."""
    assets: dict[int, dict[str, Any]] = {}
    for row in rows:
        asset_id = int(row["id"])
        asset = assets.setdefault(
            asset_id,
            {
                "id": asset_id,
                "ip": row["ip"],
                "mac": row["mac"],
                "mac_vendor": row["mac_vendor"],
                "hostname": row["hostname"],
                "os_guess": row["os_guess"],
                "discovered_via": row["discovered_via"],
                "network_cidr": row["network_cidr"],
                "first_seen_run_id": row["first_seen_run_id"],
                "last_seen_run_id": row["last_seen_run_id"],
                "ports": [],
            },
        )
        if row["port"] is not None:
            asset["ports"].append(
                {
                    "port": row["port"],
                    "protocol": row["protocol"],
                    "state": row["state"],
                    "service": row["service"],
                    "product": row["product"],
                    "version": row["version"],
                }
            )
    return list(assets.values())
