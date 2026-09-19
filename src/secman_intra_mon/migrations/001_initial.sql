-- 001_initial.sql — secman_intra_mon schema
-- Applied by `secman-intra-mon db init`. Plain DDL, one statement per ;-block.

CREATE TABLE IF NOT EXISTS scan_runs (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    started_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finished_at TIMESTAMP NULL,
    command VARCHAR(512) NOT NULL,
    params_json TEXT,
    tool_versions_json TEXT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS networks (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    cidr VARCHAR(64) NOT NULL UNIQUE,
    discovered_via VARCHAR(128) NOT NULL DEFAULT '',
    depth INT NOT NULL DEFAULT 0,
    first_seen_run_id BIGINT UNSIGNED,
    last_seen_run_id BIGINT UNSIGNED,
    INDEX idx_networks_last_seen (last_seen_run_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS assets (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    ip VARCHAR(45) NOT NULL UNIQUE,
    mac VARCHAR(17) NULL,
    mac_vendor VARCHAR(255) NULL,
    hostname VARCHAR(255) NULL,
    os_guess VARCHAR(255) NULL,
    discovered_via VARCHAR(32) NOT NULL DEFAULT '',
    network_cidr VARCHAR(64) NULL,
    first_seen_run_id BIGINT UNSIGNED NOT NULL,
    last_seen_run_id BIGINT UNSIGNED NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_assets_last_seen (last_seen_run_id),
    INDEX idx_assets_network (network_cidr)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS ports (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    asset_id BIGINT UNSIGNED NOT NULL,
    port INT UNSIGNED NOT NULL,
    protocol VARCHAR(8) NOT NULL DEFAULT 'tcp',
    state VARCHAR(16) NOT NULL DEFAULT 'open',
    service VARCHAR(128) NOT NULL DEFAULT '',
    product VARCHAR(255) NOT NULL DEFAULT '',
    version VARCHAR(255) NOT NULL DEFAULT '',
    first_seen_run_id BIGINT UNSIGNED NOT NULL,
    last_seen_run_id BIGINT UNSIGNED NOT NULL,
    UNIQUE KEY uq_asset_port (asset_id, port, protocol),
    CONSTRAINT fk_ports_asset FOREIGN KEY (asset_id) REFERENCES assets (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS schema_migrations (
    version VARCHAR(64) PRIMARY KEY,
    applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
