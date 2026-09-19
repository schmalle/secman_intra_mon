-- 002_llm.sql — LLM enrichment: asset classification and findings
-- Applied by `secman-intra-mon db init`. Plain DDL, one statement per ;-block.

CREATE TABLE IF NOT EXISTS asset_enrichment (
    asset_id BIGINT UNSIGNED PRIMARY KEY,
    device_type VARCHAR(64) NOT NULL DEFAULT '',
    asset_role VARCHAR(255) NOT NULL DEFAULT '',
    criticality VARCHAR(16) NOT NULL DEFAULT '',
    confidence DOUBLE NOT NULL DEFAULT 0,
    rationale TEXT,
    model VARCHAR(128) NOT NULL DEFAULT '',
    classified_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_enrichment_asset FOREIGN KEY (asset_id) REFERENCES assets (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS findings (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    asset_id BIGINT UNSIGNED NOT NULL,
    severity VARCHAR(16) NOT NULL DEFAULT 'info',
    title VARCHAR(255) NOT NULL,
    detail TEXT,
    model VARCHAR(128) NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_findings_severity (severity),
    CONSTRAINT fk_findings_asset FOREIGN KEY (asset_id) REFERENCES assets (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
