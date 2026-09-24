-- Dienst-Checks (HTTP/Suchwort, TLS-Zertifikat, TCP-Port, DNS)
CREATE TABLE checks (
    id              BIGSERIAL PRIMARY KEY,
    name            TEXT NOT NULL,
    kind            TEXT NOT NULL CHECK (kind IN ('http', 'tcp', 'dns', 'tls')),
    target          TEXT NOT NULL,
    config          JSONB NOT NULL DEFAULT '{}',
    interval_s      INT NOT NULL DEFAULT 60,
    timeout_s       INT NOT NULL DEFAULT 10,
    device_id       BIGINT REFERENCES devices(id) ON DELETE SET NULL,
    enabled         BOOLEAN NOT NULL DEFAULT true,
    status          TEXT NOT NULL DEFAULT 'unknown',
    status_since    TIMESTAMPTZ,
    fail_count      INT NOT NULL DEFAULT 0,
    last_check      TIMESTAMPTZ,
    last_ms         REAL,
    last_message    TEXT,
    cert_expires_at TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE check_results (
    time     TIMESTAMPTZ NOT NULL,
    check_id BIGINT NOT NULL REFERENCES checks(id) ON DELETE CASCADE,
    ok       BOOLEAN NOT NULL,
    ms       REAL
);
SELECT create_hypertable('check_results', by_range('time', INTERVAL '7 days'));
CREATE INDEX check_results_check_time_idx ON check_results (check_id, time DESC);
ALTER TABLE check_results SET (timescaledb.compress, timescaledb.compress_segmentby = 'check_id');
SELECT add_compression_policy('check_results', INTERVAL '7 days');

-- Alarme für Checks
ALTER TABLE alert_rules ADD COLUMN check_id BIGINT REFERENCES checks(id) ON DELETE CASCADE;
ALTER TABLE alert_rules DROP CONSTRAINT alert_rules_kind_check;
ALTER TABLE alert_rules ADD CONSTRAINT alert_rules_kind_check CHECK (kind IN ('device_down', 'new_device', 'mac_changed',
    'disk_usage', 'cpu_usage', 'mem_usage', 'temperature', 'check_down', 'cert_expiry'));
ALTER TABLE alerts ADD COLUMN check_id BIGINT REFERENCES checks(id) ON DELETE CASCADE;
DROP INDEX alerts_open_unique;
CREATE UNIQUE INDEX alerts_open_unique ON alerts (rule_id, COALESCE(device_id, 0), COALESCE(check_id, 0)) WHERE resolved_at IS NULL;
