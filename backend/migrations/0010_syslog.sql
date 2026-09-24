-- Empfangene Syslog-Meldungen und SNMP-Traps
CREATE TABLE syslog_messages (
    time      TIMESTAMPTZ NOT NULL,
    device_id BIGINT REFERENCES devices(id) ON DELETE SET NULL,
    source    INET NOT NULL,
    facility  SMALLINT NOT NULL,
    severity  SMALLINT NOT NULL,
    host      TEXT,
    app       TEXT,
    message   TEXT NOT NULL
);
SELECT create_hypertable('syslog_messages', by_range('time', INTERVAL '1 day'));
CREATE INDEX syslog_device_time_idx ON syslog_messages (device_id, time DESC);
CREATE INDEX syslog_severity_time_idx ON syslog_messages (severity, time DESC);
ALTER TABLE syslog_messages SET (timescaledb.compress, timescaledb.compress_segmentby = 'device_id');
SELECT add_compression_policy('syslog_messages', INTERVAL '3 days');

-- Alarmregel für Protokollmeldungen: Suchtext + höchste Schwere (threshold)
ALTER TABLE alert_rules ADD COLUMN pattern TEXT;
ALTER TABLE alert_rules DROP CONSTRAINT alert_rules_kind_check;
ALTER TABLE alert_rules ADD CONSTRAINT alert_rules_kind_check CHECK (kind IN ('device_down', 'new_device', 'mac_changed',
    'disk_usage', 'cpu_usage', 'mem_usage', 'temperature', 'check_down', 'cert_expiry', 'syslog_match'));
