-- Phase 2: Gerätetypen, tiefe Abfragen (SNMP/SSH), Zugangsdaten, Alarme, Scan-Status je Netz.

-- Geräte: Hersteller, Typ, Betriebssystem, Inventar
ALTER TABLE devices
    ADD COLUMN vendor             TEXT,
    ADD COLUMN device_type        TEXT,
    ADD COLUMN device_type_manual BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN os                 TEXT,
    ADD COLUMN model              TEXT,
    ADD COLUMN inventory          JSONB,
    ADD COLUMN inventory_at       TIMESTAMPTZ,
    ADD COLUMN inventory_error    TEXT,
    -- SSH-Host-Schlüssel beim ersten Kontakt merken (Schutz vor Man-in-the-Middle)
    ADD COLUMN ssh_host_key       TEXT,
    -- Seit wann gilt der aktuelle Status? Grundlage für „offline länger als X Minuten“
    ADD COLUMN status_since       TIMESTAMPTZ;

UPDATE devices SET status_since = COALESCE(last_check, now());

-- Letzter Scan je Netz
ALTER TABLE networks
    ADD COLUMN last_scan_at         TIMESTAMPTZ,
    ADD COLUMN last_scan_found      INT,
    ADD COLUMN last_scan_duration_s INT;

-- Zugangsdaten. Geheimnisse (Passwörter, Community, Schlüssel) liegen nur verschlüsselt
-- (AES-256-GCM) in `secret`; der Schlüssel liegt außerhalb der Datenbank.
CREATE TABLE credentials (
    id         BIGSERIAL PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    kind       TEXT NOT NULL CHECK (kind IN ('snmp_v2c', 'snmp_v3', 'ssh_password', 'ssh_key')),
    username   TEXT,
    port       INT,
    secret     TEXT NOT NULL,
    -- Automatisch bei passenden Geräten ausprobieren (nur SNMP und SSH-Schlüssel erlaubt)
    auto       BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE device_credentials (
    device_id     BIGINT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    credential_id BIGINT NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
    PRIMARY KEY (device_id, credential_id)
);

-- Messwerte aus SNMP/SSH (Zeitreihe)
CREATE TABLE device_stats (
    time      TIMESTAMPTZ NOT NULL,
    device_id BIGINT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    cpu_pct   REAL,
    mem_pct   REAL,
    disk_pct  REAL,
    temp_c    REAL,
    rx_bps    DOUBLE PRECISION,
    tx_bps    DOUBLE PRECISION
);
SELECT create_hypertable('device_stats', by_range('time', INTERVAL '7 days'));
CREATE INDEX device_stats_device_time_idx ON device_stats (device_id, time DESC);
ALTER TABLE device_stats SET (timescaledb.compress, timescaledb.compress_segmentby = 'device_id');
SELECT add_compression_policy('device_stats', INTERVAL '7 days');

-- Benachrichtigungskanäle. Konfiguration (Tokens, Passwörter, Webhook-URLs) verschlüsselt.
CREATE TABLE notification_channels (
    id         BIGSERIAL PRIMARY KEY,
    name       TEXT NOT NULL,
    kind       TEXT NOT NULL CHECK (kind IN ('email', 'ntfy', 'gotify', 'telegram', 'discord', 'teams', 'webhook')),
    config     TEXT NOT NULL,
    enabled    BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Alarmregeln
CREATE TABLE alert_rules (
    id              BIGSERIAL PRIMARY KEY,
    name            TEXT NOT NULL,
    kind            TEXT NOT NULL CHECK (kind IN ('device_down', 'new_device', 'mac_changed',
                                                  'disk_usage', 'cpu_usage', 'mem_usage', 'temperature')),
    -- NULL = alle Geräte
    device_id       BIGINT REFERENCES devices(id) ON DELETE CASCADE,
    threshold       REAL,
    duration_min    INT NOT NULL DEFAULT 0,
    channel_ids     BIGINT[] NOT NULL DEFAULT '{}',
    notify_recovery BOOLEAN NOT NULL DEFAULT true,
    enabled         BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Ausgelöste Alarme (offen = resolved_at IS NULL)
CREATE TABLE alerts (
    id          BIGSERIAL PRIMARY KEY,
    rule_id     BIGINT NOT NULL REFERENCES alert_rules(id) ON DELETE CASCADE,
    device_id   BIGINT REFERENCES devices(id) ON DELETE CASCADE,
    opened_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at TIMESTAMPTZ,
    message     TEXT NOT NULL,
    value       REAL
);
CREATE UNIQUE INDEX alerts_open_unique ON alerts (rule_id, COALESCE(device_id, 0)) WHERE resolved_at IS NULL;
CREATE INDEX alerts_opened_idx ON alerts (opened_at DESC);
