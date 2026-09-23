-- Grundschema von NetPulse.
-- Stammdaten liegen in normalen Tabellen, Messwerte in einer TimescaleDB-Hypertable.

CREATE EXTENSION IF NOT EXISTS timescaledb;

-- Benutzer der Weboberfläche (Benutzernamen werden klein geschrieben gespeichert)
CREATE TABLE users (
    id            BIGSERIAL PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL CHECK (role IN ('admin', 'viewer')),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login    TIMESTAMPTZ
);

-- Anmeldesitzungen. Gespeichert wird nur der SHA-256-Hash des Tokens,
-- ein Datenbank-Leak gibt also keine gültigen Sitzungen preis.
CREATE TABLE sessions (
    token_hash BYTEA PRIMARY KEY,
    user_id    BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX sessions_user_idx ON sessions (user_id);

-- Freigegebene Netze: Gescannt wird ausschließlich, was hier eingetragen ist.
CREATE TABLE networks (
    id         BIGSERIAL PRIMARY KEY,
    cidr       CIDR NOT NULL UNIQUE,
    name       TEXT NOT NULL,
    enabled    BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Gefundene Geräte
CREATE TABLE devices (
    id          BIGSERIAL PRIMARY KEY,
    ip          INET NOT NULL UNIQUE,
    mac         TEXT,
    hostname    TEXT,
    name        TEXT,
    notes       TEXT,
    open_ports  INT[] NOT NULL DEFAULT '{}',
    status      TEXT NOT NULL DEFAULT 'unknown' CHECK (status IN ('up', 'down', 'unknown')),
    last_rtt_ms REAL,
    monitored   BOOLEAN NOT NULL DEFAULT true,
    first_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen   TIMESTAMPTZ,
    last_check  TIMESTAMPTZ
);

-- Messwerte der Statusprüfung (Zeitreihe)
CREATE TABLE device_metrics (
    time      TIMESTAMPTZ NOT NULL,
    device_id BIGINT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    up        BOOLEAN NOT NULL,
    rtt_ms    REAL
);
SELECT create_hypertable('device_metrics', by_range('time', INTERVAL '1 day'));
CREATE INDEX device_metrics_device_time_idx ON device_metrics (device_id, time DESC);

-- Ältere Messwerte komprimieren (spart auf NAS/Raspberry Pi viel Platz)
ALTER TABLE device_metrics SET (timescaledb.compress, timescaledb.compress_segmentby = 'device_id');
SELECT add_compression_policy('device_metrics', INTERVAL '7 days');

-- Ereignisse: neu entdeckt, offline, wieder online, MAC geändert …
CREATE TABLE events (
    id        BIGSERIAL PRIMARY KEY,
    time      TIMESTAMPTZ NOT NULL DEFAULT now(),
    device_id BIGINT REFERENCES devices(id) ON DELETE CASCADE,
    kind      TEXT NOT NULL,
    message   TEXT NOT NULL
);
CREATE INDEX events_time_idx ON events (time DESC);
CREATE INDEX events_device_idx ON events (device_id, time DESC);

-- Audit-Log: wer hat wann was getan
CREATE TABLE audit_log (
    id       BIGSERIAL PRIMARY KEY,
    time     TIMESTAMPTZ NOT NULL DEFAULT now(),
    user_id  BIGINT REFERENCES users(id) ON DELETE SET NULL,
    username TEXT,
    action   TEXT NOT NULL,
    detail   JSONB NOT NULL DEFAULT '{}'
);
CREATE INDEX audit_log_time_idx ON audit_log (time DESC);

-- Persönliches Dashboard-Layout je Benutzer
CREATE TABLE dashboards (
    user_id    BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    layout     JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Einfache Schlüssel/Wert-Ablage (z. B. Ergebnis der letzten Discovery)
CREATE TABLE settings (
    key   TEXT PRIMARY KEY,
    value JSONB NOT NULL
);
