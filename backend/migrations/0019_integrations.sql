-- Verbundene Programme (z. B. Docker Backup Manager): eigener Zugangsschlüssel je Programm,
-- der nur Überwachungspausen und Ergebnis-Meldungen erlaubt
CREATE TABLE integrations (
    id             BIGSERIAL PRIMARY KEY,
    name           TEXT NOT NULL,
    kind           TEXT NOT NULL DEFAULT 'generic',
    -- SHA-256 des Schlüssels (der Schlüssel selbst wird nur einmal beim Anlegen angezeigt)
    token_hash     BYTEA NOT NULL UNIQUE,
    token_hint     TEXT NOT NULL,
    -- Rechner, auf dem die Container laufen (für die automatische Zuordnung über veröffentlichte Ports)
    host_device_id BIGINT REFERENCES devices(id) ON DELETE SET NULL,
    enabled        BOOLEAN NOT NULL DEFAULT true,
    -- zuletzt gemeldete Container/Aufgaben des Programms
    inventory      JSONB NOT NULL DEFAULT '[]',
    inventory_at   TIMESTAMPTZ,
    last_seen_at   TIMESTAMPTZ,
    last_ip        TEXT,
    version        TEXT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Von Hand festgelegte Zuordnung: Container (subject) → Geräte/Dienste in NetPulse
CREATE TABLE integration_links (
    integration_id BIGINT NOT NULL REFERENCES integrations(id) ON DELETE CASCADE,
    subject        TEXT NOT NULL,
    device_ids     BIGINT[] NOT NULL DEFAULT '{}',
    check_ids      BIGINT[] NOT NULL DEFAULT '{}',
    -- zusätzlich automatisch erkannte Zuordnungen verwenden?
    auto           BOOLEAN NOT NULL DEFAULT true,
    PRIMARY KEY (integration_id, subject)
);

-- Überwachungspause: betroffene Geräte/Dienste werden bis `until` nicht geprüft
-- (keine Messwerte, keine Ereignisse, keine Alarme, zählt nicht gegen die Verfügbarkeit)
CREATE TABLE integration_pauses (
    id             BIGSERIAL PRIMARY KEY,
    integration_id BIGINT REFERENCES integrations(id) ON DELETE CASCADE,
    subjects       TEXT[] NOT NULL DEFAULT '{}',
    reason         TEXT NOT NULL DEFAULT '',
    device_ids     BIGINT[] NOT NULL DEFAULT '{}',
    check_ids      BIGINT[] NOT NULL DEFAULT '{}',
    started_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- spätestes Ende (Sicherheitsnetz, falls das Programm sich nicht zurückmeldet); bei „fertig“ = jetzt + Nachlaufzeit
    until          TIMESTAMPTZ NOT NULL,
    ended_at       TIMESTAMPTZ
);
CREATE INDEX integration_pauses_until_idx ON integration_pauses (until DESC);

-- Ergebnisse gemeldeter Aufgaben (z. B. „Backup von nextcloud erfolgreich, 12 GB, 8 Min.“)
CREATE TABLE integration_reports (
    id             BIGSERIAL PRIMARY KEY,
    integration_id BIGINT NOT NULL REFERENCES integrations(id) ON DELETE CASCADE,
    time           TIMESTAMPTZ NOT NULL DEFAULT now(),
    kind           TEXT NOT NULL,
    subject        TEXT NOT NULL,
    status         TEXT NOT NULL CHECK (status IN ('ok', 'failed', 'cancelled')),
    message        TEXT,
    duration_s     REAL,
    size_bytes     BIGINT
);
CREATE INDEX integration_reports_idx ON integration_reports (integration_id, subject, time DESC);

-- Alarme für gemeldete Aufgaben
ALTER TABLE alert_rules DROP CONSTRAINT alert_rules_kind_check;
ALTER TABLE alert_rules ADD CONSTRAINT alert_rules_kind_check CHECK (kind IN ('device_down', 'new_device', 'mac_changed',
    'disk_usage', 'cpu_usage', 'mem_usage', 'temperature', 'check_down', 'cert_expiry', 'syslog_match', 'job_failed', 'job_missing'));
