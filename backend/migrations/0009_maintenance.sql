-- Wartungsfenster (keine Alarme während geplanter Arbeiten)
CREATE TABLE maintenance_windows (
    id         BIGSERIAL PRIMARY KEY,
    name       TEXT NOT NULL,
    kind       TEXT NOT NULL CHECK (kind IN ('once', 'weekly')),
    starts_at  TIMESTAMPTZ,
    ends_at    TIMESTAMPTZ,
    days       INT[] NOT NULL DEFAULT '{}',
    time_from  TEXT,
    time_to    TEXT,
    device_ids BIGINT[] NOT NULL DEFAULT '{}',
    check_ids  BIGINT[] NOT NULL DEFAULT '{}',
    enabled    BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Abhängigkeiten: an welchem Gerät hängt dieses Gerät (Switch, Access Point, Router)?
ALTER TABLE devices ADD COLUMN parent_id BIGINT REFERENCES devices(id) ON DELETE SET NULL;
ALTER TABLE devices ADD COLUMN parent_manual BOOLEAN NOT NULL DEFAULT false;
CREATE INDEX devices_parent_idx ON devices (parent_id);
