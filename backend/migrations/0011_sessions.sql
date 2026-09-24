-- Sitzungsverwaltung: welche Geräte sind angemeldet, einzeln abmeldbar
ALTER TABLE sessions ADD COLUMN id BIGSERIAL;
ALTER TABLE sessions ADD CONSTRAINT sessions_id_key UNIQUE (id);
ALTER TABLE sessions ADD COLUMN user_agent TEXT;
ALTER TABLE sessions ADD COLUMN ip TEXT;
ALTER TABLE sessions ADD COLUMN last_seen TIMESTAMPTZ;
