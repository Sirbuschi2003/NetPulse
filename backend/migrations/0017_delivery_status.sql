-- Zustellstatus sichtbar machen: je Kanal und je Push-Gerät der letzte Erfolg und der letzte Fehler
ALTER TABLE notification_channels
    ADD COLUMN last_attempt_at TIMESTAMPTZ,
    ADD COLUMN last_ok_at TIMESTAMPTZ,
    ADD COLUMN last_error TEXT;
ALTER TABLE push_subscriptions
    ADD COLUMN last_error TEXT,
    ADD COLUMN last_error_at TIMESTAMPTZ;
