-- Erinnerungen, solange ein Alarm offen ist
ALTER TABLE alert_rules ADD COLUMN repeat_min INT NOT NULL DEFAULT 0;
ALTER TABLE alerts ADD COLUMN last_notified_at TIMESTAMPTZ;
ALTER TABLE alerts ADD COLUMN notify_count INT NOT NULL DEFAULT 0;

-- Zurückgestellte Meldungen (Sammelmeldung, Ruhezeit)
CREATE TABLE notification_queue (
    id         BIGSERIAL PRIMARY KEY,
    channel_id BIGINT NOT NULL REFERENCES notification_channels(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    payload    JSONB NOT NULL
);
CREATE INDEX notification_queue_channel_idx ON notification_queue (channel_id, created_at);
