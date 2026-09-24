-- Zwei-Faktor-Anmeldung (TOTP). Das Geheimnis liegt verschlüsselt (Tresor) in totp_secret.
ALTER TABLE users ADD COLUMN totp_secret TEXT;
ALTER TABLE users ADD COLUMN totp_enabled BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE users ADD COLUMN totp_last_step BIGINT;

-- Geräte, die Push-Nachrichten der NetPulse-App empfangen
CREATE TABLE push_subscriptions (
    id         BIGSERIAL PRIMARY KEY,
    user_id    BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    endpoint   TEXT NOT NULL UNIQUE,
    p256dh     TEXT NOT NULL,
    auth       TEXT NOT NULL,
    device     TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_ok_at TIMESTAMPTZ
);

-- Neuer Benachrichtigungskanal: Push an die NetPulse-App
ALTER TABLE notification_channels DROP CONSTRAINT notification_channels_kind_check;
ALTER TABLE notification_channels ADD CONSTRAINT notification_channels_kind_check
    CHECK (kind IN ('email', 'ntfy', 'gotify', 'telegram', 'discord', 'teams', 'webhook', 'app'));
