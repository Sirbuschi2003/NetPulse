-- Rückmeldung vom Handy: Nachricht empfangen und angezeigt (oder warum nicht)
ALTER TABLE push_subscriptions
    ADD COLUMN last_shown_at TIMESTAMPTZ,
    ADD COLUMN last_show_error TEXT;
