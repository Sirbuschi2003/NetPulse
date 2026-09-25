-- Tageswerte der Strommessungen (dauerhaft, auch wenn die Minutenwerte nach der Aufbewahrungszeit gelöscht sind).
-- pos_wh = Energie bei positiver Leistung, neg_wh = bei negativer (z. B. Einspeisung am saldierenden Zähler).
CREATE TABLE energy_daily (
    day       DATE NOT NULL,
    device_id BIGINT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    pos_wh    DOUBLE PRECISION NOT NULL DEFAULT 0,
    neg_wh    DOUBLE PRECISION NOT NULL DEFAULT 0,
    -- Minuten mit Messwert (1440 = ganzer Tag erfasst)
    minutes   INT NOT NULL DEFAULT 0,
    PRIMARY KEY (day, device_id)
);
CREATE INDEX energy_daily_device_idx ON energy_daily (device_id, day);
