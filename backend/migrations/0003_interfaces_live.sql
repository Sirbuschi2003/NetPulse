-- Live-Datenraten, Verlauf je Schnittstelle, Internet-Anschluss, Herstellerprofile, MIB-Namen.

-- Welche Schnittstelle ist der Internet-Anschluss (WAN)? Automatisch erkannt oder von Hand gesetzt.
ALTER TABLE devices
    ADD COLUMN wan_interface        TEXT,
    ADD COLUMN wan_interface_manual BOOLEAN NOT NULL DEFAULT false;

-- WLAN-Clients (z. B. UniFi-Access-Points) als Messwert
ALTER TABLE device_stats ADD COLUMN clients REAL;

-- Datenrate je Schnittstelle (aus den tiefen Abfragen)
CREATE TABLE interface_stats (
    time      TIMESTAMPTZ NOT NULL,
    device_id BIGINT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    name      TEXT NOT NULL,
    rx_bps    DOUBLE PRECISION,
    tx_bps    DOUBLE PRECISION
);
SELECT create_hypertable('interface_stats', by_range('time', INTERVAL '7 days'));
CREATE INDEX interface_stats_device_idx ON interface_stats (device_id, name, time DESC);
ALTER TABLE interface_stats SET (timescaledb.compress, timescaledb.compress_segmentby = 'device_id, name');
SELECT add_compression_policy('interface_stats', INTERVAL '7 days');

-- Symbolische Namen für SNMP-OIDs (aus Standard- und Hersteller-MIBs), für den SNMP-Explorer
CREATE TABLE mib_names (
    oid  TEXT PRIMARY KEY,
    name TEXT NOT NULL
);

-- Name, den das Gerät selbst meldet (mDNS/Bonjour, NetBIOS, Shelly …) – getrennt vom eigenen Anzeigenamen
ALTER TABLE devices
    ADD COLUMN reported_name TEXT,
    -- Erkannte Geräte-Schnittstelle für Zusatzdaten, z. B. 'shelly'
    ADD COLUMN integration   TEXT;

-- Leistung (z. B. Shelly-Steckdosen und -Zähler)
ALTER TABLE device_stats ADD COLUMN power_w REAL;

-- Neue Zugangsart: Benutzer/Passwort für Web-Schnittstellen (z. B. Shelly)
ALTER TABLE credentials DROP CONSTRAINT credentials_kind_check;
ALTER TABLE credentials ADD CONSTRAINT credentials_kind_check
    CHECK (kind IN ('snmp_v2c', 'snmp_v3', 'ssh_password', 'ssh_key', 'http'));
