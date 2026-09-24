-- UniFi-Controller als Zugangsart (API-Schlüssel oder lokales Konto)
ALTER TABLE credentials DROP CONSTRAINT credentials_kind_check;
ALTER TABLE credentials ADD CONSTRAINT credentials_kind_check
    CHECK (kind IN ('snmp_v2c', 'snmp_v3', 'ssh_password', 'ssh_key', 'http', 'unifi'));
