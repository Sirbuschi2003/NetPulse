-- Weitere Zugangsarten: FRITZ!Box (TR-064), OPNsense-API, MikroTik RouterOS (REST)
ALTER TABLE credentials DROP CONSTRAINT IF EXISTS credentials_kind_check;
ALTER TABLE credentials ADD CONSTRAINT credentials_kind_check
    CHECK (kind IN ('snmp_v2c', 'snmp_v3', 'ssh_password', 'ssh_key', 'http', 'unifi', 'fritzbox', 'opnsense', 'mikrotik'));
