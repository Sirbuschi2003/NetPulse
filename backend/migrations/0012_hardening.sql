-- Zertifikat des UniFi-Controllers beim ersten Kontakt merken (wie beim SSH-Host-Schlüssel)
ALTER TABLE devices ADD COLUMN tls_pin TEXT;
-- SNMP v2c überträgt die Community unverschlüsselt: nicht mehr automatisch an alle Geräte senden
UPDATE credentials SET auto = false WHERE kind = 'snmp_v2c';
