-- WLAN-Signal je Client (aus dem UniFi-Controller), für den Verlauf beim Gerät
ALTER TABLE device_stats ADD COLUMN wifi_signal REAL;
