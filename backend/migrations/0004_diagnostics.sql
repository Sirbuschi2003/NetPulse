-- Protokoll der letzten tiefen Abfrage je Gerät (Schritte mit Ergebnis) – für den Reiter „Diagnose“
ALTER TABLE devices ADD COLUMN inventory_log JSONB;
