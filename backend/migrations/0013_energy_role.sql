-- Rolle einer Strommessung: Verbrauch, Erzeugung (z. B. Balkonkraftwerk) oder Netz-Zähler; NULL = automatisch
ALTER TABLE devices ADD COLUMN energy_role TEXT CHECK (energy_role IN ('consumer', 'producer', 'grid'));
