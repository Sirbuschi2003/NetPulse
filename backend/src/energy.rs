//! Energie-Auswertung: verdichtet die Minutenwerte der Strommessungen zu Tageswerten und
//! rechnet daraus Verbrauch, Erzeugung, Netzbezug, Einspeisung, Eigenverbrauch und Kosten.

use std::{collections::HashMap, time::Duration};

use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use crate::AppState;

/// Rolle einer Strommessung: eingestellt oder am Namen erkannt (Balkonkraftwerk, PV …)
pub const ROLE_SQL: &str = r"COALESCE(d.energy_role, CASE WHEN lower(COALESCE(d.name, '') || ' ' || COALESCE(d.reported_name, '') || ' ' || COALESCE(d.hostname, ''))
    ~ '(balkon|solar|photovolt|wechselrichter|inverter|\mpv\M|\mbkw\M)' THEN 'producer' ELSE 'consumer' END)";

/// Hintergrund-Aufgabe: alle 10 Minuten heute und gestern neu berechnen (beim ersten Mal alles Vorhandene)
pub async fn run(state: AppState) {
    tokio::time::sleep(Duration::from_secs(20)).await;
    let mut tick = tokio::time::interval(Duration::from_secs(600));
    loop {
        tick.tick().await;
        if let Err(e) = aggregate(&state.db).await {
            tracing::warn!("Energie-Tageswerte konnten nicht berechnet werden: {e:#}");
        }
    }
}

pub async fn aggregate(db: &PgPool) -> sqlx::Result<()> {
    let tz = crate::scanner::schedule::timezone().name().to_string();
    let empty: bool = sqlx::query_scalar("SELECT NOT EXISTS (SELECT 1 FROM energy_daily)").fetch_one(db).await?;
    // Immer ganze Tage (Ortszeit) neu rechnen, damit die Summen stimmen
    sqlx::query(
        "INSERT INTO energy_daily (day, device_id, pos_wh, neg_wh, minutes)
         SELECT (b AT TIME ZONE $1)::date, device_id, sum(greatest(w, 0)) / 60.0, sum(greatest(-w, 0)) / 60.0, count(*)
           FROM (SELECT device_id, time_bucket('1 minute', time) AS b, avg(power_w)::float8 AS w
                   FROM device_stats
                  WHERE power_w IS NOT NULL
                    AND ($2 OR time >= ((date_trunc('day', now() AT TIME ZONE $1) - interval '1 day') AT TIME ZONE $1))
                  GROUP BY 1, 2) x
          GROUP BY 1, 2
         ON CONFLICT (day, device_id) DO UPDATE
            SET pos_wh = EXCLUDED.pos_wh, neg_wh = EXCLUDED.neg_wh, minutes = EXCLUDED.minutes",
    )
    .bind(&tz)
    .bind(empty)
    .execute(db)
    .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Einstellungen
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EnergySettings {
    /// Hauptzähler am Hausanschluss (None = keiner; Geräte mit Rolle „Netz“ zählen dann als Netz-Messung)
    pub main_id: Option<i64>,
    /// „net“ = saldierend (+ Bezug, − Einspeisung), „gross“ = misst den Gesamtverbrauch
    pub main_mode: String,
    /// Strompreis in Cent je kWh
    pub price_ct: Option<f64>,
    /// Einspeisevergütung in Cent je kWh
    pub feed_in_ct: Option<f64>,
}

impl Default for EnergySettings {
    fn default() -> Self {
        Self { main_id: None, main_mode: "net".into(), price_ct: None, feed_in_ct: None }
    }
}

impl EnergySettings {
    pub fn validate(&self) -> Result<(), String> {
        if !matches!(self.main_mode.as_str(), "net" | "gross") {
            return Err("Unbekannte Messart".into());
        }
        for v in [self.price_ct, self.feed_in_ct].into_iter().flatten() {
            if !(0.0..=500.0).contains(&v) {
                return Err("Preise bitte in Cent je kWh zwischen 0 und 500 angeben".into());
            }
        }
        Ok(())
    }
}

pub async fn load_settings(db: &PgPool) -> EnergySettings {
    sqlx::query_scalar::<_, serde_json::Value>("SELECT value FROM settings WHERE key = 'energy'")
        .fetch_optional(db)
        .await
        .ok()
        .flatten()
        .and_then(|v| serde_json::from_value(v).ok())
        .unwrap_or_default()
}

pub async fn save_settings(db: &PgPool, s: &EnergySettings) -> sqlx::Result<()> {
    sqlx::query("INSERT INTO settings (key, value) VALUES ('energy', $1) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value")
        .bind(serde_json::to_value(s).unwrap_or_default())
        .execute(db)
        .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Rechnung
// ---------------------------------------------------------------------------

/// Energie einer Messung in einem Zeitraum (kWh): bei positiver bzw. negativer Leistung
#[derive(Clone, Copy, Default, Debug)]
pub struct Flow {
    pub pos: f64,
    pub neg: f64,
}

impl Flow {
    pub fn abs(&self) -> f64 {
        self.pos + self.neg
    }
}

#[derive(Serialize, Default, Debug)]
pub struct Figures {
    pub consumption: Option<f64>,
    pub production: Option<f64>,
    pub import: Option<f64>,
    pub export: Option<f64>,
    /// selbst genutzter Solarstrom
    pub self_use: Option<f64>,
    /// Anteil des Verbrauchs aus eigener Erzeugung (0–1)
    pub autarky: Option<f64>,
    /// Anteil der Erzeugung, der selbst genutzt wird (0–1)
    pub self_use_rate: Option<f64>,
    /// Kosten für den Netzbezug minus Einspeisevergütung (Euro)
    pub cost: Option<f64>,
    /// Ersparnis durch eigene Erzeugung (Euro)
    pub savings: Option<f64>,
}

/// Wie die Messungen zu verrechnen sind
pub struct Model {
    /// Geräte-ID → Rolle
    pub roles: HashMap<i64, String>,
    pub main_id: Option<i64>,
    pub net: bool,
    pub price_ct: Option<f64>,
    pub feed_in_ct: Option<f64>,
}

impl Model {
    pub fn figures(&self, flows: &HashMap<i64, Flow>) -> Figures {
        let role = |id: &i64| self.roles.get(id).map(String::as_str).unwrap_or("consumer");
        let mut production: Option<f64> = None;
        let mut consumers: Option<f64> = None;
        let mut grid: Option<Flow> = None;
        for (id, f) in flows {
            if Some(*id) == self.main_id {
                continue;
            }
            match role(id) {
                "producer" => *production.get_or_insert(0.0) += f.abs(),
                "grid" => {
                    let g = grid.get_or_insert_with(Flow::default);
                    g.pos += f.pos;
                    g.neg += f.neg;
                }
                _ => *consumers.get_or_insert(0.0) += f.abs(),
            }
        }
        let main = self.main_id.and_then(|id| flows.get(&id).copied());
        let main_is_grid = self.main_id.is_some_and(|id| role(&id) == "grid");
        let mut out = Figures { production, ..Default::default() };
        // Netz-Messung: saldierender Hauptzähler oder Geräte mit Rolle „Netz“
        let grid = match main {
            Some(m) if self.net || main_is_grid => Some(m),
            Some(m) => {
                out.consumption = Some(m.abs());
                grid
            }
            None => grid,
        };
        if let Some(g) = grid {
            out.import = Some(g.pos);
            out.export = Some(g.neg);
            if out.consumption.is_none() {
                // saldierend: Verbrauch = Bezug − Einspeisung + Erzeugung
                out.consumption = Some((g.pos - g.neg + production.unwrap_or(0.0)).max(0.0));
            }
        }
        if out.consumption.is_none() {
            out.consumption = consumers;
        }
        if let (Some(p), Some(e)) = (production, out.export) {
            out.self_use = Some((p - e).max(0.0));
        }
        if let Some(s) = out.self_use {
            out.autarky = out.consumption.filter(|c| *c > 0.0).map(|c| (s / c).min(1.0));
            out.self_use_rate = production.filter(|p| *p > 0.0).map(|p| (s / p).min(1.0));
        }
        let euro = |kwh: f64, ct: f64| kwh * ct / 100.0;
        let feed_in = euro(out.export.unwrap_or(0.0), self.feed_in_ct.unwrap_or(0.0));
        if let (Some(price), Some(import)) = (self.price_ct, out.import) {
            out.cost = Some(euro(import, price) - feed_in);
        }
        if let (Some(price), Some(s)) = (self.price_ct, out.self_use) {
            out.savings = Some(euro(s, price) + feed_in);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn model() -> Model {
        let roles = HashMap::from([(1, "consumer".to_string()), (2, "producer".to_string()), (3, "consumer".to_string())]);
        Model { roles, main_id: Some(1), net: true, price_ct: Some(30.0), feed_in_ct: Some(8.0) }
    }

    #[test]
    fn saldierender_zaehler() {
        // Hauptzähler: 10 kWh bezogen, 2 kWh eingespeist; PV 6 kWh; Kühlschrank 1 kWh
        let flows = HashMap::from([
            (1, Flow { pos: 10.0, neg: 2.0 }),
            (2, Flow { pos: 6.0, neg: 0.0 }),
            (3, Flow { pos: 1.0, neg: 0.0 }),
        ]);
        let f = model().figures(&flows);
        assert_eq!(f.import, Some(10.0));
        assert_eq!(f.export, Some(2.0));
        assert_eq!(f.production, Some(6.0));
        assert_eq!(f.consumption, Some(14.0)); // 10 − 2 + 6
        assert_eq!(f.self_use, Some(4.0));
        assert!((f.cost.unwrap() - (3.0 - 0.16)).abs() < 1e-9);
        assert!((f.savings.unwrap() - (1.2 + 0.16)).abs() < 1e-9);
        assert!((f.autarky.unwrap() - 4.0 / 14.0).abs() < 1e-9);
    }

    #[test]
    fn brutto_zaehler() {
        let flows = HashMap::from([(1, Flow { pos: 12.0, neg: 0.0 }), (2, Flow { pos: 6.0, neg: 0.0 })]);
        let mut m = model();
        m.net = false;
        let f = m.figures(&flows);
        assert_eq!(f.consumption, Some(12.0));
        assert_eq!(f.import, None);
    }

    #[test]
    fn ohne_hauptzaehler() {
        let flows = HashMap::from([(2, Flow { pos: 6.0, neg: 0.0 }), (3, Flow { pos: 1.0, neg: 0.0 })]);
        let mut m = model();
        m.main_id = None;
        let f = m.figures(&flows);
        assert_eq!(f.consumption, Some(1.0));
        assert_eq!(f.production, Some(6.0));
        assert_eq!(f.import, None);
        assert_eq!(f.self_use, None);
    }
}
