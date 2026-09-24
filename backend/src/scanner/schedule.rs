//! Zeitplan für die automatische Geräte-Suche („Discovery“).
//!
//! - `interval`: alle X Minuten (gerechnet ab dem letzten vollständigen Scan – ein Neustart löst keinen Scan aus)
//! - `daily`   : täglich zu festen Uhrzeiten (Zeitzone aus `TZ`, Standard Europe/Berlin);
//!   ein verpasster Termin (Gerät war aus) wird einmal nachgeholt
//! - `manual`  : nur auf Knopfdruck bzw. wenn ein neues Netz eingetragen wird

use chrono::{DateTime, Duration, NaiveTime, TimeZone, Utc};
use chrono_tz::Tz;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::PgPool;

use crate::config::Config;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Schedule {
    pub mode: String,
    pub interval_min: u32,
    pub times: Vec<String>,
    /// Beim Start des Containers sofort scannen
    pub on_start: bool,
}

impl Schedule {
    pub fn default_for(config: &Config) -> Self {
        Self {
            // Standard: nachts suchen – ein Neustart des Containers löst dann keinen Scan aus
            mode: "daily".into(),
            interval_min: (config.discovery_interval.as_secs() / 60).max(1) as u32,
            times: vec!["03:00".into()],
            on_start: false,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if !["interval", "daily", "manual"].contains(&self.mode.as_str()) {
            return Err("Unbekannter Modus".into());
        }
        if self.mode == "interval" && !(5..=10_080).contains(&self.interval_min) {
            return Err("Intervall muss zwischen 5 Minuten und 7 Tagen liegen".into());
        }
        if self.mode == "daily" && (self.times.is_empty() || self.times.len() > 24) {
            return Err("Bitte 1 bis 24 Uhrzeiten angeben".into());
        }
        for t in &self.times {
            NaiveTime::parse_from_str(t.trim(), "%H:%M").map_err(|_| format!("„{t}“ ist keine Uhrzeit (Format 03:00)"))?;
        }
        Ok(())
    }
}

/// Zeitzone für Uhrzeiten im Zeitplan
pub fn timezone() -> Tz {
    std::env::var("TZ").ok().and_then(|t| t.parse().ok()).unwrap_or(chrono_tz::Europe::Berlin)
}

pub async fn load(db: &PgPool, config: &Config) -> Schedule {
    let row: Option<(serde_json::Value,)> = sqlx::query_as("SELECT value FROM settings WHERE key = 'discovery_schedule'")
        .fetch_optional(db)
        .await
        .ok()
        .flatten();
    row.and_then(|(v,)| serde_json::from_value(v).ok()).unwrap_or_else(|| Schedule::default_for(config))
}

pub async fn save(db: &PgPool, schedule: &Schedule) -> sqlx::Result<()> {
    sqlx::query(
        "INSERT INTO settings (key, value) VALUES ('discovery_schedule', $1)
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
    )
    .bind(json!(schedule))
    .execute(db)
    .await?;
    Ok(())
}

pub async fn last_full_scan(db: &PgPool) -> Option<DateTime<Utc>> {
    let row: Option<(serde_json::Value,)> = sqlx::query_as("SELECT value FROM settings WHERE key = 'last_full_scan'")
        .fetch_optional(db)
        .await
        .ok()
        .flatten();
    row.and_then(|(v,)| v["time"].as_str().and_then(|t| t.parse().ok()))
}

pub async fn set_last_full_scan(db: &PgPool, time: DateTime<Utc>) -> sqlx::Result<()> {
    sqlx::query(
        "INSERT INTO settings (key, value) VALUES ('last_full_scan', $1)
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
    )
    .bind(json!({ "time": time }))
    .execute(db)
    .await?;
    Ok(())
}

/// Wann ist der nächste vollständige Scan fällig? `None` = nie automatisch.
pub fn next_due(schedule: &Schedule, last: Option<DateTime<Utc>>, now: DateTime<Utc>, tz: Tz) -> Option<DateTime<Utc>> {
    match schedule.mode.as_str() {
        "interval" => Some(last.map_or(now, |l| l + Duration::minutes(i64::from(schedule.interval_min)))),
        "daily" => {
            let local_now = now.with_timezone(&tz);
            let mut slots: Vec<DateTime<Utc>> = Vec::new();
            for day in -1..=1 {
                let date = local_now.date_naive() + Duration::days(day);
                for t in &schedule.times {
                    if let Ok(time) = NaiveTime::parse_from_str(t.trim(), "%H:%M") {
                        if let Some(slot) = tz.from_local_datetime(&date.and_time(time)).earliest() {
                            slots.push(slot.with_timezone(&Utc));
                        }
                    }
                }
            }
            slots.sort();
            let previous = slots.iter().rev().find(|s| **s <= now).copied();
            let next = slots.iter().find(|s| **s > now).copied();
            match (last, previous) {
                (None, _) => Some(now),
                (Some(l), Some(p)) if l < p => Some(now), // Termin verpasst → nachholen
                _ => next,
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: &str) -> DateTime<Utc> {
        s.parse().unwrap()
    }

    #[test]
    fn intervall_zaehlt_ab_letztem_scan() {
        let s = Schedule { mode: "interval".into(), interval_min: 60, times: vec![], on_start: false };
        let tz = chrono_tz::Europe::Berlin;
        assert_eq!(next_due(&s, Some(at("2026-09-24T10:00:00Z")), at("2026-09-24T10:30:00Z"), tz), Some(at("2026-09-24T11:00:00Z")));
        assert_eq!(next_due(&s, None, at("2026-09-24T10:30:00Z"), tz), Some(at("2026-09-24T10:30:00Z")));
    }

    #[test]
    fn taeglich_mit_nachholen() {
        let s = Schedule { mode: "daily".into(), interval_min: 0, times: vec!["03:00".into()], on_start: false };
        let tz = chrono_tz::Europe::Berlin; // Sommerzeit: 03:00 Berlin = 01:00 UTC
        // letzter Scan heute 01:00 UTC → nächster morgen 01:00 UTC
        assert_eq!(next_due(&s, Some(at("2026-09-24T01:00:05Z")), at("2026-09-24T09:00:00Z"), tz), Some(at("2026-09-25T01:00:00Z")));
        // letzter Scan gestern → heutiger Termin verpasst → sofort
        assert_eq!(next_due(&s, Some(at("2026-09-23T01:00:05Z")), at("2026-09-24T09:00:00Z"), tz), Some(at("2026-09-24T09:00:00Z")));
        let manual = Schedule { mode: "manual".into(), ..s };
        assert_eq!(next_due(&manual, None, at("2026-09-24T09:00:00Z"), tz), None);
    }
}
