//! Echtzeit-Spur: fragt Geräte mit schneller lokaler API (derzeit Shelly) im Sekundentakt ab
//! und verteilt die Werte sofort per Server-Sent Events an alle offenen Browser.
//!
//! Getrennt von der tiefen Abfrage (Inventar alle paar Minuten): hier nur eine einzige, kleine
//! Anfrage je Gerät, Geräteinfo und passende Zugangsdaten bleiben im Speicher.
//! In die Datenbank geht höchstens ein Messwert pro Minute (Datensparsamkeit).

use std::{
    collections::HashMap,
    net::Ipv4Addr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use chrono::Utc;
use futures::{stream, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::PgPool;
use tokio::sync::broadcast;

use super::{load_credentials, shelly, Credential};
use crate::AppState;

// ---------------------------------------------------------------------------
// Verteiler für Live-Meldungen
// ---------------------------------------------------------------------------

pub struct Hub {
    tx: broadcast::Sender<Arc<str>>,
    latest: Mutex<HashMap<i64, Value>>,
}

impl Default for Hub {
    fn default() -> Self {
        let (tx, _) = broadcast::channel(64);
        Self { tx, latest: Mutex::default() }
    }
}

impl Hub {
    pub fn subscribe(&self) -> broadcast::Receiver<Arc<str>> {
        self.tx.subscribe()
    }

    /// Anzahl offener Browser-Verbindungen
    pub fn clients(&self) -> usize {
        self.tx.receiver_count()
    }

    pub fn publish(&self, event: &Value) {
        // Fehler heißt nur: gerade niemand verbunden
        let _ = self.tx.send(event.to_string().into());
    }

    /// Gesamtstand für neu verbundene Browser
    pub fn snapshot(&self) -> Value {
        let latest = self.latest.lock().unwrap();
        let devices: Vec<&Value> = latest.values().collect();
        json!({ "type": "shelly", "full": true, "time": Utc::now(), "devices": devices, "total_power_w": total_power(devices.iter().copied()) })
    }
}

fn total_power<'a>(devices: impl Iterator<Item = &'a Value>) -> Option<f64> {
    let mut any = false;
    let sum: f64 = devices
        .filter(|d| d["ok"].as_bool() == Some(true))
        .filter_map(|d| d["power_w"].as_f64())
        .inspect(|_| any = true)
        .sum();
    any.then_some((sum * 10.0).round() / 10.0)
}

// ---------------------------------------------------------------------------
// Einstellungen
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct LiveSettings {
    pub enabled: bool,
    /// Abfrage-Takt in Sekunden
    pub interval_s: u32,
}

impl Default for LiveSettings {
    fn default() -> Self {
        Self { enabled: true, interval_s: 5 }
    }
}

impl LiveSettings {
    pub fn validate(&self) -> Result<(), String> {
        if !(2..=300).contains(&self.interval_s) {
            return Err("Takt muss zwischen 2 und 300 Sekunden liegen".into());
        }
        Ok(())
    }
}

pub async fn load_settings(db: &PgPool) -> LiveSettings {
    let row: Option<(Value,)> = sqlx::query_as("SELECT value FROM settings WHERE key = 'live_settings'")
        .fetch_optional(db)
        .await
        .ok()
        .flatten();
    row.and_then(|(v,)| serde_json::from_value(v).ok()).unwrap_or_default()
}

pub async fn save_settings(db: &PgPool, settings: &LiveSettings) -> sqlx::Result<()> {
    sqlx::query(
        "INSERT INTO settings (key, value) VALUES ('live_settings', $1)
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
    )
    .bind(json!(settings))
    .execute(db)
    .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Abfrage-Schleife
// ---------------------------------------------------------------------------

#[derive(sqlx::FromRow)]
struct Target {
    id: i64,
    ip: String,
    label: String,
}

/// Was pro Gerät zwischen den Durchläufen im Speicher bleibt
struct Cached {
    info: shelly::Info,
    info_at: Instant,
    cred: Option<Credential>,
    cred_tried_at: Option<Instant>,
    failures: u32,
    skip_until: Option<Instant>,
}

const INFO_REFRESH: Duration = Duration::from_secs(15 * 60);
const CRED_RETRY: Duration = Duration::from_secs(5 * 60);
const STORE_EVERY: Duration = Duration::from_secs(60);

pub async fn run(state: AppState) {
    tokio::time::sleep(Duration::from_secs(10)).await;
    let mut cache: HashMap<i64, Cached> = HashMap::new();
    let mut last_store = Instant::now();

    loop {
        let settings = load_settings(&state.db).await;
        let interval = Duration::from_secs(u64::from(settings.interval_s.max(2)));
        if !settings.enabled {
            state.hub.latest.lock().unwrap().clear();
            tokio::time::sleep(Duration::from_secs(15)).await;
            continue;
        }
        let started = Instant::now();
        let perf = crate::perf::Timer::new("Echtzeit Shelly (Runde)");
        let targets: Vec<Target> = match sqlx::query_as(
            "SELECT id, host(ip) AS ip, COALESCE(name, reported_name, hostname, host(ip)) AS label
               FROM devices WHERE integration = 'shelly' AND status = 'up'",
        )
        .fetch_all(&state.db)
        .await
        {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!("Echtzeit-Abfrage: Geräte konnten nicht geladen werden: {e}");
                tokio::time::sleep(interval).await;
                continue;
            }
        };

        // Antwortzeit begrenzen, damit ein hängendes Gerät den Takt nicht bremst
        let limit = interval.clamp(Duration::from_secs(2), Duration::from_secs(6));
        let jobs: Vec<(Target, Option<Cached>)> = targets.into_iter().map(|t| { let c = cache.remove(&t.id); (t, c) }).collect();
        let results: Vec<(i64, Option<Cached>, Option<Value>)> = stream::iter(jobs)
            .map(|(t, c)| poll_one(&state, t, c, limit))
            .buffer_unordered(32)
            .collect()
            .await;

        // Übrig sind nur Geräte, die nicht mehr abgefragt werden (offline, kein Shelly mehr)
        cache.clear();
        let mut changed = Vec::new();
        let mut store: Vec<(i64, f32)> = Vec::new();
        {
            let mut latest = state.hub.latest.lock().unwrap();
            latest.retain(|id, _| results.iter().any(|(r, _, _)| r == id));
            for (id, cached, value) in results {
                if let Some(c) = cached {
                    cache.insert(id, c);
                }
                let Some(value) = value else { continue };
                if let Some(w) = value["power_w"].as_f64() {
                    store.push((id, w as f32));
                }
                if latest.get(&id).is_none_or(|old| !same(old, &value)) {
                    changed.push(value.clone());
                }
                latest.insert(id, value);
            }
            let total = total_power(latest.values());
            state.hub.publish(&json!({ "type": "shelly", "time": Utc::now(), "devices": changed, "total_power_w": total }));
        }

        if last_store.elapsed() >= STORE_EVERY && !store.is_empty() {
            last_store = Instant::now();
            let (ids, watts): (Vec<i64>, Vec<f32>) = store.into_iter().unzip();
            let result = sqlx::query(
                "INSERT INTO device_stats (time, device_id, power_w)
                 SELECT now(), u.id, u.w FROM UNNEST($1::bigint[], $2::real[]) AS u(id, w)",
            )
            .bind(&ids)
            .bind(&watts)
            .execute(&state.db)
            .await;
            if let Err(e) = result {
                tracing::warn!("Echtzeit-Messwerte konnten nicht gespeichert werden: {e}");
            }
        }

        drop(perf);
        let elapsed = started.elapsed();
        tokio::time::sleep(interval.saturating_sub(elapsed).max(Duration::from_millis(500))).await;
    }
}

/// Gleich bis auf den Zeitstempel?
fn same(a: &Value, b: &Value) -> bool {
    let strip = |v: &Value| {
        let mut v = v.clone();
        if let Some(o) = v.as_object_mut() {
            o.remove("time");
        }
        v
    };
    strip(a) == strip(b)
}

async fn poll_one(state: &AppState, t: Target, cached: Option<Cached>, limit: Duration) -> (i64, Option<Cached>, Option<Value>) {
    let Ok(ip) = t.ip.parse::<Ipv4Addr>() else { return (t.id, None, None) };
    let offline = |error: &str| Some(json!({ "id": t.id, "label": t.label, "ok": false, "error": error, "time": Utc::now() }));

    let mut c = match cached {
        Some(c) if c.info_at.elapsed() < INFO_REFRESH => c,
        previous => match tokio::time::timeout(limit * 2, shelly::probe(ip)).await.ok().flatten() {
            Some(info) => Cached {
                info,
                info_at: Instant::now(),
                cred: previous.as_ref().and_then(|p| p.cred.clone()),
                cred_tried_at: previous.as_ref().and_then(|p| p.cred_tried_at),
                failures: 0,
                skip_until: None,
            },
            None => return (t.id, previous, offline("Shelly antwortet nicht")),
        },
    };
    if c.skip_until.is_some_and(|s| Instant::now() < s) {
        return (t.id, Some(c), offline("antwortet nicht – nächster Versuch in Kürze"));
    }

    let result = if c.info.auth && c.cred.is_none() {
        if c.cred_tried_at.is_some_and(|at| at.elapsed() < CRED_RETRY) {
            Err(anyhow::anyhow!("Passwortgeschützt – passende HTTP-Zugangsdaten fehlen"))
        } else {
            c.cred_tried_at = Some(Instant::now());
            find_credential(state, t.id, ip, &mut c, limit).await
        }
    } else {
        tokio::time::timeout(limit, shelly::status(ip, &c.info, c.cred.as_ref()))
            .await
            .unwrap_or_else(|_| Err(anyhow::anyhow!("Zeitüberschreitung")))
    };

    match result {
        Ok(data) => {
            c.failures = 0;
            c.skip_until = None;
            let value = json!({
                "id": t.id,
                "label": t.label,
                "ok": true,
                "time": Utc::now(),
                "model": c.info.model,
                "power_w": data["power_w"],
                "energy_kwh": data["energy_kwh"],
                "temp_c": data["temp_c"],
                "humidity_pct": data["humidity_pct"],
                "battery_pct": data["battery_pct"],
                "rssi": data["rssi"],
                "channels": data["channels"],
            });
            (t.id, Some(c), Some(value))
        }
        Err(e) => {
            let message = format!("{e:#}");
            if message.contains("Anmeldung") {
                // Passwort geändert? Beim nächsten Versuch Zugangsdaten neu suchen
                c.cred = None;
            }
            c.failures += 1;
            if c.failures >= 3 {
                // Nicht erreichbare Geräte seltener fragen (bis 5 Minuten)
                c.skip_until = Some(Instant::now() + Duration::from_secs(u64::from(c.failures.min(10)) * 30));
            }
            tracing::debug!("Echtzeit {} ({}): {message}", t.label, t.ip);
            (t.id, Some(c), offline(&message))
        }
    }
}

/// Die zugeordneten bzw. automatischen HTTP-Zugangsdaten durchprobieren und die passende merken
async fn find_credential(state: &AppState, device_id: i64, ip: Ipv4Addr, c: &mut Cached, limit: Duration) -> anyhow::Result<Value> {
    let creds = load_credentials(state, device_id).await?;
    for cred in creds.into_iter().filter(|cr| cr.kind == "http" && (cr.linked || c.info.generation >= 2)) {
        if let Ok(Ok(data)) = tokio::time::timeout(limit, shelly::status(ip, &c.info, Some(&cred))).await {
            c.cred = Some(cred);
            return Ok(data);
        }
    }
    anyhow::bail!("Passwortgeschützt – passende HTTP-Zugangsdaten fehlen")
}
