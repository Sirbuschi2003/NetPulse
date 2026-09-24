//! Leistungsdaten für die Seite „System“: Wie lange brauchen die einzelnen Aufgaben,
//! wie oft laufen sie, und wie viel CPU/RAM verbraucht NetPulse selbst?

use std::{
    collections::BTreeMap,
    sync::{Mutex, OnceLock},
    time::Instant,
};

use chrono::{DateTime, Utc};
use serde_json::{json, Value};

#[derive(Default, Clone)]
struct Stat {
    runs: u64,
    total_ms: f64,
    max_ms: f64,
    last_ms: f64,
    last_at: Option<DateTime<Utc>>,
}

fn stats() -> &'static Mutex<BTreeMap<&'static str, Stat>> {
    static STATS: OnceLock<Mutex<BTreeMap<&'static str, Stat>>> = OnceLock::new();
    STATS.get_or_init(Mutex::default)
}

fn started() -> Instant {
    static START: OnceLock<Instant> = OnceLock::new();
    *START.get_or_init(Instant::now)
}

/// Misst die Dauer bis zum Ende des Gültigkeitsbereichs
pub struct Timer {
    name: &'static str,
    start: Instant,
}

impl Timer {
    pub fn new(name: &'static str) -> Self {
        started();
        Self { name, start: Instant::now() }
    }
}

impl Drop for Timer {
    fn drop(&mut self) {
        let ms = self.start.elapsed().as_secs_f64() * 1000.0;
        let mut map = stats().lock().unwrap();
        let s = map.entry(self.name).or_default();
        s.runs += 1;
        s.total_ms += ms;
        s.max_ms = s.max_ms.max(ms);
        s.last_ms = ms;
        s.last_at = Some(Utc::now());
    }
}

pub fn tasks() -> Vec<Value> {
    let minutes = (started().elapsed().as_secs_f64() / 60.0).max(1.0 / 60.0);
    stats()
        .lock()
        .unwrap()
        .iter()
        .map(|(name, s)| {
            json!({
                "name": name,
                "runs": s.runs,
                "per_min": (s.runs as f64 / minutes * 10.0).round() / 10.0,
                "avg_ms": (s.total_ms / s.runs.max(1) as f64).round(),
                "max_ms": s.max_ms.round(),
                "last_ms": s.last_ms.round(),
                "last_at": s.last_at,
                // Anteil an der Laufzeit (grober Hinweis, wo die Zeit hingeht; Wartezeiten zählen mit)
                "busy_pct": (s.total_ms / (minutes * 60_000.0) * 1000.0).round() / 10.0,
            })
        })
        .collect()
}

/// CPU (seit der letzten Abfrage und seit dem Start) und Arbeitsspeicher des Prozesses (nur Linux)
pub fn process() -> Value {
    static LAST: OnceLock<Mutex<Option<(f64, Instant)>>> = OnceLock::new();
    let read = || -> Option<(f64, f64, u64)> {
        let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
        // Felder nach dem Prozessnamen in Klammern
        let rest = stat.rsplit_once(')')?.1;
        let f: Vec<&str> = rest.split_whitespace().collect();
        let ticks = f.get(11)?.parse::<f64>().ok()? + f.get(12)?.parse::<f64>().ok()?;
        let threads = f.get(17)?.parse::<u64>().ok()?;
        let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
        let rss_pages: f64 = statm.split_whitespace().nth(1)?.parse().ok()?;
        Some((ticks / 100.0, rss_pages * 4096.0 / 1_048_576.0, threads))
    };
    let Some((cpu_s, rss_mb, threads)) = read() else { return json!({ "available": false }) };
    let uptime = started().elapsed().as_secs_f64().max(1.0);
    let mut last = LAST.get_or_init(Mutex::default).lock().unwrap();
    let now_pct = last.map(|(prev, at)| {
        let dt = at.elapsed().as_secs_f64();
        if dt > 0.5 { (cpu_s - prev) / dt * 100.0 } else { 0.0 }
    });
    *last = Some((cpu_s, Instant::now()));
    json!({
        "available": true,
        "cpu_pct_now": now_pct.map(|p| (p * 10.0).round() / 10.0),
        "cpu_pct_avg": (cpu_s / uptime * 1000.0).round() / 10.0,
        "cpu_seconds": cpu_s.round(),
        "rss_mb": (rss_mb * 10.0).round() / 10.0,
        "threads": threads,
        "uptime_s": uptime.round(),
    })
}
