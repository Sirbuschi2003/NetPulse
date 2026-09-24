//! Statusprüfung: prüft alle überwachten Geräte im festen Takt (Standard: jede Minute)
//! und speichert Erreichbarkeit und Antwortzeit als Zeitreihe.

use std::{net::Ipv4Addr, sync::Arc, time::Duration};

use anyhow::Result;
use futures::{stream, StreamExt};

use crate::{
    scanner::net::{self, Pinger},
    AppState,
};

/// Ein zu prüfendes Gerät, wie es aus der Datenbank kommt
#[derive(sqlx::FromRow)]
struct Target {
    id: i64,
    ip: String,
    status: String,
    open_ports: Vec<i32>,
    label: Option<String>,
}

/// Ergebnis einer Prüfung
struct Check {
    id: i64,
    up: bool,
    rtt_ms: Option<f32>,
    previous_status: String,
    label: String,
}

pub async fn run(state: AppState, pinger: Arc<Pinger>) {
    let mut ticker = tokio::time::interval(state.config.monitor_interval);
    // Dauert eine Runde länger als das Intervall, wird die nächste nicht doppelt gestartet
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        ticker.tick().await;
        if let Err(e) = check_all(&state, &pinger).await {
            tracing::error!("Statusprüfung fehlgeschlagen: {e:#}");
        }
    }
}

async fn check_all(state: &AppState, pinger: &Arc<Pinger>) -> Result<()> {
    let _perf = crate::perf::Timer::new("Erreichbarkeit (Runde über alle Geräte)");
    let targets: Vec<Target> = sqlx::query_as(
        "SELECT id, host(ip) AS ip, status, open_ports, COALESCE(name, hostname) AS label
           FROM devices WHERE monitored AND family(ip) = 4",
    )
    .fetch_all(&state.db)
    .await?;
    if targets.is_empty() {
        return Ok(());
    }

    let checks: Vec<Check> = stream::iter(targets)
        .map(|target| {
            let pinger = pinger.clone();
            async move {
                let rtt = match target.ip.parse::<Ipv4Addr>() {
                    Ok(addr) => check_device(&pinger, addr, &target.open_ports).await,
                    Err(_) => None,
                };
                let label = match target.label {
                    Some(name) => format!("{name} ({})", target.ip),
                    None => target.ip,
                };
                Check {
                    id: target.id,
                    up: rtt.is_some(),
                    rtt_ms: rtt.map(|d| d.as_secs_f32() * 1000.0),
                    previous_status: target.status,
                    label,
                }
            }
        })
        .buffer_unordered(64)
        .collect()
        .await;

    // Alle Ergebnisse mit wenigen Datenbankbefehlen schreiben (UNNEST = Listen als Tabelle)
    let ids: Vec<i64> = checks.iter().map(|c| c.id).collect();
    let ups: Vec<bool> = checks.iter().map(|c| c.up).collect();
    let rtts: Vec<Option<f32>> = checks.iter().map(|c| c.rtt_ms).collect();

    let mut tx = state.db.begin().await?;
    sqlx::query(
        "INSERT INTO device_metrics (time, device_id, up, rtt_ms)
         SELECT now(), u.id, u.up, u.rtt FROM UNNEST($1::bigint[], $2::boolean[], $3::real[]) AS u(id, up, rtt)",
    )
    .bind(&ids)
    .bind(&ups)
    .bind(&rtts)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE devices d SET
             status_since = CASE WHEN d.status = (CASE WHEN u.up THEN 'up' ELSE 'down' END)
                                 THEN COALESCE(d.status_since, now()) ELSE now() END,
             status      = CASE WHEN u.up THEN 'up' ELSE 'down' END,
             last_rtt_ms = u.rtt,
             last_check  = now(),
             last_seen   = CASE WHEN u.up THEN now() ELSE d.last_seen END
           FROM UNNEST($1::bigint[], $2::boolean[], $3::real[]) AS u(id, up, rtt)
          WHERE d.id = u.id",
    )
    .bind(&ids)
    .bind(&ups)
    .bind(&rtts)
    .execute(&mut *tx)
    .await?;

    // Statuswechsel als Ereignis festhalten
    for check in &checks {
        let status = if check.up { "up" } else { "down" };
        let first_check_ok = check.previous_status == "unknown" && check.up;
        if check.previous_status != status && !first_check_ok {
            let message = if check.up {
                format!("{} ist wieder erreichbar", check.label)
            } else {
                format!("{} ist nicht erreichbar", check.label)
            };
            sqlx::query("INSERT INTO events (device_id, kind, message) VALUES ($1, $2, $3)")
                .bind(check.id)
                .bind(status)
                .bind(message)
                .execute(&mut *tx)
                .await?;
        }
    }
    tx.commit().await?;

    // Statuswechsel sofort an offene Browser melden
    let changes: Vec<_> = checks
        .iter()
        .filter(|c| c.previous_status != if c.up { "up" } else { "down" })
        .map(|c| serde_json::json!({ "id": c.id, "status": if c.up { "up" } else { "down" }, "label": c.label }))
        .collect();
    if !changes.is_empty() {
        state.hub.publish(&serde_json::json!({ "type": "status", "devices": changes }));
    }

    let down = checks.iter().filter(|c| !c.up).count();
    tracing::debug!("Statusprüfung: {} Geräte, {down} nicht erreichbar", checks.len());
    Ok(())
}

/// Erst Ping; antwortet das Gerät nicht, werden bekannte offene Ports per TCP geprüft.
async fn check_device(pinger: &Pinger, ip: Ipv4Addr, open_ports: &[i32]) -> Option<Duration> {
    if let Some(rtt) = pinger.ping(ip, Duration::from_secs(1), 2).await {
        return Some(rtt);
    }
    let known: Vec<u16> = open_ports.iter().filter_map(|&p| u16::try_from(p).ok()).take(3).collect();
    let ports = if known.is_empty() { net::LIVENESS_PORTS } else { &known[..] };
    net::tcp_alive(ip, ports, Duration::from_secs(1)).await
}
