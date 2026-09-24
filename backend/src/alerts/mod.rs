//! Alarmierung: prüft alle 20 Sekunden die Regeln und verschickt Benachrichtigungen.
//!
//! Regeltypen:
//! - `device_down`  : Gerät länger als `duration_min` Minuten offline (mit Entwarnung)
//! - `new_device`   : neues Gerät im Netz
//! - `mac_changed`  : MAC-Adresse einer IP hat sich geändert (möglicher Angriff)
//! - `disk_usage`, `cpu_usage`, `mem_usage`, `temperature`: Schwellwert aus SNMP/SSH-Messwerten
//!
//! Solange ein Alarm offen ist, erinnert NetPulse auf Wunsch alle `repeat_min` Minuten daran.

pub mod deliver;
pub mod notify;

use std::time::Duration;

use anyhow::Result;
use serde_json::Value;
use sqlx::FromRow;

use crate::AppState;
use notify::{Notification, Severity};

#[derive(FromRow, Clone)]
pub(crate) struct Rule {
    pub id: i64,
    pub name: String,
    pub kind: String,
    pub device_id: Option<i64>,
    pub threshold: Option<f32>,
    pub duration_min: i32,
    pub channel_ids: Vec<i64>,
    pub notify_recovery: bool,
    pub repeat_min: i32,
}

pub async fn run(state: AppState) {
    tokio::time::sleep(Duration::from_secs(15)).await;
    // Beim Start nur neue Ereignisse melden, nicht die komplette Historie
    let mut cursor: i64 = sqlx::query_as::<_, (Option<i64>,)>("SELECT max(id) FROM events")
        .fetch_one(&state.db)
        .await
        .map(|r| r.0.unwrap_or(0))
        .unwrap_or(0);
    let mut tick = tokio::time::interval(Duration::from_secs(20));
    loop {
        tick.tick().await;
        match evaluate(&state, cursor).await {
            Ok(new_cursor) => cursor = new_cursor,
            Err(e) => tracing::error!("Alarmprüfung fehlgeschlagen: {e:#}"),
        }
    }
}

async fn evaluate(state: &AppState, cursor: i64) -> Result<i64> {
    let rules: Vec<Rule> = sqlx::query_as(
        "SELECT id, name, kind, device_id, threshold, duration_min, channel_ids, notify_recovery, repeat_min
           FROM alert_rules WHERE enabled",
    )
    .fetch_all(&state.db)
    .await?;

    let new_cursor = event_rules(state, &rules, cursor).await?;
    for rule in &rules {
        let result = match rule.kind.as_str() {
            "device_down" => device_down(state, rule).await,
            "disk_usage" | "cpu_usage" | "mem_usage" | "temperature" => threshold(state, rule).await,
            _ => Ok(()),
        };
        if let Err(e) = result {
            tracing::error!("Regel „{}“: {e:#}", rule.name);
        }
    }
    if let Err(e) = reminders(state, &rules).await {
        tracing::error!("Erinnerungen: {e:#}");
    }
    Ok(new_cursor)
}

fn device_link(state: &AppState, device_id: i64) -> Option<String> {
    state.config.public_url.as_ref().map(|u| format!("{u}/#/device/{device_id}"))
}

/// Ereignisbasierte Regeln: neues Gerät, MAC geändert
async fn event_rules(state: &AppState, rules: &[Rule], cursor: i64) -> Result<i64> {
    let events: Vec<(i64, Option<i64>, String, String)> = sqlx::query_as(
        "SELECT id, device_id, kind, message FROM events
          WHERE id > $1 AND kind IN ('discovered', 'mac_changed', 'ssh_key_changed') ORDER BY id LIMIT 500",
    )
    .bind(cursor)
    .fetch_all(&state.db)
    .await?;
    let mut last = cursor;
    for (event_id, device_id, kind, message) in events {
        last = event_id;
        let rule_kind = match kind.as_str() {
            "discovered" => "new_device",
            _ => "mac_changed", // auch geänderte SSH-Host-Schlüssel sind sicherheitsrelevant
        };
        for rule in rules.iter().filter(|r| r.kind == rule_kind) {
            if rule.device_id.is_some() && rule.device_id != device_id {
                continue;
            }
            sqlx::query("INSERT INTO alerts (rule_id, device_id, message, resolved_at) VALUES ($1, $2, $3, now())")
                .bind(rule.id)
                .bind(device_id)
                .bind(&message)
                .execute(&state.db)
                .await?;
            let severity = if rule_kind == "new_device" { Severity::Info } else { Severity::Warning };
            let title = if rule_kind == "new_device" { "Neues Gerät im Netz" } else { "Sicherheitshinweis" };
            let mut n = Notification::new(title, message.clone(), severity, device_id.and_then(|id| device_link(state, id)));
            n.device_id = device_id;
            dispatch(state, rule, n).await;
        }
    }
    Ok(last)
}

async fn device_down(state: &AppState, rule: &Rule) -> Result<()> {
    // Neue Ausfälle
    let down: Vec<(i64, String, i64)> = sqlx::query_as(
        "SELECT d.id, COALESCE(d.name, d.reported_name, d.hostname, host(d.ip)) || ' (' || host(d.ip) || ')',
                (EXTRACT(EPOCH FROM now() - d.status_since) / 60)::bigint
           FROM devices d
          WHERE d.monitored AND d.status = 'down'
            AND d.status_since <= now() - make_interval(mins => $1)
            AND ($2::bigint IS NULL OR d.id = $2)",
    )
    .bind(rule.duration_min)
    .bind(rule.device_id)
    .fetch_all(&state.db)
    .await?;
    for (device_id, label, minutes) in down {
        let message = if minutes > 0 { format!("{label} ist seit {minutes} Min. nicht erreichbar") } else { format!("{label} ist nicht erreichbar") };
        if open_alert(state, rule, Some(device_id), &message, None).await? {
            let n = Notification::new(format!("Offline: {label}"), message, Severity::Critical, device_link(state, device_id))
                .device(device_id);
            let n = if minutes > 0 { n.var("wert", format!("seit {minutes} Min. offline")) } else { n };
            dispatch(state, rule, n).await;
        }
    }

    // Entwarnung für wieder erreichbare (oder nicht mehr überwachte) Geräte
    let resolved: Vec<(i64, String, i64)> = sqlx::query_as(
        "UPDATE alerts a SET resolved_at = now()
           FROM devices d
          WHERE a.rule_id = $1 AND a.resolved_at IS NULL AND d.id = a.device_id
            AND (d.status <> 'down' OR NOT d.monitored)
          RETURNING d.id, COALESCE(d.name, d.reported_name, d.hostname, host(d.ip)) || ' (' || host(d.ip) || ')',
                    (EXTRACT(EPOCH FROM a.resolved_at - a.opened_at) / 60)::bigint",
    )
    .bind(rule.id)
    .fetch_all(&state.db)
    .await?;
    if rule.notify_recovery {
        for (device_id, label, minutes) in resolved {
            let n = Notification::new(
                format!("Wieder online: {label}"),
                format!("{label} ist wieder erreichbar (Alarm bestand {minutes} Min.)"),
                Severity::Resolved,
                device_link(state, device_id),
            )
            .device(device_id)
            .var("wert", format!("{minutes} Min. Ausfall"));
            dispatch(state, rule, n).await;
        }
    }
    Ok(())
}

async fn threshold(state: &AppState, rule: &Rule) -> Result<()> {
    let Some(limit) = rule.threshold else { return Ok(()) };
    // Spaltenname stammt aus einer festen Liste – kein SQL aus Benutzereingaben
    let (column, what, unit) = match rule.kind.as_str() {
        "disk_usage" => ("disk_pct", "Speicherbelegung", "%"),
        "cpu_usage" => ("cpu_pct", "CPU-Auslastung", "%"),
        "mem_usage" => ("mem_pct", "RAM-Auslastung", "%"),
        _ => ("temp_c", "Temperatur", "°C"),
    };
    // Wert muss über die gesamte Dauer über dem Schwellwert liegen (mindestens die letzte Messung)
    let window = rule.duration_min.max(0);
    let rows: Vec<(i64, String, Option<f32>, Option<f32>)> = sqlx::query_as(&format!(
        "SELECT s.device_id, COALESCE(d.name, d.hostname, host(d.ip)) || ' (' || host(d.ip) || ')',
                (array_agg(s.{column} ORDER BY s.time DESC))[1],
                min(s.{column}) FILTER (WHERE s.time > now() - make_interval(mins => $2))
           FROM device_stats s JOIN devices d ON d.id = s.device_id
          WHERE s.time > now() - make_interval(mins => GREATEST($2, 0) + 15)
            AND s.{column} IS NOT NULL AND ($1::bigint IS NULL OR s.device_id = $1)
          GROUP BY s.device_id, d.name, d.hostname, d.ip"
    ))
    .bind(rule.device_id)
    .bind(window)
    .fetch_all(&state.db)
    .await?;

    for (device_id, label, latest, window_min) in rows {
        let Some(latest) = latest else { continue };
        let sustained = if window > 0 { window_min.unwrap_or(latest) } else { latest };
        if sustained > limit {
            let message = format!("{what} von {label} liegt bei {latest:.0} {unit} (Grenze {limit:.0} {unit})");
            if open_alert(state, rule, Some(device_id), &message, Some(latest)).await? {
                let n = Notification::new(format!("{what} hoch: {label}"), message, Severity::Warning, device_link(state, device_id))
                    .device(device_id)
                    .var("wert", format!("{latest:.0} {unit} (Grenze {limit:.0} {unit})"));
                dispatch(state, rule, n).await;
            }
        } else if latest <= limit {
            let closed: Option<(i64,)> = sqlx::query_as(
                "UPDATE alerts SET resolved_at = now() WHERE rule_id = $1 AND device_id = $2 AND resolved_at IS NULL RETURNING id",
            )
            .bind(rule.id)
            .bind(device_id)
            .fetch_optional(&state.db)
            .await?;
            if closed.is_some() && rule.notify_recovery {
                let n = Notification::new(
                    format!("{what} wieder normal: {label}"),
                    format!("{what} von {label} liegt wieder bei {latest:.0} {unit}"),
                    Severity::Resolved,
                    device_link(state, device_id),
                )
                .device(device_id)
                .var("wert", format!("{latest:.0} {unit}"));
                dispatch(state, rule, n).await;
            }
        }
    }
    Ok(())
}

/// Offene Alarme erneut melden, solange sie bestehen (je Regel einstellbar)
async fn reminders(state: &AppState, rules: &[Rule]) -> Result<()> {
    for rule in rules.iter().filter(|r| r.repeat_min > 0) {
        // Meldung ohne die ursprüngliche Dauer („seit 5 Min.“) – die aktuelle Dauer kommt dazu
        let due: Vec<(i64, Option<i64>, String, i32, i64)> = sqlx::query_as(
            "UPDATE alerts SET last_notified_at = now(), notify_count = notify_count + 1
              WHERE rule_id = $1 AND resolved_at IS NULL
                AND COALESCE(last_notified_at, opened_at) <= now() - make_interval(mins => $2)
              RETURNING id, device_id, message, notify_count, (EXTRACT(EPOCH FROM now() - opened_at) / 60)::bigint",
        )
        .bind(rule.id)
        .bind(rule.repeat_min)
        .fetch_all(&state.db)
        .await?;
        for (_, device_id, message, count, minutes) in due {
            let severity = if rule.kind == "device_down" { Severity::Critical } else { Severity::Warning };
            let mut n = Notification::new(
                format!("Erinnerung ({count}.): {}", rule.name),
                format!("{} – besteht seit {minutes} Min.", strip_duration(&message)),
                severity,
                device_id.and_then(|id| device_link(state, id)),
            );
            n.device_id = device_id;
            dispatch(state, rule, n).await;
        }
    }
    Ok(())
}

/// „NAS ist seit 5 Min. nicht erreichbar“ → „NAS ist nicht erreichbar“
fn strip_duration(message: &str) -> String {
    match (message.find(" seit "), message.find(" Min. ")) {
        (Some(a), Some(b)) if b > a => format!("{}{}", &message[..a], &message[b + 5..]),
        _ => message.to_string(),
    }
}

/// Legt einen offenen Alarm an; `false`, wenn für Regel+Gerät schon einer offen ist.
async fn open_alert(state: &AppState, rule: &Rule, device_id: Option<i64>, message: &str, value: Option<f32>) -> sqlx::Result<bool> {
    let inserted: Option<(i64,)> = sqlx::query_as(
        "INSERT INTO alerts (rule_id, device_id, message, value, last_notified_at) VALUES ($1, $2, $3, $4, now())
         ON CONFLICT (rule_id, (COALESCE(device_id, 0))) WHERE resolved_at IS NULL DO NOTHING
         RETURNING id",
    )
    .bind(rule.id)
    .bind(device_id)
    .bind(message)
    .bind(value)
    .fetch_optional(&state.db)
    .await?;
    Ok(inserted.is_some())
}

/// Platzhalter ergänzen, im Browser anzeigen und an alle Kanäle der Regel zustellen
async fn dispatch(state: &AppState, rule: &Rule, mut n: Notification) {
    n.vars.insert("regel".into(), rule.name.clone());
    n.vars.insert(
        "zeit".into(),
        chrono::Utc::now().with_timezone(&crate::scanner::schedule::timezone()).format("%d.%m.%Y %H:%M").to_string(),
    );
    n.vars.insert("tag".into(), format!("rule-{}-{}", rule.id, n.device_id.unwrap_or(0)));
    if let Some(device_id) = n.device_id {
        let row: Option<(String, String)> =
            sqlx::query_as("SELECT COALESCE(name, reported_name, hostname, host(ip)), host(ip) FROM devices WHERE id = $1")
                .bind(device_id)
                .fetch_optional(&state.db)
                .await
                .ok()
                .flatten();
        if let Some((label, ip)) = row {
            n.vars.insert("geraet".into(), label);
            n.vars.insert("ip".into(), format!("({ip})"));
        }
    }

    // Sofort als Hinweis in allen offenen Browsern anzeigen (unabhängig von den Kanälen)
    state.hub.publish(&serde_json::json!({
        "type": "alert",
        "title": n.title,
        "message": n.message,
        "severity": n.severity.name(),
        "rule": rule.name,
        "device_id": n.device_id,
    }));
    let channels: Vec<(i64, String, String, String)> = match sqlx::query_as(
        "SELECT id, name, kind, config FROM notification_channels WHERE enabled AND id = ANY($1)",
    )
    .bind(&rule.channel_ids)
    .fetch_all(&state.db)
    .await
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Kanäle nicht ladbar: {e}");
            return;
        }
    };
    for (id, name, kind, sealed) in channels {
        match state.vault.open_value::<Value>(&sealed) {
            Ok(config) => deliver::to_channel(state, id, &name, &kind, config, &n).await,
            Err(e) => tracing::warn!("Kanal {id} ({name}) nicht lesbar: {e:#}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dauer_entfernen() {
        assert_eq!(strip_duration("NAS (10.0.0.5) ist seit 5 Min. nicht erreichbar"), "NAS (10.0.0.5) ist nicht erreichbar");
        assert_eq!(strip_duration("CPU hoch"), "CPU hoch");
    }
}
