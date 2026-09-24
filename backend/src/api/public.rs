//! Öffentliche Statusseite und Netzwerkkarte.
//!
//! Die Statusseite ist ohne Anmeldung über einen geheimen Link erreichbar (`/status.html#<token>`).
//! Sie zeigt nur, was ausdrücklich freigegeben wurde – Anzeigename, Status und Verfügbarkeit,
//! keine IP-Adressen oder sonstigen Details.

use axum::{
    extract::{Path, State},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    audit,
    auth::{self, AdminUser, CurrentUser},
    error::{ApiError, ApiResult},
    AppState,
};

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct StatusItem {
    /// `device` oder `check`
    kind: String,
    id: i64,
    /// Eigener Anzeigename (sonst Name des Geräts/Dienstes)
    #[serde(default)]
    label: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct StatusPage {
    enabled: bool,
    title: String,
    #[serde(default)]
    description: String,
    token: String,
    items: Vec<StatusItem>,
}

async fn load(st: &AppState) -> StatusPage {
    let row: Option<(Value,)> =
        sqlx::query_as("SELECT value FROM settings WHERE key = 'status_page'").fetch_optional(&st.db).await.ok().flatten();
    row.and_then(|(v,)| serde_json::from_value(v).ok()).unwrap_or_else(|| StatusPage {
        enabled: false,
        title: "Status".into(),
        description: String::new(),
        token: auth::random_token(24),
        items: vec![],
    })
}

async fn save(st: &AppState, page: &StatusPage) -> sqlx::Result<()> {
    sqlx::query("INSERT INTO settings (key, value) VALUES ('status_page', $1) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value")
        .bind(json!(page))
        .execute(&st.db)
        .await?;
    Ok(())
}

pub async fn get_config(State(st): State<AppState>, _admin: AdminUser) -> Json<StatusPage> {
    Json(load(&st).await)
}

#[derive(Deserialize)]
pub struct StatusInput {
    enabled: bool,
    title: String,
    #[serde(default)]
    description: String,
    items: Vec<StatusItem>,
    /// Neuen geheimen Link erzeugen (alter Link funktioniert dann nicht mehr)
    #[serde(default)]
    new_token: bool,
}

pub async fn set_config(State(st): State<AppState>, AdminUser(user): AdminUser, Json(req): Json<StatusInput>) -> ApiResult<Json<StatusPage>> {
    if req.items.len() > 100 || req.items.iter().any(|i| !matches!(i.kind.as_str(), "device" | "check")) {
        return Err(ApiError::BadRequest("Ungültige Einträge".into()));
    }
    let mut page = load(&st).await;
    page.enabled = req.enabled;
    page.title = req.title.trim().chars().take(80).collect();
    page.description = req.description.trim().chars().take(500).collect();
    page.items = req
        .items
        .into_iter()
        .map(|mut i| {
            i.label = i.label.map(|l| l.trim().chars().take(80).collect::<String>()).filter(|l| !l.is_empty());
            i
        })
        .collect();
    if req.new_token || page.token.len() < 20 {
        page.token = auth::random_token(24);
    }
    save(&st, &page).await?;
    audit::by(&st.db, &user, "status_page", json!({ "enabled": page.enabled, "items": page.items.len() })).await;
    Ok(Json(page))
}

/// Öffentlich: Status der freigegebenen Einträge
pub async fn public_status(State(st): State<AppState>, Path(token): Path<String>) -> ApiResult<Json<Value>> {
    let page = load(&st).await;
    // Vergleich in konstanter Zeit ist hier nicht nötig (Token ist lang und zufällig), aber keine Hinweise geben
    if !page.enabled || token.len() < 20 || token != page.token {
        return Err(ApiError::NotFound);
    }
    let mut items = Vec::new();
    for item in &page.items {
        type Row = (String, String, Option<f64>, Option<Vec<Option<f64>>>);
        let row: Option<Row> = if item.kind == "device" {
            sqlx::query_as(
                "SELECT COALESCE(d.name, d.reported_name, d.hostname, 'Gerät'),
                        CASE WHEN NOT d.monitored THEN 'unknown' ELSE d.status END,
                        (SELECT round(100.0 * avg(CASE WHEN up THEN 1 ELSE 0 END), 2)::float8 FROM device_metrics
                          WHERE device_id = d.id AND time > now() - interval '30 days'),
                        (SELECT array_agg(a ORDER BY day) FROM (
                           SELECT g.day, (SELECT round(100.0 * avg(CASE WHEN up THEN 1 ELSE 0 END), 2)::float8 FROM device_metrics m
                                            WHERE m.device_id = d.id AND m.time >= g.day AND m.time < g.day + interval '1 day') AS a
                             FROM generate_series(date_trunc('day', now()) - interval '29 days', date_trunc('day', now()), interval '1 day') AS g(day)) x)
                   FROM devices d WHERE d.id = $1",
            )
        } else {
            sqlx::query_as(
                "SELECT c.name, CASE WHEN NOT c.enabled THEN 'unknown' ELSE c.status END,
                        (SELECT round(100.0 * avg(CASE WHEN ok THEN 1 ELSE 0 END), 2)::float8 FROM check_results
                          WHERE check_id = c.id AND time > now() - interval '30 days'),
                        (SELECT array_agg(a ORDER BY day) FROM (
                           SELECT g.day, (SELECT round(100.0 * avg(CASE WHEN ok THEN 1 ELSE 0 END), 2)::float8 FROM check_results r
                                            WHERE r.check_id = c.id AND r.time >= g.day AND r.time < g.day + interval '1 day') AS a
                             FROM generate_series(date_trunc('day', now()) - interval '29 days', date_trunc('day', now()), interval '1 day') AS g(day)) x)
                   FROM checks c WHERE c.id = $1",
            )
        }
        .bind(item.id)
        .fetch_optional(&st.db)
        .await?;
        if let Some((name, status, uptime, days)) = row {
            let status = match status.as_str() {
                "up" => "ok",
                "warn" => "degraded",
                "down" => "down",
                _ => "unknown",
            };
            items.push(json!({ "name": item.label.clone().unwrap_or(name), "status": status, "uptime_30d": uptime, "days": days }));
        }
    }
    let down = items.iter().filter(|i| i["status"] == "down").count();
    let degraded = items.iter().filter(|i| i["status"] == "degraded").count();
    let overall = if down > 0 { "down" } else if degraded > 0 { "degraded" } else { "ok" };
    Ok(Json(json!({
        "title": page.title,
        "description": page.description,
        "overall": overall,
        "items": items,
        "updated": chrono::Utc::now(),
    })))
}

// ---------------------------------------------------------------------------
// Netzwerkkarte
// ---------------------------------------------------------------------------

#[derive(Serialize, sqlx::FromRow)]
pub struct Node {
    id: i64,
    label: String,
    ip: String,
    device_type: String,
    status: String,
    monitored: bool,
    parent_id: Option<i64>,
    parent_manual: bool,
    wan: bool,
}

pub async fn topology(State(st): State<AppState>, _user: CurrentUser) -> ApiResult<Json<Vec<Node>>> {
    let nodes = sqlx::query_as::<_, Node>(
        "SELECT id, COALESCE(name, reported_name, hostname, host(ip)) AS label, host(ip) AS ip,
                COALESCE(device_type, 'unknown') AS device_type, status, monitored, parent_id, parent_manual,
                wan_interface IS NOT NULL AS wan
           FROM devices ORDER BY ip",
    )
    .fetch_all(&st.db)
    .await?;
    Ok(Json(nodes))
}
