//! Geräte, Messwerte und Ereignisse.

use axum::{
    extract::{Path, Query, State},
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::FromRow;

use crate::{
    audit,
    auth::{AdminUser, CurrentUser},
    error::{ApiError, ApiResult},
    AppState,
};

/// `host(ip)` wandelt den PostgreSQL-Typ INET in Text ohne Netzmaske um
const DEVICE_COLUMNS: &str = "id, host(ip) AS ip, mac, hostname, name, notes, open_ports, status, \
                              last_rtt_ms, monitored, first_seen, last_seen, last_check";

const EVENT_SELECT: &str = "SELECT e.id, e.time, e.device_id, \
                            COALESCE(d.name, d.hostname, host(d.ip)) AS device_label, e.kind, e.message \
                            FROM events e LEFT JOIN devices d ON d.id = e.device_id";

#[derive(Serialize, FromRow)]
pub struct Device {
    id: i64,
    ip: String,
    mac: Option<String>,
    hostname: Option<String>,
    name: Option<String>,
    notes: Option<String>,
    open_ports: Vec<i32>,
    status: String,
    last_rtt_ms: Option<f32>,
    monitored: bool,
    first_seen: DateTime<Utc>,
    last_seen: Option<DateTime<Utc>>,
    last_check: Option<DateTime<Utc>>,
}

#[derive(Serialize, FromRow)]
pub struct Event {
    id: i64,
    time: DateTime<Utc>,
    device_id: Option<i64>,
    device_label: Option<String>,
    kind: String,
    message: String,
}

#[derive(Serialize, FromRow)]
struct Summary {
    total: i64,
    up: i64,
    down: i64,
    unknown: i64,
    unmonitored: i64,
    new_24h: i64,
}

pub async fn summary(State(st): State<AppState>, _user: CurrentUser) -> ApiResult<Json<Value>> {
    let counts: Summary = sqlx::query_as(
        "SELECT count(*) AS total,
                count(*) FILTER (WHERE monitored AND status = 'up')      AS up,
                count(*) FILTER (WHERE monitored AND status = 'down')    AS down,
                count(*) FILTER (WHERE monitored AND status = 'unknown') AS unknown,
                count(*) FILTER (WHERE NOT monitored)                    AS unmonitored,
                count(*) FILTER (WHERE first_seen > now() - interval '24 hours') AS new_24h
           FROM devices",
    )
    .fetch_one(&st.db)
    .await?;
    let last: Option<(Value,)> = sqlx::query_as("SELECT value FROM settings WHERE key = 'last_discovery'")
        .fetch_optional(&st.db)
        .await?;
    Ok(Json(json!({ "devices": counts, "last_discovery": last.map(|l| l.0) })))
}

pub async fn list(State(st): State<AppState>, _user: CurrentUser) -> ApiResult<Json<Vec<Device>>> {
    let sql = format!("SELECT {DEVICE_COLUMNS} FROM devices ORDER BY ip");
    let devices = sqlx::query_as::<_, Device>(&sql).fetch_all(&st.db).await?;
    Ok(Json(devices))
}

#[derive(Deserialize)]
pub struct RangeQuery {
    hours: Option<i32>,
}

#[derive(Serialize, FromRow)]
struct MetricPoint {
    bucket: DateTime<Utc>,
    rtt_ms: Option<f32>,
    /// Anteil erfolgreicher Prüfungen im Zeitfenster (0.0 – 1.0)
    availability: Option<f32>,
}

pub async fn detail(
    State(st): State<AppState>,
    _user: CurrentUser,
    Path(id): Path<i64>,
    Query(q): Query<RangeQuery>,
) -> ApiResult<Json<Value>> {
    let hours = q.hours.unwrap_or(24).clamp(1, 24 * 90);
    let sql = format!("SELECT {DEVICE_COLUMNS} FROM devices WHERE id = $1");
    let device = sqlx::query_as::<_, Device>(&sql)
        .bind(id)
        .fetch_optional(&st.db)
        .await?
        .ok_or(ApiError::NotFound)?;

    // Zeitfenster so zusammenfassen, dass ca. 300 Punkte im Diagramm landen
    let bucket_minutes = (hours * 60 / 300).max(1);
    let points = sqlx::query_as::<_, MetricPoint>(
        "SELECT time_bucket(make_interval(mins => $2), time) AS bucket,
                avg(rtt_ms)::real AS rtt_ms,
                avg(CASE WHEN up THEN 1.0 ELSE 0.0 END)::real AS availability
           FROM device_metrics
          WHERE device_id = $1 AND time > now() - make_interval(hours => $3)
          GROUP BY bucket
          ORDER BY bucket",
    )
    .bind(id)
    .bind(bucket_minutes)
    .bind(hours)
    .fetch_all(&st.db)
    .await?;

    let sql = format!("{EVENT_SELECT} WHERE e.device_id = $1 ORDER BY e.time DESC LIMIT 50");
    let events = sqlx::query_as::<_, Event>(&sql).bind(id).fetch_all(&st.db).await?;

    Ok(Json(json!({
        "device": device,
        "points": points,
        "events": events,
        "bucket_minutes": bucket_minutes,
    })))
}

#[derive(Deserialize, Serialize)]
pub struct DeviceUpdate {
    name: Option<String>,
    notes: Option<String>,
    monitored: Option<bool>,
}

pub async fn update(
    State(st): State<AppState>,
    AdminUser(user): AdminUser,
    Path(id): Path<i64>,
    Json(req): Json<DeviceUpdate>,
) -> ApiResult<Json<Device>> {
    if req.name.as_deref().is_some_and(|n| n.chars().count() > 200) {
        return Err(ApiError::BadRequest("Name darf höchstens 200 Zeichen haben".into()));
    }
    if req.notes.as_deref().is_some_and(|n| n.chars().count() > 5000) {
        return Err(ApiError::BadRequest("Notizen dürfen höchstens 5000 Zeichen haben".into()));
    }

    // Nicht mitgeschickte Felder bleiben unverändert, leere Texte löschen den Wert
    let sql = format!(
        "UPDATE devices SET
            name      = CASE WHEN $2::text IS NULL THEN name  ELSE NULLIF(trim($2), '') END,
            notes     = CASE WHEN $3::text IS NULL THEN notes ELSE NULLIF(trim($3), '') END,
            monitored = COALESCE($4::boolean, monitored),
            status    = CASE WHEN $4::boolean = false THEN 'unknown' ELSE status END
          WHERE id = $1
          RETURNING {DEVICE_COLUMNS}"
    );
    let device = sqlx::query_as::<_, Device>(&sql)
        .bind(id)
        .bind(&req.name)
        .bind(&req.notes)
        .bind(req.monitored)
        .fetch_optional(&st.db)
        .await?
        .ok_or(ApiError::NotFound)?;

    audit::by(&st.db, &user, "device_update", json!({ "device_id": id, "ip": device.ip, "changes": req })).await;
    Ok(Json(device))
}

pub async fn remove(
    State(st): State<AppState>,
    AdminUser(user): AdminUser,
    Path(id): Path<i64>,
) -> ApiResult<Json<Value>> {
    let (ip,): (String,) = sqlx::query_as("DELETE FROM devices WHERE id = $1 RETURNING host(ip)")
        .bind(id)
        .fetch_optional(&st.db)
        .await?
        .ok_or(ApiError::NotFound)?;
    audit::by(&st.db, &user, "device_delete", json!({ "device_id": id, "ip": ip })).await;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
pub struct EventQuery {
    limit: Option<i64>,
}

pub async fn events(
    State(st): State<AppState>,
    _user: CurrentUser,
    Query(q): Query<EventQuery>,
) -> ApiResult<Json<Vec<Event>>> {
    let limit = q.limit.unwrap_or(100).clamp(1, 500);
    let sql = format!("{EVENT_SELECT} ORDER BY e.time DESC LIMIT $1");
    let events = sqlx::query_as::<_, Event>(&sql).bind(limit).fetch_all(&st.db).await?;
    Ok(Json(events))
}
