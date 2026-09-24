//! Dienst-Checks verwalten und auswerten.

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
    checks,
    error::{ApiError, ApiResult},
    AppState,
};

#[derive(Serialize, FromRow)]
pub struct CheckRow {
    id: i64,
    name: String,
    kind: String,
    target: String,
    config: Value,
    interval_s: i32,
    timeout_s: i32,
    device_id: Option<i64>,
    device_label: Option<String>,
    enabled: bool,
    status: String,
    status_since: Option<DateTime<Utc>>,
    last_check: Option<DateTime<Utc>>,
    last_ms: Option<f32>,
    last_message: Option<String>,
    cert_expires_at: Option<DateTime<Utc>>,
    /// Verfügbarkeit der letzten 24 h in Prozent
    uptime_24h: Option<f64>,
    /// Die letzten 40 Ergebnisse (ältestes zuerst) für die Heartbeat-Anzeige
    beats: Option<Vec<bool>>,
}

const SELECT: &str = "SELECT c.id, c.name, c.kind, c.target, c.config, c.interval_s, c.timeout_s, c.device_id,
        COALESCE(d.name, d.reported_name, d.hostname, host(d.ip)) AS device_label, c.enabled, c.status, c.status_since,
        c.last_check, c.last_ms, c.last_message, c.cert_expires_at,
        (SELECT round(100.0 * avg(CASE WHEN ok THEN 1 ELSE 0 END), 2)::float8 FROM check_results r
          WHERE r.check_id = c.id AND r.time > now() - interval '24 hours') AS uptime_24h,
        (SELECT array_agg(ok ORDER BY time) FROM (SELECT ok, time FROM check_results r WHERE r.check_id = c.id
          ORDER BY time DESC LIMIT 40) x) AS beats
   FROM checks c LEFT JOIN devices d ON d.id = c.device_id";

pub async fn list(State(st): State<AppState>, _user: CurrentUser) -> ApiResult<Json<Vec<CheckRow>>> {
    let sql = format!("{SELECT} ORDER BY (c.status = 'down') DESC, (c.status = 'warn') DESC, c.name");
    Ok(Json(sqlx::query_as::<_, CheckRow>(&sql).fetch_all(&st.db).await?))
}

async fn one(st: &AppState, id: i64) -> ApiResult<CheckRow> {
    let sql = format!("{SELECT} WHERE c.id = $1");
    sqlx::query_as::<_, CheckRow>(&sql).bind(id).fetch_optional(&st.db).await?.ok_or(ApiError::NotFound)
}

#[derive(Deserialize, Serialize)]
pub struct CheckInput {
    name: Option<String>,
    kind: Option<String>,
    target: Option<String>,
    #[serde(default)]
    config: Option<Value>,
    interval_s: Option<i32>,
    timeout_s: Option<i32>,
    device_id: Option<i64>,
    enabled: Option<bool>,
}

fn validate(kind: &str, target: &str) -> ApiResult<()> {
    if !checks::KINDS.contains(&kind) {
        return Err(ApiError::BadRequest("Unbekannte Check-Art".into()));
    }
    let target = target.trim();
    if target.is_empty() || target.len() > 500 {
        return Err(ApiError::BadRequest("Ziel fehlt".into()));
    }
    if kind == "http" && !(target.starts_with("http://") || target.starts_with("https://")) {
        return Err(ApiError::BadRequest("URL muss mit http:// oder https:// beginnen".into()));
    }
    if kind == "tcp" && !target.contains(':') {
        return Err(ApiError::BadRequest("Bitte Host und Port angeben, z. B. 192.168.178.10:22".into()));
    }
    Ok(())
}

fn clean_config(config: Option<Value>) -> Value {
    match config {
        Some(Value::Object(map)) => Value::Object(map.into_iter().take(20).collect()),
        _ => json!({}),
    }
}

pub async fn create(State(st): State<AppState>, AdminUser(user): AdminUser, Json(req): Json<CheckInput>) -> ApiResult<Json<CheckRow>> {
    let kind = req.kind.clone().unwrap_or_default();
    let target = req.target.clone().unwrap_or_default();
    validate(&kind, &target)?;
    let name = req.name.as_deref().map(str::trim).filter(|n| !n.is_empty()).unwrap_or(target.trim()).chars().take(100).collect::<String>();
    let (id,): (i64,) = sqlx::query_as(
        "INSERT INTO checks (name, kind, target, config, interval_s, timeout_s, device_id, enabled)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id",
    )
    .bind(&name)
    .bind(&kind)
    .bind(target.trim())
    .bind(clean_config(req.config.clone()))
    .bind(req.interval_s.unwrap_or(60).clamp(10, 86_400))
    .bind(req.timeout_s.unwrap_or(10).clamp(1, 60))
    .bind(req.device_id)
    .bind(req.enabled.unwrap_or(true))
    .fetch_one(&st.db)
    .await?;
    audit::by(&st.db, &user, "check_add", json!({ "id": id, "name": name, "target": target })).await;
    Ok(Json(one(&st, id).await?))
}

pub async fn update(
    State(st): State<AppState>,
    AdminUser(user): AdminUser,
    Path(id): Path<i64>,
    Json(req): Json<CheckInput>,
) -> ApiResult<Json<CheckRow>> {
    let current = one(&st, id).await?;
    let kind = req.kind.clone().unwrap_or(current.kind);
    let target = req.target.clone().unwrap_or(current.target);
    validate(&kind, &target)?;
    sqlx::query(
        "UPDATE checks SET name = COALESCE(NULLIF(trim($2), ''), name), kind = $3, target = $4,
                config = COALESCE($5, config), interval_s = COALESCE($6, interval_s), timeout_s = COALESCE($7, timeout_s),
                device_id = $8, enabled = COALESCE($9, enabled), fail_count = 0, last_check = NULL
          WHERE id = $1",
    )
    .bind(id)
    .bind(&req.name)
    .bind(&kind)
    .bind(target.trim())
    .bind(req.config.clone().map(|c| clean_config(Some(c))))
    .bind(req.interval_s.map(|i| i.clamp(10, 86_400)))
    .bind(req.timeout_s.map(|t| t.clamp(1, 60)))
    .bind(req.device_id)
    .bind(req.enabled)
    .execute(&st.db)
    .await?;
    audit::by(&st.db, &user, "check_update", json!({ "id": id })).await;
    Ok(Json(one(&st, id).await?))
}

pub async fn remove(State(st): State<AppState>, AdminUser(user): AdminUser, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    let (name,): (String,) =
        sqlx::query_as("DELETE FROM checks WHERE id = $1 RETURNING name").bind(id).fetch_optional(&st.db).await?.ok_or(ApiError::NotFound)?;
    audit::by(&st.db, &user, "check_delete", json!({ "id": id, "name": name })).await;
    Ok(Json(json!({ "ok": true })))
}

/// Sofort prüfen und Ergebnis zurückgeben
pub async fn run_now(State(st): State<AppState>, _admin: AdminUser, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    let check: checks::Check =
        sqlx::query_as("SELECT id, name, kind, target, config, timeout_s, status, fail_count FROM checks WHERE id = $1")
            .bind(id)
            .fetch_optional(&st.db)
            .await?
            .ok_or(ApiError::NotFound)?;
    let outcome = checks::execute(&st, &check).await.map_err(|e| ApiError::BadRequest(format!("{e:#}")))?;
    Ok(Json(json!({ "outcome": outcome, "check": one(&st, id).await? })))
}

#[derive(Deserialize)]
pub struct HistoryQuery {
    hours: Option<i32>,
}

#[derive(Serialize, FromRow)]
pub struct HistoryPoint {
    bucket: DateTime<Utc>,
    ms: Option<f32>,
    availability: Option<f32>,
}

pub async fn history(
    State(st): State<AppState>,
    _user: CurrentUser,
    Path(id): Path<i64>,
    Query(q): Query<HistoryQuery>,
) -> ApiResult<Json<Value>> {
    let hours = q.hours.unwrap_or(24).clamp(1, 24 * 90);
    let bucket = (hours * 60 / 300).max(1);
    let points = sqlx::query_as::<_, HistoryPoint>(
        "SELECT time_bucket(make_interval(mins => $2), time) AS bucket, avg(ms)::real AS ms,
                avg(CASE WHEN ok THEN 1.0 ELSE 0.0 END)::real AS availability
           FROM check_results WHERE check_id = $1 AND time > now() - make_interval(hours => $3)
          GROUP BY bucket ORDER BY bucket",
    )
    .bind(id)
    .bind(bucket)
    .bind(hours)
    .fetch_all(&st.db)
    .await?;
    let uptime: Vec<(String, Option<f64>)> = sqlx::query_as(
        "SELECT p.label, (SELECT round(100.0 * avg(CASE WHEN ok THEN 1 ELSE 0 END), 3)::float8 FROM check_results
                           WHERE check_id = $1 AND time > now() - p.span)
           FROM (VALUES ('24 h', interval '24 hours'), ('7 Tage', interval '7 days'), ('30 Tage', interval '30 days')) AS p(label, span)",
    )
    .bind(id)
    .fetch_all(&st.db)
    .await?;
    Ok(Json(json!({
        "check": one(&st, id).await?,
        "points": points,
        "uptime": uptime.into_iter().map(|(label, value)| json!({ "label": label, "value": value })).collect::<Vec<_>>(),
    })))
}
