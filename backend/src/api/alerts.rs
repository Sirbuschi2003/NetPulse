//! Benachrichtigungskanäle, Alarmregeln und ausgelöste Alarme.

use axum::{
    extract::{Path, Query, State},
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sqlx::FromRow;

use crate::{
    alerts::notify::{self, Notification, Severity},
    audit,
    auth::{AdminUser, CurrentUser},
    error::{ApiError, ApiResult},
    AppState,
};

const CHANNEL_KINDS: &[&str] = &["email", "ntfy", "gotify", "telegram", "discord", "teams", "webhook", "app"];
const RULE_KINDS: &[&str] =
    &["device_down", "new_device", "mac_changed", "disk_usage", "cpu_usage", "mem_usage", "temperature"];
const MASK: &str = "••••••";

// ---------------------------------------------------------------------------
// Kanäle
// ---------------------------------------------------------------------------

/// Geheime Felder für die Anzeige maskieren
fn masked(config: &Value) -> Value {
    let mut out = config.as_object().cloned().unwrap_or_default();
    for key in notify::SECRET_FIELDS {
        if out.get(*key).and_then(Value::as_str).is_some_and(|v| !v.is_empty()) {
            out.insert((*key).to_string(), json!(MASK));
        }
    }
    Value::Object(out)
}

async fn channel_json(st: &AppState, id: i64) -> ApiResult<Value> {
    let (name, kind, sealed, enabled): (String, String, String, bool) =
        sqlx::query_as("SELECT name, kind, config, enabled FROM notification_channels WHERE id = $1")
            .bind(id)
            .fetch_optional(&st.db)
            .await?
            .ok_or(ApiError::NotFound)?;
    let config: Value = st.vault.open_value(&sealed)?;
    Ok(json!({ "id": id, "name": name, "kind": kind, "enabled": enabled, "config": masked(&config) }))
}

pub async fn list_channels(State(st): State<AppState>, _admin: AdminUser) -> ApiResult<Json<Vec<Value>>> {
    let ids: Vec<(i64,)> = sqlx::query_as("SELECT id FROM notification_channels ORDER BY name").fetch_all(&st.db).await?;
    let mut out = Vec::new();
    for (id,) in ids {
        out.push(channel_json(&st, id).await?);
    }
    Ok(Json(out))
}

#[derive(Deserialize)]
pub struct ChannelInput {
    name: Option<String>,
    kind: Option<String>,
    enabled: Option<bool>,
    #[serde(default)]
    config: Map<String, Value>,
}

pub async fn create_channel(
    State(st): State<AppState>,
    AdminUser(user): AdminUser,
    Json(req): Json<ChannelInput>,
) -> ApiResult<Json<Value>> {
    let name = req.name.as_deref().map(str::trim).filter(|n| !n.is_empty()).unwrap_or("Kanal");
    let kind = req.kind.as_deref().unwrap_or_default();
    if !CHANNEL_KINDS.contains(&kind) {
        return Err(ApiError::BadRequest("Unbekannter Kanaltyp".into()));
    }
    let config = Value::Object(req.config);
    let (id,): (i64,) = sqlx::query_as(
        "INSERT INTO notification_channels (name, kind, config, enabled) VALUES ($1, $2, $3, $4) RETURNING id",
    )
    .bind(name)
    .bind(kind)
    .bind(st.vault.seal(&config)?)
    .bind(req.enabled.unwrap_or(true))
    .fetch_one(&st.db)
    .await?;
    audit::by(&st.db, &user, "channel_add", json!({ "id": id, "name": name, "kind": kind })).await;
    Ok(Json(channel_json(&st, id).await?))
}

pub async fn update_channel(
    State(st): State<AppState>,
    AdminUser(user): AdminUser,
    Path(id): Path<i64>,
    Json(req): Json<ChannelInput>,
) -> ApiResult<Json<Value>> {
    let (sealed,): (String,) = sqlx::query_as("SELECT config FROM notification_channels WHERE id = $1")
        .bind(id)
        .fetch_optional(&st.db)
        .await?
        .ok_or(ApiError::NotFound)?;
    let mut config: Map<String, Value> = st.vault.open_value(&sealed)?;
    for (key, value) in req.config {
        // Maskierte Werte bedeuten „unverändert lassen“
        if value.as_str() != Some(MASK) {
            config.insert(key, value);
        }
    }
    sqlx::query(
        "UPDATE notification_channels SET name = COALESCE(NULLIF(trim($2), ''), name),
                enabled = COALESCE($3, enabled), config = $4 WHERE id = $1",
    )
    .bind(id)
    .bind(&req.name)
    .bind(req.enabled)
    .bind(st.vault.seal(&Value::Object(config))?)
    .execute(&st.db)
    .await?;
    audit::by(&st.db, &user, "channel_update", json!({ "id": id })).await;
    Ok(Json(channel_json(&st, id).await?))
}

pub async fn delete_channel(
    State(st): State<AppState>,
    AdminUser(user): AdminUser,
    Path(id): Path<i64>,
) -> ApiResult<Json<Value>> {
    let (name,): (String,) = sqlx::query_as("DELETE FROM notification_channels WHERE id = $1 RETURNING name")
        .bind(id)
        .fetch_optional(&st.db)
        .await?
        .ok_or(ApiError::NotFound)?;
    sqlx::query("UPDATE alert_rules SET channel_ids = array_remove(channel_ids, $1)")
        .bind(id)
        .execute(&st.db)
        .await?;
    audit::by(&st.db, &user, "channel_delete", json!({ "id": id, "name": name })).await;
    Ok(Json(json!({ "ok": true })))
}

/// Testnachricht senden – zeigt Fehler direkt in der Oberfläche an
pub async fn test_channel(State(st): State<AppState>, _admin: AdminUser, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    let (kind, sealed): (String, String) =
        sqlx::query_as("SELECT kind, config FROM notification_channels WHERE id = $1")
            .bind(id)
            .fetch_optional(&st.db)
            .await?
            .ok_or(ApiError::NotFound)?;
    let config: Value = st.vault.open_value(&sealed)?;
    let notification = Notification {
        title: "Testnachricht von NetPulse".into(),
        message: "Wenn du das liest, funktioniert dieser Benachrichtigungskanal. 🎉".into(),
        severity: Severity::Info,
        link: st.config.public_url.clone(),
    };
    if kind == "app" {
        let message = crate::push::PushMessage {
            title: &notification.title,
            body: &notification.message,
            severity: "info",
            url: "/#/alerts",
            tag: "test",
        };
        let (ok, failed) = crate::push::send(&st, None, &message).await.map_err(|e| ApiError::BadRequest(format!("{e:#}")))?;
        if ok == 0 {
            return Err(ApiError::BadRequest(format!(
                "Kein Gerät erreicht ({failed} fehlgeschlagen) – zuerst auf dem Handy unter „Mein Konto“ Push aktivieren"
            )));
        }
        return Ok(Json(json!({ "ok": true, "sent": ok })));
    }
    notify::send(&kind, &config, &notification)
        .await
        .map_err(|e| ApiError::BadRequest(format!("Senden fehlgeschlagen: {e:#}")))?;
    Ok(Json(json!({ "ok": true })))
}

// ---------------------------------------------------------------------------
// Regeln
// ---------------------------------------------------------------------------

#[derive(Serialize, FromRow)]
pub struct RuleRow {
    id: i64,
    name: String,
    kind: String,
    device_id: Option<i64>,
    device_label: Option<String>,
    threshold: Option<f32>,
    duration_min: i32,
    channel_ids: Vec<i64>,
    notify_recovery: bool,
    enabled: bool,
}

const RULE_SELECT: &str = "SELECT r.id, r.name, r.kind, r.device_id, COALESCE(d.name, d.hostname, host(d.ip)) AS device_label,
                                  r.threshold, r.duration_min, r.channel_ids, r.notify_recovery, r.enabled
                             FROM alert_rules r LEFT JOIN devices d ON d.id = r.device_id";

pub async fn list_rules(State(st): State<AppState>, _admin: AdminUser) -> ApiResult<Json<Vec<RuleRow>>> {
    let sql = format!("{RULE_SELECT} ORDER BY r.name");
    Ok(Json(sqlx::query_as::<_, RuleRow>(&sql).fetch_all(&st.db).await?))
}

#[derive(Deserialize, Serialize)]
pub struct RuleInput {
    name: Option<String>,
    kind: Option<String>,
    device_id: Option<i64>,
    threshold: Option<f32>,
    duration_min: Option<i32>,
    channel_ids: Option<Vec<i64>>,
    notify_recovery: Option<bool>,
    enabled: Option<bool>,
}

pub async fn create_rule(
    State(st): State<AppState>,
    AdminUser(user): AdminUser,
    Json(req): Json<RuleInput>,
) -> ApiResult<Json<RuleRow>> {
    let kind = req.kind.as_deref().unwrap_or_default();
    if !RULE_KINDS.contains(&kind) {
        return Err(ApiError::BadRequest("Unbekannter Regeltyp".into()));
    }
    let needs_threshold = matches!(kind, "disk_usage" | "cpu_usage" | "mem_usage" | "temperature");
    if needs_threshold && req.threshold.is_none() {
        return Err(ApiError::BadRequest("Bitte einen Schwellwert angeben".into()));
    }
    let name = req.name.as_deref().map(str::trim).filter(|n| !n.is_empty()).unwrap_or(kind);
    let (id,): (i64,) = sqlx::query_as(
        "INSERT INTO alert_rules (name, kind, device_id, threshold, duration_min, channel_ids, notify_recovery, enabled)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id",
    )
    .bind(name)
    .bind(kind)
    .bind(req.device_id)
    .bind(req.threshold)
    .bind(req.duration_min.unwrap_or(if kind == "device_down" { 5 } else { 0 }).clamp(0, 10_080))
    .bind(req.channel_ids.clone().unwrap_or_default())
    .bind(req.notify_recovery.unwrap_or(true))
    .bind(req.enabled.unwrap_or(true))
    .fetch_one(&st.db)
    .await?;
    audit::by(&st.db, &user, "rule_add", json!({ "id": id, "rule": req })).await;
    let sql = format!("{RULE_SELECT} WHERE r.id = $1");
    Ok(Json(sqlx::query_as::<_, RuleRow>(&sql).bind(id).fetch_one(&st.db).await?))
}

pub async fn update_rule(
    State(st): State<AppState>,
    AdminUser(user): AdminUser,
    Path(id): Path<i64>,
    Json(req): Json<RuleInput>,
) -> ApiResult<Json<RuleRow>> {
    let updated = sqlx::query(
        "UPDATE alert_rules SET
            name = COALESCE(NULLIF(trim($2), ''), name),
            device_id = $3,
            threshold = COALESCE($4, threshold),
            duration_min = COALESCE($5, duration_min),
            channel_ids = COALESCE($6, channel_ids),
            notify_recovery = COALESCE($7, notify_recovery),
            enabled = COALESCE($8, enabled)
          WHERE id = $1",
    )
    .bind(id)
    .bind(&req.name)
    .bind(req.device_id)
    .bind(req.threshold)
    .bind(req.duration_min.map(|d| d.clamp(0, 10_080)))
    .bind(&req.channel_ids)
    .bind(req.notify_recovery)
    .bind(req.enabled)
    .execute(&st.db)
    .await?;
    if updated.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    audit::by(&st.db, &user, "rule_update", json!({ "id": id, "rule": req })).await;
    let sql = format!("{RULE_SELECT} WHERE r.id = $1");
    Ok(Json(sqlx::query_as::<_, RuleRow>(&sql).bind(id).fetch_one(&st.db).await?))
}

pub async fn delete_rule(
    State(st): State<AppState>,
    AdminUser(user): AdminUser,
    Path(id): Path<i64>,
) -> ApiResult<Json<Value>> {
    let (name,): (String,) = sqlx::query_as("DELETE FROM alert_rules WHERE id = $1 RETURNING name")
        .bind(id)
        .fetch_optional(&st.db)
        .await?
        .ok_or(ApiError::NotFound)?;
    audit::by(&st.db, &user, "rule_delete", json!({ "id": id, "name": name })).await;
    Ok(Json(json!({ "ok": true })))
}

// ---------------------------------------------------------------------------
// Alarme
// ---------------------------------------------------------------------------

#[derive(Serialize, FromRow)]
pub struct AlertRow {
    id: i64,
    rule_name: String,
    rule_kind: String,
    device_id: Option<i64>,
    device_label: Option<String>,
    opened_at: DateTime<Utc>,
    resolved_at: Option<DateTime<Utc>>,
    message: String,
}

#[derive(Deserialize)]
pub struct AlertQuery {
    open: Option<bool>,
    limit: Option<i64>,
}

pub async fn list_alerts(
    State(st): State<AppState>,
    _user: CurrentUser,
    Query(q): Query<AlertQuery>,
) -> ApiResult<Json<Vec<AlertRow>>> {
    let alerts = sqlx::query_as::<_, AlertRow>(
        "SELECT a.id, r.name AS rule_name, r.kind AS rule_kind, a.device_id,
                COALESCE(d.name, d.hostname, host(d.ip)) AS device_label,
                a.opened_at, a.resolved_at, a.message
           FROM alerts a JOIN alert_rules r ON r.id = a.rule_id LEFT JOIN devices d ON d.id = a.device_id
          WHERE NOT $1 OR a.resolved_at IS NULL
          ORDER BY (a.resolved_at IS NULL) DESC, a.opened_at DESC
          LIMIT $2",
    )
    .bind(q.open.unwrap_or(false))
    .bind(q.limit.unwrap_or(200).clamp(1, 1000))
    .fetch_all(&st.db)
    .await?;
    Ok(Json(alerts))
}
