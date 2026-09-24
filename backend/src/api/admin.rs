//! Verwaltung: Netze, Scans, Benutzer, Audit-Log. Alles hier erfordert die Rolle „admin“.

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
    auth::{self, AdminUser, CurrentUser},
    error::{ApiError, ApiResult},
    scanner::{self, ScanRequest},
    AppState,
};

// ---------------------------------------------------------------------------
// Netze
// ---------------------------------------------------------------------------

#[derive(Serialize, FromRow)]
pub struct Network {
    id: i64,
    cidr: String,
    name: String,
    enabled: bool,
    created_at: DateTime<Utc>,
    last_scan_at: Option<DateTime<Utc>>,
    last_scan_found: Option<i32>,
    last_scan_duration_s: Option<i32>,
    device_count: i64,
}

const NETWORK_SELECT: &str = "SELECT n.id, n.cidr::text AS cidr, n.name, n.enabled, n.created_at,
                                     n.last_scan_at, n.last_scan_found, n.last_scan_duration_s,
                                     (SELECT count(*) FROM devices d WHERE d.ip << n.cidr) AS device_count
                                FROM networks n";

pub async fn list_networks(State(st): State<AppState>, _admin: AdminUser) -> ApiResult<Json<Vec<Network>>> {
    let sql = format!("{NETWORK_SELECT} ORDER BY n.cidr");
    Ok(Json(sqlx::query_as::<_, Network>(&sql).fetch_all(&st.db).await?))
}

#[derive(Deserialize)]
pub struct NewNetwork {
    cidr: String,
    name: String,
}

pub async fn add_network(
    State(st): State<AppState>,
    AdminUser(user): AdminUser,
    Json(req): Json<NewNetwork>,
) -> ApiResult<Json<Network>> {
    let (addr, prefix) =
        scanner::net::parse_cidr(&req.cidr).map_err(|e| ApiError::BadRequest(e.to_string()))?;
    let name = req.name.trim();
    if name.is_empty() || name.chars().count() > 100 {
        return Err(ApiError::BadRequest("Bitte einen Namen (max. 100 Zeichen) angeben".into()));
    }
    let cidr = format!("{addr}/{prefix}");
    let (id,): (i64,) = sqlx::query_as(
        "INSERT INTO networks (cidr, name) VALUES ($1::cidr, $2) ON CONFLICT (cidr) DO NOTHING RETURNING id",
    )
    .bind(&cidr)
    .bind(name)
    .fetch_optional(&st.db)
    .await?
    .ok_or_else(|| ApiError::BadRequest(format!("Netz {cidr} ist bereits eingetragen")))?;

    audit::by(&st.db, &user, "network_add", json!({ "cidr": cidr, "name": name })).await;
    // Neues Netz sofort scannen – hat Vorrang vor einem laufenden Durchlauf
    let _ = st.scan_tx.send(ScanRequest::Network(id));
    let sql = format!("{NETWORK_SELECT} WHERE n.id = $1");
    Ok(Json(sqlx::query_as::<_, Network>(&sql).bind(id).fetch_one(&st.db).await?))
}

pub async fn delete_network(
    State(st): State<AppState>,
    AdminUser(user): AdminUser,
    Path(id): Path<i64>,
) -> ApiResult<Json<Value>> {
    let (cidr,): (String,) = sqlx::query_as("DELETE FROM networks WHERE id = $1 RETURNING cidr::text")
        .bind(id)
        .fetch_optional(&st.db)
        .await?
        .ok_or(ApiError::NotFound)?;
    audit::by(&st.db, &user, "network_delete", json!({ "cidr": cidr })).await;
    Ok(Json(json!({ "ok": true })))
}

pub async fn trigger_scan(State(st): State<AppState>, AdminUser(user): AdminUser) -> ApiResult<Json<Value>> {
    let _ = st.scan_tx.send(ScanRequest::All);
    audit::by(&st.db, &user, "scan_trigger", json!({})).await;
    Ok(Json(json!({ "ok": true })))
}

pub async fn scan_network(
    State(st): State<AppState>,
    AdminUser(user): AdminUser,
    Path(id): Path<i64>,
) -> ApiResult<Json<Value>> {
    let _ = st.scan_tx.send(ScanRequest::Network(id));
    audit::by(&st.db, &user, "scan_trigger", json!({ "network_id": id })).await;
    Ok(Json(json!({ "ok": true })))
}

pub async fn scan_status(State(st): State<AppState>, _user: CurrentUser) -> Json<Value> {
    Json(st.scan_progress.snapshot())
}

// ---------------------------------------------------------------------------
// Benutzer
// ---------------------------------------------------------------------------

#[derive(Serialize, FromRow)]
pub struct UserRow {
    id: i64,
    username: String,
    role: String,
    created_at: DateTime<Utc>,
    last_login: Option<DateTime<Utc>>,
    totp_enabled: bool,
}

pub async fn list_users(State(st): State<AppState>, _admin: AdminUser) -> ApiResult<Json<Vec<UserRow>>> {
    let users = sqlx::query_as::<_, UserRow>(
        "SELECT id, username, role, created_at, last_login, totp_enabled FROM users ORDER BY username",
    )
    .fetch_all(&st.db)
    .await?;
    Ok(Json(users))
}

#[derive(Deserialize)]
pub struct NewUser {
    username: String,
    password: String,
    role: String,
}

pub async fn add_user(
    State(st): State<AppState>,
    AdminUser(admin): AdminUser,
    Json(req): Json<NewUser>,
) -> ApiResult<Json<UserRow>> {
    let username = req.username.trim().to_lowercase();
    let valid_name = (3..=32).contains(&username.len())
        && username.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c));
    if !valid_name {
        return Err(ApiError::BadRequest(
            "Benutzername: 3–32 Zeichen, erlaubt sind a–z, 0–9, Punkt, Minus, Unterstrich".into(),
        ));
    }
    if req.role != "admin" && req.role != "viewer" {
        return Err(ApiError::BadRequest("Rolle muss 'admin' oder 'viewer' sein".into()));
    }
    auth::validate_password(&req.password).map_err(ApiError::BadRequest)?;

    let hash = auth::hash_password(req.password).await?;
    let user = sqlx::query_as::<_, UserRow>(
        "INSERT INTO users (username, password_hash, role) VALUES ($1, $2, $3)
         ON CONFLICT (username) DO NOTHING
         RETURNING id, username, role, created_at, last_login",
    )
    .bind(&username)
    .bind(hash)
    .bind(&req.role)
    .fetch_optional(&st.db)
    .await?
    .ok_or_else(|| ApiError::BadRequest(format!("Benutzer '{username}' existiert bereits")))?;

    audit::by(&st.db, &admin, "user_add", json!({ "username": username, "role": req.role })).await;
    Ok(Json(user))
}

pub async fn delete_user(
    State(st): State<AppState>,
    AdminUser(admin): AdminUser,
    Path(id): Path<i64>,
) -> ApiResult<Json<Value>> {
    if id == admin.id {
        return Err(ApiError::BadRequest("Das eigene Konto kann nicht gelöscht werden".into()));
    }
    // Sicherstellen, dass immer mindestens ein Admin übrig bleibt
    let target: (String, String) = sqlx::query_as("SELECT username, role FROM users WHERE id = $1")
        .bind(id)
        .fetch_optional(&st.db)
        .await?
        .ok_or(ApiError::NotFound)?;
    if target.1 == "admin" {
        let (admins,): (i64,) = sqlx::query_as("SELECT count(*) FROM users WHERE role = 'admin'")
            .fetch_one(&st.db)
            .await?;
        if admins <= 1 {
            return Err(ApiError::BadRequest("Der letzte Admin kann nicht gelöscht werden".into()));
        }
    }
    sqlx::query("DELETE FROM users WHERE id = $1").bind(id).execute(&st.db).await?;
    audit::by(&st.db, &admin, "user_delete", json!({ "username": target.0 })).await;
    Ok(Json(json!({ "ok": true })))
}

// ---------------------------------------------------------------------------
// Audit-Log
// ---------------------------------------------------------------------------

#[derive(Serialize, FromRow)]
pub struct AuditEntry {
    id: i64,
    time: DateTime<Utc>,
    username: Option<String>,
    action: String,
    detail: Value,
}

#[derive(Deserialize)]
pub struct AuditQuery {
    limit: Option<i64>,
}

pub async fn audit_log(
    State(st): State<AppState>,
    _admin: AdminUser,
    Query(q): Query<AuditQuery>,
) -> ApiResult<Json<Vec<AuditEntry>>> {
    let limit = q.limit.unwrap_or(200).clamp(1, 1000);
    let entries = sqlx::query_as::<_, AuditEntry>(
        "SELECT id, time, username, action, detail FROM audit_log ORDER BY time DESC LIMIT $1",
    )
    .bind(limit)
    .fetch_all(&st.db)
    .await?;
    Ok(Json(entries))
}

// ---------------------------------------------------------------------------
// Zeitplan der Geräte-Suche
// ---------------------------------------------------------------------------

async fn discovery_view(st: &AppState) -> Value {
    use scanner::schedule;
    let plan = schedule::load(&st.db, &st.config).await;
    let last = schedule::last_full_scan(&st.db).await;
    let tz = schedule::timezone();
    let next = schedule::next_due(&plan, last, Utc::now(), tz);
    json!({ "schedule": plan, "last_run": last, "next_run": next, "timezone": tz.name() })
}

pub async fn get_discovery(State(st): State<AppState>, _admin: AdminUser) -> Json<Value> {
    Json(discovery_view(&st).await)
}

pub async fn set_discovery(
    State(st): State<AppState>,
    AdminUser(user): AdminUser,
    Json(mut plan): Json<scanner::schedule::Schedule>,
) -> ApiResult<Json<Value>> {
    plan.times = plan.times.iter().map(|t| t.trim().to_string()).filter(|t| !t.is_empty()).collect();
    plan.times.sort();
    plan.times.dedup();
    plan.validate().map_err(ApiError::BadRequest)?;
    scanner::schedule::save(&st.db, &plan).await?;
    audit::by(&st.db, &user, "discovery_schedule", json!(plan)).await;
    Ok(Json(discovery_view(&st).await))
}

// ---------------------------------------------------------------------------
// System-Log (die letzten Meldungen aus dem Speicher)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct LogQuery {
    level: Option<String>,
    q: Option<String>,
    limit: Option<usize>,
}

pub async fn system_log(_admin: AdminUser, Query(q): Query<LogQuery>) -> Json<Vec<crate::logbuf::LogLine>> {
    Json(crate::logbuf::recent(
        q.level.as_deref().unwrap_or("info"),
        q.q.as_deref().unwrap_or("").trim(),
        q.limit.unwrap_or(500).clamp(1, 5000),
    ))
}

// ---------------------------------------------------------------------------
// Echtzeit-Abfrage
// ---------------------------------------------------------------------------

pub async fn get_live(State(st): State<AppState>, _user: CurrentUser) -> Json<crate::collect::fast::LiveSettings> {
    Json(crate::collect::fast::load_settings(&st.db).await)
}

pub async fn set_live(
    State(st): State<AppState>,
    AdminUser(user): AdminUser,
    Json(settings): Json<crate::collect::fast::LiveSettings>,
) -> ApiResult<Json<crate::collect::fast::LiveSettings>> {
    settings.validate().map_err(ApiError::BadRequest)?;
    crate::collect::fast::save_settings(&st.db, &settings).await?;
    audit::by(&st.db, &user, "live_settings", json!(settings)).await;
    Ok(Json(settings))
}

/// Zwei-Faktor-Anmeldung eines Benutzers zurücksetzen (z. B. Handy verloren)
pub async fn reset_totp(State(st): State<AppState>, AdminUser(admin): AdminUser, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    let target: Option<(String,)> = sqlx::query_as(
        "UPDATE users SET totp_enabled = false, totp_secret = NULL, totp_last_step = NULL WHERE id = $1 RETURNING username",
    )
    .bind(id)
    .fetch_optional(&st.db)
    .await?;
    let (username,) = target.ok_or(ApiError::NotFound)?;
    audit::by(&st.db, &admin, "totp_reset", json!({ "username": username })).await;
    Ok(Json(json!({ "ok": true })))
}
