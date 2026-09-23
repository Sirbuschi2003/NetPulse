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
    auth::{self, AdminUser},
    error::{ApiError, ApiResult},
    scanner, AppState,
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
}

pub async fn list_networks(State(st): State<AppState>, _admin: AdminUser) -> ApiResult<Json<Vec<Network>>> {
    let networks = sqlx::query_as::<_, Network>(
        "SELECT id, cidr::text AS cidr, name, enabled, created_at FROM networks ORDER BY cidr",
    )
    .fetch_all(&st.db)
    .await?;
    Ok(Json(networks))
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
    let network = sqlx::query_as::<_, Network>(
        "INSERT INTO networks (cidr, name) VALUES ($1::cidr, $2)
         ON CONFLICT (cidr) DO NOTHING
         RETURNING id, cidr::text AS cidr, name, enabled, created_at",
    )
    .bind(&cidr)
    .bind(name)
    .fetch_optional(&st.db)
    .await?
    .ok_or_else(|| ApiError::BadRequest(format!("Netz {cidr} ist bereits eingetragen")))?;

    audit::by(&st.db, &user, "network_add", json!({ "cidr": cidr, "name": name })).await;
    st.scan_trigger.notify_one();
    Ok(Json(network))
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
    st.scan_trigger.notify_one();
    audit::by(&st.db, &user, "scan_trigger", json!({})).await;
    Ok(Json(json!({ "ok": true })))
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
}

pub async fn list_users(State(st): State<AppState>, _admin: AdminUser) -> ApiResult<Json<Vec<UserRow>>> {
    let users = sqlx::query_as::<_, UserRow>(
        "SELECT id, username, role, created_at, last_login FROM users ORDER BY username",
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
