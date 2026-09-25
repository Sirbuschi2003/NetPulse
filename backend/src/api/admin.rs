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
         RETURNING id, username, role, created_at, last_login, totp_enabled",
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
    // Handy verloren: auch alle Sitzungen dieses Benutzers beenden
    sqlx::query("DELETE FROM sessions WHERE user_id = $1").bind(id).execute(&st.db).await?;
    audit::by(&st.db, &admin, "totp_reset", json!({ "username": username })).await;
    Ok(Json(json!({ "ok": true })))
}

// ---------------------------------------------------------------------------
// Systemzustand (CPU, RAM, Dauer der Aufgaben)
// ---------------------------------------------------------------------------

pub async fn system(State(st): State<AppState>, _admin: AdminUser) -> ApiResult<Json<Value>> {
    let (db_mb, devices, monitored, shellys, checks): (f64, i64, i64, i64, i64) = sqlx::query_as(
        "SELECT pg_database_size(current_database())::float8 / 1048576,
                (SELECT count(*) FROM devices), (SELECT count(*) FROM devices WHERE monitored),
                (SELECT count(*) FROM devices WHERE integration = 'shelly'), (SELECT count(*) FROM checks WHERE enabled)",
    )
    .fetch_one(&st.db)
    .await?;
    let live = crate::collect::fast::load_settings(&st.db).await;
    Ok(Json(json!({
        "process": crate::perf::process(),
        "tasks": crate::perf::tasks(),
        "db_mb": (db_mb * 10.0).round() / 10.0,
        "devices": devices,
        "monitored": monitored,
        "shellys": shellys,
        "checks": checks,
        "browsers": st.hub.clients(),
        "live_interval_s": live.interval_s,
        "live_enabled": live.enabled,
        "inventory_interval_min": st.config.inventory_interval.as_secs() / 60,
        "monitor_interval_s": st.config.monitor_interval.as_secs(),
    })))
}

// ---------------------------------------------------------------------------
// Wartungsfenster
// ---------------------------------------------------------------------------

pub async fn list_maintenance(State(st): State<AppState>, _user: CurrentUser) -> ApiResult<Json<Value>> {
    let windows: Vec<crate::maintenance::Window> =
        sqlx::query_as(&format!("{} ORDER BY enabled DESC, name", crate::maintenance::SELECT)).fetch_all(&st.db).await?;
    let now = Utc::now();
    let tz = scanner::schedule::timezone();
    let list: Vec<Value> = windows
        .iter()
        .map(|w| {
            let mut v = json!(w);
            v["active"] = json!(w.active_at(now, tz));
            v
        })
        .collect();
    // Für die Oberfläche: was ist gerade in Wartung?
    let active: Vec<&crate::maintenance::Window> = windows.iter().filter(|w| w.active_at(now, tz)).collect();
    let all = active.iter().any(|w| w.device_ids.is_empty() && w.check_ids.is_empty());
    let device_ids: Vec<i64> = active.iter().flat_map(|w| w.device_ids.clone()).collect();
    let check_ids: Vec<i64> = active.iter().flat_map(|w| w.check_ids.clone()).collect();
    Ok(Json(json!({ "windows": list, "active": { "all": all, "device_ids": device_ids, "check_ids": check_ids } })))
}

#[derive(Deserialize, Serialize)]
pub struct MaintenanceInput {
    name: String,
    kind: String,
    starts_at: Option<DateTime<Utc>>,
    ends_at: Option<DateTime<Utc>>,
    #[serde(default)]
    days: Vec<i32>,
    time_from: Option<String>,
    time_to: Option<String>,
    #[serde(default)]
    device_ids: Vec<i64>,
    #[serde(default)]
    check_ids: Vec<i64>,
    enabled: Option<bool>,
}

fn validate_maintenance(m: &MaintenanceInput) -> ApiResult<()> {
    if m.name.trim().is_empty() || m.name.len() > 100 {
        return Err(ApiError::BadRequest("Bitte einen Namen angeben".into()));
    }
    match m.kind.as_str() {
        "once" => match (m.starts_at, m.ends_at) {
            (Some(a), Some(b)) if a < b => Ok(()),
            _ => Err(ApiError::BadRequest("Beginn und Ende angeben (Ende nach Beginn)".into())),
        },
        "weekly" => {
            let ok = |t: &Option<String>| t.as_deref().is_some_and(|t| chrono::NaiveTime::parse_from_str(t, "%H:%M").is_ok());
            if m.days.is_empty() || m.days.iter().any(|d| !(1..=7).contains(d)) {
                return Err(ApiError::BadRequest("Mindestens einen Wochentag wählen".into()));
            }
            if !ok(&m.time_from) || !ok(&m.time_to) {
                return Err(ApiError::BadRequest("Uhrzeiten im Format 03:00 angeben".into()));
            }
            Ok(())
        }
        _ => Err(ApiError::BadRequest("Unbekannte Art".into())),
    }
}

pub async fn create_maintenance(
    State(st): State<AppState>,
    AdminUser(user): AdminUser,
    Json(m): Json<MaintenanceInput>,
) -> ApiResult<Json<Value>> {
    validate_maintenance(&m)?;
    let (id,): (i64,) = sqlx::query_as(
        "INSERT INTO maintenance_windows (name, kind, starts_at, ends_at, days, time_from, time_to, device_ids, check_ids, enabled)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id",
    )
    .bind(m.name.trim())
    .bind(&m.kind)
    .bind(m.starts_at)
    .bind(m.ends_at)
    .bind(&m.days)
    .bind(&m.time_from)
    .bind(&m.time_to)
    .bind(&m.device_ids)
    .bind(&m.check_ids)
    .bind(m.enabled.unwrap_or(true))
    .fetch_one(&st.db)
    .await?;
    audit::by(&st.db, &user, "maintenance_add", json!({ "id": id, "window": m })).await;
    Ok(Json(json!({ "id": id })))
}

pub async fn update_maintenance(
    State(st): State<AppState>,
    AdminUser(user): AdminUser,
    Path(id): Path<i64>,
    Json(m): Json<MaintenanceInput>,
) -> ApiResult<Json<Value>> {
    validate_maintenance(&m)?;
    let done = sqlx::query(
        "UPDATE maintenance_windows SET name = $2, kind = $3, starts_at = $4, ends_at = $5, days = $6, time_from = $7,
                time_to = $8, device_ids = $9, check_ids = $10, enabled = COALESCE($11, enabled) WHERE id = $1",
    )
    .bind(id)
    .bind(m.name.trim())
    .bind(&m.kind)
    .bind(m.starts_at)
    .bind(m.ends_at)
    .bind(&m.days)
    .bind(&m.time_from)
    .bind(&m.time_to)
    .bind(&m.device_ids)
    .bind(&m.check_ids)
    .bind(m.enabled)
    .execute(&st.db)
    .await?;
    if done.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    audit::by(&st.db, &user, "maintenance_update", json!({ "id": id })).await;
    Ok(Json(json!({ "ok": true })))
}

pub async fn delete_maintenance(State(st): State<AppState>, AdminUser(user): AdminUser, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    let (name,): (String,) = sqlx::query_as("DELETE FROM maintenance_windows WHERE id = $1 RETURNING name")
        .bind(id)
        .fetch_optional(&st.db)
        .await?
        .ok_or(ApiError::NotFound)?;
    audit::by(&st.db, &user, "maintenance_delete", json!({ "id": id, "name": name })).await;
    Ok(Json(json!({ "ok": true })))
}

// ---------------------------------------------------------------------------
// Empfangene Protokolle (Syslog, SNMP-Traps)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct RemoteLogQuery {
    device: Option<i64>,
    /// höchste Schwere (0 = Notfall … 7 = Debug)
    severity: Option<i16>,
    q: Option<String>,
    /// `syslog` oder `trap`
    source: Option<String>,
    hours: Option<i32>,
    limit: Option<i64>,
}

#[derive(Serialize, FromRow)]
pub struct RemoteLog {
    time: DateTime<Utc>,
    device_id: Option<i64>,
    device_label: Option<String>,
    source: String,
    facility: i16,
    severity: i16,
    host: Option<String>,
    app: Option<String>,
    message: String,
}

pub async fn remote_logs(State(st): State<AppState>, _admin: AdminUser, Query(q): Query<RemoteLogQuery>) -> ApiResult<Json<Value>> {
    let text = q.q.as_deref().map(str::trim).filter(|t| !t.is_empty())
        .map(|t| format!("%{}%", t.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_")));
    let rows = sqlx::query_as::<_, RemoteLog>(
        "SELECT m.time, m.device_id, COALESCE(d.name, d.reported_name, d.hostname) AS device_label, host(m.source) AS source,
                m.facility, m.severity, m.host, m.app, m.message
           FROM syslog_messages m LEFT JOIN devices d ON d.id = m.device_id
          WHERE m.time > now() - make_interval(hours => $1)
            AND ($2::bigint IS NULL OR m.device_id = $2)
            AND m.severity <= $3
            AND ($4::text IS NULL OR m.message ILIKE $4 OR m.app ILIKE $4 OR m.host ILIKE $4)
            AND ($5::text IS NULL OR ($5 = 'trap') = (m.app = 'snmp-trap'))
          ORDER BY m.time DESC LIMIT $6",
    )
    .bind(q.hours.unwrap_or(24).clamp(1, 24 * 90))
    .bind(q.device)
    .bind(q.severity.unwrap_or(7))
    .bind(&text)
    .bind(q.source.as_deref().filter(|s| *s == "syslog" || *s == "trap"))
    .bind(q.limit.unwrap_or(500).clamp(1, 5000))
    .fetch_all(&st.db)
    .await?;
    let (last_hour,): (i64,) = sqlx::query_as("SELECT count(*) FROM syslog_messages WHERE time > now() - interval '1 hour'")
        .fetch_one(&st.db)
        .await?;
    Ok(Json(json!({
        "items": rows,
        "last_hour": last_hour,
        "syslog_port": st.config.syslog_port,
        "trap_port": st.config.trap_port,
    })))
}

/// Alle Sitzungen eines Benutzers beenden (z. B. Handy verloren)
pub async fn end_user_sessions(State(st): State<AppState>, AdminUser(admin): AdminUser, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    let done = sqlx::query("DELETE FROM sessions WHERE user_id = $1").bind(id).execute(&st.db).await?;
    audit::by(&st.db, &admin, "sessions_revoked", json!({ "user_id": id, "count": done.rows_affected() })).await;
    Ok(Json(json!({ "ended": done.rows_affected() })))
}

// ---------------------------------------------------------------------------
// Sicherheit: 2FA-Pflicht
// ---------------------------------------------------------------------------

pub async fn get_security(State(st): State<AppState>, _admin: AdminUser) -> ApiResult<Json<Value>> {
    let (without,): (i64,) = sqlx::query_as("SELECT count(*) FROM users WHERE NOT totp_enabled").fetch_one(&st.db).await?;
    Ok(Json(json!({
        "require_totp": crate::auth::totp_required(&st).await,
        "forced_by_env": st.config.require_totp,
        "users_without_totp": without,
    })))
}

#[derive(Deserialize)]
pub struct SecuritySettings {
    require_totp: bool,
}

pub async fn set_security(
    State(st): State<AppState>,
    AdminUser(user): AdminUser,
    Json(req): Json<SecuritySettings>,
) -> ApiResult<Json<Value>> {
    if st.config.require_totp && !req.require_totp {
        return Err(ApiError::BadRequest("Die 2FA-Pflicht ist über REQUIRE_TOTP fest eingeschaltet".into()));
    }
    if req.require_totp {
        // Nicht aussperren: Wer die Pflicht einschaltet, muss 2FA selbst schon nutzen
        let (own,): (bool,) = sqlx::query_as("SELECT totp_enabled FROM users WHERE id = $1").bind(user.id).fetch_one(&st.db).await?;
        if !own {
            return Err(ApiError::BadRequest("Bitte zuerst für dein eigenes Konto 2FA einrichten (Mein Konto)".into()));
        }
    }
    sqlx::query(
        "INSERT INTO settings (key, value) VALUES ('security', jsonb_build_object('require_totp', $1::bool))
         ON CONFLICT (key) DO UPDATE SET value = settings.value || EXCLUDED.value",
    )
    .bind(req.require_totp)
    .execute(&st.db)
    .await?;
    audit::by(&st.db, &user, "security_settings", json!({ "require_totp": req.require_totp })).await;
    get_security(State(st), AdminUser(user)).await
}
