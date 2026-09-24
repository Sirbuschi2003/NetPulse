//! Geräte, Messwerte, Inventar und Ereignisse.

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
    classify,
    error::{ApiError, ApiResult},
    AppState,
};

/// `host(ip)` wandelt den PostgreSQL-Typ INET in Text ohne Netzmaske um
const DEVICE_COLUMNS: &str = "id, host(ip) AS ip, mac, hostname, name, notes, open_ports, status, status_since, \
                              last_rtt_ms, monitored, first_seen, last_seen, last_check, vendor, \
                              COALESCE(device_type, 'unknown') AS device_type, device_type_manual, os, model, \
                              inventory_at, inventory_error, wan_interface, wan_interface_manual, reported_name, integration, \
                              EXISTS (SELECT 1 FROM device_credentials dc WHERE dc.device_id = devices.id) AS has_credentials";

const EVENT_SELECT: &str = "SELECT e.id, e.time, e.device_id, \
                            COALESCE(d.name, d.reported_name, d.hostname, host(d.ip)) AS device_label, e.kind, e.message \
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
    status_since: Option<DateTime<Utc>>,
    last_rtt_ms: Option<f32>,
    monitored: bool,
    first_seen: DateTime<Utc>,
    last_seen: Option<DateTime<Utc>>,
    last_check: Option<DateTime<Utc>>,
    vendor: Option<String>,
    device_type: String,
    device_type_manual: bool,
    os: Option<String>,
    model: Option<String>,
    inventory_at: Option<DateTime<Utc>>,
    inventory_error: Option<String>,
    wan_interface: Option<String>,
    wan_interface_manual: bool,
    reported_name: Option<String>,
    integration: Option<String>,
    has_credentials: bool,
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
    let (open_alerts,): (i64,) = sqlx::query_as("SELECT count(*) FROM alerts WHERE resolved_at IS NULL")
        .fetch_one(&st.db)
        .await?;
    let wan_devices: Vec<(i64, String, String, String)> = sqlx::query_as(
        "SELECT id, COALESCE(name, reported_name, hostname, host(ip)), wan_interface, COALESCE(device_type, 'unknown')
           FROM devices WHERE wan_interface IS NOT NULL
          ORDER BY (device_type IN ('router', 'firewall')) DESC, id",
    )
    .fetch_all(&st.db)
    .await?;
    // Aktuelle Leistung aller Geräte mit Strommessung (z. B. Shelly), Messwert höchstens 15 Minuten alt
    let power: Vec<(i64, String, f32)> = sqlx::query_as(
        "SELECT DISTINCT ON (s.device_id) s.device_id, COALESCE(d.name, d.reported_name, d.hostname, host(d.ip)), s.power_w
           FROM device_stats s JOIN devices d ON d.id = s.device_id
          WHERE s.power_w IS NOT NULL AND s.time > now() - interval '15 minutes'
          ORDER BY s.device_id, s.time DESC",
    )
    .fetch_all(&st.db)
    .await?;
    let types: Vec<(String, i64)> =
        sqlx::query_as("SELECT COALESCE(device_type, 'unknown'), count(*) FROM devices GROUP BY 1 ORDER BY 2 DESC")
            .fetch_all(&st.db)
            .await?;
    Ok(Json(json!({
        "devices": counts,
        "last_discovery": last.map(|l| l.0),
        "scan": st.scan_progress.snapshot(),
        "open_alerts": open_alerts,
        "types": types.into_iter().map(|(t, n)| json!({ "type": t, "count": n })).collect::<Vec<_>>(),
        "power": power
            .into_iter()
            .map(|(id, label, watt)| json!({ "id": id, "label": label, "power_w": watt }))
            .collect::<Vec<_>>(),
        "wan_devices": wan_devices
            .into_iter()
            .map(|(id, label, iface, kind)| json!({ "id": id, "label": label, "interface": iface, "device_type": kind }))
            .collect::<Vec<_>>(),
    })))
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

#[derive(Serialize, FromRow)]
struct StatPoint {
    bucket: DateTime<Utc>,
    cpu_pct: Option<f32>,
    mem_pct: Option<f32>,
    disk_pct: Option<f32>,
    temp_c: Option<f32>,
    rx_bps: Option<f64>,
    tx_bps: Option<f64>,
    clients: Option<f32>,
    power_w: Option<f32>,
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

    let stats_bucket = bucket_minutes.max(5);
    let stats = sqlx::query_as::<_, StatPoint>(
        "SELECT time_bucket(make_interval(mins => $2), time) AS bucket,
                avg(cpu_pct)::real AS cpu_pct, avg(mem_pct)::real AS mem_pct, avg(disk_pct)::real AS disk_pct,
                avg(temp_c)::real AS temp_c, avg(rx_bps) AS rx_bps, avg(tx_bps) AS tx_bps,
                avg(clients)::real AS clients, avg(power_w)::real AS power_w
           FROM device_stats
          WHERE device_id = $1 AND time > now() - make_interval(hours => $3)
          GROUP BY bucket
          ORDER BY bucket",
    )
    .bind(id)
    .bind(stats_bucket)
    .bind(hours)
    .fetch_all(&st.db)
    .await?;

    let (inventory, ssh_host_key): (Option<Value>, Option<String>) =
        sqlx::query_as("SELECT inventory, ssh_host_key FROM devices WHERE id = $1")
            .bind(id)
            .fetch_one(&st.db)
            .await?;
    let credential_ids: Vec<(i64,)> =
        sqlx::query_as("SELECT credential_id FROM device_credentials WHERE device_id = $1")
            .bind(id)
            .fetch_all(&st.db)
            .await?;

    let sql = format!("{EVENT_SELECT} WHERE e.device_id = $1 ORDER BY e.time DESC LIMIT 50");
    let events = sqlx::query_as::<_, Event>(&sql).bind(id).fetch_all(&st.db).await?;

    Ok(Json(json!({
        "device": device,
        "points": points,
        "stats": stats,
        "inventory": inventory,
        "ssh_host_key": ssh_host_key,
        "credential_ids": credential_ids.into_iter().map(|c| c.0).collect::<Vec<_>>(),
        "events": events,
        "bucket_minutes": bucket_minutes,
    })))
}

#[derive(Deserialize, Serialize)]
pub struct DeviceUpdate {
    name: Option<String>,
    notes: Option<String>,
    monitored: Option<bool>,
    /// Gerätetyp von Hand setzen; „auto“ schaltet zurück auf automatische Erkennung
    device_type: Option<String>,
    /// Internet-Schnittstelle von Hand setzen; leerer Text = automatisch erkennen
    wan_interface: Option<String>,
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
    if let Some(kind) = req.device_type.as_deref() {
        if kind != "auto" && !classify::TYPES.contains(&kind) {
            return Err(ApiError::BadRequest(format!("Unbekannter Gerätetyp: {kind}")));
        }
    }

    // Nicht mitgeschickte Felder bleiben unverändert, leere Texte löschen den Wert
    let sql = format!(
        "UPDATE devices SET
            name      = CASE WHEN $2::text IS NULL THEN name  ELSE NULLIF(trim($2), '') END,
            notes     = CASE WHEN $3::text IS NULL THEN notes ELSE NULLIF(trim($3), '') END,
            monitored = COALESCE($4::boolean, monitored),
            status    = CASE WHEN $4::boolean = false THEN 'unknown' ELSE status END,
            status_since = CASE WHEN $4::boolean IS NOT NULL AND $4::boolean <> monitored THEN now() ELSE status_since END,
            device_type = CASE WHEN $5::text IS NULL OR $5 = 'auto' THEN device_type ELSE $5 END,
            device_type_manual = CASE WHEN $5::text IS NULL THEN device_type_manual ELSE $5 <> 'auto' END,
            wan_interface = CASE WHEN $6::text IS NULL THEN wan_interface ELSE NULLIF(trim($6), '') END,
            wan_interface_manual = CASE WHEN $6::text IS NULL THEN wan_interface_manual ELSE trim($6) <> '' END
          WHERE id = $1
          RETURNING {DEVICE_COLUMNS}"
    );
    let device = sqlx::query_as::<_, Device>(&sql)
        .bind(id)
        .bind(&req.name)
        .bind(&req.notes)
        .bind(req.monitored)
        .bind(&req.device_type)
        .bind(&req.wan_interface)
        .fetch_optional(&st.db)
        .await?
        .ok_or(ApiError::NotFound)?;

    if req.device_type.as_deref() == Some("auto") {
        crate::scanner::reclassify(&st.db, id).await?;
    }
    audit::by(&st.db, &user, "device_update", json!({ "device_id": id, "ip": device.ip, "changes": req })).await;
    if req.device_type.as_deref() == Some("auto") {
        let sql = format!("SELECT {DEVICE_COLUMNS} FROM devices WHERE id = $1");
        return Ok(Json(sqlx::query_as::<_, Device>(&sql).bind(id).fetch_one(&st.db).await?));
    }
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
pub struct CredentialAssignment {
    ids: Vec<i64>,
}

/// Zugangsdaten eines Geräts festlegen und sofort abfragen
pub async fn set_credentials(
    State(st): State<AppState>,
    AdminUser(user): AdminUser,
    Path(id): Path<i64>,
    Json(req): Json<CredentialAssignment>,
) -> ApiResult<Json<Value>> {
    let mut tx = st.db.begin().await?;
    sqlx::query("DELETE FROM device_credentials WHERE device_id = $1").bind(id).execute(&mut *tx).await?;
    sqlx::query(
        "INSERT INTO device_credentials (device_id, credential_id)
         SELECT $1, c.id FROM credentials c WHERE c.id = ANY($2) ON CONFLICT DO NOTHING",
    )
    .bind(id)
    .bind(&req.ids)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    audit::by(&st.db, &user, "device_credentials", json!({ "device_id": id, "credential_ids": req.ids })).await;
    let _ = st.poll_tx.send(id);
    Ok(Json(json!({ "ok": true })))
}

/// Tiefe Abfrage sofort starten
pub async fn poll_now(State(st): State<AppState>, _admin: AdminUser, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    let _ = st.poll_tx.send(id);
    Ok(Json(json!({ "ok": true })))
}

/// Gespeicherten SSH-Host-Schlüssel vergessen (z. B. nach Neuinstallation des Geräts)
pub async fn reset_ssh_key(
    State(st): State<AppState>,
    AdminUser(user): AdminUser,
    Path(id): Path<i64>,
) -> ApiResult<Json<Value>> {
    sqlx::query("UPDATE devices SET ssh_host_key = NULL, inventory_error = NULL WHERE id = $1")
        .bind(id)
        .execute(&st.db)
        .await?;
    audit::by(&st.db, &user, "ssh_key_reset", json!({ "device_id": id })).await;
    let _ = st.poll_tx.send(id);
    Ok(Json(json!({ "ok": true })))
}

/// Aktuelle Datenraten aller Schnittstellen (für die Live-Ansicht, alle ~2 s abgefragt)
pub async fn live(State(st): State<AppState>, _user: CurrentUser, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    crate::collect::live::live(&st, id)
        .await
        .map(Json)
        .map_err(|e| ApiError::BadRequest(format!("{e:#}")))
}

#[derive(Deserialize)]
pub struct InterfaceQuery {
    name: String,
    hours: Option<i32>,
}

#[derive(Serialize, FromRow)]
pub struct InterfacePoint {
    bucket: DateTime<Utc>,
    rx_bps: Option<f64>,
    tx_bps: Option<f64>,
}

/// Verlauf der Datenrate einer Schnittstelle
pub async fn interface_history(
    State(st): State<AppState>,
    _user: CurrentUser,
    Path(id): Path<i64>,
    Query(q): Query<InterfaceQuery>,
) -> ApiResult<Json<Vec<InterfacePoint>>> {
    let hours = q.hours.unwrap_or(24).clamp(1, 24 * 90);
    let bucket = (hours * 60 / 300).max(5);
    let points = sqlx::query_as::<_, InterfacePoint>(
        "SELECT time_bucket(make_interval(mins => $3), time) AS bucket, avg(rx_bps) AS rx_bps, avg(tx_bps) AS tx_bps
           FROM interface_stats
          WHERE device_id = $1 AND name = $2 AND time > now() - make_interval(hours => $4)
          GROUP BY bucket ORDER BY bucket",
    )
    .bind(id)
    .bind(&q.name)
    .bind(bucket)
    .bind(hours)
    .fetch_all(&st.db)
    .await?;
    Ok(Json(points))
}

#[derive(Deserialize)]
pub struct SnmpQuery {
    oid: Option<String>,
    max: Option<usize>,
}

/// SNMP-Explorer: beliebigen Teilbaum lesen, mit Namen aus den MIBs
pub async fn snmp_explorer(
    State(st): State<AppState>,
    _admin: AdminUser,
    Path(id): Path<i64>,
    Query(q): Query<SnmpQuery>,
) -> ApiResult<Json<Value>> {
    let start = q.oid.as_deref().filter(|o| !o.trim().is_empty()).unwrap_or("1.3.6.1.2.1.1");
    let base = crate::mib::resolve(&st.db, start)
        .await?
        .ok_or_else(|| ApiError::BadRequest(format!("„{start}“ ist weder eine OID noch ein bekannter MIB-Name")))?;
    let (ip,): (String,) = sqlx::query_as("SELECT host(ip) FROM devices WHERE id = $1")
        .bind(id)
        .fetch_optional(&st.db)
        .await?
        .ok_or(ApiError::NotFound)?;
    let creds = crate::collect::load_credentials(&st, id).await?;
    let cred = creds
        .iter()
        .find(|c| c.linked && c.kind.starts_with("snmp"))
        .ok_or_else(|| ApiError::BadRequest("Dem Gerät sind keine SNMP-Zugangsdaten zugeordnet".into()))?;
    let addr = ip.parse().map_err(|_| ApiError::BadRequest("Nur IPv4 wird unterstützt".into()))?;
    let max = q.max.unwrap_or(500).clamp(1, 5000);
    let mut session = crate::collect::snmp::open(addr, cred).await.map_err(|e| ApiError::BadRequest(format!("{e:#}")))?;
    let rows = crate::collect::snmp::walk(&mut session, &base, max)
        .await
        .map_err(|e| ApiError::BadRequest(format!("{e:#}")))?;
    let oids: Vec<Vec<u64>> = rows.iter().map(|(o, _)| o.clone()).collect();
    let names = crate::mib::names_for(&st.db, &oids).await?;
    let (mib_count,): (i64,) = sqlx::query_as("SELECT count(*) FROM mib_names").fetch_one(&st.db).await?;
    let rows: Vec<Value> = rows
        .iter()
        .map(|(oid, value)| {
            let (kind, text) = value.describe();
            json!({ "oid": crate::collect::snmp::dotted(oid), "name": names.get(oid), "type": kind, "value": text })
        })
        .collect();
    Ok(Json(json!({
        "base": crate::collect::snmp::dotted(&base),
        "truncated": rows.len() >= max,
        "mib_names": mib_count,
        "rows": rows,
    })))
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

async fn diagnose_view(st: &AppState, id: i64) -> ApiResult<Json<Value>> {
    type Row = (Option<Value>, Option<String>, Option<DateTime<Utc>>);
    let row: Option<Row> =
        sqlx::query_as("SELECT inventory_log, inventory_error, inventory_at FROM devices WHERE id = $1")
            .bind(id)
            .fetch_optional(&st.db)
            .await?;
    let (log, error, at) = row.ok_or(ApiError::NotFound)?;
    Ok(Json(json!({ "log": log, "error": error, "inventory_at": at })))
}

/// Protokoll der letzten tiefen Abfrage: welche Schritte wurden versucht, was ging schief
pub async fn diagnose(State(st): State<AppState>, _user: CurrentUser, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    diagnose_view(&st, id).await
}

/// Gerät sofort abfragen und das frische Protokoll zurückgeben
pub async fn diagnose_now(State(st): State<AppState>, _admin: AdminUser, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    if let Err(e) = crate::collect::poll_device(&st, id).await {
        tracing::warn!("Diagnose von Gerät {id}: {e:#}");
    }
    diagnose_view(&st, id).await
}
