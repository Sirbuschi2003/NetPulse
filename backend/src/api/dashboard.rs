//! Persönliches Dashboard-Layout. Der Aufbau der Widgets wird von der Weboberfläche
//! festgelegt, der Server speichert ihn nur (mit Größenbegrenzung).

use axum::{extract::State, Json};
use serde_json::{json, Value};

use crate::{
    auth::CurrentUser,
    error::{ApiError, ApiResult},
    AppState,
};

fn default_layout() -> Value {
    json!([
        { "type": "summary", "size": 3 },
        { "type": "internet", "size": 2 },
        { "type": "power", "size": 1 },
        { "type": "smarthome", "size": 3 },
        { "type": "alerts", "size": 1 },
        { "type": "down", "size": 1 },
        { "type": "types", "size": 1 },
        { "type": "events", "size": 2 },
        { "type": "status_chart", "size": 1 },
        { "type": "services", "size": 1 },
        { "type": "new", "size": 1 },
        { "type": "slowest", "size": 1 }
    ])
}

pub async fn load(State(st): State<AppState>, user: CurrentUser) -> ApiResult<Json<Value>> {
    let row: Option<(Value,)> = sqlx::query_as("SELECT layout FROM dashboards WHERE user_id = $1")
        .bind(user.id)
        .fetch_optional(&st.db)
        .await?;
    Ok(Json(row.map(|r| r.0).unwrap_or_else(default_layout)))
}

pub async fn save(
    State(st): State<AppState>,
    user: CurrentUser,
    Json(layout): Json<Value>,
) -> ApiResult<Json<Value>> {
    let widgets = layout
        .as_array()
        .ok_or_else(|| ApiError::BadRequest("Layout muss eine Liste von Widgets sein".into()))?;
    if widgets.len() > 50 || layout.to_string().len() > 32_000 {
        return Err(ApiError::BadRequest("Layout ist zu groß".into()));
    }
    sqlx::query(
        "INSERT INTO dashboards (user_id, layout) VALUES ($1, $2)
         ON CONFLICT (user_id) DO UPDATE SET layout = EXCLUDED.layout, updated_at = now()",
    )
    .bind(user.id)
    .bind(&layout)
    .execute(&st.db)
    .await?;
    Ok(Json(layout))
}

// ---------------------------------------------------------------------------
// Puls: kompakte Verlaufsdaten für Mini-Diagramme (Dashboard, Geräteliste, Kopfzeile)
// ---------------------------------------------------------------------------

/// Höchstens einmal pro Minute neu berechnen – die Liste wird oft und von mehreren Browsern geladen
fn pulse_cache() -> &'static std::sync::Mutex<Option<(std::time::Instant, Value)>> {
    static CACHE: std::sync::OnceLock<std::sync::Mutex<Option<(std::time::Instant, Value)>>> = std::sync::OnceLock::new();
    CACHE.get_or_init(Default::default)
}

#[derive(sqlx::FromRow)]
struct DevicePulse {
    device_id: i64,
    avail_24h: Option<f64>,
    rtt: Option<Vec<Option<f32>>>,
}

#[derive(sqlx::FromRow)]
struct HourPulse {
    hour: chrono::DateTime<chrono::Utc>,
    up_pct: Option<f64>,
    rtt_ms: Option<f64>,
}

/// Verfügbarkeit (24 h) und Antwortzeit-Verlauf (2 h, 20 Punkte) je Gerät; Verlauf des ganzen Netzes (24 h, stündlich)
pub async fn pulse(State(st): State<AppState>, _user: CurrentUser) -> ApiResult<Json<Value>> {
    if let Some((at, value)) = pulse_cache().lock().unwrap().as_ref() {
        if at.elapsed() < std::time::Duration::from_secs(60) {
            return Ok(Json(value.clone()));
        }
    }
    let devices: Vec<DevicePulse> = sqlx::query_as(
        "WITH avail AS (
             SELECT device_id, round(100.0 * avg(CASE WHEN up THEN 1 ELSE 0 END), 2)::float8 AS avail_24h
               FROM device_metrics WHERE time > now() - interval '24 hours' GROUP BY device_id
         ), buckets AS (
             SELECT device_id, time_bucket('6 minutes', time) AS b, avg(rtt_ms)::real AS rtt
               FROM device_metrics WHERE time > now() - interval '2 hours' GROUP BY device_id, b
         ), spark AS (
             SELECT device_id, array_agg(rtt ORDER BY b) AS rtt FROM buckets GROUP BY device_id
         )
         SELECT a.device_id, a.avail_24h, s.rtt FROM avail a LEFT JOIN spark s USING (device_id)",
    )
    .fetch_all(&st.db)
    .await?;
    let hours: Vec<HourPulse> = sqlx::query_as(
        "SELECT time_bucket('1 hour', m.time) AS hour,
                round(100.0 * avg(CASE WHEN m.up THEN 1 ELSE 0 END), 2)::float8 AS up_pct,
                avg(m.rtt_ms)::float8 AS rtt_ms
           FROM device_metrics m JOIN devices d ON d.id = m.device_id AND d.monitored
          WHERE m.time > now() - interval '24 hours'
          GROUP BY hour ORDER BY hour",
    )
    .fetch_all(&st.db)
    .await?;
    let (checks_total, checks_up, checks_down, checks_warn): (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT count(*) FILTER (WHERE enabled), count(*) FILTER (WHERE enabled AND status = 'up'),
                count(*) FILTER (WHERE enabled AND status = 'down'), count(*) FILTER (WHERE enabled AND status = 'warn')
           FROM checks",
    )
    .fetch_one(&st.db)
    .await?;
    let (events_24h,): (i64,) = sqlx::query_as("SELECT count(*) FROM events WHERE time > now() - interval '24 hours'")
        .fetch_one(&st.db)
        .await?;
    let total_avail = {
        let v: Vec<f64> = hours.iter().filter_map(|h| h.up_pct).collect();
        (!v.is_empty()).then(|| (v.iter().sum::<f64>() / v.len() as f64 * 100.0).round() / 100.0)
    };
    let value = json!({
        "devices": devices.iter().map(|d| (d.device_id.to_string(), json!({ "avail_24h": d.avail_24h, "rtt": d.rtt })))
            .collect::<serde_json::Map<String, Value>>(),
        "network": {
            "avail_24h": total_avail,
            "hours": hours.iter().map(|h| json!({ "t": h.hour, "up_pct": h.up_pct, "rtt_ms": h.rtt_ms })).collect::<Vec<_>>(),
        },
        "checks": { "total": checks_total, "up": checks_up, "down": checks_down, "warn": checks_warn },
        "events_24h": events_24h,
    });
    *pulse_cache().lock().unwrap() = Some((std::time::Instant::now(), value.clone()));
    Ok(Json(value))
}
