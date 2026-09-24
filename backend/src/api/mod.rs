//! REST-API unter `/api/…` und Auslieferung der Weboberfläche.

mod admin;
mod alerts;
mod checks;
mod credentials;
mod dashboard;
mod devices;
mod session;
mod stream;

use axum::{
    extract::State,
    http::{header, HeaderValue, StatusCode},
    middleware,
    routing::{delete, get, post, put},
    Router,
};
use tower_http::{services::ServeDir, set_header::SetResponseHeaderLayer, trace::TraceLayer};

use crate::{auth, AppState};

pub fn router(state: AppState) -> Router {
    let api = Router::new()
        // Anmeldung
        .route("/login", post(session::login))
        .route("/logout", post(session::logout))
        .route("/me", get(session::me))
        .route("/me/password", post(session::change_password))
        .route("/me/totp", get(session::totp_status))
        .route("/me/totp/setup", post(session::totp_setup))
        .route("/me/totp/enable", post(session::totp_enable))
        .route("/me/totp/disable", post(session::totp_disable))
        .route("/push/key", get(session::push_key))
        .route("/push/subscribe", post(session::push_subscribe))
        .route("/push/unsubscribe", post(session::push_unsubscribe))
        .route("/push/devices", get(session::push_devices))
        .route("/push/test", post(session::push_test))
        // Geräte & Status
        .route("/summary", get(devices::summary))
        .route("/devices", get(devices::list))
        .route("/devices/{id}", get(devices::detail).patch(devices::update).delete(devices::remove))
        .route("/devices/{id}/credentials", put(devices::set_credentials))
        .route("/devices/{id}/poll", post(devices::poll_now))
        .route("/devices/{id}/diagnose", get(devices::diagnose).post(devices::diagnose_now))
        .route("/devices/{id}/ssh-key", delete(devices::reset_ssh_key))
        .route("/devices/{id}/live", get(devices::live))
        .route("/devices/{id}/interfaces/history", get(devices::interface_history))
        .route("/devices/{id}/snmp", get(devices::snmp_explorer))
        .route("/events", get(devices::events))
        .route("/checks", get(checks::list).post(checks::create))
        .route("/checks/{id}", axum::routing::patch(checks::update).delete(checks::remove))
        .route("/checks/{id}/run", post(checks::run_now))
        .route("/checks/{id}/history", get(checks::history))
        .route("/alerts", get(alerts::list_alerts))
        // Dashboard (pro Benutzer)
        .route("/dashboard", get(dashboard::load).put(dashboard::save))
        // Netze & Scans
        .route("/networks", get(admin::list_networks).post(admin::add_network))
        .route("/networks/{id}", delete(admin::delete_network))
        .route("/networks/{id}/scan", post(admin::scan_network))
        .route("/scan", post(admin::trigger_scan))
        .route("/scan/status", get(admin::scan_status))
        .route("/settings/discovery", get(admin::get_discovery).put(admin::set_discovery))
        .route("/settings/live", get(admin::get_live).put(admin::set_live))
        .route("/stream", get(stream::events))
        // Zugangsdaten
        .route("/credentials", get(credentials::list).post(credentials::create))
        .route("/credentials/{id}", axum::routing::patch(credentials::update).delete(credentials::remove))
        .route("/credentials/{id}/test", post(credentials::test))
        .route("/credentials/{id}/scan", post(credentials::scan).get(credentials::scan_status))
        .route("/credentials/{id}/devices", get(credentials::devices).put(credentials::set_devices))
        // Alarmierung
        .route("/channels", get(alerts::list_channels).post(alerts::create_channel))
        .route("/channels/{id}", axum::routing::patch(alerts::update_channel).delete(alerts::delete_channel))
        .route("/channels/{id}/test", post(alerts::test_channel))
        .route("/settings/smtp", get(alerts::get_smtp).put(alerts::set_smtp))
        .route("/settings/smtp/test", post(alerts::test_smtp))
        .route("/alert-rules", get(alerts::list_rules).post(alerts::create_rule))
        .route("/alert-rules/{id}", axum::routing::patch(alerts::update_rule).delete(alerts::delete_rule))
        // Verwaltung
        .route("/users", get(admin::list_users).post(admin::add_user))
        .route("/users/{id}", delete(admin::delete_user))
        .route("/users/{id}/totp", delete(admin::reset_totp))
        .route("/audit", get(admin::audit_log))
        .route("/logs", get(admin::system_log))
        .route("/system", get(admin::system))
        .route("/maintenance", get(admin::list_maintenance).post(admin::create_maintenance))
        .route("/maintenance/{id}", axum::routing::patch(admin::update_maintenance).delete(admin::delete_maintenance))
        .layer(middleware::from_fn(auth::csrf_guard));

    Router::new()
        .nest("/api", api)
        .route("/healthz", get(health))
        // no-cache: Der Browser fragt bei jedem Aufruf kurz nach, ob sich die Datei geändert hat –
        // so ist nach einem Update sofort die neue Oberfläche aktiv (sonst meist nur „304 Not Modified“)
        .fallback_service(ServeDir::new(&state.config.web_dir))
        .layer(SetResponseHeaderLayer::if_not_present(header::CACHE_CONTROL, HeaderValue::from_static("no-cache")))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Für Docker-Healthchecks: 200, wenn die Datenbank erreichbar ist
async fn health(State(state): State<AppState>) -> StatusCode {
    match sqlx::query("SELECT 1").execute(&state.db).await {
        Ok(_) => StatusCode::OK,
        Err(_) => StatusCode::SERVICE_UNAVAILABLE,
    }
}
