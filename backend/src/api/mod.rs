//! REST-API unter `/api/…` und Auslieferung der Weboberfläche.

mod admin;
mod alerts;
mod credentials;
mod dashboard;
mod devices;
mod session;

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
        // Geräte & Status
        .route("/summary", get(devices::summary))
        .route("/devices", get(devices::list))
        .route("/devices/{id}", get(devices::detail).patch(devices::update).delete(devices::remove))
        .route("/devices/{id}/credentials", put(devices::set_credentials))
        .route("/devices/{id}/poll", post(devices::poll_now))
        .route("/devices/{id}/ssh-key", delete(devices::reset_ssh_key))
        .route("/events", get(devices::events))
        .route("/alerts", get(alerts::list_alerts))
        // Dashboard (pro Benutzer)
        .route("/dashboard", get(dashboard::load).put(dashboard::save))
        // Netze & Scans
        .route("/networks", get(admin::list_networks).post(admin::add_network))
        .route("/networks/{id}", delete(admin::delete_network))
        .route("/networks/{id}/scan", post(admin::scan_network))
        .route("/scan", post(admin::trigger_scan))
        .route("/scan/status", get(admin::scan_status))
        // Zugangsdaten
        .route("/credentials", get(credentials::list).post(credentials::create))
        .route("/credentials/{id}", axum::routing::patch(credentials::update).delete(credentials::remove))
        // Alarmierung
        .route("/channels", get(alerts::list_channels).post(alerts::create_channel))
        .route("/channels/{id}", axum::routing::patch(alerts::update_channel).delete(alerts::delete_channel))
        .route("/channels/{id}/test", post(alerts::test_channel))
        .route("/alert-rules", get(alerts::list_rules).post(alerts::create_rule))
        .route("/alert-rules/{id}", axum::routing::patch(alerts::update_rule).delete(alerts::delete_rule))
        // Verwaltung
        .route("/users", get(admin::list_users).post(admin::add_user))
        .route("/users/{id}", delete(admin::delete_user))
        .route("/audit", get(admin::audit_log))
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
