//! REST-API unter `/api/…` und Auslieferung der Weboberfläche.

mod admin;
mod dashboard;
mod devices;
mod session;

use axum::{
    extract::State,
    http::StatusCode,
    middleware,
    routing::{delete, get, post},
    Router,
};
use tower_http::{services::ServeDir, trace::TraceLayer};

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
        .route("/events", get(devices::events))
        // Dashboard (pro Benutzer)
        .route("/dashboard", get(dashboard::load).put(dashboard::save))
        // Verwaltung (nur Admins)
        .route("/networks", get(admin::list_networks).post(admin::add_network))
        .route("/networks/{id}", delete(admin::delete_network))
        .route("/scan", post(admin::trigger_scan))
        .route("/users", get(admin::list_users).post(admin::add_user))
        .route("/users/{id}", delete(admin::delete_user))
        .route("/audit", get(admin::audit_log))
        .layer(middleware::from_fn(auth::csrf_guard));

    Router::new()
        .nest("/api", api)
        .route("/healthz", get(health))
        .fallback_service(ServeDir::new(&state.config.web_dir))
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
