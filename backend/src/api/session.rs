//! Login, Logout, eigenes Konto.

use axum::{
    extract::State,
    http::{header, HeaderMap},
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{
    audit,
    auth::{self, CurrentUser},
    error::{ApiError, ApiResult},
    AppState,
};

#[derive(Deserialize)]
pub struct LoginRequest {
    username: String,
    password: String,
}

pub async fn login(State(st): State<AppState>, Json(req): Json<LoginRequest>) -> ApiResult<Response> {
    let username = req.username.trim().to_lowercase();
    if st.login_limiter.is_locked(&username) {
        return Err(ApiError::TooManyRequests);
    }

    let user: Option<(i64, String, String, String)> =
        sqlx::query_as("SELECT id, username, role, password_hash FROM users WHERE username = $1")
            .bind(&username)
            .fetch_optional(&st.db)
            .await?;

    // Auch bei unbekanntem Benutzer einen Hash prüfen, damit die Antwortzeit nichts verrät
    let hash = user.as_ref().map(|u| u.3.clone()).unwrap_or_else(|| auth::dummy_hash().to_string());
    let valid = auth::verify_password(req.password, hash).await;

    // `let … else`: Wenn das Muster nicht passt, wird der else-Zweig ausgeführt
    let Some((id, name, role, _)) = user.filter(|_| valid) else {
        st.login_limiter.record_failure(&username);
        audit::log(&st.db, None, Some(&username), "login_failed", json!({})).await;
        return Err(ApiError::InvalidCredentials);
    };

    st.login_limiter.reset(&username);
    let token = auth::create_session(&st.db, id, st.config.session_hours).await?;
    sqlx::query("UPDATE users SET last_login = now() WHERE id = $1")
        .bind(id)
        .execute(&st.db)
        .await?;
    audit::log(&st.db, Some(id), Some(&name), "login", json!({})).await;

    let max_age = i64::from(st.config.session_hours) * 3600;
    let cookie = auth::session_cookie(&token, max_age, st.config.cookie_secure);
    let user = CurrentUser { id, username: name, role };
    Ok(([(header::SET_COOKIE, cookie)], Json(user)).into_response())
}

pub async fn logout(State(st): State<AppState>, headers: HeaderMap) -> ApiResult<Response> {
    if let Some(token) = auth::session_token(&headers) {
        sqlx::query("DELETE FROM sessions WHERE token_hash = $1")
            .bind(auth::token_hash(&token))
            .execute(&st.db)
            .await?;
    }
    let cookie = auth::session_cookie("", 0, st.config.cookie_secure);
    Ok(([(header::SET_COOKIE, cookie)], Json(json!({ "ok": true }))).into_response())
}

pub async fn me(user: CurrentUser) -> Json<CurrentUser> {
    Json(user)
}

#[derive(Deserialize)]
pub struct PasswordChange {
    old_password: String,
    new_password: String,
}

pub async fn change_password(
    State(st): State<AppState>,
    user: CurrentUser,
    headers: HeaderMap,
    Json(req): Json<PasswordChange>,
) -> ApiResult<Json<Value>> {
    auth::validate_password(&req.new_password).map_err(ApiError::BadRequest)?;

    let (hash,): (String,) = sqlx::query_as("SELECT password_hash FROM users WHERE id = $1")
        .bind(user.id)
        .fetch_one(&st.db)
        .await?;
    if !auth::verify_password(req.old_password, hash).await {
        return Err(ApiError::BadRequest("Aktuelles Passwort ist falsch".into()));
    }

    let new_hash = auth::hash_password(req.new_password).await?;
    sqlx::query("UPDATE users SET password_hash = $2 WHERE id = $1")
        .bind(user.id)
        .bind(new_hash)
        .execute(&st.db)
        .await?;

    // Alle anderen Sitzungen dieses Benutzers beenden (z. B. auf fremden Geräten)
    let current = auth::session_token(&headers).map(|t| auth::token_hash(&t)).unwrap_or_default();
    sqlx::query("DELETE FROM sessions WHERE user_id = $1 AND token_hash <> $2")
        .bind(user.id)
        .bind(current)
        .execute(&st.db)
        .await?;

    audit::by(&st.db, &user, "password_change", json!({})).await;
    Ok(Json(json!({ "ok": true })))
}
