//! Anmeldung und Zugriffsschutz.
//!
//! - Passwörter: Argon2id (aktueller Standard, u. a. vom BSI empfohlen)
//! - Sitzungen: zufälliges 256-Bit-Token im HttpOnly-Cookie, in der DB nur als SHA-256-Hash
//! - CSRF-Schutz: SameSite=Strict + Pflicht-Header bei allen ändernden Anfragen
//! - Brute-Force-Schutz: Sperre nach 5 Fehlversuchen für 5 Minuten

use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

use argon2::{
    password_hash::{
        rand_core::{OsRng, RngCore},
        PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
    },
    Argon2,
};
use axum::{
    extract::{FromRequestParts, Request},
    http::{header, request::Parts, HeaderMap, Method},
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::PgPool;

use crate::{error::ApiError, AppState};

pub const SESSION_COOKIE: &str = "netpulse_session";
/// Diesen Header muss jede ändernde Anfrage mitschicken. Fremde Webseiten können
/// ihn wegen der Same-Origin-Policy nicht setzen.
const CSRF_HEADER: &str = "x-netpulse-csrf";

// ---------------------------------------------------------------------------
// Passwörter
// ---------------------------------------------------------------------------

pub fn validate_password(password: &str) -> Result<(), String> {
    if password.chars().count() < 12 {
        return Err("Passwort muss mindestens 12 Zeichen lang sein".into());
    }
    if password.len() > 256 {
        return Err("Passwort ist zu lang".into());
    }
    Ok(())
}

/// Hashing ist absichtlich rechenintensiv, deshalb läuft es in einem eigenen Thread
/// und blockiert den Webserver nicht.
pub async fn hash_password(password: String) -> anyhow::Result<String> {
    tokio::task::spawn_blocking(move || {
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map(|h| h.to_string())
            .map_err(|e| anyhow::anyhow!("Passwort-Hashing fehlgeschlagen: {e}"))
    })
    .await?
}

pub async fn verify_password(password: String, hash: String) -> bool {
    tokio::task::spawn_blocking(move || {
        PasswordHash::new(&hash)
            .map(|parsed| Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok())
            .unwrap_or(false)
    })
    .await
    .unwrap_or(false)
}

/// Hash, gegen den bei unbekannten Benutzernamen geprüft wird. So dauert ein Login-Versuch
/// immer gleich lang und verrät nicht, ob ein Benutzer existiert.
pub fn dummy_hash() -> &'static str {
    static DUMMY: OnceLock<String> = OnceLock::new();
    DUMMY.get_or_init(|| {
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(b"netpulse-dummy-password", &salt)
            .expect("Argon2 mit Standardparametern")
            .to_string()
    })
}

// ---------------------------------------------------------------------------
// Sitzungen
// ---------------------------------------------------------------------------

/// Kryptografisch sicherer Zufallswert als Hex-Text (`bytes` Byte → doppelt so viele Zeichen)
pub fn random_token(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    OsRng.fill_bytes(&mut buf);
    hex::encode(buf)
}

pub fn token_hash(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

pub async fn create_session(db: &PgPool, user_id: i64, hours: i32) -> Result<String, sqlx::Error> {
    let token = random_token(32);
    sqlx::query(
        "INSERT INTO sessions (token_hash, user_id, expires_at)
         VALUES ($1, $2, now() + make_interval(hours => $3))",
    )
    .bind(token_hash(&token))
    .bind(user_id)
    .bind(hours)
    .execute(db)
    .await?;
    Ok(token)
}

pub fn session_cookie(token: &str, max_age_secs: i64, secure: bool) -> String {
    let secure = if secure { "; Secure" } else { "" };
    format!("{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age_secs}{secure}")
}

/// Liest das Sitzungs-Token aus dem Cookie-Header.
pub fn session_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(name, _)| *name == SESSION_COOKIE)
        .map(|(_, value)| value.to_string())
}

// ---------------------------------------------------------------------------
// Extraktoren: Ein Handler, der `CurrentUser` als Parameter nimmt, ist automatisch
// nur für angemeldete Benutzer erreichbar; `AdminUser` nur für Admins.
// ---------------------------------------------------------------------------

#[derive(Clone, Serialize, sqlx::FromRow)]
pub struct CurrentUser {
    pub id: i64,
    pub username: String,
    pub role: String,
}

impl FromRequestParts<AppState> for CurrentUser {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let token = session_token(&parts.headers).ok_or(ApiError::Unauthorized)?;
        let user = sqlx::query_as::<_, CurrentUser>(
            "SELECT u.id, u.username, u.role
               FROM sessions s JOIN users u ON u.id = s.user_id
              WHERE s.token_hash = $1 AND s.expires_at > now()",
        )
        .bind(token_hash(&token))
        .fetch_optional(&state.db)
        .await?;
        user.ok_or(ApiError::Unauthorized)
    }
}

pub struct AdminUser(pub CurrentUser);

impl FromRequestParts<AppState> for AdminUser {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let user = CurrentUser::from_request_parts(parts, state).await?;
        if user.role == "admin" {
            Ok(AdminUser(user))
        } else {
            Err(ApiError::Forbidden)
        }
    }
}

/// Middleware: Ändernde Anfragen (POST, PUT, PATCH, DELETE) ohne CSRF-Header ablehnen.
pub async fn csrf_guard(request: Request, next: Next) -> Response {
    let safe_method = matches!(*request.method(), Method::GET | Method::HEAD | Method::OPTIONS);
    let has_header = request.headers().get(CSRF_HEADER).is_some_and(|v| v == "1");
    if !safe_method && !has_header {
        return ApiError::Forbidden.into_response();
    }
    next.run(request).await
}

// ---------------------------------------------------------------------------
// Brute-Force-Schutz
// ---------------------------------------------------------------------------

const MAX_FAILURES: u32 = 5;
const LOCK_DURATION: Duration = Duration::from_secs(5 * 60);

#[derive(Default)]
pub struct LoginLimiter {
    /// Benutzername → (Anzahl Fehlversuche, Zeitpunkt des letzten Fehlversuchs)
    failures: Mutex<HashMap<String, (u32, Instant)>>,
}

impl LoginLimiter {
    pub fn is_locked(&self, username: &str) -> bool {
        let failures = self.failures.lock().unwrap();
        failures
            .get(username)
            .is_some_and(|(count, last)| *count >= MAX_FAILURES && last.elapsed() < LOCK_DURATION)
    }

    pub fn record_failure(&self, username: &str) {
        let mut failures = self.failures.lock().unwrap();
        // Alte Einträge entfernen, damit die Tabelle nicht endlos wächst
        if failures.len() > 10_000 {
            failures.retain(|_, (_, last)| last.elapsed() < LOCK_DURATION);
        }
        let entry = failures.entry(username.to_string()).or_insert((0, Instant::now()));
        if entry.1.elapsed() >= LOCK_DURATION {
            entry.0 = 0;
        }
        entry.0 += 1;
        entry.1 = Instant::now();
    }

    pub fn reset(&self, username: &str) {
        self.failures.lock().unwrap().remove(username);
    }
}
