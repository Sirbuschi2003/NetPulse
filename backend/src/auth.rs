//! Anmeldung und Zugriffsschutz.
//!
//! - Passwörter: Argon2id (aktueller Standard, u. a. vom BSI empfohlen)
//! - Sitzungen: zufälliges 256-Bit-Token im HttpOnly-Cookie, in der DB nur als SHA-256-Hash
//! - CSRF-Schutz: SameSite=Strict + Pflicht-Header bei allen ändernden Anfragen
//! - Brute-Force-Schutz: Grenzen je Benutzer+IP, je IP und je Benutzer (siehe unten)

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
/// Mit HTTPS: `__Host-`-Präfix – der Browser akzeptiert das Cookie dann nur von genau diesem Host
/// (keine Übernahme durch Nachbar-Subdomains hinter demselben Proxy)
pub const SESSION_COOKIE_SECURE: &str = "__Host-netpulse_session";
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
/// Höchstens 4 gleichzeitige Argon2-Berechnungen (je ~19 MB RAM) – schützt NAS/Pi vor Überlastung
fn argon_slots() -> &'static tokio::sync::Semaphore {
    static SLOTS: OnceLock<tokio::sync::Semaphore> = OnceLock::new();
    SLOTS.get_or_init(|| tokio::sync::Semaphore::new(4))
}

pub async fn hash_password(password: String) -> anyhow::Result<String> {
    let _slot = argon_slots().acquire().await?;
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
    let Ok(_slot) = argon_slots().acquire().await else { return false };
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

pub async fn create_session(db: &PgPool, user_id: i64, hours: i32, headers: &HeaderMap) -> Result<String, sqlx::Error> {
    let token = random_token(32);
    let user_agent: Option<String> = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.chars().take(300).collect());
    sqlx::query(
        "INSERT INTO sessions (token_hash, user_id, expires_at, user_agent, ip, last_seen)
         VALUES ($1, $2, now() + make_interval(hours => $3), $4, $5, now())",
    )
    .bind(token_hash(&token))
    .bind(user_id)
    .bind(hours)
    .bind(user_agent)
    .bind(client_ip(headers))
    .execute(db)
    .await?;
    Ok(token)
}

/// Adresse des Browsers für die Anzeige (vom vorgeschalteten Proxy gemeldet; nur zur Information)
pub fn client_ip(headers: &HeaderMap) -> Option<String> {
    let header = |name: &str| headers.get(name).and_then(|v| v.to_str().ok()).map(str::trim).filter(|v| !v.is_empty());
    header("x-real-ip")
        .or_else(|| header("x-forwarded-for").and_then(|v| v.split(',').next()).map(str::trim))
        .filter(|ip| ip.parse::<std::net::IpAddr>().is_ok())
        .map(str::to_string)
}

/// Ist die Sitzung noch gültig? (für lange offene Verbindungen wie den Live-Stream)
pub async fn session_valid(db: &PgPool, token_hash: &[u8]) -> bool {
    sqlx::query_as::<_, (i64,)>("SELECT 1 FROM sessions WHERE token_hash = $1 AND expires_at > now()")
        .bind(token_hash)
        .fetch_optional(db)
        .await
        .map(|r| r.is_some())
        .unwrap_or(true)
}

pub fn session_cookie(token: &str, max_age_secs: i64, secure: bool) -> String {
    if secure {
        format!("{SESSION_COOKIE_SECURE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age_secs}; Secure")
    } else {
        format!("{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age_secs}")
    }
}

/// Liest das Sitzungs-Token aus dem Cookie-Header.
pub fn session_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(name, _)| *name == SESSION_COOKIE_SECURE || *name == SESSION_COOKIE)
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
        if user.is_some() {
            // „Zuletzt aktiv“ höchstens einmal pro Minute schreiben
            let db = state.db.clone();
            let hash = token_hash(&token);
            tokio::spawn(async move {
                let _ = sqlx::query(
                    "UPDATE sessions SET last_seen = now() WHERE token_hash = $1 AND (last_seen IS NULL OR last_seen < now() - interval '1 minute')",
                )
                .bind(hash)
                .execute(&db)
                .await;
            });
        }
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
//
// Jeder Versuch wird VOR der Passwortprüfung gezählt (auch parallele Anfragen) und erst bei
// Erfolg zurückgenommen. Grenzen je 15 Minuten:
// - Benutzer + IP: 5 Versuche  → ein Angreifer sperrt nur sich selbst, nicht den echten Benutzer
// - IP:           20 Versuche  → gegen das Durchprobieren vieler Benutzernamen
// - Benutzer:     50 Versuche  → gegen verteilte Angriffe von vielen Adressen

const WINDOW: Duration = Duration::from_secs(15 * 60);
const LIMIT_USER_IP: u32 = 5;
const LIMIT_IP: u32 = 20;
const LIMIT_USER: u32 = 50;

#[derive(Default)]
pub struct LoginLimiter {
    counters: Mutex<HashMap<String, (u32, Instant)>>,
}

impl LoginLimiter {
    fn keys(username: &str, ip: &str) -> [(String, u32); 3] {
        [
            (format!("ui:{username}|{ip}"), LIMIT_USER_IP),
            (format!("i:{ip}"), LIMIT_IP),
            (format!("u:{username}"), LIMIT_USER),
        ]
    }

    /// Versuch anmelden; `false` = gesperrt (dann nicht prüfen)
    pub fn try_attempt(&self, username: &str, ip: &str) -> bool {
        let mut map = self.counters.lock().unwrap();
        if map.len() > 20_000 {
            map.retain(|_, (_, since)| since.elapsed() < WINDOW);
        }
        let keys = Self::keys(username, ip);
        let current = |map: &HashMap<String, (u32, Instant)>, key: &str| {
            map.get(key).filter(|(_, since)| since.elapsed() < WINDOW).map_or(0, |(n, _)| *n)
        };
        if keys.iter().any(|(key, limit)| current(&map, key) >= *limit) {
            return false;
        }
        for (key, _) in keys {
            let entry = map.entry(key).or_insert((0, Instant::now()));
            if entry.1.elapsed() >= WINDOW {
                *entry = (0, Instant::now());
            }
            entry.0 += 1;
        }
        true
    }

    /// Erfolgreiche Prüfung: Versuch wieder abziehen
    pub fn success(&self, username: &str, ip: &str) {
        let mut map = self.counters.lock().unwrap();
        let [(user_ip, _), (ip_key, _), (user, _)] = Self::keys(username, ip);
        map.remove(&user_ip);
        for key in [ip_key, user] {
            if let Some(entry) = map.get_mut(&key) {
                entry.0 = entry.0.saturating_sub(1);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sperre_je_benutzer_und_ip() {
        let l = LoginLimiter::default();
        for _ in 0..LIMIT_USER_IP {
            assert!(l.try_attempt("admin", "203.0.113.9"));
        }
        assert!(!l.try_attempt("admin", "203.0.113.9"), "Angreifer ist gesperrt");
        assert!(l.try_attempt("admin", "192.168.1.20"), "echter Admin von anderer Adresse nicht");
        l.success("admin", "192.168.1.20");
    }
}
