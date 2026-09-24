//! Live-Meldungen per Server-Sent Events (`GET /api/stream`).
//!
//! Der Browser hält eine Verbindung offen und bekommt neue Messwerte und Statuswechsel sofort,
//! ohne ständig nachzufragen. Nach 30 Minuten wird die Verbindung beendet; der Browser baut sie
//! automatisch neu auf – dabei wird die Anmeldung erneut geprüft.

use std::{convert::Infallible, time::Duration};

use axum::{
    extract::State,
    http::{header::HeaderName, HeaderValue},
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse,
    },
};
use futures::{stream, Stream, StreamExt};
use tokio::sync::broadcast::error::RecvError;

use crate::{auth::CurrentUser, AppState};

/// `X-Accel-Buffering: no`: Nginx (z. B. Nginx Proxy Manager) leitet die Meldungen sofort weiter
pub async fn events(State(st): State<AppState>, user: CurrentUser, headers: axum::http::HeaderMap) -> impl IntoResponse {
    let hash = crate::auth::session_token(&headers).map(|t| crate::auth::token_hash(&t)).unwrap_or_default();
    (
        [(HeaderName::from_static("x-accel-buffering"), HeaderValue::from_static("no"))],
        sse(st, user, hash),
    )
}

fn sse(st: AppState, user: CurrentUser, hash: Vec<u8>) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let admin = user.role == "admin";
    // Endet nach 30 Minuten oder sobald die Sitzung abgemeldet wurde (Prüfung alle 30 s)
    let db = st.db.clone();
    let end = async move {
        let started = std::time::Instant::now();
        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;
            if started.elapsed() > Duration::from_secs(30 * 60) || !crate::auth::session_valid(&db, &hash).await {
                break;
            }
        }
    };
    let rx = st.hub.subscribe();
    let first = st.hub.snapshot().to_string();
    let initial = stream::once(async move { Ok(Event::default().data(first)) });
    let updates = stream::unfold(rx, move |mut rx| async move {
        loop {
            match rx.recv().await {
                // Protokollmeldungen (Syslog/Traps) nur an Admins – wie die Seite „Protokolle“
                Ok(message) if !admin && message.contains("\"type\":\"syslog\"") => continue,
                Ok(message) => return Some((Ok(Event::default().data(&*message)), rx)),
                // Browser zu langsam: verpasste Zwischenstände überspringen
                Err(RecvError::Lagged(_)) => continue,
                Err(RecvError::Closed) => return None,
            }
        }
    });
    let stream = initial.chain(updates).take_until(end);
    Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(20)))
}
