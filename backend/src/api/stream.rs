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
pub async fn events(State(st): State<AppState>, user: CurrentUser) -> impl IntoResponse {
    (
        [(HeaderName::from_static("x-accel-buffering"), HeaderValue::from_static("no"))],
        sse(st, user),
    )
}

fn sse(st: AppState, _user: CurrentUser) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = st.hub.subscribe();
    let first = st.hub.snapshot().to_string();
    let initial = stream::once(async move { Ok(Event::default().data(first)) });
    let updates = stream::unfold(rx, |mut rx| async move {
        loop {
            match rx.recv().await {
                Ok(message) => return Some((Ok(Event::default().data(&*message)), rx)),
                // Browser zu langsam: verpasste Zwischenstände überspringen
                Err(RecvError::Lagged(_)) => continue,
                Err(RecvError::Closed) => return None,
            }
        }
    });
    let stream = initial.chain(updates).take_until(tokio::time::sleep(Duration::from_secs(30 * 60)));
    Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(20)))
}
