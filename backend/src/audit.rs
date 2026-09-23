//! Audit-Log: nachvollziehbar machen, wer wann was geändert hat (DSGVO Art. 32, ISO 27001).

use serde_json::Value;
use sqlx::PgPool;

use crate::auth::CurrentUser;

/// Schreibt einen Eintrag. Ein Fehler beim Protokollieren bricht die eigentliche Aktion nicht ab,
/// wird aber geloggt.
pub async fn log(db: &PgPool, user_id: Option<i64>, username: Option<&str>, action: &str, detail: Value) {
    let result = sqlx::query("INSERT INTO audit_log (user_id, username, action, detail) VALUES ($1, $2, $3, $4)")
        .bind(user_id)
        .bind(username)
        .bind(action)
        .bind(detail)
        .execute(db)
        .await;
    if let Err(e) = result {
        tracing::error!("Audit-Eintrag '{action}' konnte nicht gespeichert werden: {e}");
    }
}

/// Kurzform für Aktionen eines angemeldeten Benutzers
pub async fn by(db: &PgPool, user: &CurrentUser, action: &str, detail: Value) {
    log(db, Some(user.id), Some(&user.username), action, detail).await;
}
