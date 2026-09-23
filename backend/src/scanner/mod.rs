//! Agentenlose Datenerfassung.
//!
//! - `discovery`: findet Geräte in den freigegebenen Netzen (Ping, TCP, ARP, DNS, Port-Scan)
//! - `monitor`  : prüft bekannte Geräte regelmäßig auf Erreichbarkeit und speichert Messwerte
//! - `net`      : Netzwerk-Hilfsfunktionen

pub mod discovery;
pub mod monitor;
pub mod net;

use sqlx::PgPool;

pub async fn add_event(db: &PgPool, device_id: i64, kind: &str, message: &str) -> sqlx::Result<()> {
    sqlx::query("INSERT INTO events (device_id, kind, message) VALUES ($1, $2, $3)")
        .bind(device_id)
        .bind(kind)
        .bind(message)
        .execute(db)
        .await?;
    Ok(())
}
