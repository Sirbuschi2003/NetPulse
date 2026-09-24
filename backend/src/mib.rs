//! Namen für SNMP-OIDs aus rund 4.800 Standard- und Hersteller-MIBs (Quelle: LibreNMS-MIB-Sammlung,
//! IETF/IANA). Die Liste ist komprimiert ins Programm eingebettet und wird beim ersten Start
//! einmalig im Hintergrund in die Tabelle `mib_names` geladen.

use std::{collections::HashMap, io::Read};

use anyhow::Result;
use flate2::read::GzDecoder;
use sqlx::PgPool;

static MIB_DATA: &[u8] = include_bytes!("../data/mibnames.tsv.gz");

/// Lädt die Namen, falls die Tabelle noch leer oder veraltet ist. Läuft im Hintergrund.
pub async fn load(db: PgPool) {
    if let Err(e) = load_inner(&db).await {
        tracing::error!("MIB-Namen konnten nicht geladen werden: {e:#}");
    }
}

async fn load_inner(db: &PgPool) -> Result<()> {
    let version = format!("{}", MIB_DATA.len());
    let current: Option<(serde_json::Value,)> =
        sqlx::query_as("SELECT value FROM settings WHERE key = 'mib_names_version'").fetch_optional(db).await?;
    if current.is_some_and(|c| c.0 == serde_json::json!(version)) {
        return Ok(());
    }
    tracing::info!("Lade SNMP-MIB-Namen in die Datenbank (einmalig, dauert etwa eine Minute) …");
    let rows = tokio::task::spawn_blocking(|| -> Result<Vec<(String, String)>> {
        let mut text = String::new();
        GzDecoder::new(MIB_DATA).read_to_string(&mut text)?;
        Ok(text
            .lines()
            .filter_map(|l| l.split_once('\t'))
            .map(|(o, n)| (o.to_string(), n.to_string()))
            .collect())
    })
    .await??;

    let mut tx = db.begin().await?;
    sqlx::query("TRUNCATE mib_names").execute(&mut *tx).await?;
    for chunk in rows.chunks(20_000) {
        let (oids, names): (Vec<&str>, Vec<&str>) = chunk.iter().map(|(o, n)| (o.as_str(), n.as_str())).unzip();
        sqlx::query("INSERT INTO mib_names (oid, name) SELECT * FROM UNNEST($1::text[], $2::text[]) ON CONFLICT DO NOTHING")
            .bind(&oids)
            .bind(&names)
            .execute(&mut *tx)
            .await?;
    }
    sqlx::query(
        "INSERT INTO settings (key, value) VALUES ('mib_names_version', $1)
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
    )
    .bind(serde_json::json!(version))
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    tracing::info!("{} SNMP-MIB-Namen geladen", rows.len());
    Ok(())
}

fn dotted(parts: &[u64]) -> String {
    parts.iter().map(u64::to_string).collect::<Vec<_>>().join(".")
}

/// Liefert zu jeder OID den Namen des längsten bekannten Präfixes plus Rest,
/// z. B. 1.3.6.1.2.1.31.1.1.1.6.3 → „ifHCInOctets.3“.
pub async fn names_for(db: &PgPool, oids: &[Vec<u64>]) -> sqlx::Result<HashMap<Vec<u64>, String>> {
    let oids: Vec<&Vec<u64>> = oids.iter().filter(|o| o.len() <= 128).take(100).collect();
    let mut prefixes: Vec<String> = oids.iter().flat_map(|o| (1..=o.len()).map(|n| dotted(&o[..n]))).collect();
    prefixes.sort();
    prefixes.dedup();
    let known: HashMap<String, String> = sqlx::query_as::<_, (String, String)>("SELECT oid, name FROM mib_names WHERE oid = ANY($1)")
        .bind(&prefixes)
        .fetch_all(db)
        .await?
        .into_iter()
        .collect();
    Ok(oids
        .iter()
        .filter_map(|oid| {
            (1..=oid.len()).rev().find_map(|n| {
                known.get(&dotted(&oid[..n])).map(|name| {
                    let rest = &oid[n..];
                    let name = if rest.is_empty() { name.clone() } else { format!("{name}.{}", dotted(rest)) };
                    ((*oid).clone(), name)
                })
            })
        })
        .collect())
}

/// Symbolischen Namen („ifTable“) oder Zahlenform („1.3.6.1.2.1.2.2“) in eine OID auflösen
pub async fn resolve(db: &PgPool, input: &str) -> sqlx::Result<Option<Vec<u64>>> {
    let input = input.trim().trim_start_matches('.');
    if input.chars().all(|c| c.is_ascii_digit() || c == '.') {
        let parts: Option<Vec<u64>> = input.split('.').map(|p| p.parse().ok()).collect();
        return Ok(parts.filter(|p| !p.is_empty()));
    }
    let row: Option<(String,)> = sqlx::query_as("SELECT oid FROM mib_names WHERE name = $1 ORDER BY length(oid) LIMIT 1")
        .bind(input)
        .fetch_optional(db)
        .await?;
    Ok(row.and_then(|(o,)| o.split('.').map(|p| p.parse().ok()).collect()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eingebettete_liste_ist_lesbar() {
        let mut text = String::new();
        GzDecoder::new(MIB_DATA).read_to_string(&mut text).unwrap();
        assert!(text.lines().count() > 500_000);
        assert!(text.contains("1.3.6.1.2.1.31.1.1.1.6\tifHCInOctets"));
    }
}
