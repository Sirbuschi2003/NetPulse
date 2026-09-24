//! Tiefe Abfragen („Inventar“) über SNMP und SSH.
//!
//! Alle `INVENTORY_INTERVAL_MIN` Minuten werden Geräte mit zugeordneten Zugangsdaten abgefragt.
//! Zugangsdaten mit „automatisch ausprobieren“ werden bei Geräten ohne Zuordnung getestet
//! (SNMP immer, SSH nur mit Schlüssel und nur bei offenem Port) und bei Erfolg fest zugeordnet.

pub mod check;
pub mod live;
pub mod shelly;
pub mod snmp;
pub mod ssh;

use std::{net::Ipv4Addr, time::Duration};

use anyhow::Result;
use futures::{stream, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use tokio::sync::mpsc::UnboundedReceiver;

use crate::{scanner, AppState};

/// Geheimer Teil einer Zugangsangabe (liegt verschlüsselt in der Datenbank)
#[derive(Serialize, Deserialize, Default, Clone)]
pub struct Secret {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub community: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passphrase: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priv_protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priv_password: Option<String>,
}

pub struct Credential {
    pub id: i64,
    pub kind: String,
    pub username: Option<String>,
    pub port: Option<i32>,
    pub secret: Secret,
    pub linked: bool,
}

impl Credential {
    fn is_snmp(&self) -> bool {
        self.kind.starts_with("snmp")
    }
}

/// Wie oft Geräte ohne passende Zugangsdaten erneut automatisch probiert werden
const AUTO_RETRY: &str = "6 hours";

pub async fn run(state: AppState, mut requests: UnboundedReceiver<i64>) {
    tokio::time::sleep(Duration::from_secs(20)).await;
    let mut tick = tokio::time::interval(Duration::from_secs(60));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        let ids: Vec<i64> = tokio::select! {
            _ = tick.tick() => match due_devices(&state).await {
                Ok(ids) => ids,
                Err(e) => { tracing::error!("Inventar: Geräteliste nicht ladbar: {e:#}"); continue; }
            },
            Some(id) = requests.recv() => {
                let mut ids = vec![id];
                while let Ok(id) = requests.try_recv() { ids.push(id); }
                ids
            }
        };
        stream::iter(ids)
            .for_each_concurrent(8, |id| {
                let state = state.clone();
                async move {
                    if let Err(e) = poll_device(&state, id).await {
                        tracing::warn!("Inventar für Gerät {id} fehlgeschlagen: {e:#}");
                    }
                }
            })
            .await;
    }
}

async fn due_devices(state: &AppState) -> sqlx::Result<Vec<i64>> {
    let rows: Vec<(i64,)> = sqlx::query_as(&format!(
        "SELECT d.id FROM devices d
          WHERE d.status = 'up' AND (
                ((d.integration IS NOT NULL OR EXISTS (SELECT 1 FROM device_credentials dc WHERE dc.device_id = d.id))
                 AND (d.inventory_at IS NULL OR d.inventory_at < now() - make_interval(secs => $1)))
             OR (d.integration IS NULL AND NOT EXISTS (SELECT 1 FROM device_credentials dc WHERE dc.device_id = d.id)
                 AND EXISTS (SELECT 1 FROM credentials c WHERE c.auto)
                 AND (d.inventory_at IS NULL OR d.inventory_at < now() - interval '{AUTO_RETRY}')))
          ORDER BY d.inventory_at NULLS FIRST
          LIMIT 200"
    ))
    .bind(state.config.inventory_interval.as_secs_f64())
    .fetch_all(&state.db)
    .await?;
    Ok(rows.into_iter().map(|r| r.0).collect())
}

#[derive(sqlx::FromRow)]
struct CredentialRow {
    id: i64,
    kind: String,
    username: Option<String>,
    port: Option<i32>,
    secret: String,
    linked: bool,
}

#[derive(sqlx::FromRow)]
struct DeviceRow {
    ip: String,
    open_ports: Vec<i32>,
    ssh_host_key: Option<String>,
    inventory: Option<Value>,
    inventory_error: Option<String>,
    label: String,
    device_type: Option<String>,
    wan_interface: Option<String>,
    wan_interface_manual: bool,
    integration: Option<String>,
}

pub(crate) async fn load_credentials(state: &AppState, device_id: i64) -> Result<Vec<Credential>> {
    let rows: Vec<CredentialRow> = sqlx::query_as(
        "SELECT c.id, c.kind, c.username, c.port, c.secret,
                EXISTS (SELECT 1 FROM device_credentials dc WHERE dc.device_id = $1 AND dc.credential_id = c.id) AS linked
           FROM credentials c
          WHERE c.auto OR c.id IN (SELECT credential_id FROM device_credentials WHERE device_id = $1)
          ORDER BY 6 DESC, c.id",
    )
    .bind(device_id)
    .fetch_all(&state.db)
    .await?;
    let mut creds = Vec::new();
    for row in rows {
        match state.vault.open_value::<Secret>(&row.secret) {
            Ok(secret) => creds.push(Credential {
                id: row.id,
                kind: row.kind,
                username: row.username,
                port: row.port,
                secret,
                linked: row.linked,
            }),
            Err(e) => tracing::error!("Zugangsdaten {}: {e:#}", row.id),
        }
    }
    Ok(creds)
}

/// Fragt ein Gerät ab und speichert Inventar, Messwerte und abgeleitete Angaben.
pub async fn poll_device(state: &AppState, device_id: i64) -> Result<()> {
    let row: Option<DeviceRow> = sqlx::query_as(
        "SELECT host(ip) AS ip, open_ports, ssh_host_key, inventory, inventory_error,
                COALESCE(name, reported_name, hostname, host(ip)) AS label, device_type, wan_interface, wan_interface_manual,
                integration
           FROM devices WHERE id = $1",
    )
    .bind(device_id)
    .fetch_optional(&state.db)
    .await?;
    let Some(DeviceRow {
        ip,
        open_ports,
        ssh_host_key: host_key,
        inventory: previous,
        inventory_error: previous_error,
        label,
        device_type,
        wan_interface,
        wan_interface_manual,
        integration,
    }) = row
    else {
        return Ok(());
    };
    let Ok(addr) = ip.parse::<Ipv4Addr>() else { return Ok(()) };

    let credentials = load_credentials(state, device_id).await?;
    let has_linked = credentials.iter().any(|c| c.linked);
    let mut errors: Vec<String> = Vec::new();
    let mut inventory = Map::new();

    // SNMP: zugeordnete zuerst, dann automatische
    for cred in credentials.iter().filter(|c| c.is_snmp()) {
        match snmp::collect(addr, cred).await {
            Ok(data) => {
                inventory.insert("snmp".into(), data);
                link(state, device_id, cred).await?;
                break;
            }
            Err(e) if cred.linked => errors.push(format!("SNMP: {e:#}")),
            Err(_) => {} // automatischer Versuch – Fehlschlag ist normal
        }
    }

    // SSH: Passwort-Zugänge nur bei fester Zuordnung (sonst würde das Passwort an fremde Geräte gehen)
    for cred in credentials.iter().filter(|c| c.kind.starts_with("ssh")) {
        let port = cred.port.unwrap_or(22);
        if !cred.linked && (cred.kind != "ssh_key" || !open_ports.contains(&port)) {
            continue;
        }
        match ssh::collect(addr, cred, host_key.as_deref()).await {
            Ok(result) => {
                if host_key.is_none() {
                    sqlx::query("UPDATE devices SET ssh_host_key = $2 WHERE id = $1")
                        .bind(device_id)
                        .bind(&result.host_key)
                        .execute(&state.db)
                        .await?;
                }
                inventory.insert("ssh".into(), result.data);
                link(state, device_id, cred).await?;
                break;
            }
            Err(ssh::SshError::HostKeyChanged { expected, seen }) => {
                let message = format!(
                    "SSH-Host-Schlüssel von {label} hat sich geändert ({expected} → {seen}). Abfrage gestoppt – \
                     bei Neuinstallation in der Geräteansicht zurücksetzen, sonst möglicher Angriff prüfen."
                );
                if !previous_error.as_deref().unwrap_or_default().contains("Host-Schlüssel") {
                    scanner::add_event(&state.db, device_id, "ssh_key_changed", &message).await?;
                }
                errors.push("SSH: Host-Schlüssel hat sich geändert".into());
                break;
            }
            Err(ssh::SshError::Failed(e)) if cred.linked => errors.push(format!("SSH: {e}")),
            Err(ssh::SshError::Failed(_)) => {}
        }
    }

    // Shelly: Daten über die lokale HTTP-API; Passwort nur, falls am Gerät eines gesetzt ist.
    // HTTP-Zugangsdaten gehen ausschließlich an Geräte, die sich vorher als Shelly ausgewiesen haben.
    if integration.as_deref() == Some("shelly") {
        if let Some(info) = shelly::probe(addr).await {
            let http_creds: Vec<&Credential> = credentials.iter().filter(|c| c.kind == "http").collect();
            let result = if info.auth && !http_creds.is_empty() {
                let mut last = Err(anyhow::anyhow!("Anmeldung fehlgeschlagen"));
                for cred in http_creds {
                    last = shelly::collect(addr, &info, Some(cred)).await;
                    if last.is_ok() {
                        link(state, device_id, cred).await?;
                        break;
                    }
                }
                last
            } else {
                shelly::collect(addr, &info, None).await
            };
            match result {
                Ok(data) => {
                    inventory.insert("shelly".into(), data);
                }
                Err(e) => errors.push(format!("Shelly: {e:#}")),
            }
        }
    }

    if inventory.is_empty() {
        // Nur bei fest zugeordneten Zugangsdaten ist ein Fehlschlag eine Meldung wert;
        // dass automatische Versuche nicht passen, ist der Normalfall.
        let error = if has_linked || integration.is_some() { errors.join(" · ") } else { String::new() };
        sqlx::query("UPDATE devices SET inventory_at = now(), inventory_error = NULLIF($2, '') WHERE id = $1")
            .bind(device_id)
            .bind(error)
            .execute(&state.db)
            .await?;
        return Ok(());
    }

    let now = chrono::Utc::now();
    inventory.insert("collected_at".into(), json!(now));
    let inventory = Value::Object(inventory);
    let wan = if wan_interface_manual {
        wan_interface
    } else {
        detect_wan(&inventory, device_type.as_deref())
    };
    let rates = interface_rates(&inventory, previous.as_ref());
    let stats = derive_stats(&inventory, &rates, wan.as_deref());
    let derived = derive_fields(&inventory);

    sqlx::query(
        "UPDATE devices SET
             inventory = $2, inventory_at = now(), inventory_error = NULLIF($3, ''),
             os = COALESCE($4, os), model = COALESCE($5, model),
             hostname = COALESCE(hostname, $6), vendor = COALESCE($7, vendor),
             wan_interface = $8, reported_name = COALESCE($9, reported_name)
         WHERE id = $1",
    )
    .bind(device_id)
    .bind(&inventory)
    .bind(errors.join(" · "))
    .bind(derived.os)
    .bind(derived.model)
    .bind(derived.hostname)
    .bind(derived.vendor)
    .bind(&wan)
    .bind(derived.reported_name)
    .execute(&state.db)
    .await?;

    if stats.iter().any(Option::is_some) {
        sqlx::query(
            "INSERT INTO device_stats (time, device_id, cpu_pct, mem_pct, disk_pct, temp_c, rx_bps, tx_bps, clients, power_w)
             VALUES (now(), $1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(device_id)
        .bind(stats[0].map(|v| v as f32))
        .bind(stats[1].map(|v| v as f32))
        .bind(stats[2].map(|v| v as f32))
        .bind(stats[3].map(|v| v as f32))
        .bind(stats[4])
        .bind(stats[5])
        .bind(stats[6].map(|v| v as f32))
        .bind(stats[7].map(|v| v as f32))
        .execute(&state.db)
        .await?;
    }
    // Verlauf je Schnittstelle (höchstens 64, nur mit Messwert)
    let rates: Vec<&InterfaceRate> = rates.iter().filter(|r| r.rx.is_some() || r.tx.is_some()).take(64).collect();
    if !rates.is_empty() {
        sqlx::query(
            "INSERT INTO interface_stats (time, device_id, name, rx_bps, tx_bps)
             SELECT now(), $1, u.name, u.rx, u.tx FROM UNNEST($2::text[], $3::float8[], $4::float8[]) AS u(name, rx, tx)",
        )
        .bind(device_id)
        .bind(rates.iter().map(|r| r.name.clone()).collect::<Vec<_>>())
        .bind(rates.iter().map(|r| r.rx).collect::<Vec<_>>())
        .bind(rates.iter().map(|r| r.tx).collect::<Vec<_>>())
        .execute(&state.db)
        .await?;
    }
    scanner::reclassify(&state.db, device_id).await?;
    Ok(())
}

/// Erfolgreiche automatische Zugangsdaten fest zuordnen
async fn link(state: &AppState, device_id: i64, cred: &Credential) -> sqlx::Result<()> {
    if !cred.linked {
        sqlx::query("INSERT INTO device_credentials (device_id, credential_id) VALUES ($1, $2) ON CONFLICT DO NOTHING")
            .bind(device_id)
            .bind(cred.id)
            .execute(&state.db)
            .await?;
    }
    Ok(())
}

struct Derived {
    reported_name: Option<String>,
    os: Option<String>,
    model: Option<String>,
    hostname: Option<String>,
    vendor: Option<String>,
}

fn text(v: &Value) -> Option<String> {
    v.as_str().map(str::trim).filter(|s| !s.is_empty()).map(str::to_string)
}

fn derive_fields(inv: &Value) -> Derived {
    let ssh = &inv["ssh"];
    let snmp = &inv["snmp"];
    let shelly = &inv["shelly"];
    let snmp_os = text(&snmp["sys_descr"]).map(|d| d.lines().next().unwrap_or_default().chars().take(120).collect());
    let shelly_os = shelly["generation"].as_u64().map(|g| format!("Shelly Gen{g}"));
    Derived {
        reported_name: text(&shelly["name"]),
        os: text(&ssh["os"]).or(snmp_os).or(shelly_os),
        model: text(&ssh["model"])
            .or_else(|| text(&shelly["model"]))
            .or_else(|| text(&snmp["synology"]["model"]))
            .or_else(|| text(&snmp["ups"]["model"]))
            .or_else(|| text(&snmp["model"])),
        hostname: text(&ssh["hostname"]).or_else(|| text(&snmp["sys_name"])).map(|h| h.to_lowercase()),
        vendor: text(&ssh["vendor"]).filter(|v| !v.eq_ignore_ascii_case("To Be Filled By O.E.M.")),
    }
}

pub(crate) struct InterfaceRate {
    name: String,
    rx: Option<f64>,
    tx: Option<f64>,
}

/// Datenrate je Schnittstelle aus der Differenz der Byte-Zähler zur vorherigen Abfrage
fn interface_rates(inv: &Value, previous: Option<&Value>) -> Vec<InterfaceRate> {
    let Some(prev) = previous else { return vec![] };
    let seconds = match (inv["collected_at"].as_str(), prev["collected_at"].as_str()) {
        (Some(a), Some(b)) => chrono::DateTime::parse_from_rfc3339(a)
            .ok()
            .zip(chrono::DateTime::parse_from_rfc3339(b).ok())
            .map(|(a, b)| (a - b).num_milliseconds() as f64 / 1000.0),
        _ => None,
    };
    let Some(seconds) = seconds.filter(|s| *s > 10.0 && *s < 7200.0) else { return vec![] };
    let source = if inv["ssh"]["interfaces"].is_array() { "ssh" } else { "snmp" };
    let (Some(now), Some(before)) = (inv[source]["interfaces"].as_array(), prev[source]["interfaces"].as_array()) else {
        return vec![];
    };
    now.iter()
        // Loopback (Typ 24) nicht mitzählen
        .filter(|iface| iface["type"].as_f64() != Some(24.0))
        .filter_map(|iface| {
            let name = iface["name"].as_str()?.to_string();
            let old = before.iter().find(|b| b["name"] == iface["name"])?;
            let rate = |field: &str| {
                let (n, o) = (iface[field].as_f64()?, old[field].as_f64()?);
                (n >= o).then(|| (n - o) * 8.0 / seconds)
            };
            Some(InterfaceRate { name, rx: rate("rx_bytes"), tx: rate("tx_bytes") })
        })
        .collect()
}

/// Internet-Anschluss erkennen: Schnittstelle der Standardroute (bei Routern/Firewalls)
/// oder eine Schnittstelle mit sprechendem Namen („WAN“, „Internet“, „PPPoE“ …)
fn detect_wan(inv: &Value, device_type: Option<&str>) -> Option<String> {
    let is_gateway = matches!(device_type, Some("router" | "firewall" | "network"));
    let route = text(&inv["snmp"]["default_route_if"]).or_else(|| text(&inv["ssh"]["default_route_if"]));
    if is_gateway {
        if let Some(route) = route {
            return Some(route);
        }
    }
    let interfaces = inv["snmp"]["interfaces"].as_array().or_else(|| inv["ssh"]["interfaces"].as_array())?;
    const HINTS: &[&str] = &["wan", "internet", "pppoe", "dsl", "wwan", "lte", "uplink"];
    interfaces
        .iter()
        .find(|i| {
            let label = format!("{} {}", i["name"].as_str().unwrap_or(""), i["alias"].as_str().unwrap_or("")).to_lowercase();
            label.split(|c: char| !c.is_alphanumeric()).any(|word| HINTS.iter().any(|h| word.starts_with(h)))
        })
        .and_then(|i| text(&i["name"]))
}

/// Messwerte: [CPU %, RAM %, höchste Datenträger-Belegung %, Temperatur °C, Empfang bit/s, Senden bit/s,
/// WLAN-Clients, Leistung W]
/// Bei Geräten mit Internet-Anschluss zählt dessen Datenrate, sonst die Summe aller Schnittstellen.
fn derive_stats(inv: &Value, rates: &[InterfaceRate], wan: Option<&str>) -> [Option<f64>; 8] {
    let ssh = &inv["ssh"];
    let snmp = &inv["snmp"];
    let cpu = ssh["cpu_pct"].as_f64().or_else(|| snmp["cpu_pct"].as_f64());
    let storage = snmp["storage"].as_array();
    let mem = ssh["mem_pct"].as_f64().or_else(|| {
        storage?.iter().find(|s| s["kind"] == "ram").and_then(|s| s["pct"].as_f64())
    });
    let disk = ssh["disks"]
        .as_array()
        .and_then(|d| d.iter().filter_map(|x| x["pct"].as_f64()).reduce(f64::max))
        .or_else(|| {
            storage?.iter().filter(|s| s["kind"] == "disk").filter_map(|s| s["pct"].as_f64()).reduce(f64::max)
        });
    let temp = [
        ssh["temp_c"].as_f64(),
        snmp["temp_c"].as_f64(),
        snmp["synology"]["temp_c"].as_f64(),
        snmp["mikrotik"]["temp_c"].as_f64(),
        inv["shelly"]["temp_c"].as_f64(),
    ]
    .into_iter()
    .flatten()
    .reduce(f64::max);
    let clients = snmp["unifi"]["clients"].as_f64().or_else(|| snmp["mikrotik"]["clients"].as_f64());

    let (rx, tx) = match wan.and_then(|w| rates.iter().find(|r| r.name == w)) {
        Some(r) => (r.rx, r.tx),
        None if rates.is_empty() => (None, None),
        None => (Some(rates.iter().filter_map(|r| r.rx).sum()), Some(rates.iter().filter_map(|r| r.tx).sum())),
    };
    [cpu, mem, disk, temp, rx, tx, clients, inv["shelly"]["power_w"].as_f64()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn datenrate_aus_zaehlerdifferenz() {
        let prev = json!({ "collected_at": "2026-01-01T10:00:00Z",
            "ssh": { "interfaces": [{ "name": "eth0", "rx_bytes": 1000.0, "tx_bytes": 500.0 }] } });
        let now = json!({ "collected_at": "2026-01-01T10:05:00Z",
            "ssh": { "cpu_pct": 12.5, "mem_pct": 40.0,
                     "disks": [{ "pct": 10.0 }, { "pct": 80.0 }],
                     "interfaces": [{ "name": "eth0", "rx_bytes": 301000.0, "tx_bytes": 500.0 }] } });
        let rates = interface_rates(&now, Some(&prev));
        let s = derive_stats(&now, &rates, None);
        assert_eq!(s[0], Some(12.5));
        assert_eq!(s[2], Some(80.0));
        assert_eq!(s[4], Some(8000.0)); // 300.000 Byte in 300 s = 8.000 bit/s
        assert_eq!(s[5], Some(0.0));
    }
}
