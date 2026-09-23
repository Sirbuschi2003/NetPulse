//! Geräteerkennung: durchsucht alle freigegebenen Netze nach aktiven Geräten.
//!
//! Ablauf je Durchlauf:
//! 1. Jede Adresse per ICMP-Ping prüfen, bei fehlender Antwort per TCP-Verbindungsversuch
//! 2. ARP-Tabelle lesen: findet auch Geräte, die Ping und TCP blockieren (nur lokales Segment)
//! 3. Für jedes aktive Gerät offene Ports und DNS-Namen ermitteln und speichern

use std::{
    collections::{HashMap, HashSet},
    net::Ipv4Addr,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::Result;
use futures::{stream, StreamExt};
use serde_json::json;

use crate::{
    scanner::{
        add_event,
        net::{self, Pinger},
    },
    AppState,
};

pub async fn run(state: AppState, pinger: Arc<Pinger>) {
    // Kurz warten, damit der Webserver zuerst startet
    tokio::time::sleep(Duration::from_secs(5)).await;
    loop {
        match discover_once(&state, &pinger).await {
            Ok(Some(found)) => tracing::info!("Discovery abgeschlossen: {found} aktive Geräte"),
            Ok(None) => tracing::info!("Keine Netze freigegeben – Discovery übersprungen"),
            Err(e) => tracing::error!("Discovery fehlgeschlagen: {e:#}"),
        }
        // Warten bis zum nächsten Intervall – oder bis jemand „Jetzt scannen“ klickt
        tokio::select! {
            _ = tokio::time::sleep(state.config.discovery_interval) => {}
            _ = state.scan_trigger.notified() => tracing::info!("Scan manuell gestartet"),
        }
    }
}

async fn discover_once(state: &AppState, pinger: &Arc<Pinger>) -> Result<Option<usize>> {
    let started = Instant::now();
    let networks: Vec<(String,)> = sqlx::query_as("SELECT cidr::text FROM networks WHERE enabled")
        .fetch_all(&state.db)
        .await?;

    let mut targets: Vec<Ipv4Addr> = Vec::new();
    for (cidr,) in &networks {
        match net::parse_cidr(cidr) {
            Ok((addr, prefix)) => targets.extend(net::hosts(addr, prefix)),
            Err(e) => tracing::warn!("Netz {cidr} übersprungen: {e}"),
        }
    }
    targets.sort();
    targets.dedup();
    if targets.is_empty() {
        return Ok(None);
    }
    tracing::info!("Discovery startet: {} Adressen in {} Netz(en)", targets.len(), networks.len());

    // 1. Wer antwortet? 128 Adressen gleichzeitig prüfen
    let alive: Vec<(Ipv4Addr, Option<Duration>)> = stream::iter(targets.iter().copied())
        .map(|ip| {
            let pinger = pinger.clone();
            async move {
                let rtt = match pinger.ping(ip, Duration::from_millis(800)).await {
                    Some(rtt) => Some(rtt),
                    None => net::tcp_alive(ip, net::LIVENESS_PORTS, Duration::from_millis(500)).await,
                };
                (ip, rtt)
            }
        })
        .buffer_unordered(128)
        .filter_map(|(ip, rtt)| async move { rtt.map(|rtt| (ip, Some(rtt))) })
        .collect()
        .await;
    let mut found: HashMap<Ipv4Addr, Option<Duration>> = alive.into_iter().collect();

    // 2. ARP-Tabelle: Der Kernel hat beim Pingen jede antwortende MAC-Adresse gelernt
    let arp = Arc::new(net::read_arp_table());
    let wanted: HashSet<Ipv4Addr> = targets.iter().copied().collect();
    for ip in arp.keys().filter(|ip| wanted.contains(ip)) {
        found.entry(*ip).or_insert(None);
    }

    // 3. Details sammeln und speichern (16 Geräte parallel, je Gerät ~30 Port-Prüfungen)
    let count = found.len();
    let results: Vec<Result<()>> = stream::iter(found)
        .map(|(ip, rtt)| {
            let state = state.clone();
            let mac = arp.get(&ip).cloned();
            async move { store_device(&state, ip, rtt, mac).await }
        })
        .buffer_unordered(16)
        .collect()
        .await;
    for error in results.into_iter().filter_map(Result::err) {
        tracing::warn!("Gerät konnte nicht gespeichert werden: {error:#}");
    }

    let summary = json!({
        "time": chrono::Utc::now(),
        "found": count,
        "scanned": targets.len(),
        "duration_s": started.elapsed().as_secs(),
    });
    sqlx::query(
        "INSERT INTO settings (key, value) VALUES ('last_discovery', $1)
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
    )
    .bind(summary)
    .execute(&state.db)
    .await?;
    Ok(Some(count))
}

async fn store_device(state: &AppState, ip: Ipv4Addr, rtt: Option<Duration>, mac: Option<String>) -> Result<()> {
    let ports: Vec<i32> = net::scan_ports(ip).await.into_iter().map(i32::from).collect();
    let hostname = net::reverse_dns(ip).await;
    let rtt_ms = rtt.map(|d| d.as_secs_f32() * 1000.0);

    // Einfügen oder aktualisieren. `xmax = 0` ist ein PostgreSQL-Trick, um zu erkennen,
    // ob die Zeile neu eingefügt wurde; `old` liefert die vorherige MAC-Adresse.
    let (id, inserted, old_mac): (i64, bool, Option<String>) = sqlx::query_as(
        "WITH old AS (SELECT mac FROM devices WHERE ip = $1::inet)
         INSERT INTO devices (ip, mac, hostname, open_ports, status, last_rtt_ms, last_seen, last_check)
         VALUES ($1::inet, $2, $3, $4, 'up', $5, now(), now())
         ON CONFLICT (ip) DO UPDATE SET
             mac        = COALESCE(EXCLUDED.mac, devices.mac),
             hostname   = COALESCE(EXCLUDED.hostname, devices.hostname),
             open_ports = EXCLUDED.open_ports,
             last_seen  = now()
         RETURNING id, (xmax = 0), (SELECT mac FROM old)",
    )
    .bind(ip.to_string())
    .bind(&mac)
    .bind(&hostname)
    .bind(&ports)
    .bind(rtt_ms)
    .fetch_one(&state.db)
    .await?;

    let label = hostname.unwrap_or_else(|| ip.to_string());
    if inserted {
        add_event(&state.db, id, "discovered", &format!("Neues Gerät entdeckt: {label} ({ip})")).await?;
    } else if let (Some(old), Some(new)) = (&old_mac, &mac) {
        if old != new {
            let message = format!(
                "MAC-Adresse von {ip} hat sich geändert: {old} → {new} (neues Gerät oder möglicher ARP-Spoofing-Versuch)"
            );
            add_event(&state.db, id, "mac_changed", &message).await?;
        }
    }
    Ok(())
}
