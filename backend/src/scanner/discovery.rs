//! Geräteerkennung: durchsucht die freigegebenen Netze nach aktiven Geräten.
//!
//! Jedes Netz wird einzeln gescannt. Aufträge kommen über einen Kanal:
//! - regelmäßig alle `DISCOVERY_INTERVAL_MIN` Minuten für alle Netze,
//! - sofort für ein gerade hinzugefügtes Netz (hat Vorrang vor dem Rest eines laufenden Durchlaufs),
//! - „Jetzt scannen“ in der Oberfläche.
//!
//! Ablauf je Netz:
//! 1. Jede Adresse per ICMP-Ping prüfen, bei fehlender Antwort per TCP-Verbindungsversuch
//! 2. ARP-Tabelle lesen: findet auch Geräte, die Ping und TCP blockieren (nur lokales Segment)
//! 3. Für jedes aktive Gerät Ports, DNS-Name und Hersteller ermitteln, Typ erkennen, speichern

use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::Ipv4Addr,
    sync::{atomic::Ordering, Arc},
    time::{Duration, Instant},
};

use anyhow::Result;
use futures::{stream, StreamExt};
use serde_json::json;
use tokio::sync::mpsc::UnboundedReceiver;

use crate::{
    oui,
    scanner::{
        add_event,
        names,
        net::{self, Pinger},
        reclassify, ScanRequest,
    },
    AppState,
};

/// Gleichzeitig geprüfte Adressen. Bewusst begrenzt: Jede Adresse im lokalen Netz erzeugt einen
/// ARP-Eintrag, und die Nachbartabelle des Kernels fasst standardmäßig nur ca. 1024 Einträge.
const SWEEP_PARALLEL: usize = 128;

pub async fn run(state: AppState, pinger: Arc<Pinger>, mut requests: UnboundedReceiver<ScanRequest>) {
    // Kurz warten, damit der Webserver zuerst startet
    tokio::time::sleep(Duration::from_secs(5)).await;
    let mut next_full_scan = tokio::time::Instant::now();

    loop {
        let first = tokio::select! {
            request = requests.recv() => match request {
                Some(request) => request,
                None => return,
            },
            _ = tokio::time::sleep_until(next_full_scan) => ScanRequest::All,
        };

        let mut queue: VecDeque<i64> = VecDeque::new();
        let mut full = false;
        take(first, &mut queue, &mut full);
        while let Ok(request) = requests.try_recv() {
            take(request, &mut queue, &mut full);
        }
        if full {
            next_full_scan = tokio::time::Instant::now() + state.config.discovery_interval;
            match enabled_network_ids(&state).await {
                Ok(ids) => {
                    for id in ids {
                        if !queue.contains(&id) {
                            queue.push_back(id);
                        }
                    }
                }
                Err(e) => tracing::error!("Netze konnten nicht geladen werden: {e:#}"),
            }
        }

        while let Some(network_id) = queue.pop_front() {
            if let Err(e) = scan_network(&state, &pinger, network_id, queue.len()).await {
                tracing::error!("Scan von Netz {network_id} fehlgeschlagen: {e:#}");
            }
            // Während des Scans eingegangene Aufträge berücksichtigen
            while let Ok(request) = requests.try_recv() {
                if let ScanRequest::Network(id) = request {
                    if !queue.contains(&id) {
                        queue.push_front(id);
                    }
                }
            }
        }
        state.scan_progress.finish();
    }
}

fn take(request: ScanRequest, queue: &mut VecDeque<i64>, full: &mut bool) {
    match request {
        ScanRequest::All => *full = true,
        // Einzelaufträge (z. B. neues Netz) kommen nach vorne
        ScanRequest::Network(id) if !queue.contains(&id) => queue.push_front(id),
        ScanRequest::Network(_) => {}
    }
}

async fn enabled_network_ids(state: &AppState) -> sqlx::Result<Vec<i64>> {
    let rows: Vec<(i64,)> = sqlx::query_as("SELECT id FROM networks WHERE enabled ORDER BY masklen(cidr) DESC, cidr")
        .fetch_all(&state.db)
        .await?;
    Ok(rows.into_iter().map(|r| r.0).collect())
}

async fn scan_network(state: &AppState, pinger: &Arc<Pinger>, network_id: i64, queued: usize) -> Result<()> {
    let Some((cidr,)): Option<(String,)> =
        sqlx::query_as("SELECT cidr::text FROM networks WHERE id = $1 AND enabled")
            .bind(network_id)
            .fetch_optional(&state.db)
            .await?
    else {
        return Ok(()); // inzwischen gelöscht oder deaktiviert
    };
    let (addr, prefix) = net::parse_cidr(&cidr)?;
    let targets = net::hosts(addr, prefix);
    let started = Instant::now();
    let progress = state.scan_progress.clone();
    progress.start(&cidr, targets.len(), queued);
    tracing::info!("Scan startet: {cidr} ({} Adressen)", targets.len());

    // 1. Wer antwortet? Ein Ping (600 ms), sonst TCP-Verbindungsversuch (400 ms)
    let alive: Vec<(Ipv4Addr, Option<Duration>)> = stream::iter(targets.iter().copied())
        .map(|ip| {
            let pinger = pinger.clone();
            let progress = progress.clone();
            async move {
                let rtt = match pinger.ping(ip, Duration::from_millis(600), 1).await {
                    Some(rtt) => Some(rtt),
                    None => net::tcp_alive(ip, net::LIVENESS_PORTS, Duration::from_millis(400)).await,
                };
                progress.done.fetch_add(1, Ordering::Relaxed);
                if rtt.is_some() {
                    progress.found.fetch_add(1, Ordering::Relaxed);
                }
                (ip, rtt)
            }
        })
        .buffer_unordered(SWEEP_PARALLEL)
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
    progress.found.store(found.len(), Ordering::Relaxed);

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

    let duration = started.elapsed().as_secs();
    sqlx::query(
        "UPDATE networks SET last_scan_at = now(), last_scan_found = $2, last_scan_duration_s = $3 WHERE id = $1",
    )
    .bind(network_id)
    .bind(count as i32)
    .bind(duration as i32)
    .execute(&state.db)
    .await?;
    let summary = json!({
        "time": chrono::Utc::now(),
        "network": cidr,
        "found": count,
        "scanned": targets.len(),
        "duration_s": duration,
    });
    sqlx::query(
        "INSERT INTO settings (key, value) VALUES ('last_discovery', $1)
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
    )
    .bind(summary)
    .execute(&state.db)
    .await?;
    tracing::info!("Scan von {cidr} abgeschlossen: {count} aktive Geräte in {duration} s");
    Ok(())
}

async fn store_device(state: &AppState, ip: Ipv4Addr, rtt: Option<Duration>, mac: Option<String>) -> Result<()> {
    let ports: Vec<i32> = net::scan_ports(ip).await.into_iter().map(i32::from).collect();
    // Namen aus DNS, mDNS/Bonjour und NetBIOS parallel abfragen; Shelly an Port 80 erkennen
    let shelly_probe = async {
        if ports.contains(&80) {
            crate::collect::shelly::probe(ip).await
        } else {
            None
        }
    };
    let (hostname, mdns, netbios, shelly) =
        tokio::join!(net::reverse_dns(ip), names::mdns_name(ip), names::netbios_name(ip), shelly_probe);
    let reported_name = shelly.as_ref().and_then(|s| s.name.clone()).or(mdns).or(netbios);
    let integration = shelly.as_ref().map(|_| "shelly");
    let model = shelly.as_ref().and_then(|s| s.model.clone());
    let vendor = if shelly.is_some() { Some("Shelly".to_string()) } else { mac.as_deref().and_then(oui::lookup) };
    let rtt_ms = rtt.map(|d| d.as_secs_f32() * 1000.0);

    // Einfügen oder aktualisieren. `xmax = 0` ist ein PostgreSQL-Trick, um zu erkennen,
    // ob die Zeile neu eingefügt wurde; `old` liefert die vorherige MAC-Adresse.
    let (id, inserted, old_mac): (i64, bool, Option<String>) = sqlx::query_as(
        "WITH old AS (SELECT mac FROM devices WHERE ip = $1::inet)
         INSERT INTO devices (ip, mac, hostname, vendor, open_ports, status, status_since, last_rtt_ms, last_seen, last_check,
                              reported_name, integration, model)
         VALUES ($1::inet, $2, $3, $4, $5, 'up', now(), $6, now(), now(), $7, $8, $9)
         ON CONFLICT (ip) DO UPDATE SET
             mac           = COALESCE(EXCLUDED.mac, devices.mac),
             hostname      = COALESCE(EXCLUDED.hostname, devices.hostname),
             vendor        = COALESCE(EXCLUDED.vendor, devices.vendor),
             open_ports    = EXCLUDED.open_ports,
             reported_name = COALESCE(EXCLUDED.reported_name, devices.reported_name),
             integration   = COALESCE(EXCLUDED.integration, devices.integration),
             model         = COALESCE(devices.model, EXCLUDED.model),
             last_seen     = now()
         RETURNING id, (xmax = 0), (SELECT mac FROM old)",
    )
    .bind(ip.to_string())
    .bind(&mac)
    .bind(&hostname)
    .bind(&vendor)
    .bind(&ports)
    .bind(rtt_ms)
    .bind(&reported_name)
    .bind(integration)
    .bind(&model)
    .fetch_one(&state.db)
    .await?;

    reclassify(&state.db, id).await?;

    let label = reported_name.or(hostname).unwrap_or_else(|| ip.to_string());
    if inserted {
        let vendor_info = vendor.map(|v| format!(", {v}")).unwrap_or_default();
        add_event(&state.db, id, "discovered", &format!("Neues Gerät entdeckt: {label} ({ip}{vendor_info})")).await?;
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
