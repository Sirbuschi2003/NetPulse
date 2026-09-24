//! Netzwerk-Hilfsfunktionen: Netze zerlegen, ICMP-Ping, TCP-Prüfung, ARP-Tabelle, Reverse-DNS.

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::atomic::{AtomicU16, Ordering},
    time::{Duration, Instant},
};

use anyhow::{bail, Context, Result};
use futures::future::join_all;
use surge_ping::{Client, Config, PingIdentifier, PingSequence};
use tokio::net::TcpStream;

/// Ports, die bei der Erkennung geprüft werden. Sie verraten viel über den Gerätetyp
/// (z. B. 9100 = Drucker, 8006 = Proxmox, 5000/5001 = Synology, 3389 = Windows-RDP).
pub const COMMON_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 548, 554, 631, 993, 1883, 3306, 3389, 5000, 5001,
    5432, 5900, 5985, 5986, 8006, 8080, 8443, 9100,
];

/// Ports für die Erreichbarkeitsprüfung, wenn ein Gerät nicht auf Ping antwortet
/// (Windows blockiert Ping z. B. standardmäßig).
pub const LIVENESS_PORTS: &[u16] = &[443, 80, 22, 445, 3389];

/// Größtes erlaubtes Netz pro Eintrag: /16 = 65.534 Adressen (ein Scan dauert dann einige Minuten)
pub const MIN_PREFIX: u8 = 16;

/// Zerlegt „192.168.1.0/24“ in Netzadresse und Präfix. Host-Bits werden auf 0 gesetzt,
/// aus „192.168.1.17/24“ wird also „192.168.1.0/24“.
pub fn parse_cidr(input: &str) -> Result<(Ipv4Addr, u8)> {
    let (addr, prefix) = input
        .trim()
        .split_once('/')
        .context("Netz bitte im Format 192.168.1.0/24 angeben")?;
    let addr: Ipv4Addr = addr.parse().context("Ungültige IPv4-Adresse")?;
    let prefix: u8 = prefix.parse().context("Ungültiges Präfix")?;
    if prefix > 32 {
        bail!("Präfix muss zwischen /{MIN_PREFIX} und /32 liegen");
    }
    if prefix < MIN_PREFIX {
        bail!("Netz zu groß: höchstens /{MIN_PREFIX} (65.534 Adressen) pro Eintrag – bitte aufteilen");
    }
    let mask = u32::MAX << (32 - prefix);
    Ok((Ipv4Addr::from(u32::from(addr) & mask), prefix))
}

/// Alle nutzbaren Host-Adressen eines Netzes (ohne Netz- und Broadcast-Adresse).
pub fn hosts(network: Ipv4Addr, prefix: u8) -> Vec<Ipv4Addr> {
    let start = u32::from(network);
    let size = 1u32 << (32 - prefix);
    let range = if prefix >= 31 { 0..size } else { 1..size - 1 };
    range.map(|i| Ipv4Addr::from(start + i)).collect()
}

// ---------------------------------------------------------------------------
// ICMP-Ping
// ---------------------------------------------------------------------------

pub struct Pinger {
    /// `None`, wenn ICMP nicht erlaubt ist (fehlende Capability NET_RAW)
    client: Option<Client>,
    next_id: AtomicU16,
}

impl Pinger {
    pub fn new() -> Self {
        let client = match Client::new(&Config::default()) {
            Ok(client) => Some(client),
            Err(e) => {
                tracing::warn!(
                    "ICMP-Ping nicht verfügbar ({e}) – es werden nur TCP-Prüfungen genutzt. \
                     Der Container braucht die Capability NET_RAW."
                );
                None
            }
        };
        Self { client, next_id: AtomicU16::new(1) }
    }

    /// Sendet bis zu `tries` Pings. Liefert die Antwortzeit oder `None`.
    pub async fn ping(&self, ip: Ipv4Addr, timeout: Duration, tries: u16) -> Option<Duration> {
        let client = self.client.as_ref()?;
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let mut pinger = client.pinger(IpAddr::V4(ip), PingIdentifier(id)).await;
        pinger.timeout(timeout);
        for seq in 0..tries {
            if let Ok((_, rtt)) = pinger.ping(PingSequence(seq), &[0u8; 32]).await {
                return Some(rtt);
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// TCP
// ---------------------------------------------------------------------------

pub enum TcpResult {
    /// Port offen
    Open(Duration),
    /// Port geschlossen – das Gerät hat aber geantwortet, ist also erreichbar
    Refused(Duration),
    /// Keine Antwort (Gerät aus oder Firewall verwirft)
    NoAnswer,
}

pub async fn tcp_probe(ip: Ipv4Addr, port: u16, timeout: Duration) -> TcpResult {
    let started = Instant::now();
    match tokio::time::timeout(timeout, TcpStream::connect(SocketAddr::from((ip, port)))).await {
        Ok(Ok(_)) => TcpResult::Open(started.elapsed()),
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
            TcpResult::Refused(started.elapsed())
        }
        _ => TcpResult::NoAnswer,
    }
}

/// Prüft mehrere Ports gleichzeitig; liefert die schnellste Antwortzeit, falls das Gerät reagiert.
pub async fn tcp_alive(ip: Ipv4Addr, ports: &[u16], timeout: Duration) -> Option<Duration> {
    let probes = ports.iter().map(|&port| tcp_probe(ip, port, timeout));
    join_all(probes)
        .await
        .into_iter()
        .filter_map(|result| match result {
            TcpResult::Open(rtt) | TcpResult::Refused(rtt) => Some(rtt),
            TcpResult::NoAnswer => None,
        })
        .min()
}

/// Liefert alle offenen Ports aus `COMMON_PORTS`.
pub async fn scan_ports(ip: Ipv4Addr) -> Vec<u16> {
    let probes = COMMON_PORTS.iter().map(|&port| async move {
        matches!(tcp_probe(ip, port, Duration::from_millis(700)).await, TcpResult::Open(_)).then_some(port)
    });
    join_all(probes).await.into_iter().flatten().collect()
}

// ---------------------------------------------------------------------------
// ARP und DNS
// ---------------------------------------------------------------------------

/// Liest die ARP-Tabelle des Linux-Kernels (IP → MAC). Funktioniert nur mit
/// `network_mode: host` und nur für Geräte im selben Netzsegment.
pub fn read_arp_table() -> HashMap<Ipv4Addr, String> {
    let Ok(content) = std::fs::read_to_string("/proc/net/arp") else {
        return HashMap::new();
    };
    // Format: IP address  HW type  Flags  HW address  Mask  Device
    content
        .lines()
        .skip(1)
        .filter_map(|line| {
            let cols: Vec<&str> = line.split_whitespace().collect();
            let ip: Ipv4Addr = cols.first()?.parse().ok()?;
            let flags = u32::from_str_radix(cols.get(2)?.trim_start_matches("0x"), 16).ok()?;
            let mac = cols.get(3)?.to_lowercase();
            // Flag 0x2 = Eintrag vollständig aufgelöst
            (flags & 0x2 != 0 && mac != "00:00:00:00:00:00").then_some((ip, mac))
        })
        .collect()
}

/// Rückwärtsauflösung IP → Name (z. B. „nas.fritz.box“), höchstens 3 Sekunden.
pub async fn reverse_dns(ip: Ipv4Addr) -> Option<String> {
    let lookup = tokio::task::spawn_blocking(move || dns_lookup::lookup_addr(&IpAddr::V4(ip)).ok());
    let name = tokio::time::timeout(Duration::from_secs(3), lookup).await.ok()?.ok()??;
    let name = name.trim_end_matches('.').to_string();
    (name != ip.to_string()).then_some(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_wird_normalisiert() {
        let (addr, prefix) = parse_cidr("192.168.1.17/24").unwrap();
        assert_eq!(addr, Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(prefix, 24);
    }

    #[test]
    fn zu_grosse_netze_werden_abgelehnt() {
        assert!(parse_cidr("10.0.0.0/8").is_err());
        assert!(parse_cidr("10.0.0.0/15").is_err());
        assert_eq!(parse_cidr("10.10.0.0/16").unwrap().1, 16);
        assert!(parse_cidr("10.0.0.0/33").is_err());
        assert!(parse_cidr("kein-netz").is_err());
    }

    #[test]
    fn hosts_ohne_netz_und_broadcast() {
        let hosts = hosts(Ipv4Addr::new(192, 168, 1, 0), 24);
        assert_eq!(hosts.len(), 254);
        assert_eq!(hosts.first(), Some(&Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(hosts.last(), Some(&Ipv4Addr::new(192, 168, 1, 254)));
        assert_eq!(super::hosts(Ipv4Addr::new(10, 0, 0, 5), 32), vec![Ipv4Addr::new(10, 0, 0, 5)]);
    }
}
