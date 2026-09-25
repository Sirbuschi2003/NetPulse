//! Verbundene Geräte („Clients“) aus verschiedenen Quellen, einheitlich aufbereitet.
//!
//! Quellen (nach Aussagekraft sortiert – beim Zusammenführen gewinnt die bessere):
//! - `unifi`    UniFi-Controller: WLAN/Kabel, AP/Switch-Port, Signal, Datenraten
//! - `mikrotik` MikroTik RouterOS (REST): WLAN-Registrierungen, Bridge-Hosts, ARP, DHCP
//! - `fritzbox` AVM FRITZ!Box (TR-064): Geräteliste, WLAN-Signal, Verbindungsgeschwindigkeit
//! - `wifi`     Linux/OpenWrt-Access-Points per SSH (`iw station dump`)
//! - `opnsense` OPNsense-API: ARP, DHCP-Namen, Datenrate je Gerät (Top Talkers)
//! - `switch`   verwaltete Switches per SNMP (BRIDGE-/Q-BRIDGE-MIB): Port je MAC-Adresse
//! - `router`   ARP-Tabellen und DHCP-Leases (SSH/SNMP): IP ↔ MAC ↔ Name
//!
//! Jeder Client ist ein JSON-Objekt mit (soweit bekannt): `mac`, `ip`, `name`, `hostname`, `vendor`,
//! `type` (wireless|wired), `uplink_name`/`uplink_mac`/`port`, `ssid`, `band`, `channel`, `wifi_standard`,
//! `signal_dbm`, `satisfaction`, `link_down_kbps`/`link_up_kbps`, `down_bps`/`up_bps`,
//! `down_bytes`/`up_bytes`, `uptime_s`, `connected_at`, `network`, `vlan`, `guest` und `source`.
//! Richtung immer aus Sicht des Clients: „down“ = zum Client, „up“ = vom Client.

use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

use serde_json::{json, Map, Value};

/// (Schlüssel, Anzeige, Rang – kleiner = aussagekräftiger)
pub const SOURCES: &[(&str, &str, u8)] = &[
    ("unifi", "UniFi", 0),
    ("mikrotik", "MikroTik", 1),
    ("fritzbox", "FRITZ!Box", 2),
    ("wifi", "WLAN-Access-Point", 3),
    ("opnsense", "OPNsense", 4),
    ("switch", "Switch", 5),
    ("router", "Router", 6),
];

pub fn source_label(key: &str) -> &'static str {
    SOURCES.iter().find(|s| s.0 == key).map_or("Netz", |s| s.1)
}

pub fn rank(key: &str) -> u8 {
    SOURCES.iter().find(|s| s.0 == key).map_or(9, |s| s.2)
}

/// MAC-Adresse vereinheitlichen: „AA-BB-CC-DD-EE-FF“, „aabb.ccdd.eeff“ → „aa:bb:cc:dd:ee:ff“
pub fn norm_mac(raw: &str) -> Option<String> {
    let hex: String = raw.chars().filter(char::is_ascii_hexdigit).collect::<String>().to_lowercase();
    if hex.len() != 12 || hex == "000000000000" || hex == "ffffffffffff" {
        return None;
    }
    let mac = (0..6).map(|i| &hex[i * 2..i * 2 + 2]).collect::<Vec<_>>().join(":");
    Some(mac)
}

pub fn band_of_mhz(mhz: f64) -> Option<&'static str> {
    match mhz as u32 {
        2400..=2500 => Some("2,4 GHz"),
        4900..=5900 => Some("5 GHz"),
        5925..=7125 => Some("6 GHz"),
        _ => None,
    }
}

/// Neuer Client-Eintrag einer Quelle
pub fn client(source: &str, mac: &str) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("source".into(), json!(source));
    m.insert("mac".into(), json!(mac));
    m
}

/// Wert nur setzen, wenn vorhanden
pub fn put(m: &mut Map<String, Value>, key: &str, value: Value) {
    if !value.is_null() && value != json!("") {
        m.insert(key.into(), value);
    }
}

// ---------------------------------------------------------------------------
// Datenraten aus Byte-Zählern (zwei Abfragen im Abstand → Bit/s)
// ---------------------------------------------------------------------------

type Counters = HashMap<String, (f64, f64, Instant)>;
static COUNTERS: Mutex<Option<Counters>> = Mutex::new(None);

/// `key`: eindeutig je Quelle und Client (z. B. „wifi:12:aa:bb…“). Zähler-Neustart → keine Rate.
pub fn rates(key: &str, down_bytes: Option<f64>, up_bytes: Option<f64>) -> (Option<f64>, Option<f64>) {
    let (Some(down), Some(up)) = (down_bytes, up_bytes) else { return (None, None) };
    let now = Instant::now();
    let mut guard = COUNTERS.lock().unwrap();
    let map = guard.get_or_insert_with(HashMap::new);
    // Alte Einträge (Geräte längst weg) aufräumen
    if map.len() > 5000 {
        map.retain(|_, v| now.duration_since(v.2) < Duration::from_secs(3600));
    }
    let previous = map.insert(key.to_string(), (down, up, now));
    match previous {
        Some((d0, u0, t0)) => {
            let secs = now.duration_since(t0).as_secs_f64();
            if secs < 1.0 || down < d0 || up < u0 {
                return (None, None);
            }
            (Some((down - d0) * 8.0 / secs), Some((up - u0) * 8.0 / secs))
        }
        None => (None, None),
    }
}

// ---------------------------------------------------------------------------
// SSH: Ausgabe des Sammel-Skripts (Linux, OpenWrt, OPNsense/pfSense)
// ---------------------------------------------------------------------------

/// SSID, Kanal und Frequenz (MHz) einer WLAN-Schnittstelle
type WifiIf<'a> = (Option<&'a str>, Option<u32>, Option<f64>);

/// Zeilen `wifi_if=IF|SSID|KANAL|MHZ`, `sta=IF|<iw station dump>`, `neigh=IP|MAC|IF`, `lease=MAC|IP|NAME`.
/// `device_key` macht die Zählerschlüssel für die Datenraten eindeutig.
pub fn from_ssh(lines: &[(&str, &str)], device_key: &str) -> Vec<Value> {
    let mut out: Vec<Value> = Vec::new();
    // WLAN-Schnittstellen: SSID, Kanal, Band
    let mut ifs: HashMap<&str, WifiIf> = HashMap::new();
    for (k, v) in lines {
        if *k == "wifi_if" {
            let p: Vec<&str> = v.split('|').collect();
            if let Some(name) = p.first() {
                ifs.insert(
                    name,
                    (p.get(1).copied().filter(|s| !s.trim().is_empty()), p.get(2).and_then(|c| c.trim().parse().ok()), p.get(3).and_then(|f| f.trim().parse().ok())),
                );
            }
        }
    }
    // Stationen blockweise
    let mut current: Option<Map<String, Value>> = None;
    let mut counters = (None, None);
    let finish = |c: Option<Map<String, Value>>, counters: (Option<f64>, Option<f64>), out: &mut Vec<Value>| {
        if let Some(mut c) = c {
            let mac = c["mac"].as_str().unwrap_or_default().to_string();
            let (down, up) = rates(&format!("{device_key}:wifi:{mac}"), counters.0, counters.1);
            put(&mut c, "down_bps", json!(down));
            put(&mut c, "up_bps", json!(up));
            out.push(Value::Object(c));
        }
    };
    for (k, v) in lines {
        if *k != "sta" {
            continue;
        }
        let Some((ifname, line)) = v.split_once('|') else { continue };
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("Station ") {
            finish(current.take(), counters, &mut out);
            counters = (None, None);
            let Some(mac) = rest.split_whitespace().next().and_then(norm_mac) else { continue };
            let mut c = client("wifi", &mac);
            c.insert("type".into(), json!("wireless"));
            c.insert("interface".into(), json!(ifname));
            if let Some((ssid, channel, mhz)) = ifs.get(ifname) {
                put(&mut c, "ssid", json!(ssid));
                put(&mut c, "channel", json!(channel));
                put(&mut c, "band", json!(mhz.and_then(band_of_mhz)));
            }
            current = Some(c);
            continue;
        }
        let Some(c) = current.as_mut() else { continue };
        let Some((key, value)) = line.split_once(':') else { continue };
        let value = value.trim();
        let first_num = || value.split_whitespace().next().and_then(|n| n.parse::<f64>().ok());
        match key.trim() {
            "rx bytes" => counters.1 = first_num(),
            "tx bytes" => counters.0 = first_num(),
            "signal" => put(c, "signal_dbm", json!(first_num())),
            // Bitraten in MBit/s → kbit/s (wie UniFi)
            "tx bitrate" => {
                put(c, "link_down_kbps", json!(first_num().map(|m| m * 1000.0)));
                put(c, "wifi_standard", json!(wifi_standard(value)));
            }
            "rx bitrate" => put(c, "link_up_kbps", json!(first_num().map(|m| m * 1000.0))),
            "connected time" => {
                let secs = first_num();
                put(c, "uptime_s", json!(secs));
                put(c, "connected_at", json!(secs.map(|s| chrono::Utc::now() - chrono::Duration::seconds(s as i64))));
            }
            _ => {}
        }
        if key.trim() == "rx bytes" || key.trim() == "tx bytes" {
            put(c, if key.trim() == "tx bytes" { "down_bytes" } else { "up_bytes" }, json!(first_num()));
        }
    }
    finish(current.take(), counters, &mut out);

    // Namen aus DHCP-Leases, IP aus ARP
    let mut names: HashMap<String, (Option<String>, Option<String>)> = HashMap::new();
    for (k, v) in lines.iter().filter(|(k, _)| *k == "lease") {
        let _ = k;
        let p: Vec<&str> = v.split('|').collect();
        let Some(mac) = p.first().and_then(|m| norm_mac(m)) else { continue };
        let ip = p.get(1).map(|s| s.trim().to_string()).filter(|s| s.parse::<std::net::Ipv4Addr>().is_ok());
        let name = p.get(2).map(|s| s.trim().trim_matches('"').to_string()).filter(|s| !s.is_empty() && s != "*");
        names.insert(mac, (ip, name));
    }
    let mut neigh: HashMap<String, (String, Option<String>)> = HashMap::new();
    for (_, v) in lines.iter().filter(|(k, _)| *k == "neigh") {
        let p: Vec<&str> = v.split('|').collect();
        let (Some(ip), Some(mac)) = (p.first().map(|s| s.trim()), p.get(1).and_then(|m| norm_mac(m))) else { continue };
        if ip.parse::<std::net::Ipv4Addr>().is_err() {
            continue;
        }
        neigh.insert(mac, (ip.to_string(), p.get(2).map(|s| s.trim().to_string()).filter(|s| !s.is_empty())));
    }
    // WLAN-Stationen ergänzen
    for c in out.iter_mut() {
        let mac = c["mac"].as_str().unwrap_or_default().to_string();
        let obj = c.as_object_mut().expect("Objekt");
        if let Some((ip, iface)) = neigh.get(&mac) {
            let _ = iface;
            put(obj, "ip", json!(ip));
        }
        if let Some((ip, name)) = names.get(&mac) {
            if !obj.contains_key("ip") {
                put(obj, "ip", json!(ip));
            }
            put(obj, "name", json!(name));
        }
    }
    // Alle übrigen Geräte, die der Router kennt (ARP/DHCP) – ohne Verbindungsangaben
    let known: std::collections::HashSet<String> = out.iter().filter_map(|c| c["mac"].as_str().map(str::to_string)).collect();
    let mut macs: Vec<&String> = neigh.keys().chain(names.keys()).collect();
    macs.sort();
    macs.dedup();
    for mac in macs {
        if known.contains(mac) {
            continue;
        }
        let mut c = client("router", mac);
        let lease = names.get(mac);
        let ip = neigh.get(mac).map(|n| n.0.clone()).or_else(|| lease.and_then(|l| l.0.clone()));
        put(&mut c, "ip", json!(ip));
        put(&mut c, "name", json!(lease.and_then(|l| l.1.clone())));
        put(&mut c, "network", json!(neigh.get(mac).and_then(|n| n.1.clone())));
        out.push(Value::Object(c));
    }
    out
}

/// „VHT-MCS 9 80MHz …“ → „Wi-Fi 5“
fn wifi_standard(bitrate: &str) -> Option<&'static str> {
    if bitrate.contains("EHT") {
        Some("Wi-Fi 7")
    } else if bitrate.contains("HE-") {
        Some("Wi-Fi 6")
    } else if bitrate.contains("VHT") {
        Some("Wi-Fi 5")
    } else if bitrate.contains("MCS") {
        Some("Wi-Fi 4")
    } else {
        None
    }
}

/// Schalter-Ports mit höchstens so vielen MAC-Adressen gelten als Endgeräte-Port
/// (mehr = Verbindung zu einem weiteren Switch/Access Point → dort ist der Client nicht direkt angeschlossen)
pub const EDGE_PORT_MAX_MACS: usize = 3;

/// Weiterleitungstabelle eines Switches → Clients mit Port
/// `fdb`: (MAC, Port-Name, VLAN)
pub fn from_fdb(fdb: &[(String, String, Option<u64>)]) -> Vec<Value> {
    let mut per_port: HashMap<&str, usize> = HashMap::new();
    for (_, port, _) in fdb {
        *per_port.entry(port.as_str()).or_default() += 1;
    }
    let mut seen = std::collections::HashSet::new();
    fdb.iter()
        .filter(|(mac, port, _)| per_port.get(port.as_str()).copied().unwrap_or(0) <= EDGE_PORT_MAX_MACS && seen.insert(mac.clone()))
        .map(|(mac, port, vlan)| {
            let mut c = client("switch", mac);
            c.insert("type".into(), json!("wired"));
            c.insert("port".into(), json!(port));
            put(&mut c, "vlan", json!(vlan));
            Value::Object(c)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Zusammenführen mehrerer Quellen
// ---------------------------------------------------------------------------

/// Einträge je MAC zusammenführen: pro Feld gewinnt die aussagekräftigste Quelle.
/// Jeder Eintrag bringt `source` und `source_id` (Gerät, das ihn gemeldet hat) mit.
pub fn merge(entries: Vec<Value>) -> Vec<Value> {
    let mut groups: HashMap<String, Vec<Value>> = HashMap::new();
    let mut order: Vec<String> = Vec::new();
    for e in entries {
        let Some(mac) = e["mac"].as_str().and_then(norm_mac) else { continue };
        if !groups.contains_key(&mac) {
            order.push(mac.clone());
        }
        groups.entry(mac).or_default().push(e);
    }
    order
        .into_iter()
        .filter_map(|mac| {
            let mut list = groups.remove(&mac)?;
            list.sort_by_key(|e| rank(e["source"].as_str().unwrap_or_default()));
            let mut merged = Map::new();
            let mut sources: Vec<Value> = Vec::new();
            for e in &list {
                sources.push(json!({ "source": e["source"], "source_id": e["source_id"] }));
                for (k, v) in e.as_object().into_iter().flatten() {
                    if !v.is_null() && !merged.contains_key(k) {
                        merged.insert(k.clone(), v.clone());
                    }
                }
            }
            merged.insert("mac".into(), json!(mac));
            let best = merged["source"].as_str().unwrap_or_default().to_string();
            merged.insert("source_label".into(), json!(source_label(&best)));
            merged.insert("sources".into(), Value::Array(sources));
            Some(Value::Object(merged))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_formate() {
        assert_eq!(norm_mac("AA-BB-CC-00-11-22").as_deref(), Some("aa:bb:cc:00:11:22"));
        assert_eq!(norm_mac("aabb.cc00.1122").as_deref(), Some("aa:bb:cc:00:11:22"));
        assert_eq!(norm_mac("ff:ff:ff:ff:ff:ff"), None);
        assert_eq!(norm_mac("zz"), None);
    }

    #[test]
    fn iw_station_dump() {
        let raw = "wifi_if=wlan0|Heimnetz|36|5180
sta=wlan0|Station 26:d2:e4:a5:2a:f0 (on wlan0)
sta=wlan0|\tinactive time:\t120 ms
sta=wlan0|\trx bytes:\t1000
sta=wlan0|\ttx bytes:\t8000
sta=wlan0|\tsignal:  \t-58 [-60, -61] dBm
sta=wlan0|\ttx bitrate:\t866.7 MBit/s VHT-MCS 9 80MHz short GI VHT-NSS 2
sta=wlan0|\trx bitrate:\t650.0 MBit/s VHT-MCS 7 80MHz VHT-NSS 2
sta=wlan0|\tconnected time:\t3600 seconds
neigh=192.168.1.20|26:d2:e4:a5:2a:f0|br-lan
neigh=192.168.1.30|aa:bb:cc:00:00:30|br-lan
lease=26:d2:e4:a5:2a:f0|192.168.1.20|handy
lease=aa:bb:cc:00:00:30|192.168.1.30|drucker";
        let lines: Vec<(&str, &str)> = raw.lines().filter_map(|l| l.split_once('=')).collect();
        let list = from_ssh(&lines, "t1");
        assert_eq!(list.len(), 2);
        let sta = &list[0];
        assert_eq!(sta["source"], "wifi");
        assert_eq!(sta["ssid"], "Heimnetz");
        assert_eq!(sta["band"], "5 GHz");
        assert_eq!(sta["signal_dbm"], -58.0);
        assert_eq!(sta["link_down_kbps"], 866_700.0);
        assert_eq!(sta["wifi_standard"], "Wi-Fi 5");
        assert_eq!(sta["ip"], "192.168.1.20");
        assert_eq!(sta["name"], "handy");
        assert_eq!(sta["down_bytes"], 8000.0);
        let other = &list[1];
        assert_eq!(other["source"], "router");
        assert_eq!(other["name"], "drucker");
        assert_eq!(other["ip"], "192.168.1.30");
    }

    #[test]
    fn datenrate_aus_zaehlern() {
        assert_eq!(rates("t-rate", Some(0.0), Some(0.0)), (None, None));
        std::thread::sleep(Duration::from_millis(1100));
        let (down, up) = rates("t-rate", Some(1000.0), Some(500.0));
        assert!(down.unwrap() > 6000.0 && down.unwrap() < 8000.0);
        assert!(up.unwrap() > 3000.0);
        // Zähler zurückgesetzt (Neustart) → keine Rate
        assert_eq!(rates("t-rate", Some(10.0), Some(10.0)), (None, None));
    }

    #[test]
    fn switch_ports_ohne_uplinks() {
        let fdb = vec![
            ("aa:00:00:00:00:01".into(), "Port 3".into(), Some(1)),
            ("aa:00:00:00:00:02".into(), "Port 24".into(), Some(1)),
            ("aa:00:00:00:00:03".into(), "Port 24".into(), Some(1)),
            ("aa:00:00:00:00:04".into(), "Port 24".into(), Some(1)),
            ("aa:00:00:00:00:05".into(), "Port 24".into(), Some(1)),
        ];
        let list = from_fdb(&fdb);
        assert_eq!(list.len(), 1);
        assert_eq!(list[0]["port"], "Port 3");
    }

    #[test]
    fn zusammenfuehren_nach_rang() {
        let merged = merge(vec![
            json!({ "source": "router", "source_id": 1, "mac": "AA:00:00:00:00:01", "ip": "10.0.0.5", "name": "laptop" }),
            json!({ "source": "switch", "source_id": 2, "mac": "aa:00:00:00:00:01", "port": "Port 3", "type": "wired" }),
            json!({ "source": "unifi", "source_id": 3, "mac": "aa:00:00:00:00:01", "name": "Laptop Thomas", "down_bps": 1000.0 }),
        ]);
        assert_eq!(merged.len(), 1);
        let m = &merged[0];
        assert_eq!(m["name"], "Laptop Thomas");
        assert_eq!(m["ip"], "10.0.0.5");
        assert_eq!(m["port"], "Port 3");
        assert_eq!(m["source"], "unifi");
        assert_eq!(m["source_label"], "UniFi");
        assert_eq!(m["sources"].as_array().unwrap().len(), 3);
    }
}
