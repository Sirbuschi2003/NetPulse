//! MikroTik RouterOS 7 über die REST-API (Benutzer mit Gruppe „read“).
//!
//! In RouterOS: *IP → Services → www-ssl* einschalten (Zertifikat nötig) oder *www* (HTTP, nur im LAN).
//! - WLAN-Registrierungen (Paket „wireless“, „wifi“ oder CAPsMAN): Signal, Raten, Bytes, Laufzeit
//! - Bridge-Hosts: an welchem Port ein Gerät hängt
//! - ARP und DHCP-Leases: IP und Namen

use std::{collections::HashMap, net::Ipv4Addr};

use anyhow::{anyhow, bail, Result};
use reqwest::{Client, StatusCode};
use serde_json::{json, Map, Value};

use super::{
    netclients::{self, put},
    tls::{self, Pin},
    Credential,
};

async fn get(http: &Client, base: &str, user: &str, password: &str, path: &str) -> Result<Vec<Value>> {
    let response = http.get(format!("{base}/rest{path}")).basic_auth(user, Some(password)).send().await?;
    match response.status() {
        s if s.is_success() => Ok(response.json::<Value>().await?.as_array().cloned().unwrap_or_default()),
        StatusCode::UNAUTHORIZED => bail!("Anmeldung abgelehnt – Benutzer/Passwort prüfen"),
        // Paket nicht installiert (z. B. kein „wireless“)
        StatusCode::BAD_REQUEST | StatusCode::NOT_FOUND => Ok(Vec::new()),
        s => bail!("RouterOS antwortete mit {s} für {path}"),
    }
}

/// „-52@6Mbps“, „-52“ → -52
fn signal(v: &Value) -> Option<f64> {
    v.as_str()?.split('@').next()?.trim().parse().ok()
}

/// „866.6Mbps-80MHz/2S/SGI“, „54Mbps“ → kbit/s
fn rate_kbps(v: &Value) -> Option<f64> {
    let s = v.as_str()?;
    let end = s.find("bps")?;
    let (num, unit) = s[..end].split_at(s[..end].len() - 1);
    let n: f64 = num.parse().ok()?;
    Some(match unit {
        "G" => n * 1_000_000.0,
        "M" => n * 1000.0,
        "k" => n,
        _ => return None,
    })
}

/// „1w2d3h4m5s“ → Sekunden
fn duration_s(v: &Value) -> Option<f64> {
    let s = v.as_str()?;
    let mut total = 0.0;
    let mut num = String::new();
    for ch in s.chars() {
        if ch.is_ascii_digit() || ch == '.' {
            num.push(ch);
            continue;
        }
        let n: f64 = num.parse().unwrap_or(0.0);
        num.clear();
        total += n * match ch {
            'w' => 604_800.0,
            'd' => 86_400.0,
            'h' => 3600.0,
            'm' => 60.0,
            's' => 1.0,
            _ => 0.0,
        };
    }
    Some(total)
}

pub async fn collect(ip: Ipv4Addr, cred: &Credential, pinned: Option<&str>) -> Result<(Value, Option<String>)> {
    let user = cred.username.clone().filter(|u| !u.is_empty()).ok_or_else(|| anyhow!("Benutzername fehlt"))?;
    let password = cred.secret.password.clone().unwrap_or_default();
    let port = cred.port.and_then(|p| u16::try_from(p).ok()).unwrap_or(443);
    let pin = Pin::new(pinned);
    let http = tls::client(pin.clone())?;
    let base = if port == 80 { format!("http://{ip}") } else { format!("https://{ip}:{port}") };

    let identity = match http.get(format!("{base}/rest/system/resource")).basic_auth(&user, Some(&password)).send().await {
        Ok(r) if r.status().is_success() => r.json::<Value>().await.unwrap_or(Value::Null),
        Ok(r) if r.status() == StatusCode::UNAUTHORIZED => bail!("Anmeldung abgelehnt – Benutzer/Passwort prüfen"),
        Ok(r) => bail!("RouterOS antwortete mit {} – REST-API erst ab RouterOS 7.1", r.status()),
        Err(e) => {
            let e = anyhow::Error::from(e);
            if tls::pin_mismatch(&e) {
                bail!(tls::PIN_CHANGED);
            }
            bail!("Port {port} nicht erreichbar – in RouterOS unter IP → Services „www-ssl“ (oder „www“, dann Port 80) einschalten");
        }
    };

    let mut clients: HashMap<String, Map<String, Value>> = HashMap::new();
    let key_of = |mac: &str| format!("{ip}:mikrotik:{mac}");
    // WLAN: klassisches „wireless“, neues „wifi“ (RouterOS 7.13+) und CAPsMAN
    for path in ["/interface/wireless/registration-table", "/interface/wifi/registration-table", "/caps-man/registration-table"] {
        for r in get(&http, &base, &user, &password, path).await? {
            let Some(mac) = r["mac-address"].as_str().and_then(netclients::norm_mac) else { continue };
            let c = clients.entry(mac.clone()).or_insert_with(|| netclients::client("mikrotik", &mac));
            c.insert("type".into(), json!("wireless"));
            put(c, "interface", r["interface"].clone());
            put(c, "ssid", r["ssid"].clone());
            put(c, "band", json!(r["band"].as_str().map(|b| if b.starts_with("2") { "2,4 GHz" } else if b.starts_with("5") { "5 GHz" } else { "6 GHz" })));
            put(c, "signal_dbm", json!(signal(&r["signal-strength"]).or_else(|| signal(&r["signal"]))));
            put(c, "link_down_kbps", json!(rate_kbps(&r["tx-rate"])));
            put(c, "link_up_kbps", json!(rate_kbps(&r["rx-rate"])));
            put(c, "ip", r["last-ip"].clone());
            let uptime = duration_s(&r["uptime"]);
            put(c, "uptime_s", json!(uptime));
            put(c, "connected_at", json!(uptime.map(|u| chrono::Utc::now() - chrono::Duration::seconds(u as i64))));
            // „bytes“: empfangen vom Client, gesendet zum Client
            if let Some((rx, tx)) = r["bytes"].as_str().and_then(|b| b.split_once(',')) {
                let (up, down) = (rx.trim().parse::<f64>().ok(), tx.trim().parse::<f64>().ok());
                put(c, "up_bytes", json!(up));
                put(c, "down_bytes", json!(down));
                let (d, u) = netclients::rates(&key_of(&mac), down, up);
                put(c, "down_bps", json!(d));
                put(c, "up_bps", json!(u));
            }
        }
    }
    // Bridge-Hosts: Port je MAC (wie die Weiterleitungstabelle eines Switches)
    let hosts = get(&http, &base, &user, &password, "/interface/bridge/host").await?;
    let fdb: Vec<(String, String, Option<u64>)> = hosts
        .iter()
        .filter(|h| h["local"].as_str() != Some("true") && h["local"].as_bool() != Some(true))
        .filter_map(|h| {
            Some((
                h["mac-address"].as_str().and_then(netclients::norm_mac)?,
                h["on-interface"].as_str()?.to_string(),
                h["vid"].as_str().and_then(|v| v.parse().ok()),
            ))
        })
        .collect();
    for sw in netclients::from_fdb(&fdb) {
        let Some(mac) = sw["mac"].as_str().map(str::to_string) else { continue };
        if clients.get(&mac).is_some_and(|c| c.get("type") == Some(&json!("wireless"))) {
            continue;
        }
        let c = clients.entry(mac.clone()).or_insert_with(|| netclients::client("mikrotik", &mac));
        c.insert("type".into(), json!("wired"));
        put(c, "port", sw["port"].clone());
        put(c, "vlan", sw["vlan"].clone());
    }
    // ARP + DHCP: IP und Namen
    for a in get(&http, &base, &user, &password, "/ip/arp").await? {
        let Some(mac) = a["mac-address"].as_str().and_then(netclients::norm_mac) else { continue };
        let c = clients.entry(mac.clone()).or_insert_with(|| netclients::client("mikrotik", &mac));
        if !c.contains_key("ip") {
            put(c, "ip", a["address"].clone());
        }
        put(c, "network", a["interface"].clone());
    }
    for l in get(&http, &base, &user, &password, "/ip/dhcp-server/lease").await? {
        let Some(mac) = l["mac-address"].as_str().and_then(netclients::norm_mac) else { continue };
        let c = clients.entry(mac.clone()).or_insert_with(|| netclients::client("mikrotik", &mac));
        put(c, "name", json!(l["comment"].as_str().filter(|s| !s.is_empty()).or(l["host-name"].as_str())));
        put(c, "hostname", l["host-name"].clone());
        if !c.contains_key("ip") {
            put(c, "ip", l["address"].clone());
        }
    }

    let clients: Vec<Value> = clients.into_values().map(Value::Object).collect();
    Ok((
        json!({
            "port": port,
            "board": identity["board-name"],
            "version": identity["version"],
            "cpu_pct": identity["cpu-load"].as_str().and_then(|c| c.parse::<f64>().ok()).or(identity["cpu-load"].as_f64()),
            "clients_total": clients.len(),
            "clients": clients,
        }),
        pin.seen(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn werte_umrechnen() {
        assert_eq!(signal(&json!("-52@6Mbps")), Some(-52.0));
        assert_eq!(signal(&json!("-61")), Some(-61.0));
        assert_eq!(rate_kbps(&json!("866.6Mbps-80MHz/2S/SGI")), Some(866_600.0));
        assert_eq!(rate_kbps(&json!("54Mbps")), Some(54_000.0));
        assert_eq!(rate_kbps(&json!("1.2Gbps")), Some(1_200_000.0));
        assert_eq!(duration_s(&json!("1d2h3m4s")), Some(93_784.0));
        assert_eq!(duration_s(&json!("45s")), Some(45.0));
    }
}
