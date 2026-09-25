//! OPNsense über die REST-API (API-Schlüssel + Secret eines eigenen Benutzers).
//!
//! Benötigte Rechte (System → Zugang → Benutzer → Berechtigungen), nur lesend:
//! „Diagnostics: ARP Table“, „Reporting: Traffic“, „Services: DHCP(v4): Leases“ bzw. „Kea DHCP“/„Dnsmasq“.
//!
//! - ARP-Tabelle: IP, MAC, Schnittstelle (VLAN), Hersteller
//! - DHCP-Leases: Gerätenamen (ISC, Kea oder Dnsmasq – je nachdem, was läuft)
//! - Top Talkers: aktuelle Datenrate je Gerät (Download/Upload)

use std::{collections::HashMap, net::Ipv4Addr};

use anyhow::{anyhow, bail, Result};
use reqwest::{Client, StatusCode};
use serde_json::{json, Value};

use super::{
    netclients::{self, put},
    tls::{self, Pin},
    Credential,
};

async fn get(http: &Client, base: &str, key: &str, secret: &str, path: &str) -> Result<Value> {
    let response = http.get(format!("{base}{path}")).basic_auth(key, Some(secret)).send().await?;
    match response.status() {
        s if s.is_success() => Ok(response.json().await?),
        StatusCode::UNAUTHORIZED => bail!("API-Schlüssel/Secret abgelehnt"),
        StatusCode::FORBIDDEN => bail!("Keine Berechtigung für {path} – dem API-Benutzer das Recht geben"),
        StatusCode::NOT_FOUND => bail!("{path} nicht vorhanden"),
        s => bail!("OPNsense antwortete mit {s} für {path}"),
    }
}

/// Liest ARP, DHCP-Namen und Datenraten. `pinned`: gemerkter Zertifikats-Fingerabdruck.
pub async fn collect(ip: Ipv4Addr, cred: &Credential, pinned: Option<&str>) -> Result<(Value, Option<String>)> {
    let key = cred.username.clone().filter(|k| !k.is_empty()).ok_or_else(|| anyhow!("API-Schlüssel fehlt (Feld Benutzername)"))?;
    let secret = cred.secret.password.clone().filter(|s| !s.is_empty()).ok_or_else(|| anyhow!("API-Secret fehlt"))?;
    let port = cred.port.and_then(|p| u16::try_from(p).ok()).unwrap_or(443);
    let pin = Pin::new(pinned);
    let http = tls::client(pin.clone())?;
    let base = format!("https://{ip}:{port}");

    let arp = match get(&http, &base, &key, &secret, "/api/diagnostics/interface/getArp").await {
        Ok(v) => v,
        Err(e) if tls::pin_mismatch(&e) => bail!(tls::PIN_CHANGED),
        Err(e) if tls::unreachable(&e) => bail!("Port {port} nicht erreichbar"),
        Err(e) => return Err(e),
    };
    let mut clients: HashMap<String, serde_json::Map<String, Value>> = HashMap::new();
    for row in arp.as_array().into_iter().flatten() {
        let Some(mac) = row["mac"].as_str().and_then(netclients::norm_mac) else { continue };
        if row["expired"].as_bool() == Some(true) {
            continue;
        }
        let c = clients.entry(mac.clone()).or_insert_with(|| netclients::client("opnsense", &mac));
        put(c, "ip", row["ip"].clone());
        put(c, "vendor", row["manufacturer"].clone());
        put(c, "hostname", row["hostname"].clone());
        put(c, "network", json!(row["intf_description"].as_str().or(row["intf"].as_str())));
    }

    // Gerätenamen aus den DHCP-Leases (je nach eingesetztem DHCP-Server)
    let mut leases_from = None;
    for path in ["/api/kea/leases4/search", "/api/dhcpv4/leases/searchLease", "/api/dnsmasq/leases/search"] {
        let Ok(res) = get(&http, &base, &key, &secret, path).await else { continue };
        let rows = res["rows"].as_array().cloned().unwrap_or_default();
        if rows.is_empty() {
            continue;
        }
        leases_from = Some(path);
        for row in rows {
            let Some(mac) = row["hwaddr"].as_str().or(row["mac"].as_str()).and_then(netclients::norm_mac) else { continue };
            let c = clients.entry(mac.clone()).or_insert_with(|| netclients::client("opnsense", &mac));
            put(c, "ip", json!(row["address"].as_str()));
            let name = row["hostname"].as_str().or(row["client-hostname"].as_str()).map(|h| h.trim_end_matches('.').to_string());
            put(c, "name", json!(name));
            put(c, "network", json!(row["if_descr"].as_str()));
        }
        break;
    }

    // Datenrate je Gerät: Top Talkers aller internen Schnittstellen (die Messung dauert ca. 2 s)
    let mut talkers = false;
    if let Ok(ifs) = get(&http, &base, &key, &secret, "/api/diagnostics/traffic/interface").await {
        let names: Vec<String> = ifs["interfaces"]
            .as_object()
            .into_iter()
            .flatten()
            .filter(|(k, v)| k.as_str() != "wan" && !v["name"].as_str().unwrap_or_default().eq_ignore_ascii_case("wan"))
            .map(|(k, _)| k.clone())
            .take(16)
            .collect();
        if !names.is_empty() {
            if let Ok(top) = get(&http, &base, &key, &secret, &format!("/api/diagnostics/traffic/top/{}", names.join(","))).await {
                talkers = true;
                let by_ip: HashMap<String, String> = clients
                    .iter()
                    .filter_map(|(mac, c)| Some((c.get("ip")?.as_str()?.to_string(), mac.clone())))
                    .collect();
                for (_, iface) in top.as_object().into_iter().flatten() {
                    for r in iface["records"].as_array().into_iter().flatten() {
                        let Some(mac) = r["address"].as_str().and_then(|a| by_ip.get(a)) else { continue };
                        let Some(c) = clients.get_mut(mac) else { continue };
                        // Aus Sicht der Schnittstelle: „out“ geht zum Gerät (Download), „in“ kommt vom Gerät (Upload)
                        let add = |c: &mut serde_json::Map<String, Value>, key: &str, v: Option<f64>| {
                            if let Some(v) = v {
                                let old = c.get(key).and_then(Value::as_f64).unwrap_or(0.0);
                                c.insert(key.into(), json!(old + v));
                            }
                        };
                        add(c, "down_bps", r["rate_bits_out"].as_f64());
                        add(c, "up_bps", r["rate_bits_in"].as_f64());
                        add(c, "down_bytes", r["cumulative_bytes_out"].as_f64());
                        add(c, "up_bytes", r["cumulative_bytes_in"].as_f64());
                    }
                }
            }
        }
    }

    let clients: Vec<Value> = clients.into_values().map(Value::Object).collect();
    Ok((
        json!({
            "port": port,
            "clients_total": clients.len(),
            "leases": leases_from.map(|p| p.split('/').nth(2).unwrap_or_default()),
            "traffic": talkers,
            "clients": clients,
        }),
        pin.seen(),
    ))
}
