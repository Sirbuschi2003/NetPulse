//! AVM FRITZ!Box über TR-064 (die offizielle Schnittstelle für Anwendungen im Heimnetz).
//!
//! Voraussetzung in der FRITZ!Box: *Heimnetz → Netzwerk → Netzwerkeinstellungen →
//! „Zugriff für Anwendungen zulassen“* und ein FRITZ!Box-Benutzer (am besten eigener mit Leserechten).
//! Gelesen werden nur Listen – es wird nichts verändert.
//!
//! - Geräteliste (Hosts): Name, IP, MAC, LAN/WLAN, aktiv, Port bzw. Geschwindigkeit
//! - WLAN-Geräte je Funknetz: Signalstärke, Verbindungsgeschwindigkeit, SSID, Kanal
//!
//! Anmeldung per HTTP-Digest (das Passwort geht nie im Klartext über das Netz).

use std::{net::Ipv4Addr, time::Duration};

use anyhow::{anyhow, bail, Context, Result};
use argon2::password_hash::rand_core::{OsRng, RngCore};
use md5::{Digest, Md5};
use reqwest::{header, Client, StatusCode};
use serde_json::{json, Value};

use super::{
    netclients::{self, put},
    Credential,
};

const PORT: u16 = 49000;

fn md5_hex(s: &str) -> String {
    hex::encode(Md5::digest(s.as_bytes()))
}

/// Wert aus `key="value"`-Liste des WWW-Authenticate-Headers
fn param<'a>(header: &'a str, key: &str) -> Option<&'a str> {
    let start = header.find(&format!("{key}="))? + key.len() + 1;
    let rest = &header[start..];
    if let Some(stripped) = rest.strip_prefix('"') {
        stripped.split('"').next()
    } else {
        rest.split(',').next().map(str::trim)
    }
}

/// Antwort-Header für HTTP-Digest (RFC 7616, MD5, qop=auth)
fn digest_header(www: &str, user: &str, password: &str, method: &str, uri: &str) -> Result<String> {
    let realm = param(www, "realm").ok_or_else(|| anyhow!("Digest ohne realm"))?;
    let nonce = param(www, "nonce").ok_or_else(|| anyhow!("Digest ohne nonce"))?;
    let mut cnonce = [0u8; 8];
    OsRng.fill_bytes(&mut cnonce);
    let cnonce = hex::encode(cnonce);
    let ha1 = md5_hex(&format!("{user}:{realm}:{password}"));
    let ha2 = md5_hex(&format!("{method}:{uri}"));
    let nc = "00000001";
    let response = md5_hex(&format!("{ha1}:{nonce}:{nc}:{cnonce}:auth:{ha2}"));
    Ok(format!(
        "Digest username=\"{user}\", realm=\"{realm}\", nonce=\"{nonce}\", uri=\"{uri}\", algorithm=MD5, qop=auth, nc={nc}, cnonce=\"{cnonce}\", response=\"{response}\""
    ))
}

struct Tr064 {
    http: Client,
    base: String,
    user: String,
    password: String,
}

impl Tr064 {
    /// SOAP-Aufruf mit Digest-Anmeldung; liefert den Antworttext
    async fn call(&self, control: &str, service: &str, action: &str) -> Result<String> {
        let body = format!(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
             s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:{action} xmlns:u=\"{service}\"/></s:Body></s:Envelope>"
        );
        let send = |auth: Option<String>| {
            let mut req = self
                .http
                .post(format!("{}{control}", self.base))
                .header(header::CONTENT_TYPE, "text/xml; charset=\"utf-8\"")
                .header("SOAPAction", format!("{service}#{action}"))
                .body(body.clone());
            if let Some(a) = auth {
                req = req.header(header::AUTHORIZATION, a);
            }
            req.send()
        };
        let first = send(None).await?;
        let response = if first.status() == StatusCode::UNAUTHORIZED {
            let www = first
                .headers()
                .get(header::WWW_AUTHENTICATE)
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| anyhow!("FRITZ!Box verlangt eine unbekannte Anmeldung"))?
                .to_string();
            send(Some(digest_header(&www, &self.user, &self.password, "POST", control)?)).await?
        } else {
            first
        };
        match response.status() {
            s if s.is_success() => Ok(response.text().await?),
            StatusCode::UNAUTHORIZED => bail!("Anmeldung abgelehnt – Benutzername/Passwort prüfen"),
            StatusCode::INTERNAL_SERVER_ERROR => bail!("Aktion {action} nicht verfügbar (FRITZ!OS zu alt oder keine Berechtigung)"),
            s => bail!("FRITZ!Box antwortete mit {s}"),
        }
    }

    async fn get_list(&self, path: &str) -> Result<String> {
        let url = if path.starts_with("http") { path.to_string() } else { format!("{}{path}", self.base) };
        let response = self.http.get(url).send().await?;
        if !response.status().is_success() {
            bail!("Liste nicht lesbar ({})", response.status());
        }
        Ok(response.text().await?)
    }
}

/// Inhalt eines XML-Elements (erstes Vorkommen), entschärft
fn tag(xml: &str, name: &str) -> Option<String> {
    let open = format!("<{name}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&format!("</{name}>"))? + start;
    let text = xml[start..end]
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&");
    let text = text.trim().to_string();
    (!text.is_empty()).then_some(text)
}

/// Alle `<Item>…</Item>`-Blöcke einer Liste
fn items(xml: &str) -> Vec<&str> {
    xml.split("<Item>").skip(1).filter_map(|block| block.split("</Item>").next()).collect()
}

/// Liest Geräte- und WLAN-Liste der FRITZ!Box
pub async fn collect(ip: Ipv4Addr, cred: &Credential) -> Result<Value> {
    let user = cred.username.clone().unwrap_or_default();
    let password = cred.secret.password.clone().filter(|p| !p.is_empty()).ok_or_else(|| anyhow!("Passwort fehlt"))?;
    let port = cred.port.and_then(|p| u16::try_from(p).ok()).unwrap_or(PORT);
    let fb = Tr064 {
        http: Client::builder().timeout(Duration::from_secs(15)).connect_timeout(Duration::from_secs(5)).user_agent("NetPulse").build()?,
        base: format!("http://{ip}:{port}"),
        user,
        password,
    };

    // Modell und FRITZ!OS-Version (ohne Anmeldung lesbar)
    let desc = fb.get_list("/tr64desc.xml").await.map_err(|e| {
        if e.downcast_ref::<reqwest::Error>().is_some_and(|r| r.is_connect() || r.is_timeout()) {
            anyhow!("Port {port} nicht erreichbar – in der FRITZ!Box „Zugriff für Anwendungen zulassen“ einschalten (Heimnetz → Netzwerk → Netzwerkeinstellungen)")
        } else {
            e
        }
    })?;
    let model = tag(&desc, "modelName").or_else(|| tag(&desc, "friendlyName"));
    let version = tag(&desc, "Display").or_else(|| tag(&desc, "modelNumber"));

    // Geräteliste
    let hosts_xml = fb.call("/upnp/control/hosts", "urn:dslforum-org:service:Hosts:1", "X_AVM-DE_GetHostListPath").await?;
    let path = tag(&hosts_xml, "NewX_AVM-DE_HostListPath").ok_or_else(|| anyhow!("Geräteliste nicht verfügbar (FRITZ!OS 7.x nötig)"))?;
    let list = fb.get_list(&path).await.context("Geräteliste")?;
    let mut clients: Vec<Value> = Vec::new();
    for item in items(&list) {
        let Some(mac) = tag(item, "MACAddress").as_deref().and_then(netclients::norm_mac) else { continue };
        if tag(item, "Active").as_deref() != Some("1") {
            continue; // nur gerade verbundene Geräte
        }
        let wifi = tag(item, "InterfaceType").is_some_and(|t| t.contains("802.11"));
        let mut c = netclients::client("fritzbox", &mac);
        put(&mut c, "ip", json!(tag(item, "IPAddress")));
        put(&mut c, "name", json!(tag(item, "X_AVM-DE_FriendlyName").or_else(|| tag(item, "HostName"))));
        put(&mut c, "hostname", json!(tag(item, "HostName")));
        c.insert("type".into(), json!(if wifi { "wireless" } else { "wired" }));
        if !wifi {
            put(&mut c, "port", json!(tag(item, "X_AVM-DE_Port").filter(|p| p != "0").map(|p| format!("LAN {p}"))));
        }
        let speed = tag(item, "X_AVM-DE_Speed").and_then(|s| s.parse::<f64>().ok()).filter(|s| *s > 0.0);
        put(&mut c, "link_down_kbps", json!(speed.map(|s| s * 1000.0)));
        put(&mut c, "guest", json!(tag(item, "X_AVM-DE_Guest").map(|g| g == "1")));
        clients.push(Value::Object(c));
    }

    // WLAN-Details je Funknetz (2,4 GHz, 5 GHz, Gastnetz, 6 GHz)
    let mut wlans = Vec::new();
    for n in 1..=4 {
        let service = format!("urn:dslforum-org:service:WLANConfiguration:{n}");
        let control = format!("/upnp/control/wlanconfig{n}");
        let Ok(info) = fb.call(&control, &service, "GetInfo").await else { continue };
        let ssid = tag(&info, "NewSSID");
        let channel = tag(&info, "NewChannel").and_then(|c| c.parse::<u32>().ok());
        let band = match channel {
            Some(1..=14) => Some("2,4 GHz"),
            Some(32..=177) => Some("5 GHz"),
            _ => None,
        };
        wlans.push(json!({ "ssid": ssid, "channel": channel, "band": band, "enabled": tag(&info, "NewEnable").as_deref() == Some("1") }));
        let Ok(path_xml) = fb.call(&control, &service, "X_AVM-DE_GetWLANDeviceListPath").await else { continue };
        let Some(path) = tag(&path_xml, "NewX_AVM-DE_WLANDeviceListPath") else { continue };
        let Ok(devices) = fb.get_list(&path).await else { continue };
        for item in items(&devices) {
            let Some(mac) = tag(item, "AssociatedDeviceMACAddress").as_deref().and_then(netclients::norm_mac) else { continue };
            let Some(c) = clients.iter_mut().find(|c| c["mac"] == mac.as_str()) else { continue };
            let obj = c.as_object_mut().expect("Objekt");
            obj.insert("type".into(), json!("wireless"));
            put(obj, "ssid", json!(ssid));
            put(obj, "channel", json!(channel));
            put(obj, "band", json!(band));
            // Signalstärke der FRITZ!Box ist 0–100 → ungefähr in dBm umrechnen (0 % ≈ −100 dBm, 100 % ≈ −50 dBm)
            if let Some(pct) = tag(item, "X_AVM-DE_SignalStrength").and_then(|s| s.parse::<f64>().ok()) {
                obj.insert("signal_pct".into(), json!(pct));
                obj.insert("signal_dbm".into(), json!((pct / 2.0 - 100.0).round()));
            }
            if let Some(speed) = tag(item, "X_AVM-DE_Speed").and_then(|s| s.parse::<f64>().ok()).filter(|s| *s > 0.0) {
                obj.insert("link_down_kbps".into(), json!(speed * 1000.0));
            }
            if let Some(rx) = tag(item, "X_AVM-DE_SpeedRX").and_then(|s| s.parse::<f64>().ok()).filter(|s| *s > 0.0) {
                obj.insert("link_up_kbps".into(), json!(rx * 1000.0));
            }
        }
    }

    Ok(json!({
        "model": model,
        "version": version,
        "wlans": wlans,
        "clients_total": clients.len(),
        "clients": clients,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_nach_rfc() {
        // Bekannter Wert aus RFC 2617 (MD5, qop=auth) – mit festem cnonce nachgerechnet
        let ha1 = md5_hex("Mufasa:testrealm@host.com:Circle Of Life");
        let ha2 = md5_hex("GET:/dir/index.html");
        let response = md5_hex(&format!("{ha1}:dcd98b7102dd2f0e8b11d0f600bfb0c093:00000001:0a4f113b:auth:{ha2}"));
        assert_eq!(response, "6629fae49393a05397450978507c4ef1");
    }

    #[test]
    fn header_parameter() {
        let www = r#"Digest realm="F!Box SOAP-Auth", nonce="ABC123", algorithm=MD5, qop="auth""#;
        assert_eq!(param(www, "realm"), Some("F!Box SOAP-Auth"));
        assert_eq!(param(www, "nonce"), Some("ABC123"));
        assert_eq!(param(www, "algorithm"), Some("MD5"));
    }

    #[test]
    fn xml_listen() {
        let xml = "<List><Item><MACAddress>AA:BB:CC:00:00:01</MACAddress><HostName>laptop</HostName><Active>1</Active></Item>\
                   <Item><MACAddress>AA:BB:CC:00:00:02</MACAddress><HostName>Tom &amp; Jerry</HostName></Item></List>";
        let list = items(xml);
        assert_eq!(list.len(), 2);
        assert_eq!(tag(list[0], "HostName").as_deref(), Some("laptop"));
        assert_eq!(tag(list[1], "HostName").as_deref(), Some("Tom & Jerry"));
        assert_eq!(tag(list[1], "Active"), None);
    }
}
