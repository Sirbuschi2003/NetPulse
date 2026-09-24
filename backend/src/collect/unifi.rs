//! UniFi-Controller (UniFi OS Server, Cloud Key, Dream Machine, UniFi Network Application).
//!
//! Zwei Wege, beide nur lesend:
//! 1. **API-Schlüssel** (empfohlen): offizielle „Network Integration API“ unter
//!    `/proxy/network/integration/v1` mit Header `X-API-KEY`. Kein Login, daher auch mit
//!    aktivierter Zwei-Faktor-Anmeldung. Schlüssel anlegen: UniFi Network → Einstellungen →
//!    Control Plane → Integrations.
//! 2. **Lokales Konto** (Benutzer + Passwort, ohne 2FA): klassische API nach `/api/auth/login`.
//!    Ist 2FA aktiv, meldet der Controller „2FA-Code nötig“ – dann Weg 1 nutzen.
//!
//! Ports: UniFi OS Server 11443, UniFi OS-Konsolen 443, ältere Network Application 8443.
//! Der Controller hat meist ein selbst signiertes Zertifikat. Es wird beim ersten Kontakt gemerkt
//! (Fingerabdruck, wie beim SSH-Host-Schlüssel); ändert es sich, wird nichts gesendet.

use std::{net::Ipv4Addr, time::Duration};

use anyhow::{anyhow, bail, Context, Result};
use futures::{stream, StreamExt};
use reqwest::{header, Client, StatusCode};
use serde_json::{json, Value};

use super::Credential;

const DEFAULT_PORTS: &[u16] = &[11443, 443, 8443];
const MAX_CLIENTS: usize = 2000;

/// Nimmt nur das gemerkte Zertifikat an (oder beim ersten Kontakt jedes) und merkt sich den Fingerabdruck
#[derive(Debug)]
struct Pin {
    expected: Option<String>,
    seen: std::sync::Mutex<Option<String>>,
    provider: std::sync::Arc<rustls::crypto::CryptoProvider>,
}

impl rustls::client::danger::ServerCertVerifier for Pin {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        use sha2::Digest;
        let fingerprint = hex::encode(sha2::Sha256::digest(end_entity.as_ref()));
        *self.seen.lock().unwrap() = Some(fingerprint.clone());
        match &self.expected {
            Some(pin) if *pin != fingerprint => Err(rustls::Error::General("NetPulse-Pin: Zertifikat geändert".into())),
            _ => Ok(rustls::client::danger::ServerCertVerified::assertion()),
        }
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

fn client(pin: std::sync::Arc<Pin>) -> Result<Client> {
    let tls = rustls::ClientConfig::builder_with_provider(pin.provider.clone())
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(pin)
        .with_no_client_auth();
    Ok(Client::builder()
        .use_preconfigured_tls(tls)
        .cookie_store(true)
        .timeout(Duration::from_secs(15))
        .connect_timeout(Duration::from_secs(5))
        .user_agent("NetPulse")
        .build()?)
}

fn ports(cred: &Credential) -> Vec<u16> {
    match cred.port.and_then(|p| u16::try_from(p).ok()) {
        Some(p) => vec![p],
        None => DEFAULT_PORTS.to_vec(),
    }
}

/// Liest Sites, Geräte (mit aktueller Auslastung) und Clients des Controllers.
/// `pinned`: gemerkter Zertifikats-Fingerabdruck; zurück kommt der gesehene (zum Merken beim ersten Mal).
pub async fn collect(ip: Ipv4Addr, cred: &Credential, pinned: Option<&str>) -> Result<(Value, Option<String>)> {
    let secret = cred.secret.password.clone().filter(|s| !s.is_empty()).ok_or_else(|| anyhow!("API-Schlüssel bzw. Passwort fehlt"))?;
    let pin = std::sync::Arc::new(Pin {
        expected: pinned.map(str::to_string),
        seen: std::sync::Mutex::default(),
        provider: std::sync::Arc::new(rustls::crypto::ring::default_provider()),
    });
    let http = client(pin.clone())?;
    let username = cred.username.clone().filter(|u| !u.trim().is_empty());
    let mut last_error = anyhow!("Controller nicht erreichbar");
    for port in ports(cred) {
        let base = format!("https://{ip}:{port}");
        let result = match &username {
            None => integration(&http, &base, &secret).await,
            Some(user) => classic(&http, &base, user, &secret).await,
        };
        match result {
            Ok(mut data) => {
                data["port"] = json!(port);
                let seen = pin.seen.lock().unwrap().clone();
                return Ok((data, seen));
            }
            Err(e) if format!("{e:?}").contains("NetPulse-Pin") => {
                bail!(
                    "Das Zertifikat des Controllers hat sich geändert – Zugangsdaten wurden NICHT gesendet (möglicher Angriff). \
                     Wurde der Controller neu installiert, beim Gerät unter „Einstellungen“ den gespeicherten Schlüssel zurücksetzen."
                );
            }
            Err(e) => {
                let unreachable = e.downcast_ref::<reqwest::Error>().is_some_and(|r| r.is_connect() || r.is_timeout());
                last_error = if unreachable { anyhow!("Port {port} nicht erreichbar") } else { e.context(format!("Port {port}")) };
                if !unreachable {
                    // Port antwortet, aber mit Fehler: weitere Ports bringen nichts
                    break;
                }
            }
        }
    }
    Err(last_error)
}

// ---------------------------------------------------------------------------
// Offizielle Integration-API (API-Schlüssel)
// ---------------------------------------------------------------------------

async fn get_key(http: &Client, url: &str, key: &str) -> Result<Value> {
    let response = http.get(url).header("X-API-KEY", key).header(header::ACCEPT, "application/json").send().await?;
    match response.status() {
        s if s.is_success() => Ok(response.json().await?),
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => bail!("API-Schlüssel wird abgelehnt (ungültig oder gelöscht?)"),
        StatusCode::NOT_FOUND => bail!("Integration-API nicht gefunden – UniFi Network 9 oder neuer nötig"),
        s => bail!("Controller antwortete mit {s}"),
    }
}

/// Alle Seiten einer Liste holen (`offset`/`limit`, Antwort `{ data, totalCount }`)
async fn get_all(http: &Client, url: &str, key: &str, max: usize) -> Result<(Vec<Value>, u64)> {
    let mut items = Vec::new();
    loop {
        let sep = if url.contains('?') { '&' } else { '?' };
        let page = get_key(http, &format!("{url}{sep}offset={}&limit=200", items.len()), key).await?;
        let data = page["data"].as_array().cloned().unwrap_or_default();
        let total = page["totalCount"].as_u64().unwrap_or((items.len() + data.len()) as u64);
        let empty = data.is_empty();
        items.extend(data);
        if empty || items.len() as u64 >= total || items.len() >= max {
            return Ok((items, total));
        }
    }
}

async fn integration(http: &Client, base: &str, key: &str) -> Result<Value> {
    // Pfad je nach Plattform: UniFi OS mit Proxy, eigenständige Network Application ohne
    let mut api = format!("{base}/proxy/network/integration/v1");
    let info = match get_key(http, &format!("{api}/info"), key).await {
        Ok(info) => info,
        Err(e) if e.to_string().contains("nicht gefunden") => {
            api = format!("{base}/integration/v1");
            get_key(http, &format!("{api}/info"), key).await?
        }
        Err(e) => return Err(e),
    };
    let (sites, _) = get_all(http, &format!("{api}/sites"), key, 100).await?;
    let mut out_sites = Vec::new();
    let mut devices = Vec::new();
    let mut clients = Vec::new();
    let mut clients_total = 0;
    for site in &sites {
        let site_id = site["id"].as_str().unwrap_or_default().to_string();
        let site_name = site["name"].as_str().unwrap_or("Standard").to_string();
        let (site_devices, _) = get_all(http, &format!("{api}/sites/{site_id}/devices"), key, 1000).await?;
        let (site_clients, total) = get_all(http, &format!("{api}/sites/{site_id}/clients"), key, MAX_CLIENTS).await.unwrap_or_default();
        clients_total += total;

        // Aktuelle Auslastung je Gerät (parallel, höchstens 8 gleichzeitig)
        let urls: Vec<String> = site_devices
            .iter()
            .map(|d| format!("{api}/sites/{site_id}/devices/{}/statistics/latest", d["id"].as_str().unwrap_or_default()))
            .collect();
        let stats: Vec<Value> = stream::iter(urls)
            .map(|url| {
                let (http, key) = (http.clone(), key.to_string());
                async move { get_key(&http, &url, &key).await.unwrap_or(Value::Null) }
            })
            .buffered(8)
            .collect()
            .await;

        let mut per_device_clients = std::collections::HashMap::<String, u64>::new();
        for c in &site_clients {
            if let Some(up) = c["uplinkDeviceId"].as_str() {
                *per_device_clients.entry(up.to_string()).or_default() += 1;
            }
        }
        for (d, s) in site_devices.iter().zip(stats) {
            let id = d["id"].as_str().unwrap_or_default();
            devices.push(json!({
                "site": site_name,
                "name": d["name"],
                "model": d["model"],
                "mac": d["macAddress"].as_str().map(str::to_lowercase),
                "ip": d["ipAddress"],
                "state": d["state"].as_str().map(str::to_lowercase),
                "firmware": d["firmwareVersion"],
                "uptime_s": s["uptimeSec"],
                "cpu_pct": s["cpuUtilizationPct"],
                "mem_pct": s["memoryUtilizationPct"],
                "load_1m": s["loadAverage1Min"],
                "tx_bps": s["uplink"]["txRateBps"],
                "rx_bps": s["uplink"]["rxRateBps"],
                "clients": per_device_clients.get(id).copied().unwrap_or(0),
                "radios": d["interfaces"]["radios"],
            }));
        }
        let mac_of: std::collections::HashMap<&str, String> = site_devices
            .iter()
            .filter_map(|d| Some((d["id"].as_str()?, d["macAddress"].as_str()?.to_lowercase())))
            .collect();
        for c in site_clients {
            clients.push(json!({
                "uplink_mac": c["uplinkDeviceId"].as_str().and_then(|id| mac_of.get(id)),
                "name": c["name"],
                "mac": c["macAddress"].as_str().map(str::to_lowercase),
                "ip": c["ipAddress"],
                "type": c["type"].as_str().map(str::to_lowercase),
                "connected_at": c["connectedAt"],
            }));
        }
        out_sites.push(json!({ "name": site_name, "devices": site_devices.len(), "clients": total }));
    }
    Ok(summarize(json!({
        "api": "integration",
        "version": info["applicationVersion"],
        "sites": out_sites,
        "devices": devices,
        "clients": clients,
        "clients_total": clients_total,
    })))
}

// ---------------------------------------------------------------------------
// Klassische API mit lokalem Konto
// ---------------------------------------------------------------------------

async fn classic(http: &Client, base: &str, user: &str, password: &str) -> Result<Value> {
    // UniFi OS; ältere Network Application nutzt /api/login ohne /proxy/network
    let mut unifi_os = true;
    let mut response = http
        .post(format!("{base}/api/auth/login"))
        .json(&json!({ "username": user, "password": password, "rememberMe": false }))
        .send()
        .await?;
    if response.status() == StatusCode::NOT_FOUND {
        unifi_os = false;
        response = http.post(format!("{base}/api/login")).json(&json!({ "username": user, "password": password })).send().await?;
    }
    let status = response.status();
    let csrf = response.headers().get("x-csrf-token").and_then(|v| v.to_str().ok()).map(str::to_string);
    let body = response.text().await.unwrap_or_default();
    if status.as_u16() == 499 || body.contains("2fa") || body.contains("2Fa") || body.contains("MFA") {
        bail!("Für dieses Konto ist die Zwei-Faktor-Anmeldung aktiv – stattdessen einen API-Schlüssel verwenden \
               (UniFi Network → Einstellungen → Control Plane → Integrations) oder ein lokales Nur-Lese-Konto ohne 2FA anlegen");
    }
    if !status.is_success() {
        bail!("Anmeldung fehlgeschlagen ({status}) – Benutzername/Passwort prüfen (lokales Konto, kein UI-Konto)");
    }
    let prefix = if unifi_os { format!("{base}/proxy/network") } else { base.to_string() };
    let get = |path: String| {
        let mut request = http.get(format!("{prefix}{path}"));
        if let Some(token) = &csrf {
            request = request.header("X-CSRF-Token", token);
        }
        async move {
            let response = request.send().await?;
            if !response.status().is_success() {
                bail!("Controller antwortete mit {}", response.status());
            }
            response.json::<Value>().await.context("Antwort nicht lesbar")
        }
    };
    let sites = get("/api/self/sites".into()).await?;
    let mut out_sites = Vec::new();
    let mut devices = Vec::new();
    let mut clients = Vec::new();
    let mut version = Value::Null;
    for site in sites["data"].as_array().into_iter().flatten() {
        let name = site["name"].as_str().unwrap_or("default");
        let label = site["desc"].as_str().unwrap_or(name).to_string();
        let site_devices = get(format!("/api/s/{name}/stat/device")).await.unwrap_or(Value::Null);
        let site_clients = get(format!("/api/s/{name}/stat/sta")).await.unwrap_or(Value::Null);
        if version.is_null() {
            version = get(format!("/api/s/{name}/stat/sysinfo")).await.map(|v| v["data"][0]["version"].clone()).unwrap_or(Value::Null);
        }
        let list = site_devices["data"].as_array().cloned().unwrap_or_default();
        let sta = site_clients["data"].as_array().cloned().unwrap_or_default();
        for d in &list {
            let num = |v: &Value| v.as_f64().or_else(|| v.as_str().and_then(|s| s.parse().ok()));
            devices.push(json!({
                "site": label,
                "name": d["name"].as_str().or(d["hostname"].as_str()),
                "model": d["model"],
                "mac": d["mac"].as_str().map(str::to_lowercase),
                "ip": d["ip"],
                "state": match d["state"].as_i64() { Some(1) => "online", Some(0) => "offline", Some(_) => "pending", None => "unknown" },
                "firmware": d["version"],
                "uptime_s": d["uptime"],
                "cpu_pct": num(&d["system-stats"]["cpu"]),
                "mem_pct": num(&d["system-stats"]["mem"]),
                "load_1m": num(&d["sys_stats"]["loadavg_1"]),
                "tx_bps": d["uplink"]["tx_bytes-r"].as_f64().map(|b| b * 8.0),
                "rx_bps": d["uplink"]["rx_bytes-r"].as_f64().map(|b| b * 8.0),
                "clients": d["num_sta"],
            }));
        }
        for c in &sta {
            clients.push(json!({
                "name": c["name"].as_str().or(c["hostname"].as_str()),
                "mac": c["mac"].as_str().map(str::to_lowercase),
                "ip": c["ip"],
                "type": if c["is_wired"].as_bool() == Some(true) { "wired" } else { "wireless" },
                "uplink_mac": c["ap_mac"].as_str().or(c["sw_mac"].as_str()).map(str::to_lowercase),
            }));
        }
        out_sites.push(json!({ "name": label, "devices": list.len(), "clients": sta.len() }));
    }
    let _ = http.post(format!("{base}/api/{}logout", if unifi_os { "auth/" } else { "" })).send().await;
    let clients_total = clients.len();
    Ok(summarize(json!({
        "api": "classic",
        "version": version,
        "sites": out_sites,
        "devices": devices,
        "clients": clients,
        "clients_total": clients_total,
    })))
}

fn summarize(mut data: Value) -> Value {
    let devices = data["devices"].as_array().cloned().unwrap_or_default();
    let online = devices.iter().filter(|d| d["state"] == "online" || d["state"] == "connected").count();
    data["devices_total"] = json!(devices.len());
    data["devices_online"] = json!(online);
    if let Some(list) = data["clients"].as_array_mut() {
        list.truncate(MAX_CLIENTS);
    }
    data
}

/// Gerätetyp aus dem UniFi-Modellkürzel
pub fn device_type(model: &str) -> Option<&'static str> {
    let m = model.to_uppercase();
    if ["UDM", "UDR", "UCG", "UXG", "USG", "UDW", "UX", "EFG"].iter().any(|p| m.starts_with(p)) {
        Some("router")
    } else if m.starts_with("USW") || (m.starts_with("US") && !m.starts_with("USP")) || m.starts_with("ECS") {
        Some("switch")
    } else if ["U6", "U7", "UAP", "UAL", "UK", "UWB", "E7", "U5", "UBB"].iter().any(|p| m.starts_with(p)) {
        Some("access_point")
    } else if m.starts_with("UVC") || m.starts_with("G4") || m.starts_with("G5") || m.starts_with("G6") {
        Some("camera")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modelle() {
        assert_eq!(device_type("U6-Pro"), Some("access_point"));
        assert_eq!(device_type("USW-Lite-8-PoE"), Some("switch"));
        assert_eq!(device_type("UDM-Pro"), Some("router"));
        assert_eq!(device_type("UCG-Ultra"), Some("router"));
        assert_eq!(device_type("Foo"), None);
    }
}
