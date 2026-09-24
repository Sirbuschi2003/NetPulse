//! Dienst-Checks (wie Uptime Kuma): prüfen, ob Webseiten, Dienste und Zertifikate funktionieren.
//!
//! Arten:
//! - `http` : URL abrufen; erwarteter Status (Standard 200–399), optional Suchwort im Inhalt
//!   (auch „darf nicht vorkommen“); bei HTTPS zusätzlich Ablaufdatum des Zertifikats
//! - `tls`  : nur das Zertifikat eines Dienstes (host:port) – Ablauf und Vertrauenswürdigkeit
//! - `tcp`  : Port erreichbar (host:port)
//! - `dns`  : Name auflösen, optional über einen bestimmten DNS-Server und mit erwarteter Adresse
//!
//! Ein Check gilt erst nach `retries` Fehlschlägen hintereinander als ausgefallen
//! (verhindert Fehlalarme durch einzelne Aussetzer).

use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::{anyhow, bail, Context, Result};
use chrono::{DateTime, Utc};
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
    DigitallySignedStruct, SignatureScheme,
};
use serde::Serialize;
use serde_json::{json, Value};
use tokio::{
    net::{TcpStream, UdpSocket},
    sync::Semaphore,
};

use crate::AppState;

pub const KINDS: &[&str] = &["http", "tcp", "dns", "tls"];

#[derive(sqlx::FromRow, Clone)]
pub struct Check {
    pub id: i64,
    pub name: String,
    pub kind: String,
    pub target: String,
    pub config: Value,
    pub timeout_s: i32,
    pub status: String,
    pub fail_count: i32,
}

/// Ergebnis eines Durchlaufs
#[derive(Serialize, Clone, Debug)]
pub struct Outcome {
    pub ok: bool,
    /// Funktioniert, aber mit Warnung (z. B. Zertifikat läuft bald ab)
    pub warn: bool,
    pub ms: Option<f32>,
    pub message: String,
    pub cert_expires_at: Option<DateTime<Utc>>,
}

impl Outcome {
    fn fail(message: impl Into<String>, ms: Option<f32>) -> Self {
        Self { ok: false, warn: false, ms, message: message.into(), cert_expires_at: None }
    }
}

// ---------------------------------------------------------------------------
// Ablauf
// ---------------------------------------------------------------------------

pub async fn run(state: AppState) {
    tokio::time::sleep(Duration::from_secs(8)).await;
    let running: Arc<Mutex<HashSet<i64>>> = Arc::default();
    let limit = Arc::new(Semaphore::new(32));
    let mut tick = tokio::time::interval(Duration::from_secs(2));
    loop {
        tick.tick().await;
        let due: Vec<Check> = match sqlx::query_as(
            "SELECT id, name, kind, target, config, timeout_s, status, fail_count FROM checks
              WHERE enabled AND (last_check IS NULL OR last_check + make_interval(secs => interval_s) <= now())",
        )
        .fetch_all(&state.db)
        .await
        {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!("Dienst-Checks: {e}");
                continue;
            }
        };
        for check in due {
            if !running.lock().unwrap().insert(check.id) {
                continue;
            }
            let (state, running, limit) = (state.clone(), running.clone(), limit.clone());
            tokio::spawn(async move {
                let _permit = limit.acquire().await;
                let id = check.id;
                if let Err(e) = execute(&state, &check).await {
                    tracing::warn!("Check „{}“: {e:#}", check.name);
                }
                running.lock().unwrap().remove(&id);
            });
        }
    }
}

/// Einmal prüfen, Ergebnis speichern und melden
pub async fn execute(state: &AppState, check: &Check) -> Result<Outcome> {
    let _perf = crate::perf::Timer::new("Dienst-Check");
    let timeout = Duration::from_secs(u64::try_from(check.timeout_s.clamp(1, 60)).unwrap_or(10));
    let outcome = match tokio::time::timeout(timeout + Duration::from_secs(2), probe(check, timeout)).await {
        Ok(Ok(o)) => o,
        Ok(Err(e)) => Outcome::fail(format!("{e:#}"), None),
        Err(_) => Outcome::fail(format!("Zeitüberschreitung nach {} s", timeout.as_secs()), None),
    };

    let retries = check.config["retries"].as_i64().unwrap_or(1).clamp(1, 10) as i32;
    let fail_count = if outcome.ok { 0 } else { check.fail_count + 1 };
    let status = if outcome.ok {
        if outcome.warn { "warn" } else { "up" }
    } else if fail_count >= retries {
        "down"
    } else if check.status == "unknown" {
        "pending"
    } else {
        check.status.as_str()
    };
    let changed = status != check.status;

    sqlx::query(
        "UPDATE checks SET status = $2, fail_count = $3, last_check = now(), last_ms = $4, last_message = $5,
                cert_expires_at = COALESCE($6, cert_expires_at),
                status_since = CASE WHEN status = $2 THEN COALESCE(status_since, now()) ELSE now() END
          WHERE id = $1",
    )
    .bind(check.id)
    .bind(status)
    .bind(fail_count)
    .bind(outcome.ms)
    .bind(&outcome.message)
    .bind(outcome.cert_expires_at)
    .execute(&state.db)
    .await?;
    sqlx::query("INSERT INTO check_results (time, check_id, ok, ms) VALUES (now(), $1, $2, $3)")
        .bind(check.id)
        .bind(outcome.ok)
        .bind(outcome.ms)
        .execute(&state.db)
        .await?;

    // Statuswechsel als Ereignis (ohne den Wechsel von „unbekannt“ auf „ok“)
    if changed && !(check.status == "unknown" && status == "up") && status != "pending" {
        let message = match status {
            "down" => format!("Dienst „{}“ ausgefallen: {}", check.name, outcome.message),
            "warn" => format!("Dienst „{}“: {}", check.name, outcome.message),
            _ => format!("Dienst „{}“ funktioniert wieder", check.name),
        };
        let kind = if status == "down" { "check_down" } else if status == "warn" { "check_warn" } else { "check_up" };
        let _ = sqlx::query("INSERT INTO events (device_id, kind, message) SELECT device_id, $2, $3 FROM checks WHERE id = $1")
            .bind(check.id)
            .bind(kind)
            .bind(&message)
            .execute(&state.db)
            .await;
    }
    state.hub.publish(&json!({
        "type": "check", "id": check.id, "status": status, "ok": outcome.ok, "ms": outcome.ms,
        "message": outcome.message, "time": Utc::now(), "changed": changed,
    }));
    Ok(outcome)
}

async fn probe(check: &Check, timeout: Duration) -> Result<Outcome> {
    match check.kind.as_str() {
        "http" => http(check, timeout).await,
        "tcp" => tcp(&check.target, timeout).await,
        "dns" => dns(check, timeout).await,
        "tls" => {
            let (host, port) = host_port(&check.target, 443)?;
            tls_outcome(&host, port, &check.config, timeout).await
        }
        other => bail!("unbekannte Art {other}"),
    }
}

/// „host:port“ oder „[v6]:port“ zerlegen
fn host_port(target: &str, default: u16) -> Result<(String, u16)> {
    let t = target.trim().trim_start_matches("https://").trim_start_matches("http://").split('/').next().unwrap_or_default();
    if let Some(rest) = t.strip_prefix('[') {
        let (h, p) = rest.split_once(']').ok_or_else(|| anyhow!("ungültige IPv6-Angabe"))?;
        let port = p.strip_prefix(':').and_then(|p| p.parse().ok()).unwrap_or(default);
        return Ok((h.to_string(), port));
    }
    match t.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => Ok((h.to_string(), p.parse().context("ungültiger Port")?)),
        _ if t.is_empty() => bail!("Ziel fehlt"),
        _ => Ok((t.to_string(), default)),
    }
}

fn ms_since(start: Instant) -> f32 {
    (start.elapsed().as_secs_f64() * 1000.0) as f32
}

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

fn expected_status(config: &Value, status: u16) -> bool {
    match config["expect_status"].as_str().map(str::trim).filter(|s| !s.is_empty()) {
        None => (200..400).contains(&status),
        Some(list) => list.split([',', ' ']).filter(|s| !s.is_empty()).any(|part| match part.split_once('-') {
            Some((a, b)) => a.parse::<u16>().ok().zip(b.parse::<u16>().ok()).is_some_and(|(a, b)| (a..=b).contains(&status)),
            None => part.parse::<u16>().ok() == Some(status),
        }),
    }
}

async fn http(check: &Check, timeout: Duration) -> Result<Outcome> {
    let url = reqwest::Url::parse(check.target.trim()).context("ungültige URL (mit http:// oder https:// angeben)")?;
    let cfg = &check.config;
    let client = reqwest::Client::builder()
        .timeout(timeout)
        .danger_accept_invalid_certs(cfg["ignore_tls"].as_bool().unwrap_or(false))
        .redirect(reqwest::redirect::Policy::limited(5))
        .user_agent("NetPulse-Check")
        .build()?;
    let method = if cfg["method"].as_str() == Some("HEAD") { reqwest::Method::HEAD } else { reqwest::Method::GET };
    let start = Instant::now();
    let mut response = match client.request(method, url.clone()).send().await {
        Ok(r) => r,
        Err(e) => {
            let reason = if e.is_timeout() {
                "Zeitüberschreitung".to_string()
            } else if e.is_connect() && root_cause(&e).contains("InternalError") {
                "TLS abgelehnt – der Server hat für diesen Namen kein Zertifikat (Hostname statt IP verwenden?)".to_string()
            } else if e.is_connect() {
                format!("keine Verbindung ({})", root_cause(&e))
            } else {
                root_cause(&e)
            };
            return Ok(Outcome::fail(reason, Some(ms_since(start))));
        }
    };
    let status = response.status();
    // Inhalt nur bei Suchwort lesen (höchstens 2 MB)
    let keyword = cfg["keyword"].as_str().map(str::trim).filter(|k| !k.is_empty());
    let mut body = Vec::new();
    if keyword.is_some() {
        while let Some(chunk) = response.chunk().await? {
            body.extend_from_slice(&chunk);
            if body.len() > 2_000_000 {
                break;
            }
        }
    }
    let ms = ms_since(start);
    let reason = status.canonical_reason().unwrap_or("");
    if !expected_status(cfg, status.as_u16()) {
        return Ok(Outcome::fail(format!("HTTP {} {reason}", status.as_u16()), Some(ms)));
    }
    let mut message = format!("HTTP {} {reason} · {ms:.0} ms", status.as_u16());
    if let Some(keyword) = keyword {
        let found = String::from_utf8_lossy(&body).to_lowercase().contains(&keyword.to_lowercase());
        let invert = cfg["keyword_invert"].as_bool().unwrap_or(false);
        if found == invert {
            return Ok(Outcome::fail(
                if invert { format!("Suchwort „{keyword}“ gefunden (darf nicht vorkommen)") } else { format!("Suchwort „{keyword}“ nicht gefunden") },
                Some(ms),
            ));
        }
        message.push_str(&format!(" · Suchwort {}", if invert { "nicht vorhanden" } else { "gefunden" }));
    }
    let mut outcome = Outcome { ok: true, warn: false, ms: Some(ms), message, cert_expires_at: None };
    if url.scheme() == "https" && cfg["check_cert"].as_bool().unwrap_or(true) {
        if let Some(host) = url.host_str() {
            if let Ok(tls) = tls_outcome(host, url.port_or_known_default().unwrap_or(443), cfg, timeout).await {
                outcome.cert_expires_at = tls.cert_expires_at;
                if !tls.ok || tls.warn {
                    outcome.warn = true;
                    outcome.message.push_str(&format!(" · {}", tls.message));
                }
            }
        }
    }
    Ok(outcome)
}

fn root_cause(e: &dyn std::error::Error) -> String {
    let mut cause = e.to_string();
    let mut source = e.source();
    while let Some(s) = source {
        cause = s.to_string();
        source = s.source();
    }
    cause
}

// ---------------------------------------------------------------------------
// TCP
// ---------------------------------------------------------------------------

async fn tcp(target: &str, timeout: Duration) -> Result<Outcome> {
    let (host, port) = host_port(target, 0)?;
    if port == 0 {
        bail!("Port fehlt (Format host:port)");
    }
    let start = Instant::now();
    match tokio::time::timeout(timeout, TcpStream::connect((host.as_str(), port))).await {
        Ok(Ok(_)) => {
            let ms = ms_since(start);
            Ok(Outcome { ok: true, warn: false, ms: Some(ms), message: format!("Port {port} offen · {ms:.0} ms"), cert_expires_at: None })
        }
        Ok(Err(e)) => Ok(Outcome::fail(format!("Port {port}: {e}"), Some(ms_since(start)))),
        Err(_) => Ok(Outcome::fail(format!("Port {port}: Zeitüberschreitung"), None)),
    }
}

// ---------------------------------------------------------------------------
// TLS-Zertifikat
// ---------------------------------------------------------------------------

/// Nimmt jedes Zertifikat an und merkt sich die Kette – geprüft wird danach separat
#[derive(Debug)]
struct Capture {
    chain: Mutex<Vec<CertificateDer<'static>>>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for Capture {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let mut chain = vec![end_entity.clone().into_owned()];
        chain.extend(intermediates.iter().map(|c| c.clone().into_owned()));
        *self.chain.lock().unwrap() = chain;
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }
    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

pub struct TlsInfo {
    pub not_after: DateTime<Utc>,
    pub subject: String,
    pub issuer: String,
    /// `Err` mit Grund, wenn das Zertifikat nicht vertrauenswürdig ist (selbst signiert, falscher Name …)
    pub trusted: Result<(), String>,
}

pub async fn tls_info(host: &str, port: u16, timeout: Duration) -> Result<TlsInfo> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let capture = Arc::new(Capture { chain: Mutex::default(), provider: provider.clone() });
    let config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(capture.clone())
        .with_no_client_auth();
    let server_name = ServerName::try_from(host.to_string()).map_err(|_| anyhow!("ungültiger Hostname"))?;
    let stream = tokio::time::timeout(timeout, TcpStream::connect((host, port))).await.map_err(|_| anyhow!("Zeitüberschreitung"))??;
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    tokio::time::timeout(timeout, connector.connect(server_name.clone(), stream))
        .await
        .map_err(|_| anyhow!("TLS-Zeitüberschreitung"))?
        .context("TLS-Verbindung fehlgeschlagen")?;
    let chain = capture.chain.lock().unwrap().clone();
    let end_entity = chain.first().ok_or_else(|| anyhow!("kein Zertifikat erhalten"))?;
    let (_, cert) = x509_parser::parse_x509_certificate(end_entity.as_ref()).map_err(|_| anyhow!("Zertifikat nicht lesbar"))?;
    let not_after = DateTime::from_timestamp(cert.validity().not_after.timestamp(), 0).ok_or_else(|| anyhow!("ungültiges Datum"))?;
    let cn = |name: &x509_parser::x509::X509Name| {
        name.iter_common_name().next().and_then(|c| c.as_str().ok()).map(str::to_string).unwrap_or_else(|| name.to_string())
    };

    let roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
    let trusted = rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider)
        .build()
        .map_err(|e| e.to_string())
        .and_then(|v| {
            v.verify_server_cert(end_entity, &chain[1..], &server_name, &[], UnixTime::now())
                .map(|_| ())
                .map_err(|e| trust_reason(&e))
        });
    Ok(TlsInfo { not_after, subject: cn(cert.subject()), issuer: cn(cert.issuer()), trusted })
}

fn trust_reason(e: &rustls::Error) -> String {
    let text = format!("{e:?}");
    if text.contains("UnknownIssuer") {
        "Aussteller unbekannt (selbst signiert oder eigene CA)".into()
    } else if text.contains("NotValidForName") {
        "Zertifikat passt nicht zum Namen".into()
    } else if text.contains("Expired") {
        "abgelaufen".into()
    } else {
        e.to_string()
    }
}

async fn tls_outcome(host: &str, port: u16, cfg: &Value, timeout: Duration) -> Result<Outcome> {
    let start = Instant::now();
    let info = match tls_info(host, port, timeout).await {
        Ok(i) => i,
        Err(e) => return Ok(Outcome::fail(format!("{e:#}"), Some(ms_since(start)))),
    };
    let ms = ms_since(start);
    let days = (info.not_after - Utc::now()).num_days();
    let warn_days = cfg["warn_days"].as_i64().unwrap_or(14);
    let until = info.not_after.format("%d.%m.%Y");
    let mut outcome = Outcome {
        ok: true,
        warn: false,
        ms: Some(ms),
        message: format!("Zertifikat für {} gültig bis {until} (noch {days} Tage), Aussteller {}", info.subject, info.issuer),
        cert_expires_at: Some(info.not_after),
    };
    if days < 0 {
        outcome.ok = false;
        outcome.message = format!("Zertifikat seit {until} abgelaufen");
    } else if days < warn_days {
        outcome.warn = true;
        outcome.message = format!("Zertifikat läuft in {days} Tagen ab ({until})");
    }
    if let Err(reason) = &info.trusted {
        if !cfg["ignore_tls"].as_bool().unwrap_or(false) && outcome.ok {
            outcome.warn = true;
            outcome.message.push_str(&format!(" · nicht vertrauenswürdig: {reason}"));
        }
    }
    Ok(outcome)
}

// ---------------------------------------------------------------------------
// DNS (kleiner eigener Client für A/AAAA – damit sich ein bestimmter DNS-Server prüfen lässt)
// ---------------------------------------------------------------------------

fn dns_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut q = Vec::with_capacity(64);
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]); // Rekursion gewünscht, 1 Frage
    for label in name.trim_end_matches('.').split('.') {
        q.push(label.len().min(63) as u8);
        q.extend_from_slice(&label.as_bytes()[..label.len().min(63)]);
    }
    q.push(0);
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&1u16.to_be_bytes());
    q
}

fn skip_name(buf: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let len = *buf.get(pos)?;
        if len == 0 {
            return Some(pos + 1);
        }
        if len & 0xC0 == 0xC0 {
            return Some(pos + 2);
        }
        pos += 1 + len as usize;
    }
}

/// (Antwortcode, gefundene Adressen)
fn dns_parse(buf: &[u8], id: u16) -> Option<(u8, Vec<IpAddr>)> {
    let u16_at = |p: usize| Some(u16::from_be_bytes([*buf.get(p)?, *buf.get(p + 1)?]));
    if u16_at(0)? != id {
        return None;
    }
    let rcode = buf.get(3)? & 0x0f;
    let (qd, an) = (u16_at(4)?, u16_at(6)?);
    let mut pos = 12;
    for _ in 0..qd {
        pos = skip_name(buf, pos)? + 4;
    }
    let mut addrs = Vec::new();
    for _ in 0..an {
        pos = skip_name(buf, pos)?;
        let rtype = u16_at(pos)?;
        let len = u16_at(pos + 8)? as usize;
        let data = buf.get(pos + 10..pos + 10 + len)?;
        match (rtype, len) {
            (1, 4) => addrs.push(IpAddr::from(<[u8; 4]>::try_from(data).ok()?)),
            (28, 16) => addrs.push(IpAddr::from(<[u8; 16]>::try_from(data).ok()?)),
            _ => {}
        }
        pos += 10 + len;
    }
    Some((rcode, addrs))
}

async fn dns(check: &Check, timeout: Duration) -> Result<Outcome> {
    let name = check.target.trim();
    let cfg = &check.config;
    let start = Instant::now();
    let server = cfg["server"].as_str().map(str::trim).filter(|s| !s.is_empty());
    let addrs: Vec<IpAddr> = match server {
        None => match tokio::time::timeout(timeout, tokio::net::lookup_host((name, 0))).await {
            Ok(Ok(list)) => list.map(|a| a.ip()).collect(),
            Ok(Err(e)) => return Ok(Outcome::fail(format!("Name nicht auflösbar: {e}"), Some(ms_since(start)))),
            Err(_) => return Ok(Outcome::fail("DNS: Zeitüberschreitung", None)),
        },
        Some(server) => {
            let addr: SocketAddr = match server.parse::<SocketAddr>() {
                Ok(a) => a,
                Err(_) => SocketAddr::new(server.parse::<IpAddr>().context("DNS-Server als IP-Adresse angeben")?, 53),
            };
            let qtype = if cfg["record"].as_str() == Some("AAAA") { 28 } else { 1 };
            let socket = UdpSocket::bind(if addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }).await?;
            let id: u16 = rand_id();
            socket.send_to(&dns_query(id, name, qtype), addr).await?;
            let mut buf = [0u8; 1500];
            let (n, from) = match tokio::time::timeout(timeout, socket.recv_from(&mut buf)).await {
                Ok(r) => r?,
                Err(_) => return Ok(Outcome::fail(format!("DNS-Server {addr} antwortet nicht"), None)),
            };
            if from.ip() != addr.ip() {
                return Ok(Outcome::fail("DNS-Antwort von fremder Adresse verworfen", None));
            }
            let (rcode, addrs) = dns_parse(&buf[..n], id).ok_or_else(|| anyhow!("ungültige DNS-Antwort"))?;
            match rcode {
                0 => addrs,
                3 => return Ok(Outcome::fail(format!("Name „{name}“ existiert nicht (NXDOMAIN)"), Some(ms_since(start)))),
                2 => return Ok(Outcome::fail("DNS-Server meldet Fehler (SERVFAIL)", Some(ms_since(start)))),
                5 => return Ok(Outcome::fail("DNS-Server verweigert die Anfrage (REFUSED)", Some(ms_since(start)))),
                other => return Ok(Outcome::fail(format!("DNS-Antwortcode {other}"), Some(ms_since(start)))),
            }
        }
    };
    let ms = ms_since(start);
    if addrs.is_empty() {
        return Ok(Outcome::fail("keine Adresse erhalten", Some(ms)));
    }
    let list: Vec<String> = addrs.iter().map(ToString::to_string).collect();
    if let Some(expect) = cfg["expect"].as_str().map(str::trim).filter(|s| !s.is_empty()) {
        if !list.iter().any(|a| a == expect) {
            return Ok(Outcome::fail(format!("erwartet {expect}, erhalten {}", list.join(", ")), Some(ms)));
        }
    }
    Ok(Outcome { ok: true, warn: false, ms: Some(ms), message: format!("{} · {ms:.0} ms", list.join(", ")), cert_expires_at: None })
}

fn rand_id() -> u16 {
    use argon2::password_hash::rand_core::{OsRng, RngCore};
    (OsRng.next_u32() & 0xffff) as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ziele_zerlegen() {
        assert_eq!(host_port("example.de:8443", 443).unwrap(), ("example.de".into(), 8443));
        assert_eq!(host_port("https://example.de/pfad", 443).unwrap(), ("example.de".into(), 443));
        assert_eq!(host_port("[2001:db8::1]:53", 0).unwrap(), ("2001:db8::1".into(), 53));
        assert!(host_port("", 1).is_err());
    }

    #[test]
    fn statuscodes() {
        assert!(expected_status(&json!({}), 200) && expected_status(&json!({}), 302) && !expected_status(&json!({}), 404));
        let cfg = json!({ "expect_status": "200, 401-403" });
        assert!(expected_status(&cfg, 401) && expected_status(&cfg, 200) && !expected_status(&cfg, 500));
    }

    #[test]
    fn dns_nachricht() {
        let q = dns_query(0x1234, "example.de", 1);
        // Antwort: Frage kopieren + eine A-Antwort mit Namensverweis (0xC00C)
        let mut r = q.clone();
        r[2] = 0x81;
        r[3] = 0x80;
        r[7] = 1;
        r.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 216, 34]);
        let (rcode, addrs) = dns_parse(&r, 0x1234).unwrap();
        assert_eq!(rcode, 0);
        assert_eq!(addrs, vec!["93.184.216.34".parse::<IpAddr>().unwrap()]);
        assert!(dns_parse(&r, 0x9999).is_none());
    }
}
