//! HTTPS zu Geräten mit selbst signiertem Zertifikat (UniFi, OPNsense, MikroTik …):
//! Das Zertifikat wird beim ersten Kontakt gemerkt („Trust on first use“, wie beim SSH-Host-Schlüssel).
//! Ändert es sich später, wird die Verbindung abgebrochen, bevor Zugangsdaten gesendet werden.

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::Result;
use reqwest::Client;

/// Nimmt nur das gemerkte Zertifikat an (oder beim ersten Kontakt jedes) und merkt sich den Fingerabdruck
#[derive(Debug)]
pub struct Pin {
    expected: Option<String>,
    seen: Mutex<Option<String>>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl Pin {
    pub fn new(expected: Option<&str>) -> Arc<Self> {
        Arc::new(Self {
            expected: expected.map(str::to_string),
            seen: Mutex::default(),
            provider: Arc::new(rustls::crypto::ring::default_provider()),
        })
    }

    /// Fingerabdruck (SHA-256, hex) des zuletzt gesehenen Zertifikats – zum Merken beim ersten Kontakt
    pub fn seen(&self) -> Option<String> {
        self.seen.lock().unwrap().clone()
    }
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

/// HTTP-Client, der nur das gemerkte Zertifikat akzeptiert
pub fn client(pin: Arc<Pin>) -> Result<Client> {
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

/// Hat das Gerät ein anderes Zertifikat als das gemerkte? (Fehler steckt tief in reqwest → hyper → rustls)
pub fn pin_mismatch(e: &anyhow::Error) -> bool {
    e.chain().any(|c| {
        let mut source: Option<&dyn std::error::Error> = Some(c);
        while let Some(err) = source {
            if err.to_string().contains("NetPulse-Pin") || format!("{err:?}").contains("NetPulse-Pin") {
                return true;
            }
            source = err.source();
        }
        false
    })
}

/// Einheitliche Meldung bei geändertem Zertifikat
pub const PIN_CHANGED: &str = "Das Zertifikat des Geräts hat sich geändert – Zugangsdaten wurden NICHT gesendet (möglicher Angriff). \
     Wurde das Gerät neu installiert, beim Gerät unter „Einstellungen“ die gemerkten Schlüssel zurücksetzen.";

/// Nur Verbindungsfehler (Gerät/Port nicht erreichbar)?
pub fn unreachable(e: &anyhow::Error) -> bool {
    e.downcast_ref::<reqwest::Error>().is_some_and(|r| r.is_connect() || r.is_timeout()) && !pin_mismatch(e)
}
