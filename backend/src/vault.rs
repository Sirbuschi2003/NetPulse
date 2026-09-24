//! Tresor für Geheimnisse (Passwörter, SNMP-Communities, SSH-Schlüssel, Webhook-Tokens).
//!
//! Verschlüsselt wird mit AES-256-GCM (authentifizierte Verschlüsselung: Manipulationen fallen auf).
//! Der Schlüssel liegt **nicht** in der Datenbank, sondern in `DATA_DIR/secret.key`
//! oder in der Umgebungsvariable `SECRET_KEY`. Ein Datenbank-Backup allein verrät also nichts.

use std::{fs, io::Write, path::Path};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{anyhow, bail, Context, Result};
use argon2::password_hash::rand_core::{OsRng, RngCore};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::{de::DeserializeOwned, Serialize};

pub struct Vault {
    cipher: Aes256Gcm,
}

impl Vault {
    /// Lädt den Schlüssel aus `SECRET_KEY` oder `data_dir/secret.key`; legt ihn beim ersten Start an.
    pub fn open(data_dir: &str, secret_key: Option<&str>) -> Result<Self> {
        let key_bytes = match secret_key {
            Some(hex_key) => hex::decode(hex_key.trim()).context("SECRET_KEY muss aus 64 Hex-Zeichen bestehen")?,
            None => load_or_create_key_file(Path::new(data_dir))?,
        };
        if key_bytes.len() != 32 {
            bail!("Der Tresor-Schlüssel muss 32 Byte (64 Hex-Zeichen) lang sein");
        }
        Ok(Self { cipher: Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes)) })
    }

    /// Verschlüsselt einen beliebigen serialisierbaren Wert → Base64(Nonce ‖ Chiffrat)
    pub fn seal<T: Serialize>(&self, value: &T) -> Result<String> {
        let plain = serde_json::to_vec(value)?;
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let cipher = self
            .cipher
            .encrypt(Nonce::from_slice(&nonce), plain.as_slice())
            .map_err(|_| anyhow!("Verschlüsselung fehlgeschlagen"))?;
        let mut out = nonce.to_vec();
        out.extend(cipher);
        Ok(B64.encode(out))
    }

    pub fn open_value<T: DeserializeOwned>(&self, sealed: &str) -> Result<T> {
        let raw = B64.decode(sealed).context("Tresor-Eintrag beschädigt")?;
        if raw.len() < 13 {
            bail!("Tresor-Eintrag beschädigt");
        }
        let (nonce, cipher) = raw.split_at(12);
        let plain = self.cipher.decrypt(Nonce::from_slice(nonce), cipher).map_err(|_| {
            anyhow!("Entschlüsselung fehlgeschlagen – wurde der Tresor-Schlüssel (secret.key) ausgetauscht?")
        })?;
        Ok(serde_json::from_slice(&plain)?)
    }
}

fn load_or_create_key_file(dir: &Path) -> Result<Vec<u8>> {
    let path = dir.join("secret.key");
    if path.exists() {
        let text = fs::read_to_string(&path).with_context(|| format!("{} nicht lesbar", path.display()))?;
        return hex::decode(text.trim()).with_context(|| format!("{} ist ungültig", path.display()));
    }
    fs::create_dir_all(dir).with_context(|| format!("Verzeichnis {} nicht anlegbar", dir.display()))?;
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);

    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&path)
        .with_context(|| format!("{} nicht anlegbar – ist DATA_DIR als Volume eingebunden?", path.display()))?;
    file.write_all(hex::encode(key).as_bytes())?;
    tracing::warn!(
        "Neuer Tresor-Schlüssel erzeugt: {}. Diese Datei unbedingt mitsichern – ohne sie sind gespeicherte Zugangsdaten nicht mehr lesbar.",
        path.display()
    );
    Ok(key.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verschluesseln_und_entschluesseln() {
        let vault = Vault::open("/nicht/benutzt", Some(&"ab".repeat(32))).unwrap();
        let sealed = vault.seal(&serde_json::json!({ "password": "geheim" })).unwrap();
        assert!(!sealed.contains("geheim"));
        let value: serde_json::Value = vault.open_value(&sealed).unwrap();
        assert_eq!(value["password"], "geheim");

        let other = Vault::open("/nicht/benutzt", Some(&"cd".repeat(32))).unwrap();
        assert!(other.open_value::<serde_json::Value>(&sealed).is_err());
    }
}
