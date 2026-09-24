//! Zwei-Faktor-Anmeldung mit Einmal-Codes (TOTP, RFC 6238) – kompatibel mit
//! Google/Microsoft Authenticator, Aegis, 2FAS, 1Password, Bitwarden …

use argon2::password_hash::rand_core::{OsRng, RngCore};
use hmac::{Hmac, Mac};
use sha1::Sha1;

const STEP: i64 = 30;
const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Neues Geheimnis (160 Bit) als Base32-Text
pub fn new_secret() -> String {
    let mut bytes = [0u8; 20];
    OsRng.fill_bytes(&mut bytes);
    base32_encode(&bytes)
}

fn base32_encode(data: &[u8]) -> String {
    let mut out = String::new();
    let (mut buffer, mut bits) = (0u32, 0);
    for &b in data {
        buffer = (buffer << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            out.push(ALPHABET[((buffer >> (bits - 5)) & 31) as usize] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    out
}

fn base32_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let (mut buffer, mut bits) = (0u32, 0);
    for c in text.chars().filter(|c| !c.is_whitespace() && *c != '=') {
        let v = ALPHABET.iter().position(|&a| a as char == c.to_ascii_uppercase())? as u32;
        buffer = (buffer << 5) | v;
        bits += 5;
        if bits >= 8 {
            out.push((buffer >> (bits - 8)) as u8);
            bits -= 8;
        }
    }
    Some(out)
}

fn code_at(secret: &[u8], step: i64) -> u32 {
    let mut mac = Hmac::<Sha1>::new_from_slice(secret).expect("HMAC akzeptiert jede Schlüssellänge");
    mac.update(&step.to_be_bytes());
    let hash = mac.finalize().into_bytes();
    let offset = (hash[19] & 0x0f) as usize;
    let value = u32::from_be_bytes([hash[offset] & 0x7f, hash[offset + 1], hash[offset + 2], hash[offset + 3]]);
    value % 1_000_000
}

/// Prüft einen 6-stelligen Code (±30 s Toleranz für ungenaue Uhren).
/// Liefert den Zeitschritt, damit ein Code nicht zweimal benutzt werden kann.
pub fn verify(secret_b32: &str, code: &str, unix_time: i64, last_used_step: Option<i64>) -> Option<i64> {
    let code: String = code.chars().filter(char::is_ascii_digit).collect();
    if code.len() != 6 {
        return None;
    }
    let code: u32 = code.parse().ok()?;
    let secret = base32_decode(secret_b32)?;
    let now = unix_time / STEP;
    (now - 1..=now + 1)
        .filter(|step| last_used_step.is_none_or(|last| *step > last))
        .find(|step| code_at(&secret, *step) == code)
}

/// Link für die Authenticator-App (wird als QR-Code angezeigt)
pub fn uri(secret_b32: &str, username: &str, issuer: &str) -> String {
    let enc = |s: &str| s.bytes().map(|b| if b.is_ascii_alphanumeric() || b"-._".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") }).collect::<String>();
    format!("otpauth://totp/{}:{}?secret={secret_b32}&issuer={}&algorithm=SHA1&digits=6&period=30", enc(issuer), enc(username), enc(issuer))
}

/// QR-Code als SVG (nur Attribute, keine Inline-Styles – passt zur Content-Security-Policy)
pub fn qr_svg(text: &str) -> Option<String> {
    let code = qrcode::QrCode::new(text.as_bytes()).ok()?;
    Some(code.render::<qrcode::render::svg::Color>().min_dimensions(220, 220).quiet_zone(true).build())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc6238_sha1() {
        // RFC 6238, Anhang B: Schlüssel „12345678901234567890“, T = 59 s → 94287082 (8-stellig) → 287082
        let secret = base32_encode(b"12345678901234567890");
        assert_eq!(secret, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        assert_eq!(code_at(b"12345678901234567890", 1), 287_082);
        assert_eq!(verify(&secret, "287 082", 59, None), Some(1));
        assert_eq!(verify(&secret, "287082", 59, Some(1)), None, "Code darf nicht zweimal gelten");
        assert_eq!(verify(&secret, "000000", 59, None), None);
        assert_eq!(base32_decode(&secret).unwrap(), b"12345678901234567890");
    }

    #[test]
    fn qr_und_uri() {
        let u = uri("ABC", "thomas", "NetPulse");
        assert!(u.starts_with("otpauth://totp/NetPulse:thomas?secret=ABC"));
        assert!(qr_svg(&u).unwrap().starts_with("<?xml") || qr_svg(&u).unwrap().contains("<svg"));
    }
}
