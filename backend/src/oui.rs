//! Hersteller anhand der MAC-Adresse erkennen (IEEE-OUI-Liste, eingebettet ins Programm).

use std::{collections::HashMap, sync::OnceLock};

/// Aufbereitete IEEE-Liste: „AABBCC<TAB>Hersteller“ je Zeile
static OUI_DATA: &str = include_str!("../data/oui.tsv");

fn table() -> &'static HashMap<u32, &'static str> {
    static TABLE: OnceLock<HashMap<u32, &'static str>> = OnceLock::new();
    TABLE.get_or_init(|| {
        OUI_DATA
            .lines()
            .filter_map(|line| {
                let (prefix, vendor) = line.split_once('\t')?;
                Some((u32::from_str_radix(prefix, 16).ok()?, vendor))
            })
            .collect()
    })
}

/// Erste drei Bytes der MAC als Zahl, z. B. „b8:27:eb:…“ → 0xB827EB
fn prefix(mac: &str) -> Option<u32> {
    let hex: String = mac.chars().filter(|c| c.is_ascii_hexdigit()).take(6).collect();
    (hex.len() == 6).then(|| u32::from_str_radix(&hex, 16).ok()).flatten()
}

/// Zufällige („private“) MAC-Adresse? Smartphones und neuere Laptops nutzen sie pro WLAN,
/// dann lässt sich kein Hersteller ermitteln.
pub fn is_random(mac: &str) -> bool {
    prefix(mac).is_some_and(|p| (p >> 16) & 0x02 != 0)
}

pub fn lookup(mac: &str) -> Option<String> {
    if is_random(mac) {
        return Some("Private MAC-Adresse".into());
    }
    table().get(&prefix(mac)?).map(|v| v.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hersteller_wird_erkannt() {
        assert_eq!(lookup("b8:27:eb:12:34:56").as_deref(), Some("Raspberry Pi Foundation"));
        assert_eq!(lookup("00-11-32-AA-BB-CC").as_deref(), Some("Synology"));
        assert!(is_random("da:a1:19:00:00:01"));
        assert_eq!(lookup("da:a1:19:00:00:01").as_deref(), Some("Private MAC-Adresse"));
        assert_eq!(lookup("kaputt"), None);
    }
}
