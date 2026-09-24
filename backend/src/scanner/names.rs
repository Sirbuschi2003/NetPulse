//! Gerätenamen über mDNS/Bonjour und NetBIOS ermitteln.
//!
//! - mDNS: Viele Geräte (Shelly, Apple, Drucker, Chromecast, Sonos, ESPHome …) beantworten eine
//!   direkte („unicast“) Rückwärtsanfrage auf Port 5353 mit ihrem Namen, z. B. „shellyplus1pm-a8f3.local“.
//! - NetBIOS: Windows-PCs und Samba-Server nennen auf Port 137 ihren Computernamen.
//!
//! Beides sind einzelne kleine UDP-Pakete, antwortet ein Gerät nicht, passiert einfach nichts.

use std::{net::Ipv4Addr, time::Duration};

use tokio::net::UdpSocket;

const TIMEOUT: Duration = Duration::from_millis(900);

async fn ask(ip: Ipv4Addr, port: u16, query: &[u8]) -> Option<Vec<u8>> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await.ok()?;
    socket.send_to(query, (ip, port)).await.ok()?;
    let mut buf = vec![0u8; 1500];
    let (n, from) = tokio::time::timeout(TIMEOUT, socket.recv_from(&mut buf)).await.ok()?.ok()?;
    (from.ip() == ip).then(|| buf[..n].to_vec())
}

// ---------------------------------------------------------------------------
// mDNS
// ---------------------------------------------------------------------------

pub async fn mdns_name(ip: Ipv4Addr) -> Option<String> {
    let answer = ask(ip, 5353, &ptr_query(ip)).await?;
    parse_ptr_answer(&answer)
}

/// DNS-Anfrage „Welcher Name gehört zu d.c.b.a.in-addr.arpa?“ (Typ PTR)
fn ptr_query(ip: Ipv4Addr) -> Vec<u8> {
    let mut q = vec![0x4e, 0x50, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    let o = ip.octets();
    for label in [o[3].to_string(), o[2].to_string(), o[1].to_string(), o[0].to_string(), "in-addr".into(), "arpa".into()] {
        q.push(label.len() as u8);
        q.extend(label.as_bytes());
    }
    q.extend([0, 0, 12, 0, 1]);
    q
}

/// Liest einen (ggf. komprimierten) DNS-Namen ab `pos`; liefert Name und Position danach
fn read_name(buf: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut end = None;
    for _ in 0..32 {
        let len = *buf.get(pos)? as usize;
        if len == 0 {
            return Some((labels.join("."), end.unwrap_or(pos + 1)));
        }
        if len & 0xc0 == 0xc0 {
            let target = ((len & 0x3f) << 8) | *buf.get(pos + 1)? as usize;
            end.get_or_insert(pos + 2);
            pos = target;
            continue;
        }
        labels.push(String::from_utf8_lossy(buf.get(pos + 1..pos + 1 + len)?).into_owned());
        pos += 1 + len;
    }
    None
}

fn parse_ptr_answer(buf: &[u8]) -> Option<String> {
    let qd = u16::from_be_bytes([*buf.get(4)?, *buf.get(5)?]);
    let an = u16::from_be_bytes([*buf.get(6)?, *buf.get(7)?]);
    let mut pos = 12;
    for _ in 0..qd {
        pos = read_name(buf, pos)?.1 + 4;
    }
    for _ in 0..an {
        let (_, after) = read_name(buf, pos)?;
        let kind = u16::from_be_bytes([*buf.get(after)?, *buf.get(after + 1)?]);
        let len = u16::from_be_bytes([*buf.get(after + 8)?, *buf.get(after + 9)?]) as usize;
        let data = after + 10;
        if kind == 12 {
            let (name, _) = read_name(buf, data)?;
            let name = name.trim_end_matches('.').trim_end_matches(".local").to_string();
            return (!name.is_empty()).then_some(name);
        }
        pos = data + len;
    }
    None
}

// ---------------------------------------------------------------------------
// NetBIOS
// ---------------------------------------------------------------------------

pub async fn netbios_name(ip: Ipv4Addr) -> Option<String> {
    // Node-Status-Anfrage für den Namen „*“ (kodiert: 'C','K' + 15 × „AA“)
    let mut q = vec![0x4e, 0x50, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0x20, b'C', b'K'];
    q.extend(std::iter::repeat_n(b'A', 30));
    q.extend([0, 0, 0x21, 0, 1]);
    let answer = ask(ip, 137, &q).await?;
    parse_netbios(&answer)
}

fn parse_netbios(buf: &[u8]) -> Option<String> {
    // Kopf (12) + Name (34) + Typ/Klasse/TTL/Länge (10) → Anzahl der Namen
    let count = *buf.get(56)? as usize;
    (0..count).find_map(|i| {
        let entry = buf.get(57 + i * 18..57 + i * 18 + 18)?;
        let suffix = entry[15];
        let group = entry[16] & 0x80 != 0;
        let name = String::from_utf8_lossy(&entry[..15]).trim().to_string();
        (suffix == 0 && !group && !name.is_empty()).then_some(name)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mdns_antwort_wird_gelesen() {
        // Antwort mit Frage (komprimiert referenziert) und PTR-Eintrag „shelly-küche.local“
        let mut a = vec![0x4e, 0x50, 0x84, 0, 0, 1, 0, 1, 0, 0, 0, 0];
        a.extend(&ptr_query(Ipv4Addr::new(10, 0, 0, 5))[12..]);
        a.extend([0xc0, 12, 0, 12, 0, 1, 0, 0, 0, 120]);
        let name = [&[13u8][..], "shelly-kueche".as_bytes(), &[5], b"local", &[0]].concat();
        a.extend((name.len() as u16).to_be_bytes());
        a.extend(name);
        assert_eq!(parse_ptr_answer(&a).as_deref(), Some("shelly-kueche"));
    }

    #[test]
    fn netbios_antwort_wird_gelesen() {
        let mut a = vec![0u8; 56];
        a.push(2);
        let mut group = b"WORKGROUP      ".to_vec();
        group.extend([0x00, 0x84, 0x00]);
        let mut pc = b"DESKTOP-4F2K   ".to_vec();
        pc.extend([0x00, 0x04, 0x00]);
        a.extend(group);
        a.extend(pc);
        assert_eq!(parse_netbios(&a).as_deref(), Some("DESKTOP-4F2K"));
    }
}
