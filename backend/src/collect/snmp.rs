//! SNMP-Abfrage (v2c und v3) für Router, Switches, Drucker, USV, NAS …
//!
//! Gelesen werden nur Standard-MIBs, die fast jedes Gerät kennt:
//! SNMPv2-MIB (System), IF-MIB (Schnittstellen), HOST-RESOURCES-MIB (CPU, RAM, Speicher),
//! Printer-MIB (Toner), UPS-MIB (Akku), ENTITY-MIB (Modell, Seriennummer), LLDP-MIB (Nachbarn)
//! sowie die Synology-MIB (Modell, Temperatur).

use std::{
    collections::BTreeMap,
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};

use anyhow::{anyhow, bail, Result};
use serde_json::{json, Map, Value};
use snmp2::{v3, AsyncSession, Oid};

use super::Credential;

const TIMEOUT: Duration = Duration::from_secs(2);

/// Eigene, besitzende Kopie eines SNMP-Werts (die Bibliothek leiht nur den Empfangspuffer aus)
#[derive(Debug, Clone)]
enum Val {
    Int(i64),
    Uint(u64),
    Bytes(Vec<u8>),
    Oid(String),
    Ip([u8; 4]),
    Missing,
}

impl Val {
    fn of(value: &snmp2::Value) -> Self {
        use snmp2::Value as V;
        match value {
            V::Integer(n) => Val::Int(*n),
            V::Counter32(n) | V::Unsigned32(n) | V::Timeticks(n) => Val::Uint(u64::from(*n)),
            V::Counter64(n) => Val::Uint(*n),
            V::OctetString(bytes) | V::Opaque(bytes) => Val::Bytes(bytes.to_vec()),
            V::ObjectIdentifier(oid) => Val::Oid(oid.to_id_string()),
            V::IpAddress(ip) => Val::Ip(*ip),
            _ => Val::Missing,
        }
    }

    fn text(&self) -> Option<String> {
        match self {
            Val::Bytes(b) => {
                let text = String::from_utf8_lossy(b).trim_matches(char::from(0)).trim().to_string();
                (!text.is_empty()).then_some(text)
            }
            Val::Int(n) => Some(n.to_string()),
            Val::Uint(n) => Some(n.to_string()),
            Val::Oid(s) => Some(s.clone()),
            Val::Ip(ip) => Some(Ipv4Addr::from(*ip).to_string()),
            Val::Missing => None,
        }
    }

    fn num(&self) -> Option<f64> {
        match self {
            Val::Int(n) => Some(*n as f64),
            Val::Uint(n) => Some(*n as f64),
            Val::Bytes(b) => String::from_utf8_lossy(b).trim().parse().ok(),
            _ => None,
        }
    }

    fn mac(&self) -> Option<String> {
        match self {
            Val::Bytes(b) if b.len() == 6 => {
                Some(b.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(":"))
            }
            _ => None,
        }
    }
}

fn oid(parts: &[u64]) -> Result<Oid<'static>> {
    Oid::from(parts).map_err(|e| anyhow!("Ungültige OID: {e:?}"))
}

fn oid_parts(oid: &Oid) -> Vec<u64> {
    oid.iter().map(|it| it.collect()).unwrap_or_default()
}

async fn open(ip: Ipv4Addr, cred: &Credential) -> Result<AsyncSession> {
    let port = cred.port.and_then(|p| u16::try_from(p).ok()).unwrap_or(161);
    let addr = SocketAddr::from((ip, port));
    let secret = &cred.secret;
    match cred.kind.as_str() {
        "snmp_v2c" => {
            let community = secret.community.as_deref().unwrap_or("public");
            Ok(AsyncSession::new_v2c(addr, community.as_bytes(), 1).await?)
        }
        "snmp_v3" => {
            let username = cred.username.as_deref().unwrap_or_default();
            let auth_password = secret.auth_password.as_deref().unwrap_or_default();
            let mut security = v3::Security::new(username.as_bytes(), auth_password.as_bytes());
            let auth_proto = secret.auth_protocol.as_deref().unwrap_or("sha1");
            if auth_proto != "none" {
                security = security.with_auth_protocol(match auth_proto {
                    "md5" => v3::AuthProtocol::Md5,
                    "sha224" => v3::AuthProtocol::Sha224,
                    "sha256" => v3::AuthProtocol::Sha256,
                    "sha384" => v3::AuthProtocol::Sha384,
                    "sha512" => v3::AuthProtocol::Sha512,
                    _ => v3::AuthProtocol::Sha1,
                });
            }
            let priv_proto = secret.priv_protocol.as_deref().unwrap_or("none");
            let auth = match (auth_proto, priv_proto) {
                ("none", _) => v3::Auth::NoAuthNoPriv,
                (_, "none") => v3::Auth::AuthNoPriv,
                (_, cipher) => v3::Auth::AuthPriv {
                    cipher: match cipher {
                        "des" => v3::Cipher::Des,
                        "aes192" => v3::Cipher::Aes192,
                        "aes256" => v3::Cipher::Aes256,
                        _ => v3::Cipher::Aes128,
                    },
                    privacy_password: secret.priv_password.clone().unwrap_or_default().into_bytes(),
                },
            };
            security = security.with_auth(auth);
            let mut session = AsyncSession::new_v3(addr, 1, security).await?;
            // Engine-ID des Agenten ermitteln (Pflicht bei v3)
            match tokio::time::timeout(TIMEOUT * 2, session.init()).await {
                Ok(Ok(())) => Ok(session),
                Ok(Err(e)) => bail!("SNMPv3-Anmeldung fehlgeschlagen: {e:?}"),
                Err(_) => bail!("Zeitüberschreitung (keine Antwort auf SNMPv3)"),
            }
        }
        other => bail!("{other} ist keine SNMP-Zugangsart"),
    }
}

/// GET mehrerer Werte (mit einer Wiederholung bei UDP-Verlust)
async fn get(session: &mut AsyncSession, oids: &[&[u64]]) -> Result<Vec<(Vec<u64>, Val)>> {
    let oids: Vec<Oid<'static>> = oids.iter().map(|o| oid(o)).collect::<Result<_>>()?;
    let refs: Vec<&Oid> = oids.iter().collect();
    for attempt in 0..2 {
        match tokio::time::timeout(TIMEOUT, session.get_many(&refs)).await {
            Ok(Ok(pdu)) => return Ok(pdu.varbinds.map(|(o, v)| (oid_parts(&o), Val::of(&v))).collect()),
            Ok(Err(e)) => bail!("SNMP-Fehler: {e:?}"),
            Err(_) if attempt == 0 => continue,
            Err(_) => bail!("Zeitüberschreitung – Gerät antwortet nicht auf SNMP (Community/Benutzer richtig?)"),
        }
    }
    unreachable!()
}

/// Alle Werte unterhalb einer OID lesen (GETBULK), höchstens `max` Einträge
async fn walk(session: &mut AsyncSession, base: &[u64], max: usize) -> Result<Vec<(Vec<u64>, Val)>> {
    let mut out = Vec::new();
    let mut current = base.to_vec();
    'outer: loop {
        let start = oid(&current)?;
        let mut response = None;
        for _ in 0..2 {
            match tokio::time::timeout(TIMEOUT, session.getbulk(&[&start], 0, 25)).await {
                Ok(Ok(pdu)) => {
                    response = Some(pdu.varbinds.map(|(o, v)| (oid_parts(&o), Val::of(&v))).collect::<Vec<_>>());
                    break;
                }
                Ok(Err(e)) => bail!("SNMP-Fehler: {e:?}"),
                Err(_) => continue,
            }
        }
        let Some(rows) = response else { bail!("Zeitüberschreitung beim Lesen von {}", dotted(base)) };
        if rows.is_empty() {
            break;
        }
        for (name, value) in rows {
            if !name.starts_with(base) || matches!(value, Val::Missing) || name <= current {
                break 'outer;
            }
            current = name.clone();
            out.push((name, value));
            if out.len() >= max {
                break 'outer;
            }
        }
    }
    Ok(out)
}

fn dotted(parts: &[u64]) -> String {
    parts.iter().map(u64::to_string).collect::<Vec<_>>().join(".")
}

/// Spalte einer Tabelle: Index (Rest der OID) → Wert
async fn column(session: &mut AsyncSession, base: &[u64], max: usize) -> BTreeMap<Vec<u64>, Val> {
    walk(session, base, max)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|(name, value)| (name[base.len()..].to_vec(), value))
        .collect()
}

// Wichtige OIDs
const SYSTEM: &[u64] = &[1, 3, 6, 1, 2, 1, 1];
const IF_TABLE: &[u64] = &[1, 3, 6, 1, 2, 1, 2, 2, 1];
const IFX_TABLE: &[u64] = &[1, 3, 6, 1, 2, 1, 31, 1, 1, 1];
const HR_STORAGE: &[u64] = &[1, 3, 6, 1, 2, 1, 25, 2, 3, 1];
const HR_PROCESSOR_LOAD: &[u64] = &[1, 3, 6, 1, 2, 1, 25, 3, 3, 1, 2];
const PRINTER_SUPPLIES: &[u64] = &[1, 3, 6, 1, 2, 1, 43, 11, 1, 1];
const UPS_MIB: &[u64] = &[1, 3, 6, 1, 2, 1, 33, 1];
const ENTITY_PHYSICAL: &[u64] = &[1, 3, 6, 1, 2, 1, 47, 1, 1, 1, 1];
const LLDP_REM_SYSNAME: &[u64] = &[1, 0, 8802, 1, 1, 2, 1, 4, 1, 1, 9];
const SYNOLOGY_SYSTEM: &[u64] = &[1, 3, 6, 1, 4, 1, 6574, 1];

fn with(base: &[u64], tail: &[u64]) -> Vec<u64> {
    base.iter().chain(tail).copied().collect()
}

pub async fn collect(ip: Ipv4Addr, cred: &Credential) -> Result<Value> {
    let mut s = open(ip, cred).await?;
    let mut data = Map::new();

    // System-Gruppe – schlägt sie fehl, sind die Zugangsdaten falsch oder SNMP ist aus
    let sys: Vec<Vec<u64>> = (1..=6).map(|i| with(SYSTEM, &[i, 0])).collect();
    let sys_refs: Vec<&[u64]> = sys.iter().map(Vec::as_slice).collect();
    let system = get(&mut s, &sys_refs).await?;
    let field = |i: u64| system.iter().find(|(o, _)| o == &with(SYSTEM, &[i, 0])).map(|(_, v)| v.clone());
    if field(1).and_then(|v| v.text()).is_none() && field(5).and_then(|v| v.text()).is_none() {
        bail!("Gerät liefert keine SNMP-Systemdaten");
    }
    data.insert("sys_descr".into(), json!(field(1).and_then(|v| v.text())));
    data.insert("sys_object_id".into(), json!(field(2).and_then(|v| v.text())));
    data.insert("uptime_s".into(), json!(field(3).and_then(|v| v.num()).map(|t| (t / 100.0) as u64)));
    data.insert("sys_contact".into(), json!(field(4).and_then(|v| v.text())));
    data.insert("sys_name".into(), json!(field(5).and_then(|v| v.text())));
    data.insert("sys_location".into(), json!(field(6).and_then(|v| v.text())));

    // Schnittstellen (IF-MIB, 64-Bit-Zähler aus ifXTable wenn vorhanden)
    let descr = column(&mut s, &with(IF_TABLE, &[2]), 256).await;
    if !descr.is_empty() {
        let if_type = column(&mut s, &with(IF_TABLE, &[3]), 256).await;
        let speed = column(&mut s, &with(IF_TABLE, &[5]), 256).await;
        let phys = column(&mut s, &with(IF_TABLE, &[6]), 256).await;
        let oper = column(&mut s, &with(IF_TABLE, &[8]), 256).await;
        let in32 = column(&mut s, &with(IF_TABLE, &[10]), 256).await;
        let out32 = column(&mut s, &with(IF_TABLE, &[16]), 256).await;
        let name = column(&mut s, &with(IFX_TABLE, &[1]), 256).await;
        let in64 = column(&mut s, &with(IFX_TABLE, &[6]), 256).await;
        let out64 = column(&mut s, &with(IFX_TABLE, &[10]), 256).await;
        let high_speed = column(&mut s, &with(IFX_TABLE, &[15]), 256).await;
        let alias = column(&mut s, &with(IFX_TABLE, &[18]), 256).await;
        let interfaces: Vec<Value> = descr
            .iter()
            .take(128)
            .map(|(idx, d)| {
                let num = |m: &BTreeMap<Vec<u64>, Val>| m.get(idx).and_then(Val::num);
                let speed_mbps = num(&high_speed).filter(|v| *v > 0.0).or_else(|| num(&speed).map(|b| b / 1e6));
                json!({
                    "index": idx.first(),
                    "name": name.get(idx).and_then(Val::text).or_else(|| d.text()),
                    "descr": d.text(),
                    "alias": alias.get(idx).and_then(Val::text),
                    "type": num(&if_type),
                    "oper": match num(&oper) { Some(1.0) => "up", Some(2.0) => "down", Some(5.0) => "dormant", _ => "unknown" },
                    "speed_mbps": speed_mbps,
                    "mac": phys.get(idx).and_then(Val::mac),
                    "rx_bytes": num(&in64).or_else(|| num(&in32)),
                    "tx_bytes": num(&out64).or_else(|| num(&out32)),
                })
            })
            .collect();
        data.insert("interfaces".into(), Value::Array(interfaces));
    }

    // Speicher und RAM (HOST-RESOURCES-MIB)
    let storage_type = column(&mut s, &with(HR_STORAGE, &[2]), 128).await;
    if !storage_type.is_empty() {
        let descr = column(&mut s, &with(HR_STORAGE, &[3]), 128).await;
        let units = column(&mut s, &with(HR_STORAGE, &[4]), 128).await;
        let size = column(&mut s, &with(HR_STORAGE, &[5]), 128).await;
        let used = column(&mut s, &with(HR_STORAGE, &[6]), 128).await;
        let storage: Vec<Value> = storage_type
            .iter()
            .filter_map(|(idx, kind)| {
                let kind = match kind {
                    Val::Oid(o) if o.ends_with(".25.2.1.2") => "ram",
                    Val::Oid(o) if o.ends_with(".25.2.1.4") => "disk",
                    Val::Oid(o) if o.ends_with(".25.2.1.3") => "virtual",
                    _ => "other",
                };
                let unit = units.get(idx).and_then(Val::num).unwrap_or(1.0);
                let size_b = size.get(idx).and_then(Val::num)? * unit;
                let used_b = used.get(idx).and_then(Val::num).unwrap_or(0.0) * unit;
                (size_b > 0.0).then(|| {
                    json!({
                        "descr": descr.get(idx).and_then(Val::text),
                        "kind": kind,
                        "size_bytes": size_b,
                        "used_bytes": used_b,
                        "pct": (used_b / size_b * 1000.0).round() / 10.0,
                    })
                })
            })
            .collect();
        data.insert("storage".into(), Value::Array(storage));
    }

    // CPU-Last: Mittelwert aller Kerne
    let loads: Vec<f64> = column(&mut s, HR_PROCESSOR_LOAD, 256).await.values().filter_map(Val::num).collect();
    if !loads.is_empty() {
        data.insert("cpu_pct".into(), json!(loads.iter().sum::<f64>() / loads.len() as f64));
        data.insert("cpu_cores".into(), json!(loads.len()));
    }

    // Drucker: Füllstände (Toner, Tinte, Trommel …)
    let supply_descr = column(&mut s, &with(PRINTER_SUPPLIES, &[6]), 64).await;
    if !supply_descr.is_empty() {
        let max = column(&mut s, &with(PRINTER_SUPPLIES, &[8]), 64).await;
        let level = column(&mut s, &with(PRINTER_SUPPLIES, &[9]), 64).await;
        let supplies: Vec<Value> = supply_descr
            .iter()
            .map(|(idx, d)| {
                let max = max.get(idx).and_then(Val::num);
                let level = level.get(idx).and_then(Val::num);
                let pct = match (level, max) {
                    (Some(l), Some(m)) if l >= 0.0 && m > 0.0 => Some((l / m * 100.0).round()),
                    _ => None,
                };
                json!({ "descr": d.text(), "level": level, "max": max, "pct": pct })
            })
            .collect();
        data.insert("printer".into(), Value::Array(supplies));
    }

    // USV (UPS-MIB)
    let ups = get(
        &mut s,
        &[
            &with(UPS_MIB, &[1, 1, 0]),
            &with(UPS_MIB, &[1, 2, 0]),
            &with(UPS_MIB, &[2, 1, 0]),
            &with(UPS_MIB, &[2, 3, 0]),
            &with(UPS_MIB, &[2, 4, 0]),
            &with(UPS_MIB, &[4, 1, 0]),
        ],
    )
    .await
    .unwrap_or_default();
    let ups_field = |tail: &[u64]| ups.iter().find(|(o, _)| o == &with(UPS_MIB, tail)).map(|(_, v)| v.clone());
    if let Some(charge) = ups_field(&[2, 4, 0]).and_then(|v| v.num()) {
        data.insert(
            "ups".into(),
            json!({
                "manufacturer": ups_field(&[1, 1, 0]).and_then(|v| v.text()),
                "model": ups_field(&[1, 2, 0]).and_then(|v| v.text()),
                "battery_status": match ups_field(&[2, 1, 0]).and_then(|v| v.num()) {
                    Some(2.0) => "normal", Some(3.0) => "niedrig", Some(4.0) => "leer", _ => "unbekannt",
                },
                "runtime_min": ups_field(&[2, 3, 0]).and_then(|v| v.num()),
                "charge_pct": charge,
                "on_battery": ups_field(&[4, 1, 0]).and_then(|v| v.num()) == Some(5.0),
            }),
        );
    }

    // Synology-NAS: Modell, Seriennummer, Temperatur
    let syno = get(
        &mut s,
        &[
            &with(SYNOLOGY_SYSTEM, &[1, 0]),
            &with(SYNOLOGY_SYSTEM, &[2, 0]),
            &with(SYNOLOGY_SYSTEM, &[5, 1, 0]),
            &with(SYNOLOGY_SYSTEM, &[5, 2, 0]),
            &with(SYNOLOGY_SYSTEM, &[5, 3, 0]),
        ],
    )
    .await
    .unwrap_or_default();
    let syno_field = |tail: &[u64]| syno.iter().find(|(o, _)| o == &with(SYNOLOGY_SYSTEM, tail)).map(|(_, v)| v.clone());
    if let Some(model) = syno_field(&[5, 1, 0]).and_then(|v| v.text()) {
        data.insert(
            "synology".into(),
            json!({
                "model": model,
                "serial": syno_field(&[5, 2, 0]).and_then(|v| v.text()),
                "version": syno_field(&[5, 3, 0]).and_then(|v| v.text()),
                "temp_c": syno_field(&[2, 0]).and_then(|v| v.num()),
                "status_ok": syno_field(&[1, 0]).and_then(|v| v.num()) == Some(1.0),
            }),
        );
    }

    // Modell und Seriennummer (ENTITY-MIB) – erste nicht-leere Angabe
    let models = column(&mut s, &with(ENTITY_PHYSICAL, &[13]), 32).await;
    let serials = column(&mut s, &with(ENTITY_PHYSICAL, &[11]), 32).await;
    data.insert("model".into(), json!(models.values().find_map(Val::text)));
    data.insert("serial".into(), json!(serials.values().find_map(Val::text)));

    // LLDP-Nachbarn (für eine spätere Netzwerkkarte)
    let neighbors: Vec<String> = column(&mut s, LLDP_REM_SYSNAME, 64).await.values().filter_map(Val::text).collect();
    if !neighbors.is_empty() {
        data.insert("lldp_neighbors".into(), json!(neighbors));
    }

    Ok(Value::Object(data))
}
