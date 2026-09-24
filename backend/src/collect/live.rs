//! Live-Datenraten: liest auf Anfrage die Byte-Zähler aller Schnittstellen eines Geräts
//! (SNMP oder SSH/Linux) und berechnet aus der Differenz zur vorherigen Abfrage die Rate.
//!
//! Die Oberfläche fragt alle ~2 Sekunden, solange die Live-Ansicht offen ist. Damit ein Gerät
//! dadurch nicht überlastet wird, wird es höchstens alle 1,5 Sekunden wirklich abgefragt.

use std::{
    collections::HashMap,
    net::Ipv4Addr,
    sync::Mutex,
    time::{Duration, Instant},
};

use anyhow::{anyhow, bail, Result};
use serde_json::{json, Value};

use super::{load_credentials, snmp, ssh, Credential};
use crate::AppState;

const MIN_INTERVAL: Duration = Duration::from_millis(1500);
const TWO_POW_32: f64 = 4_294_967_296.0;

#[derive(Default)]
pub struct LiveCache {
    entries: Mutex<HashMap<i64, Entry>>,
}

struct Entry {
    at: Instant,
    counters: HashMap<String, (Option<f64>, Option<f64>)>,
    last: Value,
}

struct Counter {
    name: String,
    alias: Option<String>,
    oper: String,
    speed_mbps: Option<f64>,
    rx: Option<f64>,
    tx: Option<f64>,
    /// 64-Bit-Zähler laufen praktisch nie über, 32-Bit-Zähler schon (bei 1 Gbit/s alle ~34 s)
    bits64: bool,
}

pub async fn live(state: &AppState, device_id: i64) -> Result<Value> {
    if let Some(entry) = state.live.entries.lock().unwrap().get(&device_id) {
        if entry.at.elapsed() < MIN_INTERVAL {
            return Ok(entry.last.clone());
        }
    }

    let (ip, host_key, wan): (String, Option<String>, Option<String>) =
        sqlx::query_as("SELECT host(ip), ssh_host_key, wan_interface FROM devices WHERE id = $1")
            .bind(device_id)
            .fetch_optional(&state.db)
            .await?
            .ok_or_else(|| anyhow!("Gerät nicht gefunden"))?;
    let addr: Ipv4Addr = ip.parse()?;
    let creds: Vec<Credential> = load_credentials(state, device_id).await?.into_iter().filter(|c| c.linked).collect();
    let (counters, source) = if let Some(cred) = creds.iter().find(|c| c.kind.starts_with("snmp")) {
        (snmp_counters(addr, cred).await?, "SNMP")
    } else if let Some(cred) = creds.iter().find(|c| c.kind.starts_with("ssh")) {
        (ssh_counters(addr, cred, host_key.as_deref()).await?, "SSH")
    } else {
        bail!("Für die Live-Ansicht braucht das Gerät zugeordnete SNMP- oder SSH-Zugangsdaten");
    };

    let now = Instant::now();
    let mut entries = state.live.entries.lock().unwrap();
    let previous = entries.get(&device_id);
    let seconds = previous
        .map(|p| now.duration_since(p.at).as_secs_f64())
        .filter(|s| *s > 0.5 && *s < 120.0);

    // Viele SNMP-Agenten aktualisieren ihre Zähler nur alle paar Sekunden. Unveränderte Zähler
    // kurz nach der letzten Abfrage heißen „noch keine neuen Daten“, nicht „0 bit/s“.
    if let (Some(prev), Some(secs)) = (previous, seconds) {
        let unchanged = counters.iter().all(|c| prev.counters.get(&c.name) == Some(&(c.rx, c.tx)));
        if unchanged && secs < 8.0 && !counters.is_empty() {
            return Ok(prev.last.clone());
        }
    }

    let interfaces: Vec<Value> = counters
        .iter()
        .map(|c| {
            let old = previous.filter(|_| seconds.is_some()).and_then(|p| p.counters.get(&c.name));
            let rate = |new: Option<f64>, old: Option<f64>| -> Option<f64> {
                let (new, old, secs) = (new?, old?, seconds?);
                let delta = if new >= old {
                    new - old
                } else if !c.bits64 && old < TWO_POW_32 {
                    new + TWO_POW_32 - old // Zählerüberlauf
                } else {
                    return None; // Zähler zurückgesetzt (z. B. Neustart)
                };
                Some(delta * 8.0 / secs)
            };
            json!({
                "name": c.name,
                "alias": c.alias,
                "oper": c.oper,
                "speed_mbps": c.speed_mbps,
                "rx_bps": rate(c.rx, old.and_then(|o| o.0)),
                "tx_bps": rate(c.tx, old.and_then(|o| o.1)),
                "rx_bytes": c.rx,
                "tx_bytes": c.tx,
            })
        })
        .collect();

    let result = json!({
        "time": chrono::Utc::now(),
        "source": source,
        "wan": wan,
        "warming_up": seconds.is_none(),
        "interfaces": interfaces,
    });
    entries.insert(
        device_id,
        Entry {
            at: now,
            counters: counters.into_iter().map(|c| (c.name, (c.rx, c.tx))).collect(),
            last: result.clone(),
        },
    );
    entries.retain(|_, e| e.at.elapsed() < Duration::from_secs(600));
    Ok(result)
}

async fn snmp_counters(ip: Ipv4Addr, cred: &Credential) -> Result<Vec<Counter>> {
    use snmp::{column, with, IFX_TABLE, IF_TABLE};
    let mut s = snmp::open(ip, cred).await?;
    let descr = column(&mut s, &with(IF_TABLE, &[2]), 256).await;
    if descr.is_empty() {
        bail!("Gerät liefert keine Schnittstellen per SNMP");
    }
    let if_type = column(&mut s, &with(IF_TABLE, &[3]), 256).await;
    let speed = column(&mut s, &with(IF_TABLE, &[5]), 256).await;
    let oper = column(&mut s, &with(IF_TABLE, &[8]), 256).await;
    let in32 = column(&mut s, &with(IF_TABLE, &[10]), 256).await;
    let out32 = column(&mut s, &with(IF_TABLE, &[16]), 256).await;
    let name = column(&mut s, &with(IFX_TABLE, &[1]), 256).await;
    let in64 = column(&mut s, &with(IFX_TABLE, &[6]), 256).await;
    let out64 = column(&mut s, &with(IFX_TABLE, &[10]), 256).await;
    let high_speed = column(&mut s, &with(IFX_TABLE, &[15]), 256).await;
    let alias = column(&mut s, &with(IFX_TABLE, &[18]), 256).await;

    Ok(descr
        .iter()
        .filter(|(idx, _)| if_type.get(*idx).and_then(|v| v.num()) != Some(24.0)) // Loopback
        .map(|(idx, d)| {
            let num = |m: &std::collections::BTreeMap<Vec<u64>, snmp::Val>| m.get(idx).and_then(|v| v.num());
            let bits64 = num(&in64).is_some();
            Counter {
                name: name.get(idx).and_then(|v| v.text()).or_else(|| d.text()).unwrap_or_default(),
                alias: alias.get(idx).and_then(|v| v.text()),
                oper: match num(&oper) {
                    Some(1.0) => "up".into(),
                    Some(2.0) => "down".into(),
                    _ => "unknown".into(),
                },
                speed_mbps: num(&high_speed).filter(|v| *v > 0.0).or_else(|| num(&speed).map(|b| b / 1e6)),
                rx: if bits64 { num(&in64) } else { num(&in32) },
                tx: if bits64 { num(&out64) } else { num(&out32) },
                bits64,
            }
        })
        .collect())
}

/// Linux: Zähler aus /proc/net/dev, Geschwindigkeit und Status aus /sys/class/net.
/// FreeBSD/OPNsense/pfSense: Zähler aus `netstat -ibn`.
const POSIX_COUNTERS: &str = "if [ -r /proc/net/dev ]; then cat /proc/net/dev; for i in /sys/class/net/*; do \
    echo \"@ ${i##*/} $(cat $i/speed 2>/dev/null || echo -) $(cat $i/operstate 2>/dev/null || echo unknown)\"; done; \
    else echo '@@BSD'; netstat -ibn; fi";

async fn ssh_counters(ip: Ipv4Addr, cred: &Credential, host_key: Option<&str>) -> Result<Vec<Counter>> {
    let output = ssh::run_command(ip, cred, host_key, POSIX_COUNTERS).await.map_err(|e| match e {
        ssh::SshError::HostKeyChanged { .. } => anyhow!("SSH-Host-Schlüssel hat sich geändert"),
        ssh::SshError::Failed(msg) => anyhow!(msg),
    })?;
    if output.contains("Inter-|") {
        Ok(parse_proc_net_dev(&output))
    } else if output.contains("@@BSD") {
        Ok(parse_netstat(&output))
    } else {
        bail!("Live-Ansicht per SSH gibt es für Linux und FreeBSD/OPNsense – für Windows bitte den Verlauf nutzen");
    }
}

/// FreeBSD `netstat -ibn`: je Schnittstelle eine „<Link#n>“-Zeile; die Byte-Zähler stehen
/// von hinten gezählt an fester Stelle (… Ibytes Opkts Oerrs Obytes Coll)
fn parse_netstat(output: &str) -> Vec<Counter> {
    let mut seen = std::collections::HashSet::new();
    output
        .lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 8 || !f.get(2)?.starts_with("<Link") {
                return None;
            }
            let down = f[0].ends_with('*');
            let name = f[0].trim_end_matches('*');
            if ["lo", "pflog", "pfsync", "enc"].iter().any(|p| name.starts_with(p)) || !seen.insert(name.to_string()) {
                return None;
            }
            let num = |i: usize| f.get(f.len() - i).and_then(|v| v.parse::<f64>().ok());
            Some(Counter {
                name: name.to_string(),
                alias: None,
                oper: if down { "down".into() } else { "up".into() },
                speed_mbps: None,
                rx: num(5),
                tx: num(2),
                bits64: true,
            })
        })
        .collect()
}

fn parse_proc_net_dev(output: &str) -> Vec<Counter> {
    let mut meta: HashMap<&str, (Option<f64>, &str)> = HashMap::new();
    for line in output.lines().filter_map(|l| l.strip_prefix("@ ")) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if let [name, speed, state, ..] = parts[..] {
            meta.insert(name, (speed.parse::<f64>().ok().filter(|s| *s > 0.0), state));
        }
    }
    output
        .lines()
        .filter_map(|line| {
            let (name, rest) = line.split_once(':')?;
            let name = name.trim();
            if name == "lo" || name.starts_with("veth") || name.starts_with("docker") || name.starts_with("br-") {
                return None;
            }
            let fields: Vec<f64> = rest.split_whitespace().filter_map(|x| x.parse().ok()).collect();
            if fields.len() < 9 {
                return None;
            }
            let (speed, oper) = meta.get(name).copied().unwrap_or((None, "unknown"));
            Some(Counter {
                name: name.to_string(),
                alias: None,
                oper: oper.to_string(),
                speed_mbps: speed,
                rx: Some(fields[0]),
                tx: Some(fields[8]),
                bits64: true,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn netstat_freebsd_wird_gelesen() {
        let out = "@@BSD\nName    Mtu Network       Address              Ipkts Ierrs Idrop     Ibytes    Opkts Oerrs     Obytes  Coll\n\
            igb0   1500 <Link#1>      00:0d:b9:4a:12:34  9123456     0     0 12345678901  8123456     0  2345678901     0\n\
            igb0      - 203.0.113.0/24 203.0.113.7        700000     -     -   90000000   600000     -    80000000     -\n\
            igb1*  1500 <Link#2>      00:0d:b9:4a:12:35        0     0     0          0        0     0           0     0\n\
            lo0   16384 <Link#3>      lo0                   100     0     0       5000      100     0        5000     0\n";
        let c = parse_netstat(out);
        assert_eq!(c.len(), 2);
        assert_eq!(c[0].name, "igb0");
        assert_eq!(c[0].rx, Some(12345678901.0));
        assert_eq!(c[0].tx, Some(2345678901.0));
        assert_eq!(c[1].oper, "down");
    }

    #[test]
    fn proc_net_dev_wird_gelesen() {
        let out = "Inter-|   Receive                                                |  Transmit\n \
            face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n    \
            lo: 100 1 0 0 0 0 0 0 100 1 0 0 0 0 0 0\n  \
            eth0: 123456 100 0 0 0 0 0 0 654321 90 0 0 0 0 0 0\n\
            @ eth0 1000 up\n@ lo - unknown\n";
        let c = parse_proc_net_dev(out);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].name, "eth0");
        assert_eq!(c[0].rx, Some(123456.0));
        assert_eq!(c[0].tx, Some(654321.0));
        assert_eq!(c[0].speed_mbps, Some(1000.0));
        assert_eq!(c[0].oper, "up");
    }
}
