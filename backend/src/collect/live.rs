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
    /// CPU-Zähler (gesamt, Leerlauf) der letzten SSH-Abfrage
    cpu_ticks: Option<(f64, f64)>,
    /// Letzte CPU/RAM-Werte per SNMP und wann sie geholt wurden (höchstens alle 10 s)
    snmp_sys: Option<(Instant, Value)>,
}

/// CPU, RAM und Temperatur aus der SSH-Ausgabe
#[derive(Default)]
struct SysSample {
    cpu_ticks: Option<(f64, f64)>,
    mem_pct: Option<f64>,
    temp_c: Option<f64>,
}

fn parse_sys(section: &str) -> SysSample {
    let mut out = SysSample::default();
    let lines = section.lines().map(str::trim).filter(|l| !l.is_empty());
    let nums = |l: &str| l.split_whitespace().filter_map(|v| v.trim_end_matches('C').parse::<f64>().ok()).collect::<Vec<_>>();
    let mut mem_total = None;
    let mut mem_avail = None;
    let mut bsd: Vec<f64> = Vec::new();
    for line in lines {
        if let Some(rest) = line.strip_prefix("cpu ") {
            // Linux /proc/stat: user nice system idle iowait irq softirq steal …
            let v = nums(rest);
            if v.len() >= 4 {
                let total: f64 = v.iter().take(8).sum();
                out.cpu_ticks = Some((total, v[3] + v.get(4).copied().unwrap_or(0.0)));
            }
        } else if let Some(rest) = line.strip_prefix("MemTotal:") {
            mem_total = nums(rest).first().copied();
        } else if let Some(rest) = line.strip_prefix("MemAvailable:") {
            mem_avail = nums(rest).first().copied();
        } else if let Some(rest) = line.strip_prefix("TEMP ") {
            out.temp_c = nums(rest).first().map(|t| if *t > 1000.0 { t / 1000.0 } else { *t });
        } else if let Some(rest) = line.strip_prefix("BSDCPU ") {
            // kern.cp_time: user nice sys intr idle
            let v = nums(rest);
            if v.len() >= 5 {
                out.cpu_ticks = Some((v.iter().sum(), v[4]));
            }
        } else if let Some(rest) = line.strip_prefix("BSDMEM ") {
            bsd = nums(rest);
        }
    }
    if let (Some(total), Some(avail)) = (mem_total, mem_avail) {
        if total > 0.0 {
            out.mem_pct = Some((total - avail) / total * 100.0);
        }
    }
    // hw.physmem hw.pagesize free inactive cache
    if let [phys, page, free, inactive, rest @ ..] = &bsd[..] {
        let cache = rest.first().copied().unwrap_or(0.0);
        if *phys > 0.0 {
            out.mem_pct = Some(((phys - (free + inactive + cache) * page) / phys * 100.0).clamp(0.0, 100.0));
        }
    }
    out
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
    let _perf = crate::perf::Timer::new("Live-Datenraten (Anfrage)");
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
    let snmp_cred = creds.iter().find(|c| c.kind.starts_with("snmp"));
    let (counters, source, sys) = if let Some(cred) = snmp_cred {
        (snmp_counters(addr, cred).await?, "SNMP", SysSample::default())
    } else if let Some(cred) = creds.iter().find(|c| c.kind.starts_with("ssh")) {
        let (counters, sys) = ssh_counters(addr, cred, host_key.as_deref()).await?;
        (counters, "SSH", sys)
    } else {
        bail!("Für die Live-Ansicht braucht das Gerät zugeordnete SNMP- oder SSH-Zugangsdaten");
    };

    // CPU/RAM per SNMP höchstens alle 10 s (die Zähler ändern sich im Gerät ohnehin selten öfter)
    let cached_snmp = state.live.entries.lock().unwrap().get(&device_id).and_then(|e| e.snmp_sys.clone());
    let snmp_sys = match (snmp_cred, cached_snmp) {
        (Some(_), Some((at, v))) if at.elapsed() < Duration::from_secs(10) => Some((at, v)),
        (Some(cred), cached) => match snmp::system_quick(addr, cred).await {
            Ok((cpu, mem)) => Some((Instant::now(), json!({ "cpu_pct": cpu, "mem_pct": mem }))),
            Err(_) => cached,
        },
        _ => None,
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

    // CPU aus der Differenz der Zähler (SSH) bzw. direkt aus SNMP
    let round = |v: f64| (v * 10.0).round() / 10.0;
    let cpu_pct = match (sys.cpu_ticks, previous.and_then(|p| p.cpu_ticks)) {
        (Some((total, idle)), Some((pt, pi))) if total > pt => Some(round(((total - pt) - (idle - pi)) / (total - pt) * 100.0)),
        _ => snmp_sys.as_ref().and_then(|(_, v)| v["cpu_pct"].as_f64()).map(round),
    };
    let mem_pct = sys.mem_pct.or_else(|| snmp_sys.as_ref().and_then(|(_, v)| v["mem_pct"].as_f64())).map(round);
    let result = json!({
        "time": chrono::Utc::now(),
        "source": source,
        "wan": wan,
        "warming_up": seconds.is_none(),
        "interfaces": interfaces,
        "system": { "cpu_pct": cpu_pct, "mem_pct": mem_pct, "temp_c": sys.temp_c.map(round) },
    });
    entries.insert(
        device_id,
        Entry {
            at: now,
            counters: counters.into_iter().map(|c| (c.name, (c.rx, c.tx))).collect(),
            last: result.clone(),
            cpu_ticks: sys.cpu_ticks,
            snmp_sys,
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
    else echo '@@BSD'; netstat -ibn; fi; \
    echo '@@SYS'; if [ -r /proc/stat ]; then head -1 /proc/stat; grep -E '^(MemTotal|MemAvailable):' /proc/meminfo; \
    t=$(cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null) && echo \"TEMP $t\"; \
    else echo \"BSDCPU $(sysctl -n kern.cp_time)\"; \
    echo \"BSDMEM $(sysctl -n hw.physmem hw.pagesize vm.stats.vm.v_free_count vm.stats.vm.v_inactive_count vm.stats.vm.v_cache_count 2>/dev/null | tr '\\n' ' ')\"; \
    t=$(sysctl -n dev.cpu.0.temperature 2>/dev/null) && echo \"TEMP $t\"; fi";

async fn ssh_counters(ip: Ipv4Addr, cred: &Credential, host_key: Option<&str>) -> Result<(Vec<Counter>, SysSample)> {
    let output = ssh::run_script_pooled(ip, cred, host_key, POSIX_COUNTERS).await.map_err(|e| match e {
        ssh::SshError::HostKeyChanged { .. } => anyhow!("SSH-Host-Schlüssel hat sich geändert"),
        ssh::SshError::Failed(msg) => anyhow!(msg),
    })?;
    let (net, sys) = output.split_once("@@SYS").unwrap_or((&output, ""));
    let sys = parse_sys(sys);
    if net.contains("Inter-|") {
        Ok((parse_proc_net_dev(net), sys))
    } else if net.contains("@@BSD") {
        Ok((parse_netstat(net), sys))
    } else {
        let first: String = output.lines().find(|l| !l.trim().is_empty()).unwrap_or("(keine Ausgabe)").chars().take(120).collect();
        bail!("Live-Ansicht per SSH gibt es für Linux und FreeBSD/OPNsense – für Windows bitte den Verlauf nutzen (Antwort des Geräts: {first})");
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
    fn system_werte() {
        let linux = parse_sys("cpu  100 0 50 800 50 0 0 0 0 0\nMemTotal:  8000000 kB\nMemAvailable: 2000000 kB\nTEMP 48500\n");
        assert_eq!(linux.cpu_ticks, Some((1000.0, 850.0)));
        assert_eq!(linux.mem_pct, Some(75.0));
        assert_eq!(linux.temp_c, Some(48.5));
        let bsd = parse_sys("BSDCPU 100 0 50 10 840\nBSDMEM 4294967296 4096 262144 262144 0 \nTEMP 51.0C\n");
        assert_eq!(bsd.cpu_ticks, Some((1000.0, 840.0)));
        assert_eq!(bsd.mem_pct, Some(50.0));
        assert_eq!(bsd.temp_c, Some(51.0));
    }

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
