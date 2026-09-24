//! Shelly-Geräte (Gen1 sowie Gen2/Gen3/Gen4 „Plus/Pro/Mini“) über ihre lokale HTTP-API.
//!
//! - Erkennung: `GET /shelly` antwortet immer ohne Anmeldung (Modell, Generation, bei Gen2+ auch der Name).
//! - Daten: Gen1 `GET /status` + `/settings` (Basic-Auth), Gen2+ `GET /rpc/Shelly.GetStatus`
//!   (Digest-Auth mit SHA-256 – das Passwort wird dabei nie im Klartext übertragen).
//!
//! Ausgewertet werden alle Kanäle: Schalter/Relais, Rollläden, Licht, Energiezähler (EM/PM),
//! Temperatur-/Feuchtesensoren, Akku, WLAN-Signal, Laufzeit und verfügbare Updates.

use std::{net::Ipv4Addr, time::Duration};

use anyhow::{anyhow, bail, Result};
use argon2::password_hash::rand_core::{OsRng, RngCore};
use reqwest::{header, StatusCode};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::Credential;

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(4))
        .connect_timeout(Duration::from_secs(2))
        .user_agent("NetPulse")
        .build()
        .expect("HTTP-Client")
}

/// Grunddaten aus `/shelly` (ohne Anmeldung)
#[derive(Clone)]
pub struct Info {
    pub generation: u8,
    pub name: Option<String>,
    pub model: Option<String>,
    pub auth: bool,
}

pub async fn probe(ip: Ipv4Addr) -> Option<Info> {
    let response = client().get(format!("http://{ip}/shelly")).send().await.ok()?;
    if !response.status().is_success() {
        return None;
    }
    let v: Value = response.json().await.ok()?;
    parse_info(&v)
}

fn parse_info(v: &Value) -> Option<Info> {
    let text = |k: &str| v[k].as_str().map(str::trim).filter(|s| !s.is_empty()).map(str::to_string);
    if let Some(generation) = v["gen"].as_u64() {
        // Gen2, Gen3, Gen4
        return Some(Info {
            generation: generation as u8,
            name: text("name"),
            model: text("app").or_else(|| text("model")),
            auth: v["auth_en"].as_bool().unwrap_or(false),
        });
    }
    if v["type"].is_string() && v["mac"].is_string() {
        return Some(Info { generation: 1, name: None, model: text("type"), auth: v["auth"].as_bool().unwrap_or(false) });
    }
    None
}

fn sha256_hex(input: &str) -> String {
    hex::encode(Sha256::digest(input.as_bytes()))
}

/// Digest-Anmeldung nach RFC 7616 (SHA-256), wie sie Shelly Gen2+ verlangt
fn digest_header(challenge: &str, method: &str, uri: &str, user: &str, password: &str) -> Option<String> {
    let param = |key: &str| {
        let start = challenge.find(&format!("{key}="))? + key.len() + 1;
        let rest = &challenge[start..];
        Some(if let Some(quoted) = rest.strip_prefix('"') {
            quoted[..quoted.find('"')?].to_string()
        } else {
            rest.split(',').next()?.trim().to_string()
        })
    };
    let realm = param("realm")?;
    let nonce = param("nonce")?;
    let algorithm = param("algorithm").unwrap_or_else(|| "SHA-256".into());
    if !algorithm.eq_ignore_ascii_case("SHA-256") {
        return None;
    }
    let mut cnonce = [0u8; 8];
    OsRng.fill_bytes(&mut cnonce);
    let cnonce = hex::encode(cnonce);
    let ha1 = sha256_hex(&format!("{user}:{realm}:{password}"));
    let ha2 = sha256_hex(&format!("{method}:{uri}"));
    let response = sha256_hex(&format!("{ha1}:{nonce}:00000001:{cnonce}:auth:{ha2}"));
    let mut header = format!(
        r#"Digest username="{user}", realm="{realm}", nonce="{nonce}", uri="{uri}", algorithm=SHA-256, qop=auth, nc=00000001, cnonce="{cnonce}", response="{response}""#
    );
    if let Some(opaque) = param("opaque") {
        header.push_str(&format!(r#", opaque="{opaque}""#));
    }
    Some(header)
}

async fn get_json(ip: Ipv4Addr, path: &str, generation: u8, cred: Option<&Credential>) -> Result<Value> {
    let url = format!("http://{ip}{path}");
    let user = cred.and_then(|c| c.username.clone()).unwrap_or_else(|| "admin".into());
    let password = cred.and_then(|c| c.secret.password.clone());
    let mut request = client().get(&url);
    if generation == 1 {
        if let Some(pw) = &password {
            request = request.basic_auth(&user, Some(pw));
        }
    }
    let mut response = request.send().await?;
    if response.status() == StatusCode::UNAUTHORIZED && generation >= 2 {
        let Some(pw) = password else { bail!("Shelly verlangt eine Anmeldung – HTTP-Zugangsdaten hinterlegen") };
        let challenge = response
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .and_then(|h| h.to_str().ok())
            .ok_or_else(|| anyhow!("Shelly sendet keine Anmelde-Aufforderung"))?
            .to_string();
        let auth = digest_header(&challenge, "GET", path, "admin", &pw)
            .ok_or_else(|| anyhow!("Unbekanntes Anmeldeverfahren des Shelly"))?;
        response = client().get(&url).header(header::AUTHORIZATION, auth).send().await?;
    }
    match response.status() {
        s if s.is_success() => Ok(response.json().await?),
        StatusCode::UNAUTHORIZED => bail!("Anmeldung am Shelly fehlgeschlagen (Passwort falsch?)"),
        s => bail!("Shelly antwortete mit {s}"),
    }
}

/// Liest alle Daten; `cred` nur nötig, wenn am Shelly ein Passwort gesetzt ist
pub async fn collect(ip: Ipv4Addr, info: &Info, cred: Option<&Credential>) -> Result<Value> {
    if info.auth && cred.is_none() {
        bail!("Shelly verlangt eine Anmeldung – HTTP-Zugangsdaten hinterlegen");
    }
    let mut data = if info.generation >= 2 {
        parse_gen2(&get_json(ip, "/rpc/Shelly.GetStatus", info.generation, cred).await?)
    } else {
        let status = get_json(ip, "/status", 1, cred).await?;
        let settings = get_json(ip, "/settings", 1, cred).await.unwrap_or(Value::Null);
        parse_gen1(&status, &settings)
    };
    data["generation"] = json!(info.generation);
    data["model"] = json!(info.model);
    if data["name"].is_null() {
        data["name"] = json!(info.name);
    }
    Ok(data)
}

fn round(v: f64, digits: i32) -> f64 {
    let f = 10f64.powi(digits);
    (v * f).round() / f
}

fn summarize(mut data: Value) -> Value {
    let channels = data["channels"].as_array().cloned().unwrap_or_default();
    let power: f64 = channels.iter().filter_map(|c| c["power_w"].as_f64()).sum();
    let energy: f64 = channels.iter().filter_map(|c| c["energy_kwh"].as_f64()).sum();
    let has_power = channels.iter().any(|c| c["power_w"].is_number());
    data["power_w"] = if has_power { json!(round(power, 1)) } else { Value::Null };
    data["energy_kwh"] = if has_power { json!(round(energy, 3)) } else { Value::Null };
    data
}

fn parse_gen2(status: &Value) -> Value {
    let mut channels = Vec::new();
    let mut temps = Vec::new();
    let mut humidity = None;
    let mut battery = None;
    if let Some(obj) = status.as_object() {
        for (key, v) in obj {
            let (kind, id) = key.split_once(':').unwrap_or((key.as_str(), "0"));
            let num = |k: &str| v[k].as_f64();
            match kind {
                "switch" | "light" | "cover" | "pm1" | "em1" | "em" => {
                    let power = num("apower").or_else(|| num("act_power")).or_else(|| num("total_act_power"));
                    let energy_wh = v["aenergy"]["total"].as_f64().or_else(|| v["total_act_energy"].as_f64());
                    channels.push(json!({
                        "kind": kind,
                        "id": id,
                        "on": v["output"].as_bool(),
                        "state": v["state"].as_str(),
                        "position": num("current_pos"),
                        "brightness": num("brightness"),
                        "power_w": power.map(|p| round(p, 1)),
                        "energy_kwh": energy_wh.map(|e| round(e / 1000.0, 3)),
                        "voltage": num("voltage"),
                        "current": num("current"),
                        "temp_c": v["temperature"]["tC"].as_f64(),
                    }));
                    if let Some(t) = v["temperature"]["tC"].as_f64() {
                        temps.push(t);
                    }
                }
                "temperature" => temps.extend(num("tC")),
                "humidity" => humidity = num("rh"),
                "devicepower" => battery = v["battery"]["percent"].as_f64(),
                _ => {}
            }
        }
    }
    channels.sort_by(|a, b| (a["kind"].as_str(), a["id"].as_str()).cmp(&(b["kind"].as_str(), b["id"].as_str())));
    let sys = &status["sys"];
    summarize(json!({
        "channels": channels,
        "temp_c": temps.into_iter().reduce(f64::max),
        "humidity_pct": humidity,
        "battery_pct": battery,
        "rssi": status["wifi"]["rssi"].as_f64(),
        "ssid": status["wifi"]["ssid"].as_str(),
        "uptime_s": sys["uptime"].as_f64(),
        "update": sys["available_updates"]["stable"]["version"].as_str(),
    }))
}

fn parse_gen1(status: &Value, settings: &Value) -> Value {
    let mut channels = Vec::new();
    let meters = status["meters"].as_array().cloned().unwrap_or_default();
    for (i, relay) in status["relays"].as_array().into_iter().flatten().enumerate() {
        let meter = meters.get(i);
        channels.push(json!({
            "kind": "switch", "id": i.to_string(), "on": relay["ison"].as_bool(),
            "power_w": meter.and_then(|m| m["power"].as_f64()).map(|p| round(p, 1)),
            // Gen1 zählt in Wattminuten
            "energy_kwh": meter.and_then(|m| m["total"].as_f64()).map(|t| round(t / 60_000.0, 3)),
        }));
    }
    for (i, emeter) in status["emeters"].as_array().into_iter().flatten().enumerate() {
        channels.push(json!({
            "kind": "em", "id": i.to_string(),
            "power_w": emeter["power"].as_f64().map(|p| round(p, 1)),
            "energy_kwh": emeter["total"].as_f64().map(|t| round(t / 1000.0, 3)),
            "voltage": emeter["voltage"].as_f64(),
            "current": emeter["current"].as_f64(),
        }));
    }
    for (i, light) in status["lights"].as_array().into_iter().flatten().enumerate() {
        channels.push(json!({ "kind": "light", "id": i.to_string(), "on": light["ison"].as_bool(), "brightness": light["brightness"].as_f64() }));
    }
    for (i, roller) in status["rollers"].as_array().into_iter().flatten().enumerate() {
        channels.push(json!({ "kind": "cover", "id": i.to_string(), "state": roller["state"].as_str(),
                              "position": roller["current_pos"].as_f64(), "power_w": roller["power"].as_f64() }));
    }
    let temp = status["tmp"]["tC"].as_f64().or_else(|| status["temperature"].as_f64());
    summarize(json!({
        "name": settings["name"].as_str().filter(|n| !n.is_empty()),
        "channels": channels,
        "temp_c": temp,
        "humidity_pct": status["hum"]["value"].as_f64(),
        "battery_pct": status["bat"]["value"].as_f64(),
        "rssi": status["wifi_sta"]["rssi"].as_f64(),
        "ssid": status["wifi_sta"]["ssid"].as_str(),
        "uptime_s": status["uptime"].as_f64(),
        "update": status["update"]["has_update"].as_bool().filter(|u| *u).and(status["update"]["new_version"].as_str()),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gen2_status_wird_ausgewertet() {
        let status = json!({
            "switch:0": { "output": true, "apower": 123.44, "voltage": 231.2, "aenergy": { "total": 4567.8 }, "temperature": { "tC": 44.1 } },
            "switch:1": { "output": false, "apower": 0.0, "aenergy": { "total": 12.0 } },
            "sys": { "uptime": 3600, "available_updates": { "stable": { "version": "1.4.4" } } },
            "wifi": { "rssi": -61, "ssid": "Heimnetz" }
        });
        let d = parse_gen2(&status);
        assert_eq!(d["power_w"], 123.4);
        assert_eq!(d["energy_kwh"], 4.58);
        assert_eq!(d["channels"][0]["on"], true);
        assert_eq!(d["temp_c"], 44.1);
        assert_eq!(d["update"], "1.4.4");
    }

    #[test]
    fn gen1_status_wird_ausgewertet() {
        let status = json!({ "relays": [{ "ison": true }], "meters": [{ "power": 50.0, "total": 600000 }],
                             "tmp": { "tC": 38.5 }, "wifi_sta": { "rssi": -70 }, "update": { "has_update": false } });
        let d = parse_gen1(&status, &json!({ "name": "Waschmaschine" }));
        assert_eq!(d["name"], "Waschmaschine");
        assert_eq!(d["power_w"], 50.0);
        assert_eq!(d["energy_kwh"], 10.0);
        assert!(d["update"].is_null());
    }

    #[test]
    fn digest_wird_berechnet() {
        let h = digest_header(r#"Digest qop="auth", realm="shellyplus1-a8f3", nonce="60dc59c6", algorithm=SHA-256"#, "GET", "/rpc/Shelly.GetStatus", "admin", "geheim").unwrap();
        assert!(h.starts_with(r#"Digest username="admin", realm="shellyplus1-a8f3", nonce="60dc59c6""#));
        assert!(h.contains("response=\""));
        assert!(parse_info(&json!({ "gen": 2, "name": "Küche", "app": "Plus1PM", "auth_en": true })).unwrap().auth);
    }
}
