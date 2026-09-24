//! Versand von Benachrichtigungen an die verschiedenen Kanäle.

use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use lettre::{
    message::header::ContentType, transport::smtp::authentication::Credentials, AsyncSmtpTransport,
    AsyncTransport, Message, Tokio1Executor,
};
use serde_json::{json, Value};

#[derive(Clone, Copy, PartialEq)]
pub enum Severity {
    Critical,
    Warning,
    Info,
    Resolved,
}

impl Severity {
    fn emoji(self) -> &'static str {
        match self {
            Severity::Critical => "🔴",
            Severity::Warning => "🟠",
            Severity::Info => "🔵",
            Severity::Resolved => "🟢",
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::Warning => "warning",
            Severity::Info => "info",
            Severity::Resolved => "resolved",
        }
    }
    fn color(self) -> u32 {
        match self {
            Severity::Critical => 0xDC2626,
            Severity::Warning => 0xF59E0B,
            Severity::Info => 0x2563EB,
            Severity::Resolved => 0x16A34A,
        }
    }
}

pub struct Notification {
    pub title: String,
    pub message: String,
    pub severity: Severity,
    pub link: Option<String>,
}

/// Konfigurationsfelder, die als geheim gelten und in der Oberfläche maskiert werden
pub const SECRET_FIELDS: &[&str] = &["password", "token", "bot_token", "webhook_url", "secret", "url"];

fn http() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .user_agent("NetPulse")
        .build()
        .expect("HTTP-Client")
}

fn field<'a>(config: &'a Value, key: &str) -> Result<&'a str> {
    config[key]
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("Feld „{key}“ fehlt in der Kanal-Konfiguration"))
}

async fn check(response: reqwest::Response) -> Result<()> {
    let status = response.status();
    if status.is_success() {
        return Ok(());
    }
    let body: String = response.text().await.unwrap_or_default().chars().take(300).collect();
    bail!("Dienst antwortete mit {status}: {body}")
}

pub async fn send(kind: &str, config: &Value, n: &Notification) -> Result<()> {
    let title = format!("{} {}", n.severity.emoji(), n.title);
    let text_with_link = match &n.link {
        Some(link) => format!("{}\n\n{link}", n.message),
        None => n.message.clone(),
    };
    match kind {
        "email" => send_email(config, &title, &text_with_link).await,
        "ntfy" => {
            let server = config["server"].as_str().filter(|s| !s.is_empty()).unwrap_or("https://ntfy.sh");
            let priority = match n.severity {
                Severity::Critical => 5,
                Severity::Warning => 4,
                _ => 3,
            };
            let mut body = json!({
                "topic": field(config, "topic")?, "title": n.title, "message": n.message,
                "priority": priority, "tags": [match n.severity {
                    Severity::Critical => "rotating_light", Severity::Warning => "warning",
                    Severity::Resolved => "white_check_mark", Severity::Info => "information_source",
                }],
            });
            if let Some(link) = &n.link {
                body["click"] = json!(link);
            }
            let mut request = http().post(server.trim_end_matches('/')).json(&body);
            if let Some(token) = config["token"].as_str().filter(|t| !t.is_empty()) {
                request = request.bearer_auth(token);
            }
            check(request.send().await?).await
        }
        "gotify" => {
            let url = format!("{}/message", field(config, "url")?.trim_end_matches('/'));
            let priority = if n.severity == Severity::Critical { 8 } else { 5 };
            let response = http()
                .post(url)
                .header("X-Gotify-Key", field(config, "token")?)
                .json(&json!({ "title": title, "message": text_with_link, "priority": priority }))
                .send()
                .await?;
            check(response).await
        }
        "telegram" => {
            let url = format!("https://api.telegram.org/bot{}/sendMessage", field(config, "bot_token")?);
            let response = http()
                .post(url)
                .json(&json!({ "chat_id": field(config, "chat_id")?, "text": format!("{title}\n{text_with_link}"),
                               "disable_web_page_preview": true }))
                .send()
                .await?;
            check(response).await
        }
        "discord" => {
            let mut embed = json!({ "title": title, "description": n.message, "color": n.severity.color() });
            if let Some(link) = &n.link {
                embed["url"] = json!(link);
            }
            let response = http()
                .post(field(config, "webhook_url")?)
                .json(&json!({ "username": "NetPulse", "embeds": [embed] }))
                .send()
                .await?;
            check(response).await
        }
        "teams" => {
            let mut body = vec![
                json!({ "type": "TextBlock", "text": title, "weight": "Bolder", "size": "Medium", "wrap": true }),
                json!({ "type": "TextBlock", "text": n.message, "wrap": true }),
            ];
            let mut actions = vec![];
            if let Some(link) = &n.link {
                actions.push(json!({ "type": "Action.OpenUrl", "title": "In NetPulse öffnen", "url": link }));
            }
            body.push(json!({ "type": "ActionSet", "actions": actions }));
            let card = json!({
                "type": "message",
                "attachments": [{
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": { "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                                 "type": "AdaptiveCard", "version": "1.4", "body": body }
                }]
            });
            check(http().post(field(config, "webhook_url")?).json(&card).send().await?).await
        }
        "webhook" => {
            let mut request = http().post(field(config, "url")?).json(&json!({
                "source": "netpulse", "severity": n.severity.name(), "title": n.title,
                "message": n.message, "link": n.link, "time": chrono::Utc::now(),
            }));
            if let Some(secret) = config["secret"].as_str().filter(|s| !s.is_empty()) {
                request = request.header("X-NetPulse-Secret", secret);
            }
            check(request.send().await?).await
        }
        other => bail!("Unbekannter Kanaltyp: {other}"),
    }
}

async fn send_email(config: &Value, subject: &str, body: &str) -> Result<()> {
    let host = field(config, "host")?;
    let port = config["port"].as_u64().and_then(|p| u16::try_from(p).ok());
    let security = config["security"].as_str().unwrap_or("starttls");
    let mut builder = match security {
        "tls" => AsyncSmtpTransport::<Tokio1Executor>::relay(host)?,
        "none" => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host),
        _ => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(host)?,
    };
    if let Some(port) = port {
        builder = builder.port(port);
    }
    if let (Some(user), Some(pass)) = (config["username"].as_str(), config["password"].as_str()) {
        if !user.is_empty() {
            builder = builder.credentials(Credentials::new(user.to_string(), pass.to_string()));
        }
    }
    let transport = builder.timeout(Some(Duration::from_secs(20))).build();

    let mut message = Message::builder()
        .from(field(config, "from")?.parse().context("Absenderadresse ungültig")?)
        .subject(subject)
        .header(ContentType::TEXT_PLAIN);
    for to in field(config, "to")?.split([',', ';']).map(str::trim).filter(|s| !s.is_empty()) {
        message = message.to(to.parse().with_context(|| format!("Empfängeradresse ungültig: {to}"))?);
    }
    transport.send(message.body(body.to_string())?).await?;
    Ok(())
}
