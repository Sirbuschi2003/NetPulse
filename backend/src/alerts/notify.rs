//! Versand von Benachrichtigungen an die verschiedenen Kanäle.

use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use lettre::{
    message::{header::ContentType, Mailbox, MultiPart, SinglePart},
    transport::smtp::authentication::Credentials,
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
};
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// Reihenfolge = Wichtigkeit (für Sammelmeldungen zählt die höchste)
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Resolved,
    Info,
    Warning,
    Critical,
}

impl Severity {
    /// Deutsche Bezeichnung für Vorlagen
    pub fn label(self) -> &'static str {
        match self {
            Severity::Critical => "Kritisch",
            Severity::Warning => "Warnung",
            Severity::Info => "Hinweis",
            Severity::Resolved => "Behoben",
        }
    }
    pub fn emoji(self) -> &'static str {
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
    pub fn color(self) -> u32 {
        match self {
            Severity::Critical => 0xDC2626,
            Severity::Warning => 0xF59E0B,
            Severity::Info => 0x2563EB,
            Severity::Resolved => 0x16A34A,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Notification {
    pub title: String,
    pub message: String,
    pub severity: Severity,
    pub link: Option<String>,
    /// Betroffenes Gerät (für Vorlagen, Wartungsfenster und Abhängigkeiten)
    #[serde(default)]
    pub device_id: Option<i64>,
    /// Betroffener Dienst-Check (für Wartungsfenster)
    #[serde(default)]
    pub check_id: Option<i64>,
    /// Platzhalter für Vorlagen ({{geraet}}, {{ip}}, {{regel}}, {{wert}} …)
    #[serde(default)]
    pub vars: BTreeMap<String, String>,
}

impl Notification {
    pub fn new(title: impl Into<String>, message: impl Into<String>, severity: Severity, link: Option<String>) -> Self {
        Self { title: title.into(), message: message.into(), severity, link, device_id: None, check_id: None, vars: BTreeMap::new() }
    }

    pub fn device(mut self, device_id: i64) -> Self {
        self.device_id = Some(device_id);
        self
    }

    pub fn var(mut self, key: &str, value: impl ToString) -> Self {
        self.vars.insert(key.to_string(), value.to_string());
        self
    }

    /// Alle Platzhalter inklusive Titel, Meldung, Schwere, Zeit und Link
    pub fn all_vars(&self) -> BTreeMap<String, String> {
        let mut vars = self.vars.clone();
        vars.insert("titel".into(), self.title.clone());
        vars.insert("meldung".into(), self.message.clone());
        vars.insert("schwere".into(), self.severity.label().into());
        vars.insert("link".into(), self.link.clone().unwrap_or_default());
        vars.entry("zeit".into()).or_insert_with(|| {
            chrono::Utc::now().with_timezone(&crate::scanner::schedule::timezone()).format("%d.%m.%Y %H:%M").to_string()
        });
        for key in ["geraet", "ip", "regel", "wert"] {
            vars.entry(key.into()).or_default();
        }
        vars
    }
}

pub const DEFAULT_SUBJECT: &str = "[NetPulse] {{schwere}}: {{titel}}";
pub const DEFAULT_TEMPLATE: &str = "{{meldung}}\n\nGerät: {{geraet}} {{ip}}\nRegel: {{regel}}\nWert: {{wert}}\nZeit: {{zeit}}";

/// `{{name}}` durch Werte ersetzen. Zeilen wie „Regel:“ ohne Wert fallen weg.
pub fn render(template: &str, vars: &BTreeMap<String, String>) -> String {
    let mut out = template.to_string();
    for (key, value) in vars {
        out = out.replace(&format!("{{{{{key}}}}}"), value);
    }
    let lines: Vec<&str> = out
        .lines()
        .map(str::trim_end)
        .filter(|line| {
            let t = line.trim();
            !(t.ends_with(':') && t.matches(':').count() == 1 && t.chars().count() <= 30)
        })
        .collect();
    lines.join("\n").trim().to_string()
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

/// Übersichtliche HTML-Mail (die Textfassung wird zusätzlich mitgeschickt)
pub fn html_mail(n: &Notification, body: &str) -> String {
    let color = format!("#{:06x}", n.severity.color());
    let lines: String = body
        .lines()
        .map(|line| match line.split_once(": ") {
            Some((k, v)) if k.chars().count() <= 20 && !k.contains('.') => {
                format!("<span style=\"color:#64748b\">{}:</span> {}", html_escape(k), html_escape(v))
            }
            _ => html_escape(line),
        })
        .collect::<Vec<_>>()
        .join("<br>");
    let button = n.link.as_deref().filter(|l| l.starts_with("http")).map_or(String::new(), |l| {
        format!(
            "<tr><td style=\"padding:16px 26px 0\"><a href=\"{}\" style=\"display:inline-block;background:#4f46e5;color:#ffffff;\
             text-decoration:none;padding:10px 18px;border-radius:8px;font-weight:600;font-size:14px\">In NetPulse öffnen</a></td></tr>",
            html_escape(l)
        )
    });
    format!(
        "<!doctype html><html lang=\"de\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\"></head>\
         <body style=\"margin:0;background:#f3f5f9;font-family:Segoe UI,Helvetica,Arial,sans-serif\">\
         <table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" style=\"padding:24px 12px\"><tr><td align=\"center\">\
         <table role=\"presentation\" width=\"560\" cellpadding=\"0\" cellspacing=\"0\" style=\"max-width:560px;width:100%;background:#ffffff;\
         border-radius:12px;overflow:hidden;border:1px solid #e3e7ef\">\
         <tr><td style=\"background:{color};height:6px;font-size:0;line-height:0\">&nbsp;</td></tr>\
         <tr><td style=\"padding:22px 26px 4px\"><div style=\"font-size:12px;color:#64748b;letter-spacing:.06em;text-transform:uppercase\">\
         NetPulse · {sev}</div><h1 style=\"margin:6px 0 0;font-size:20px;line-height:1.3;color:#0f172a\">{title}</h1></td></tr>\
         <tr><td style=\"padding:12px 26px 0;font-size:15px;line-height:1.6;color:#334155\">{lines}</td></tr>{button}\
         <tr><td style=\"padding:22px 26px 22px;font-size:12px;color:#94a3b8\">Automatische Nachricht von NetPulse</td></tr>\
         </table></td></tr></table></body></html>",
        sev = n.severity.label(),
        title = html_escape(&n.title),
    )
}

/// Konfigurationsfelder, die als geheim gelten und in der Oberfläche maskiert werden
pub const SECRET_FIELDS: &[&str] = &["password", "token", "bot_token", "webhook_url", "secret", "url"];

fn http() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
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

/// URLs in Fehlermeldungen kürzen – sie können Tokens enthalten (Telegram-Bot, Webhooks)
pub fn redact(text: &str) -> String {
    text.split_inclusive(char::is_whitespace)
        .map(|word| {
            let trimmed = word.trim_start_matches(['(', '"', '\'']);
            match trimmed.find("://") {
                Some(i) if trimmed[..i].chars().all(|c| c.is_ascii_alphabetic()) => {
                    let rest = &trimmed[i + 3..];
                    let host = rest.split(['/', '?', '#', ' ', ')', '"']).next().unwrap_or_default();
                    let host = host.rsplit('@').next().unwrap_or(host);
                    let tail = if word.ends_with(char::is_whitespace) { " " } else { "" };
                    format!("{}://{host}/…{tail}", &trimmed[..i])
                }
                _ => word.to_string(),
            }
        })
        .collect()
}

/// Markdown-Steuerzeichen entschärfen (Discord/Teams) – Gerätenamen kommen aus dem Netz
fn md(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if "\\[]()*_`~>#|<".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

pub async fn send(kind: &str, config: &Value, n: &Notification) -> Result<()> {
    send_inner(kind, config, n).await.map_err(|e| anyhow!(redact(&format!("{e:#}"))))
}

async fn send_inner(kind: &str, config: &Value, n: &Notification) -> Result<()> {
    let title = format!("{} {}", n.severity.emoji(), n.title);
    let text_with_link = match &n.link {
        Some(link) => format!("{}\n\n{link}", n.message),
        None => n.message.clone(),
    };
    match kind {
        "email" => send_email(config, n).await,
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
            let mut embed = json!({ "title": md(&title), "description": md(&n.message), "color": n.severity.color() });
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
                json!({ "type": "TextBlock", "text": md(&title), "weight": "Bolder", "size": "Medium", "wrap": true }),
                json!({ "type": "TextBlock", "text": md(&n.message), "wrap": true }),
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

/// E-Mail nach Vorlage (Betreff/Text aus dem Kanal oder Standard) als HTML + Textfassung
async fn send_email(config: &Value, n: &Notification) -> Result<()> {
    let host = field(config, "host")
        .map_err(|_| anyhow!("Kein E-Mail-Server eingerichtet – unter Benachrichtigungen → E-Mail-Server eintragen"))?;
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

    let vars = n.all_vars();
    let text_or = |key: &str, default: &str| config[key].as_str().filter(|s| !s.trim().is_empty()).unwrap_or(default).to_string();
    let subject = render(&text_or("subject", DEFAULT_SUBJECT), &vars).replace('\n', " ");
    let template = text_or("template", DEFAULT_TEMPLATE);
    let mut text = render(&template, &vars);
    if let Some(link) = n.link.as_deref().filter(|l| !text.contains(*l)) {
        text.push_str(&format!("\n\n{link}"));
    }
    let html = html_mail(n, &render(&template.replace("{{link}}", ""), &vars));

    let from_addr: lettre::Address = field(config, "from")?.parse().context("Absenderadresse ungültig")?;
    let from_name = config["from_name"].as_str().filter(|s| !s.trim().is_empty()).unwrap_or("NetPulse");
    let mut message = Message::builder().from(Mailbox::new(Some(from_name.to_string()), from_addr)).subject(subject);
    for to in field(config, "to")?.split([',', ';']).map(str::trim).filter(|s| !s.is_empty()) {
        message = message.to(to.parse().with_context(|| format!("Empfängeradresse ungültig: {to}"))?);
    }
    let body = MultiPart::alternative()
        .singlepart(SinglePart::builder().header(ContentType::TEXT_PLAIN).body(text))
        .singlepart(SinglePart::builder().header(ContentType::TEXT_HTML).body(html));
    transport.send(message.multipart(body)?).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn geheimnisse_aus_fehlern() {
        let e = "error sending request for url (https://api.telegram.org/bot123:SECRET/sendMessage): timeout";
        let r = redact(e);
        assert!(!r.contains("SECRET"), "{r}");
        assert!(r.contains("api.telegram.org"));
        assert_eq!(md("[Klick](https://x)"), "\\[Klick\\]\\(https://x\\)");
    }

    #[test]
    fn vorlage() {
        let n = Notification::new("Offline: NAS", "NAS ist seit 5 Min. nicht erreichbar", Severity::Critical, None)
            .var("geraet", "NAS")
            .var("ip", "(10.0.0.5)")
            .var("zeit", "24.09.2026 12:00");
        let text = render(DEFAULT_TEMPLATE, &n.all_vars());
        assert!(text.starts_with("NAS ist seit 5 Min."));
        assert!(text.contains("Gerät: NAS (10.0.0.5)"));
        assert!(!text.contains("Regel:"), "leere Zeilen fallen weg: {text}");
        assert!(text.contains("Zeit: 24.09.2026 12:00"));
        assert_eq!(render(DEFAULT_SUBJECT, &n.all_vars()), "[NetPulse] Kritisch: Offline: NAS");
        assert!(html_mail(&n, &text).contains("Offline: NAS"));
        assert!(Severity::Critical > Severity::Warning && Severity::Warning > Severity::Resolved);
    }
}
