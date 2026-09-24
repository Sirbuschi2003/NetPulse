//! Die letzten Log-Zeilen im Speicher – für die Seite „System-Log“ in der Oberfläche,
//! damit man zur Fehlersuche nicht in die Container-Logs schauen muss.

use std::{
    collections::VecDeque,
    fmt::{Debug, Write},
    sync::{Mutex, OnceLock},
};

use chrono::{DateTime, Utc};
use serde::Serialize;
use tracing::{
    field::{Field, Visit},
    Event, Level, Subscriber,
};
use tracing_subscriber::{layer::Context, Layer};

const CAPACITY: usize = 5000;

#[derive(Clone, Serialize)]
pub struct LogLine {
    time: DateTime<Utc>,
    level: &'static str,
    target: String,
    message: String,
}

fn buffer() -> &'static Mutex<VecDeque<LogLine>> {
    static BUFFER: OnceLock<Mutex<VecDeque<LogLine>>> = OnceLock::new();
    BUFFER.get_or_init(|| Mutex::new(VecDeque::with_capacity(CAPACITY)))
}

pub struct BufferLayer;

struct MessageVisitor(String);

impl Visit for MessageVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.0.push_str(value);
        } else {
            let _ = write!(self.0, " {}={value}", field.name());
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn Debug) {
        if field.name() == "message" {
            let _ = write!(self.0, "{value:?}");
        } else {
            let _ = write!(self.0, " {}={value:?}", field.name());
        }
    }
}

impl<S: Subscriber> Layer<S> for BufferLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let mut visitor = MessageVisitor(String::new());
        event.record(&mut visitor);
        let meta = event.metadata();
        let level = match *meta.level() {
            Level::ERROR => "error",
            Level::WARN => "warn",
            Level::INFO => "info",
            Level::DEBUG => "debug",
            Level::TRACE => "trace",
        };
        let mut lines = buffer().lock().unwrap();
        if lines.len() >= CAPACITY {
            lines.pop_front();
        }
        lines.push_back(LogLine { time: Utc::now(), level, target: meta.target().to_string(), message: visitor.0 });
    }
}

/// Neueste Zeilen zuerst; `min_level` = "error" | "warn" | "info" | "debug"
pub fn recent(min_level: &str, query: &str, limit: usize) -> Vec<LogLine> {
    let rank = |l: &str| match l {
        "error" => 4,
        "warn" => 3,
        "info" => 2,
        "debug" => 1,
        _ => 0,
    };
    let min = rank(min_level);
    let query = query.to_lowercase();
    buffer()
        .lock()
        .unwrap()
        .iter()
        .rev()
        .filter(|l| rank(l.level) >= min)
        .filter(|l| query.is_empty() || l.message.to_lowercase().contains(&query) || l.target.contains(&query))
        .take(limit)
        .cloned()
        .collect()
}
