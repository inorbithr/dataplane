//! The agent's own recent log lines, kept in memory for the local page's Logs section.
//! A tracing layer copies each event (level `info` and above, as the log filter allows)
//! into a bounded ring, redacted ([`crate::redact`]) before it is stored. Nothing here is
//! written anywhere or sent anywhere.

use std::collections::VecDeque;
use std::fmt::Write as _;
use std::sync::{Mutex, OnceLock};

use serde::Serialize;
use tracing::field::{Field, Visit};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;

/// Lines kept.
pub const MAX_LINES: usize = 500;
/// Longest line kept, in bytes; longer lines are cut.
pub const MAX_LINE: usize = 2048;

/// One log line.
#[derive(Debug, Clone, Serialize)]
pub struct LogLine {
    /// RFC 3339.
    pub at: String,
    /// `INFO`, `WARN`, …
    pub level: String,
    /// The message and its fields, redacted.
    pub text: String,
}

fn ring() -> &'static Mutex<VecDeque<LogLine>> {
    static RING: OnceLock<Mutex<VecDeque<LogLine>>> = OnceLock::new();
    RING.get_or_init(|| Mutex::new(VecDeque::with_capacity(MAX_LINES)))
}

/// Stores one line (redacted and cut here).
pub fn push(level: &str, text: &str) {
    let mut text = crate::redact::redact(text);
    if text.len() > MAX_LINE {
        let mut cut = MAX_LINE;
        while !text.is_char_boundary(cut) {
            cut -= 1;
        }
        text.truncate(cut);
        text.push('…');
    }
    let line = LogLine {
        at: crate::enroll::now_rfc3339(),
        level: level.to_owned(),
        text,
    };
    let mut r = match ring().lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    if r.len() == MAX_LINES {
        r.pop_front();
    }
    r.push_back(line);
}

/// The newest `n` lines, oldest first.
#[must_use]
pub fn tail(n: usize) -> Vec<LogLine> {
    let r = match ring().lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    r.iter().skip(r.len().saturating_sub(n)).cloned().collect()
}

/// The layer to add to the subscriber.
#[derive(Debug, Default)]
pub struct RingLayer;

struct Fields(String);

impl Visit for Fields {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.0.insert_str(0, value);
        } else {
            let _ = write!(self.0, " {}={value}", field.name());
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.0.insert_str(0, &format!("{value:?}"));
        } else {
            let _ = write!(self.0, " {}={value:?}", field.name());
        }
    }
}

impl<S: tracing::Subscriber> Layer<S> for RingLayer {
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        if *event.metadata().level() > tracing::Level::INFO {
            return;
        }
        let mut f = Fields(String::new());
        event.record(&mut f);
        push(event.metadata().level().as_str(), f.0.trim_start());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_and_redacted() {
        for i in 0..(MAX_LINES + 10) {
            push("INFO", &format!("line {i}"));
        }
        push(
            "WARN",
            &format!("password=hunter2hunter2 {}", "x".repeat(MAX_LINE * 2)),
        );
        let t = tail(MAX_LINES * 2);
        assert!(t.len() <= MAX_LINES);
        let last = t.last().unwrap();
        assert!(!last.text.contains("hunter2"));
        assert!(last.text.len() <= MAX_LINE + 4);
    }
}
