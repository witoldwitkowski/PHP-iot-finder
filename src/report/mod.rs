//! Rendering results: terminal, JSON and standalone HTML.

pub mod html;
pub mod terminal;

use crate::model::{Confidence, Severity};

/// Marker glyph per severity. Shape differs per level so colour is never the only signal.
pub fn marker(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "◆",
        Severity::High => "▲",
        Severity::Medium => "■",
        Severity::Low => "●",
        Severity::Info => "○",
    }
}

/// Human wording for a confidence level.
pub fn confidence_words(c: Confidence) -> &'static str {
    match c {
        Confidence::Confirmed => "confirmed",
        Confidence::Likely => "likely",
        Confidence::Possible => "possible",
    }
}

/// One-line explanation of what the confidence levels mean.
pub const CONFIDENCE_LEGEND: &str = "confirmed = observed directly · likely = good evidence · possible = weak or indirect signal (for example a hidden version, or a distribution that may have back-ported the fix)";

/// Pretty JSON for a serialisable value.
pub fn json<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_string_pretty(v).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
}
