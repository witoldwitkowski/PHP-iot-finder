//! Small shared helpers: time, randomness, escaping and sanitising untrusted text.

use std::io::Read;
use std::time::{SystemTime, UNIX_EPOCH};

/// A calendar date (proleptic Gregorian, UTC).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Date {
    /// Year, e.g. 2026.
    pub year: i32,
    /// Month 1-12.
    pub month: u32,
    /// Day of month 1-31.
    pub day: u32,
}

impl Date {
    /// Parse `YYYY-MM-DD`.
    pub fn parse(s: &str) -> Option<Date> {
        let mut it = s.trim().split('-');
        let year: i32 = it.next()?.parse().ok()?;
        let month: u32 = it.next()?.parse().ok()?;
        let day: u32 = it.next()?.parse().ok()?;
        if it.next().is_some() || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
            return None;
        }
        Some(Date { year, month, day })
    }

    /// Days since 1970-01-01.
    pub fn to_days(self) -> i64 {
        days_from_civil(self.year as i64, self.month as i64, self.day as i64)
    }

    /// Today's date in UTC.
    pub fn today() -> Date {
        let secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
        Date::from_days(secs.div_euclid(86_400))
    }

    /// Build a date from days since the epoch.
    pub fn from_days(days: i64) -> Date {
        let (y, m, d) = civil_from_days(days);
        Date { year: y as i32, month: m as u32, day: d as u32 }
    }
}

impl std::fmt::Display for Date {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:04}-{:02}-{:02}", self.year, self.month, self.day)
    }
}

// Howard Hinnant's civil-date algorithms.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Seconds since the Unix epoch.
pub fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Format Unix seconds as an RFC 3339 UTC timestamp.
pub fn rfc3339(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, m, d, rem / 3600, (rem % 3600) / 60, rem % 60)
}

/// Current time as RFC 3339.
pub fn now_rfc3339() -> String {
    rfc3339(unix_now())
}

/// A filesystem-safe timestamp such as `20261024T031500Z`.
pub fn file_timestamp(secs: u64) -> String {
    rfc3339(secs).replace(['-', ':'], "")
}

/// Hex string of `n` random bytes from the OS.
pub fn random_hex(n: usize) -> std::io::Result<String> {
    let mut buf = vec![0u8; n];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut buf)?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

/// Constant-time byte comparison (used for the GUI token).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Escape text for inclusion in HTML.
pub fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// Make untrusted, device-supplied text safe to print and store.
///
/// Control characters (including ANSI escape sequences and newlines) are
/// replaced with spaces so a hostile device cannot inject terminal escapes or
/// forge report lines, whitespace is collapsed, and the result is capped at
/// `max` characters.
pub fn sanitize(s: &str, max: usize) -> String {
    let mut out = String::with_capacity(s.len().min(max + 4));
    let mut last_space = true;
    let mut count = 0;
    for c in s.chars() {
        let c = if c.is_control() || matches!(c, '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{feff}') {
            ' '
        } else {
            c
        };
        if c == ' ' {
            if last_space {
                continue;
            }
            last_space = true;
        } else {
            last_space = false;
        }
        if count >= max {
            out.push('…');
            break;
        }
        out.push(c);
        count += 1;
    }
    out.trim_end().to_string()
}

/// Replace control and bidirectional-override characters with spaces, keeping everything else.
/// A cheap backstop for text that was already sanitised at ingest.
pub fn scrub(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_control() || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{200b}'..='\u{200f}' | '\u{feff}') {
                ' '
            } else {
                c
            }
        })
        .collect()
}

/// Truncate to at most `max` characters, appending an ellipsis when cut.
pub fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

/// Lossy UTF-8 decode of at most `max` bytes.
pub fn lossy(bytes: &[u8], max: usize) -> String {
    String::from_utf8_lossy(&bytes[..bytes.len().min(max)]).into_owned()
}

/// Case-insensitive substring search without allocating a lowercase copy of `hay`.
pub fn contains_ci(hay: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    let h = hay.as_bytes();
    let n = needle.as_bytes();
    if n.len() > h.len() {
        return false;
    }
    h.windows(n.len()).any(|w| w.eq_ignore_ascii_case(n))
}

/// Format a MAC address as lowercase colon-separated hex.
pub fn fmt_mac(m: &[u8; 6]) -> String {
    format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", m[0], m[1], m[2], m[3], m[4], m[5])
}

/// Parse a MAC address in `aa:bb:..`, `aa-bb-..` or `aabbccddeeff` form.
pub fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let hex: String = s.chars().filter(|c| *c != ':' && *c != '-').collect();
    if hex.len() != 12 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 6];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn date_roundtrip() {
        for s in ["1970-01-01", "2026-10-24", "2000-02-29", "2099-12-31"] {
            let d = Date::parse(s).unwrap();
            assert_eq!(Date::from_days(d.to_days()), d);
            assert_eq!(d.to_string(), s);
        }
        assert_eq!(Date::parse("2026-10-24").unwrap().to_days() - Date::parse("2026-10-23").unwrap().to_days(), 1);
        assert!(Date::parse("2026-13-01").is_none());
        assert!(Date::parse("nonsense").is_none());
    }

    #[test]
    fn rfc3339_known() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(1_700_000_000), "2023-11-14T22:13:20Z");
    }

    #[test]
    fn sanitize_strips_escapes() {
        let s = sanitize("hello\x1b[31mred\x1b[0m\r\nworld\u{202e}x", 100);
        assert!(!s.contains('\x1b') && !s.contains('\n') && !s.contains('\u{202e}'));
        assert!(s.starts_with("hello"));
        assert_eq!(sanitize("a      b", 100), "a b");
        assert_eq!(sanitize("abcdefghij", 5), "abcde…");
    }

    #[test]
    fn scrub_keeps_text_replaces_controls() {
        assert_eq!(scrub("a\u{1b}[2Jb\u{202e}c\nd"), "a [2Jb c d");
        assert_eq!(scrub("plain é€😀"), "plain é€😀");
    }

    #[test]
    fn escape_html() {
        assert_eq!(html_escape("<a href=\"x\">&'"), "&lt;a href=&quot;x&quot;&gt;&amp;&#39;");
    }

    #[test]
    fn mac_roundtrip() {
        let m = parse_mac("AA-bb-0c-0D-ee-FF").unwrap();
        assert_eq!(fmt_mac(&m), "aa:bb:0c:0d:ee:ff");
        assert!(parse_mac("aa:bb").is_none());
        assert!(parse_mac("zz:bb:cc:dd:ee:ff").is_none());
    }

    #[test]
    fn ci_contains() {
        assert!(contains_ci("Hello PHP/8.2", "php/"));
        assert!(!contains_ci("abc", "abcd"));
    }

    #[test]
    fn ct_eq_works() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
    }
}
