//! PHP detection and version extraction from HTTP evidence.
//!
//! Evidence, from strongest to weakest:
//! 1. a `phpinfo()` page (version, SAPI and platform in one place),
//! 2. a version in `X-Powered-By: PHP/x.y.z`,
//! 3. a version in the `Server:` header (`... PHP/x.y.z`),
//! 4. version-less signals: `PHPSESSID` cookies, `X-Powered-By: PHP`, `.php` links,
//!    PHP error text.
//!
//! Banners are only claims: distributions back-port security fixes without
//! changing the version, and many devices strip or fake the header. That is why
//! each fact records whether the build looks vendor-packaged.

use super::products::{distro_hint, parse_banner};
use crate::model::HttpInfo;
use crate::util::{contains_ci, sanitize};
use crate::version::Version;
use serde::{Deserialize, Serialize};

/// What we know about PHP on one port.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct PhpFact {
    /// Port the evidence came from.
    pub port: u16,
    /// Version, when disclosed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<Version>,
    /// Where the version came from (`X-Powered-By header`, `phpinfo page`, …).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_source: Option<String>,
    /// True when the version came from a `phpinfo()` page rather than a header.
    #[serde(default)]
    pub from_phpinfo: bool,
    /// True when the build looks distribution/vendor packaged (back-ports likely).
    #[serde(default)]
    pub vendor_packaged: bool,
    /// Reason(s) vendor packaging was inferred.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor_hint: Option<String>,
    /// Server API (`Apache 2.0 Handler`, `FPM/FastCGI`, …) from phpinfo.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sapi: Option<String>,
    /// Observations that show PHP is present.
    #[serde(default)]
    pub signals: Vec<String>,
}

/// All PHP facts for a device.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct PhpDetection {
    /// One entry per port where PHP was seen.
    pub facts: Vec<PhpFact>,
}

impl PhpDetection {
    /// The fact with the most useful version information.
    pub fn best(&self) -> Option<&PhpFact> {
        self.facts.iter().max_by_key(|f| (f.version.is_some() as u8, f.from_phpinfo as u8))
    }
}

/// Facts from a `phpinfo()` page.
#[derive(Clone, Debug, PartialEq)]
pub struct PhpInfoPage {
    /// Version.
    pub version: Version,
    /// Server API.
    pub sapi: Option<String>,
    /// Distribution marker found on the page, if any.
    pub distro: Option<String>,
}

/// Strip HTML tags crudely, keeping text.
fn strip_tags(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_tag = false;
    for c in s.chars() {
        match c {
            '<' => in_tag = true,
            '>' if in_tag => {
                in_tag = false;
                out.push(' ');
            }
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    out
}

fn take_chars(s: &str, n: usize) -> &str {
    match s.char_indices().nth(n) {
        Some((i, _)) => &s[..i],
        None => s,
    }
}

/// Recognise a `phpinfo()` page and pull out version and SAPI.
pub fn parse_phpinfo(body: &str) -> Option<PhpInfoPage> {
    if !(contains_ci(body, "phpinfo()") || contains_ci(body, "PHP Version"))
        || !(contains_ci(body, "Zend") || contains_ci(body, "Configuration"))
    {
        return None;
    }
    let idx = body.find("PHP Version")?;
    let window = take_chars(&body[idx + "PHP Version".len()..], 240);
    let text = strip_tags(window);
    let text = text.trim_start_matches(|c: char| c.is_whitespace() || c == '=' || c == '>' || c == ':');
    let version = Version::parse(text)?;
    if version.major == 0 || version.major > 20 {
        return None;
    }
    let sapi = field_after(body, "Server API");
    let lower_head = body.to_ascii_lowercase();
    let lower = take_chars(&lower_head, 200_000);
    let distro = ["ubuntu", "debian", "raspbian", "centos", "red hat", "fedora", "alpine", "amazon linux", "suse"]
        .iter()
        .find(|d| lower.contains(**d))
        .map(|d| d.to_string());
    Some(PhpInfoPage { version, sapi, distro })
}

/// Value of a phpinfo row, in either HTML-table or plain-text (`label => value`) form.
fn field_after(body: &str, label: &str) -> Option<String> {
    let i = body.find(label)?;
    let rest = &body[i + label.len()..];
    let head = take_chars(rest, 200);
    let trimmed = head.trim_start();
    if let Some(t) = trimmed.strip_prefix("=>") {
        let line = t.split('\n').next().unwrap_or("");
        let v = sanitize(line, 60);
        return if v.is_empty() { None } else { Some(v) };
    }
    // HTML: skip the label's own cell, take the next cell.
    let first_close = head.find("</td>")?;
    let after = &head[first_close + 5..];
    let open = after.find("<td")?;
    let gt = after[open..].find('>')? + open + 1;
    let end = after[gt..].find("</td>").map(|e| e + gt).unwrap_or(after.len());
    let v = sanitize(&strip_tags(&after[gt..end]), 60);
    if v.is_empty() { None } else { Some(v) }
}

/// Find `PHP/x.y.z` in a header value.
fn php_version_in(header: &str) -> Option<(Version, String)> {
    parse_banner(header).into_iter().find(|p| p.name == "php").and_then(|p| p.version.map(|v| (v, p.raw)))
}

/// Count `.php` references that look like links or form targets.
fn count_php_links(body: &str) -> usize {
    let mut n = 0;
    let bytes = body.as_bytes();
    let mut from = 0;
    while let Some(pos) = body[from..].find(".php") {
        let end = from + pos + 4;
        if matches!(bytes.get(end), Some(b'"' | b'\'' | b'?' | b'#' | b'<' | b' ' | b'>' | b'/')) {
            n += 1;
            if n >= 3 {
                break;
            }
        }
        from = end;
    }
    n
}

/// Examine one HTTP service for PHP.
pub fn detect(port: u16, http: &HttpInfo, phpinfo: Option<&PhpInfoPage>) -> Option<PhpFact> {
    let mut f = PhpFact {
        port,
        version: None,
        version_source: None,
        from_phpinfo: false,
        vendor_packaged: false,
        vendor_hint: None,
        sapi: None,
        signals: vec![],
    };

    if let Some(info) = phpinfo {
        f.version = Some(info.version.clone());
        f.version_source = Some("phpinfo() page".into());
        f.from_phpinfo = true;
        f.sapi = info.sapi.clone();
        f.signals.push("phpinfo() page is reachable".into());
        if let Some(d) = &info.distro {
            f.vendor_packaged = true;
            f.vendor_hint = Some(format!("phpinfo() mentions {d}"));
        }
    }

    if let Some(pb) = &http.powered_by {
        if let Some((v, raw)) = php_version_in(pb) {
            f.signals.push(format!("X-Powered-By: {raw}"));
            if f.version.is_none() {
                f.version_source = Some("X-Powered-By header".into());
                f.version = Some(v);
            }
        } else if pb.to_ascii_lowercase().starts_with("php") {
            f.signals.push("X-Powered-By names PHP (version hidden)".into());
        }
    }

    if let Some(server) = &http.server {
        if let Some((v, raw)) = php_version_in(server) {
            f.signals.push(format!("Server header contains {raw}"));
            if f.version.is_none() {
                f.version_source = Some("Server header".into());
                f.version = Some(v);
            }
        }
        if let Some(d) = distro_hint(server) {
            if !f.vendor_packaged {
                f.vendor_hint = Some(format!("Server header names {d}"));
            }
            f.vendor_packaged = true;
        }
    }

    if http.cookie_names.iter().any(|c| c.eq_ignore_ascii_case("PHPSESSID")) {
        f.signals.push("PHPSESSID session cookie".into());
    }
    if contains_ci(&http.body, "Fatal error</b>:")
        || contains_ci(&http.body, "Parse error</b>:")
        || contains_ci(&http.body, "Warning</b>:  ")
    {
        f.signals.push("PHP error message in page".into());
    }
    if count_php_links(&http.body) > 0 && f.signals.is_empty() {
        f.signals.push("page links to .php files".into());
    }

    if let Some(v) = &f.version
        && v.looks_vendor_packaged()
    {
        f.vendor_packaged = true;
        f.vendor_hint.get_or_insert_with(|| format!("version string '{v}' looks distribution-packaged"));
    }

    if f.signals.is_empty() && f.version.is_none() { None } else { Some(f) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn http(server: Option<&str>, powered: Option<&str>, cookies: &[&str], body: &str) -> HttpInfo {
        HttpInfo {
            status: 200,
            server: server.map(Into::into),
            powered_by: powered.map(Into::into),
            cookie_names: cookies.iter().map(|s| s.to_string()).collect(),
            body: body.into(),
            ..HttpInfo::default()
        }
    }

    #[test]
    fn version_from_powered_by() {
        let f = detect(80, &http(None, Some("PHP/8.2.30"), &[], ""), None).unwrap();
        assert_eq!(f.version.unwrap().to_string(), "8.2.30");
        assert_eq!(f.version_source.as_deref(), Some("X-Powered-By header"));
        assert!(!f.vendor_packaged);
    }

    #[test]
    fn version_from_server_header_with_distro() {
        let f = detect(80, &http(Some("Apache/2.4.58 (Ubuntu) PHP/8.1.2-1ubuntu2.14"), None, &[], ""), None).unwrap();
        assert_eq!(f.version.as_ref().unwrap().branch(), "8.1");
        assert!(f.vendor_packaged);
        assert!(f.vendor_hint.is_some());
    }

    #[test]
    fn debian_suffix_marks_vendor_packaged() {
        let f = detect(80, &http(None, Some("PHP/7.4.33-1+deb11u1"), &[], ""), None).unwrap();
        assert!(f.vendor_packaged);
    }

    #[test]
    fn hidden_version_signals() {
        let f = detect(80, &http(Some("nginx"), None, &["PHPSESSID"], ""), None).unwrap();
        assert!(f.version.is_none());
        assert!(f.signals.iter().any(|s| s.contains("PHPSESSID")));
        let f = detect(80, &http(None, Some("PHP"), &[], ""), None).unwrap();
        assert!(f.version.is_none());
        let f = detect(80, &http(None, None, &[], "<a href=\"login.php\">x</a>"), None).unwrap();
        assert!(f.signals[0].contains(".php"));
    }

    #[test]
    fn not_php() {
        assert!(detect(80, &http(Some("nginx/1.24.0"), None, &["sid"], "<html>hello.phpx</html>"), None).is_none());
        assert!(detect(80, &http(Some("GoAhead-Webs"), Some("ASP.NET"), &[], ""), None).is_none());
    }

    const PHPINFO_HTML: &str = "<html><head><title>phpinfo()</title></head><body><div class=\"center\"><table><tr class=\"h\"><td><a href=\"http://www.php.net/\"><img border=\"0\" src=\"x\" alt=\"PHP logo\" /></a><h1 class=\"p\">PHP Version 8.2.30</h1></td></tr></table><table><tr><td class=\"e\">System </td><td class=\"v\">Linux box 6.1.0-18-amd64 #1 SMP Debian 6.1.76-1 </td></tr><tr><td class=\"e\">Server API </td><td class=\"v\">FPM/FastCGI </td></tr></table><p>This program makes use of the Zend Scripting Language Engine</p></div></body></html>";

    #[test]
    fn parses_phpinfo_html() {
        let p = parse_phpinfo(PHPINFO_HTML).unwrap();
        assert_eq!(p.version.to_string(), "8.2.30");
        assert_eq!(p.sapi.as_deref(), Some("FPM/FastCGI"));
        assert_eq!(p.distro.as_deref(), Some("debian"));
    }

    #[test]
    fn parses_phpinfo_text() {
        let t = "phpinfo()\nPHP Version => 7.4.33\n\nSystem => Linux router 4.14\nServer API => Apache 2.0 Handler\nZend Engine v3.4.0\n";
        let p = parse_phpinfo(t).unwrap();
        assert_eq!(p.version.to_string(), "7.4.33");
        assert_eq!(p.sapi.as_deref(), Some("Apache 2.0 Handler"));
        assert!(p.distro.is_none());
    }

    #[test]
    fn phpinfo_rejects_lookalikes() {
        assert!(parse_phpinfo("<html>PHP Version history of our product</html>").is_none());
        assert!(parse_phpinfo("").is_none());
        assert!(parse_phpinfo("phpinfo() Zend PHP Version banana").is_none());
    }

    #[test]
    fn phpinfo_beats_header_for_version() {
        let page = parse_phpinfo(PHPINFO_HTML).unwrap();
        let f = detect(80, &http(None, Some("PHP/5.6.40"), &[], ""), Some(&page)).unwrap();
        assert_eq!(f.version.unwrap().to_string(), "8.2.30");
        assert!(f.from_phpinfo);
        assert!(f.vendor_packaged, "phpinfo mentions Debian");
    }

    #[test]
    fn php_links_counter() {
        assert_eq!(count_php_links("a.php b.phpx"), 1);
        assert_eq!(count_php_links("x.php? y.php\" z.php# w.php'"), 3);
        assert_eq!(count_php_links(""), 0);
    }

    #[test]
    fn robust_to_hostile_input() {
        let mut body = String::from("PHP Version ");
        body.push_str(&"<".repeat(100_000));
        let _ = parse_phpinfo(&body);
        let _ = parse_phpinfo("PHP Version \u{1F600}\u{1F600}Zend");
        let _ = detect(80, &http(Some(&"PHP/".repeat(500)), Some("PHP/999999999999.1.1"), &[], &"é".repeat(100_000)), None);
    }
}
