//! Parsing of `Server`-style banners into product/version pairs.

use crate::version::Version;

/// One `name/version` token from a banner.
#[derive(Clone, Debug, PartialEq)]
pub struct Product {
    /// Lowercase product name, e.g. `apache`, `nginx`, `php`.
    pub name: String,
    /// Version, when present and parseable.
    pub version: Option<Version>,
    /// The raw token, e.g. `Apache/2.4.58`.
    pub raw: String,
}

/// Parse a banner such as `Apache/2.4.58 (Ubuntu) PHP/8.2.30 OpenSSL/3.0.13`.
/// Parenthesised comments are skipped (see [`distro_hint`] for those).
pub fn parse_banner(banner: &str) -> Vec<Product> {
    let mut out = Vec::new();
    let mut depth = 0usize;
    let mut token = String::new();
    let flush = |token: &mut String, out: &mut Vec<Product>| {
        if let Some((name, ver)) = token.split_once('/') {
            let name = name.trim().to_ascii_lowercase();
            if !name.is_empty() && name.len() <= 40 && name.chars().all(|c| c.is_ascii_alphanumeric() || "-_.+".contains(c)) {
                out.push(Product { name, version: Version::parse(ver), raw: token.clone() });
            }
        }
        token.clear();
    };
    for c in banner.chars() {
        match c {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            c if depth > 0 => {
                let _ = c;
            }
            c if c.is_whitespace() => flush(&mut token, &mut out),
            c => token.push(c),
        }
        if out.len() >= 16 {
            break;
        }
    }
    flush(&mut token, &mut out);
    out
}

/// Distribution names that commonly back-port security fixes without changing
/// upstream version numbers.
const DISTROS: &[&str] = &[
    "ubuntu", "debian", "raspbian", "centos", "red hat", "rhel", "fedora", "amazon", "alma", "rocky", "suse", "opensuse", "alpine",
    "oracle",
];

/// Return the distribution named in a banner comment such as `(Ubuntu)`, if any.
pub fn distro_hint(banner: &str) -> Option<String> {
    let lower = banner.to_ascii_lowercase();
    let mut rest = lower.as_str();
    while let Some(open) = rest.find('(') {
        let after = &rest[open + 1..];
        let Some(close) = after.find(')') else { break };
        let comment = &after[..close];
        if let Some(d) = DISTROS.iter().find(|d| comment.contains(**d)) {
            return Some((*d).to_string());
        }
        rest = &after[close + 1..];
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_apache_banner() {
        let p = parse_banner("Apache/2.4.58 (Ubuntu) PHP/8.2.30 OpenSSL/3.0.13 mod_fcgid/2.3.9");
        let names: Vec<_> = p.iter().map(|x| x.name.as_str()).collect();
        assert_eq!(names, vec!["apache", "php", "openssl", "mod_fcgid"]);
        assert_eq!(p[1].version.as_ref().unwrap().to_string(), "8.2.30");
    }

    #[test]
    fn parses_iot_servers() {
        let p = parse_banner("Boa/0.94.14rc21");
        assert_eq!(p[0].name, "boa");
        assert!(parse_banner("GoAhead-Webs").is_empty());
        assert_eq!(parse_banner("lighttpd/1.4.55")[0].name, "lighttpd");
        assert_eq!(parse_banner("PHP/5.6.40-0+deb8u12")[0].version.as_ref().unwrap().major, 5);
    }

    #[test]
    fn comments_are_skipped_not_parsed() {
        let p = parse_banner("nginx/1.24.0 (Ubuntu/22.04 foo/1.0)");
        assert_eq!(p.len(), 1);
    }

    #[test]
    fn distro_detection() {
        assert_eq!(distro_hint("Apache/2.4.58 (Ubuntu)").as_deref(), Some("ubuntu"));
        assert_eq!(distro_hint("Apache/2.4.57 (Debian) PHP/8.2.7").as_deref(), Some("debian"));
        assert_eq!(distro_hint("Apache/2.4.6 (CentOS) PHP/5.4.16").as_deref(), Some("centos"));
        assert_eq!(distro_hint("Apache/2.4.6 (Red Hat Enterprise Linux)").as_deref(), Some("red hat"));
        assert_eq!(distro_hint("nginx/1.24.0"), None);
        assert_eq!(distro_hint("Apache/2.4 (Unix)"), None);
        assert_eq!(distro_hint("broken (Ubuntu"), None);
    }

    #[test]
    fn garbage_is_safe() {
        assert!(parse_banner("").is_empty());
        assert!(parse_banner("////").is_empty());
        let big = "a/1.0 ".repeat(1000);
        assert!(parse_banner(&big).len() <= 17);
        let _ = parse_banner("((((");
        let _ = parse_banner("))))/");
    }
}
