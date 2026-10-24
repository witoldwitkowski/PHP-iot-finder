//! Accepted-risk suppressions.
//!
//! ```toml
//! [[allow]]
//! device  = "aa:bb:cc:dd:ee:ff"     # MAC, IP address, or "*"
//! checker = "php2shell"             # optional: omit to cover every checker
//! port    = 80                      # optional
//! reason  = "Vendor confirmed back-ported fix in firmware 2.4"
//! expires = "2027-03-01"            # optional: entry stops applying after this date
//! ```

use crate::model::Device;
use crate::util::{Date, parse_mac};
use serde::Deserialize;
use std::path::{Path, PathBuf};

/// One suppression rule.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct Entry {
    /// MAC, IP, or `*`.
    pub device: String,
    /// Checker id (optional).
    #[serde(default)]
    pub checker: Option<String>,
    /// Port (optional).
    #[serde(default)]
    pub port: Option<u16>,
    /// Why this is accepted. Required, so future-you knows.
    pub reason: String,
    /// Last day the entry applies.
    #[serde(default)]
    pub expires: Option<String>,
}

/// A parsed allowlist.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct Allowlist {
    /// Entries.
    #[serde(default)]
    pub allow: Vec<Entry>,
}

/// Default location.
pub fn default_path() -> Option<PathBuf> {
    crate::paths::config_dir().map(|d| d.join("allowlist.toml"))
}

impl Allowlist {
    /// Parse and validate.
    pub fn parse(text: &str) -> Result<Allowlist, String> {
        let a: Allowlist = toml::from_str(text).map_err(|e| e.to_string())?;
        for (i, e) in a.allow.iter().enumerate() {
            let n = i + 1;
            if e.reason.trim().is_empty() {
                return Err(format!("allow entry {n}: a non-empty `reason` is required"));
            }
            if e.device != "*" && e.device.parse::<std::net::IpAddr>().is_err() && parse_mac(&e.device).is_none() {
                return Err(format!("allow entry {n}: device '{}' is not a MAC, IP address or '*'", e.device));
            }
            if let Some(x) = &e.expires
                && Date::parse(x).is_none()
            {
                return Err(format!("allow entry {n}: bad expires date '{x}' (use YYYY-MM-DD)"));
            }
        }
        Ok(a)
    }

    /// Load from a file. A missing default file is not an error; a missing explicit one is.
    pub fn load(explicit: Option<&Path>) -> Result<Allowlist, String> {
        match explicit {
            Some(p) => {
                let t = std::fs::read_to_string(p).map_err(|e| format!("cannot read {}: {e}", p.display()))?;
                Allowlist::parse(&t).map_err(|e| format!("{}: {e}", p.display()))
            }
            None => match default_path().and_then(|p| std::fs::read_to_string(&p).ok().map(|t| (p, t))) {
                Some((p, t)) => Allowlist::parse(&t).map_err(|e| format!("{}: {e}", p.display())),
                None => Ok(Allowlist::default()),
            },
        }
    }

    fn matches(e: &Entry, d: &Device) -> bool {
        if e.device == "*" {
            return true;
        }
        if let Some(m) = parse_mac(&e.device) {
            return d.mac.as_deref().and_then(parse_mac) == Some(m);
        }
        e.device.parse::<std::net::IpAddr>().is_ok_and(|ip| ip == d.ip || d.other_ips.contains(&ip))
    }

    /// Mark matching findings as suppressed. Returns the number suppressed.
    pub fn apply(&self, devices: &mut [Device], today: Date) -> usize {
        let mut n = 0;
        for d in devices {
            let snapshot = d.clone();
            for f in &mut d.findings {
                if f.suppressed.is_some() {
                    continue;
                }
                let hit = self.allow.iter().find(|e| {
                    Self::matches(e, &snapshot)
                        && e.checker.as_deref().is_none_or(|c| c == f.checker)
                        && e.port.is_none_or(|p| Some(p) == f.port)
                        && e.expires.as_deref().and_then(Date::parse).is_none_or(|x| today <= x)
                });
                if let Some(e) = hit {
                    f.suppressed = Some(e.reason.clone());
                    n += 1;
                }
            }
        }
        n
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Confidence, Finding, Severity};

    fn dev(ip: &str, mac: Option<&str>) -> Device {
        let mut d = Device::new(ip.parse().unwrap());
        d.mac = mac.map(Into::into);
        d.findings.push(Finding::new("php2shell", "t", Severity::Critical, Confidence::Likely).port(80));
        d.findings.push(Finding::new("telnet-open", "t", Severity::High, Confidence::Confirmed).port(23));
        d
    }

    fn today() -> Date {
        Date::parse("2026-10-24").unwrap()
    }

    #[test]
    fn suppresses_by_mac_and_checker() {
        let a = Allowlist::parse("[[allow]]\ndevice='AA-BB-CC-DD-EE-FF'\nchecker='php2shell'\nreason='patched'\n").unwrap();
        let mut ds = vec![dev("192.168.1.5", Some("aa:bb:cc:dd:ee:ff")), dev("192.168.1.6", Some("11:22:33:44:55:66"))];
        assert_eq!(a.apply(&mut ds, today()), 1);
        assert_eq!(ds[0].findings[0].suppressed.as_deref(), Some("patched"));
        assert!(ds[0].findings[1].suppressed.is_none());
        assert!(ds[1].findings.iter().all(|f| f.suppressed.is_none()));
    }

    #[test]
    fn suppresses_by_ip_and_port() {
        let a = Allowlist::parse("[[allow]]\ndevice='192.168.1.5'\nport=23\nreason='isolated vlan'\n").unwrap();
        let mut ds = vec![dev("192.168.1.5", None)];
        a.apply(&mut ds, today());
        assert!(ds[0].findings[0].suppressed.is_none());
        assert!(ds[0].findings[1].suppressed.is_some());
    }

    #[test]
    fn wildcard_and_expiry() {
        let a = Allowlist::parse("[[allow]]\ndevice='*'\nchecker='telnet-open'\nreason='lab'\nexpires='2026-10-23'\n").unwrap();
        let mut ds = vec![dev("192.168.1.5", None)];
        assert_eq!(a.apply(&mut ds, today()), 0, "expired yesterday");
        assert_eq!(a.apply(&mut ds, Date::parse("2026-10-23").unwrap()), 1, "still valid on the last day");
    }

    #[test]
    fn validation() {
        assert!(Allowlist::parse("[[allow]]\ndevice='x'\nreason='r'").is_err());
        assert!(Allowlist::parse("[[allow]]\ndevice='*'\nreason=' '").is_err());
        assert!(Allowlist::parse("[[allow]]\ndevice='*'\nreason='r'\nexpires='soon'").is_err());
        assert!(Allowlist::parse("[[allow]]\ndevice='*'").is_err());
        assert!(Allowlist::parse("").unwrap().allow.is_empty());
    }

    #[test]
    fn mac_in_other_formats_matches() {
        let a = Allowlist::parse("[[allow]]\ndevice='aabbccddeeff'\nreason='r'\n").unwrap();
        let mut ds = vec![dev("192.168.1.5", Some("aa:bb:cc:dd:ee:ff"))];
        assert_eq!(a.apply(&mut ds, today()), 2);
    }
}
