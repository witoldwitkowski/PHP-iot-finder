//! Generic, data-driven checker: any advisory in the database that has no
//! dedicated checker is matched against the products named in `Server` and
//! `X-Powered-By` banners. New vulnerabilities in banner-identifiable software
//! therefore need only a TOML entry, not code.

use super::*;
use crate::advisories::Verdict;
use crate::fingerprint::products::{distro_hint, parse_banner};
use crate::model::Severity;

/// Checker id.
pub const ID: &str = "data-advisory";

/// The generic advisory checker.
pub struct DataAdvisory;

impl Checker for DataAdvisory {
    fn meta(&self) -> CheckerMeta {
        CheckerMeta {
            id: ID,
            name: "Advisory database (banner versions)",
            description: "Matches product versions from Server / X-Powered-By banners against data/advisories.toml and your own advisory file.",
            category: Category::Web,
            tags: &["data-driven", "banner", "version"],
            uses_active_probes: false,
        }
    }

    fn evaluate(&self, input: &CheckInput) -> Vec<Finding> {
        let mut out = Vec::new();
        for adv in input.db.advisory.iter().filter(|a| a.checker.is_none()) {
            for s in input.web_services() {
                let Some(http) = &s.http else { continue };
                let banners: Vec<&String> = [&http.server, &http.powered_by].into_iter().flatten().collect();
                for banner in banners {
                    for prod in parse_banner(banner).into_iter().filter(|p| p.name == adv.product) {
                        let vendor = distro_hint(banner).is_some() || prod.version.as_ref().is_some_and(|v| v.looks_vendor_packaged());
                        let verdict = match &prod.version {
                            Some(v) => adv.verdict(v),
                            None if adv.any_version => Verdict::Affected { fixed: None },
                            None => continue,
                        };
                        let (sev, conf, extra) = match verdict {
                            Verdict::Affected { fixed } => (
                                adv.severity,
                                if vendor { Confidence::Possible } else { Confidence::Likely },
                                fixed.map(|x| format!(" The fix is in {x}.")).unwrap_or_else(|| " No fixed version is known.".to_string()),
                            ),
                            Verdict::Legacy { note, unconfirmed } => (
                                if unconfirmed { Severity::Medium.min(adv.severity) } else { adv.severity },
                                if vendor || unconfirmed { Confidence::Possible } else { Confidence::Likely },
                                format!(" {note}"),
                            ),
                            Verdict::Fixed | Verdict::NotCovered => continue,
                        };
                        let note = if vendor { format!(" {BACKPORT_NOTE}") } else { String::new() };
                        let what = match &prod.version {
                            Some(v) => format!("{} {v}", prod.name),
                            None => format!("{} (version not disclosed)", prod.name),
                        };
                        let mut f = advisory_finding(adv, &adv.id, sev, conf)
                            .port(s.port)
                            .summary(format!("{what} on port {}.{extra} {}{note}", s.port, adv.summary))
                            .evidence(format!("Banner: {}", crate::util::truncate(banner, 200)));
                        f.checker = adv.id.clone();
                        out.push(f);
                    }
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::super::testutil::*;
    use super::*;

    fn db_with(toml: &str) -> AdvisoryDb {
        let mut db = AdvisoryDb::embedded();
        db.merge(AdvisoryDb::parse(toml).unwrap());
        db
    }

    const BOA: &str = r#"
[[advisory]]
id = "boa-unmaintained"
product = "boa"
title = "Boa web server is unmaintained"
severity = "high"
cves = ["CVE-2017-9833"]
summary = "Boa has been abandoned since 2005."
remediation = "Replace the firmware."
[[advisory.affected]]
from = "0.0"
"#;

    const LIGHTTPD: &str = r#"
[[advisory]]
id = "lighttpd-test"
product = "lighttpd"
title = "lighttpd test"
severity = "medium"
[[advisory.affected]]
branch = "1.4"
fixed = "1.4.60"
"#;

    #[test]
    fn matches_unfixed_product() {
        let db = db_with(BOA);
        let d = device_with_http(80, Some("Boa/0.94.14rc21"), None, &[], "");
        let f = DataAdvisory.evaluate(&input(&d, &ProbeResults::default(), &db, "2026-10-24"));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].checker, "boa-unmaintained");
        assert_eq!(f[0].severity, Severity::High);
        assert_eq!(f[0].confidence, Confidence::Likely);
        assert!(f[0].cves.contains(&"CVE-2017-9833".to_string()));
    }

    #[test]
    fn respects_fixed_versions() {
        let db = db_with(LIGHTTPD);
        let old = device_with_http(80, Some("lighttpd/1.4.55"), None, &[], "");
        let new = device_with_http(80, Some("lighttpd/1.4.66"), None, &[], "");
        assert_eq!(DataAdvisory.evaluate(&input(&old, &ProbeResults::default(), &db, "2026-10-24")).len(), 1);
        assert!(DataAdvisory.evaluate(&input(&new, &ProbeResults::default(), &db, "2026-10-24")).is_empty());
    }

    #[test]
    fn distro_banner_lowers_confidence() {
        let db = db_with(LIGHTTPD);
        let d = device_with_http(80, Some("lighttpd/1.4.55 (Debian)"), None, &[], "");
        let f = DataAdvisory.evaluate(&input(&d, &ProbeResults::default(), &db, "2026-10-24"));
        assert_eq!(f[0].confidence, Confidence::Possible);
    }

    #[test]
    fn does_not_double_report_dedicated_checkers() {
        // php2shell has a dedicated checker, so the generic one must skip it.
        let db = AdvisoryDb::embedded();
        let d = device_with_http(80, Some("Apache PHP/7.4.33"), Some("PHP/7.4.33"), &[], "");
        assert!(DataAdvisory.evaluate(&input(&d, &ProbeResults::default(), &db, "2026-10-24")).is_empty());
    }

    #[test]
    fn shipped_boa_advisory_flags_every_boa_banner() {
        let db = AdvisoryDb::embedded();
        for banner in ["Boa/0.94.14rc21", "Boa/0.94.13", "Boa", "boa/0.93.15"] {
            let d = device_with_http(80, Some(banner), None, &[], "");
            let f = DataAdvisory.evaluate(&input(&d, &ProbeResults::default(), &db, "2026-10-24"));
            assert_eq!(f.len(), 1, "{banner}");
            assert_eq!(f[0].checker, "boa-unmaintained");
            assert_eq!(f[0].severity, Severity::Medium);
            assert_eq!(f[0].confidence, Confidence::Likely);
            assert!(!f[0].cves.contains(&"CVE-2017-9833".to_string()), "disputed CVE must not be cited");
            assert!(f[0].evidence.iter().any(|e| e.contains("not yet verified")), "unverified data must say so");
        }
        for other in ["lighttpd/1.4.66", "nginx", "Boat/1.0", "GoAhead-Webs", "boa-constrictor/1.0"] {
            let d = device_with_http(80, Some(other), None, &[], "");
            assert!(DataAdvisory.evaluate(&input(&d, &ProbeResults::default(), &db, "2026-10-24")).is_empty(), "{other}");
        }
    }

    #[test]
    fn unversioned_banners_are_ignored() {
        let db = db_with(BOA);
        let d = device_with_http(80, Some("Boa"), None, &[], "");
        assert!(DataAdvisory.evaluate(&input(&d, &ProbeResults::default(), &db, "2026-10-24")).is_empty());
    }
}
