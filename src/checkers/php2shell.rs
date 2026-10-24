//! PHP2Shell (CVE-2026-109618 / CVE-2026-109619), October 2026.
//!
//! This checker never sends an exploit or anything resembling one. It compares
//! the PHP version the device discloses with the patched releases, and with
//! `--active` it additionally looks for an exposed `phpinfo()` page to learn a
//! hidden version. Version evidence can be wrong in both directions
//! (back-ported fixes, spoofed banners), which is why every finding carries a
//! confidence level.

use super::*;
use crate::advisories::Verdict;
use crate::model::Severity;

/// Id of both the checker and the advisory it implements.
pub const ID: &str = "php2shell";

/// The PHP2Shell checker.
pub struct Php2Shell;

impl Checker for Php2Shell {
    fn meta(&self) -> CheckerMeta {
        CheckerMeta {
            id: ID,
            name: "PHP2Shell (CVE-2026-109618, CVE-2026-109619)",
            description: "Unauthenticated remote code execution in PHP core, fixed 2026-10-21 in 8.5.12, 8.4.27, 8.3.36 and 8.2.35.",
            category: Category::Web,
            tags: &["php", "rce", "cve-2026-109618", "cve-2026-109619", "php2shell"],
            uses_active_probes: true,
        }
    }

    fn probes(&self, device: &Device, _db: &AdvisoryDb) -> Vec<Probe> {
        // Only chase the version where PHP is present but its version is hidden.
        let mut out = Vec::new();
        for s in device.services.iter().filter(|s| s.is_web()) {
            let http = s.http.clone().unwrap_or_default();
            if let Some(f) = php::detect(s.port, &http, None)
                && f.version.is_none()
            {
                for p in PHPINFO_PATHS {
                    out.push(Probe::active(ProbeKind::http_get(s.port, p)));
                }
            }
        }
        out
    }

    fn evaluate(&self, input: &CheckInput) -> Vec<Finding> {
        let Some(adv) = input.db.get(ID) else { return vec![] };
        input.php_facts().iter().filter_map(|f| assess(adv, f, input.active)).collect()
    }
}

fn evidence(f: &PhpFact) -> Vec<String> {
    let mut e = Vec::new();
    if let (Some(v), Some(src)) = (&f.version, &f.version_source) {
        e.push(format!("PHP {v} (from {src})"));
    }
    for s in &f.signals {
        e.push(s.clone());
    }
    if let Some(s) = &f.sapi {
        e.push(format!("Server API: {s}"));
    }
    if let Some(h) = &f.vendor_hint {
        e.push(format!("Vendor-packaging hint: {h}"));
    }
    // Device-supplied text: bounded and printable.
    e.iter().take(12).map(|x| crate::util::truncate(&crate::util::scrub(x), 300)).collect()
}

/// Judge one port's PHP evidence against the advisory.
pub fn assess(adv: &Advisory, f: &PhpFact, active: bool) -> Option<Finding> {
    let build = |sev: Severity, conf: Confidence| {
        let mut fnd = advisory_finding(adv, ID, sev, conf).port(f.port);
        fnd.evidence = evidence(f);
        fnd
    };
    let Some(v) = &f.version else {
        let hint = if active {
            "No phpinfo() page was found either."
        } else {
            "Re-run with --active to look for an exposed phpinfo() page that would reveal the version."
        };
        return Some(
            build(Severity::Medium, Confidence::Possible)
                .summary(format!(
                    "PHP is running on port {} but does not disclose its version, so PHP2Shell cannot be ruled out. {hint} Otherwise confirm the version on the device itself (php -v, or the firmware release notes). {}",
                    f.port, adv.summary
                )),
        );
    };
    if v.is_prerelease() {
        return None;
    }
    let vendor_note = if f.vendor_packaged { format!(" {BACKPORT_NOTE}") } else { String::new() };
    match adv.verdict(v) {
        Verdict::Fixed | Verdict::NotCovered => None,
        Verdict::Affected { fixed } => {
            let conf = if f.vendor_packaged { Confidence::Possible } else { Confidence::Likely };
            let fixed_txt = fixed.map(|x| format!(" The fix is in {x}.")).unwrap_or_default();
            Some(build(adv.severity, conf).summary(format!(
                "PHP {v} on port {} is older than the patched release for the {} branch.{fixed_txt} {}{vendor_note}",
                f.port,
                v.branch(),
                adv.summary
            )))
        }
        Verdict::Legacy { note, unconfirmed } => {
            let (sev, conf) = if unconfirmed {
                (Severity::Medium, Confidence::Possible)
            } else if f.vendor_packaged {
                (adv.severity, Confidence::Possible)
            } else {
                (adv.severity, Confidence::Likely)
            };
            let tail = if unconfirmed {
                "Upstream has not confirmed branches this old as affected, but they are long out of support."
            } else {
                "Treat it as vulnerable unless the vendor confirms a back-ported fix."
            };
            Some(
                build(sev, conf)
                    .summary(format!("PHP {v} on port {} is on an end-of-life branch. {note} {tail} {}{vendor_note}", f.port, adv.summary)),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::testutil::*;
    use super::*;

    fn run(d: &Device, probes: &ProbeResults) -> Vec<Finding> {
        let db = AdvisoryDb::embedded();
        Php2Shell.evaluate(&input(d, probes, &db, "2026-10-24"))
    }

    #[test]
    fn vulnerable_upstream_build_is_likely_critical() {
        let d = device_with_http(80, Some("nginx"), Some("PHP/8.2.30"), &[], "");
        let f = run(&d, &ProbeResults::default());
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Critical);
        assert_eq!(f[0].confidence, Confidence::Likely);
        assert_eq!(f[0].port, Some(80));
        assert!(f[0].cves.contains(&"CVE-2026-109618".to_string()));
        assert!(f[0].summary.contains("8.2.35"));
        assert!(f[0].remediation.contains("8.2.35"));
    }

    #[test]
    fn patched_versions_are_clean() {
        for v in ["8.2.35", "8.3.36", "8.4.27", "8.5.12", "8.5.13"] {
            let d = device_with_http(80, None, Some(&format!("PHP/{v}")), &[], "");
            assert!(run(&d, &ProbeResults::default()).is_empty(), "{v}");
        }
    }

    #[test]
    fn distro_build_is_downgraded_to_possible() {
        let d = device_with_http(80, Some("Apache/2.4.58 (Ubuntu)"), Some("PHP/8.3.6-0ubuntu0.24.04.12"), &[], "");
        let f = run(&d, &ProbeResults::default());
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].confidence, Confidence::Possible);
        assert_eq!(f[0].severity, Severity::Critical, "severity is what it would be if real");
        assert!(f[0].summary.contains("back-port"));
    }

    #[test]
    fn eol_branch_flagged() {
        let d = device_with_http(8080, None, Some("PHP/7.4.33"), &[], "");
        let f = run(&d, &ProbeResults::default());
        assert_eq!(f[0].severity, Severity::Critical);
        assert_eq!(f[0].confidence, Confidence::Likely);
        assert!(f[0].summary.contains("end-of-life"));
    }

    #[test]
    fn ancient_branch_is_only_possible() {
        let d = device_with_http(80, None, Some("PHP/5.6.40"), &[], "");
        let f = run(&d, &ProbeResults::default());
        assert_eq!(f[0].confidence, Confidence::Possible);
        assert_eq!(f[0].severity, Severity::Medium);
    }

    #[test]
    fn hidden_version_is_possible_and_asks_for_active() {
        let d = device_with_http(80, Some("nginx"), None, &["PHPSESSID"], "");
        let (db, probes) = (AdvisoryDb::embedded(), ProbeResults::default());
        let mut inp = input(&d, &probes, &db, "2026-10-24");
        inp.active = false;
        let f = Php2Shell.evaluate(&inp);
        assert_eq!(f[0].confidence, Confidence::Possible);
        assert!(f[0].summary.contains("--active"));
    }

    #[test]
    fn phpinfo_probe_reveals_hidden_version() {
        let d = device_with_http(80, Some("nginx"), None, &["PHPSESSID"], "");
        let mut probes = ProbeResults::default();
        let page = "<h1 class=\"p\">PHP Version 8.2.30</h1> phpinfo() Zend Engine <td class=\"e\">Server API </td><td class=\"v\">FPM/FastCGI </td>";
        probes.insert(
            ProbeKind::http_get(80, "/phpinfo.php"),
            Ok(ProbeData::Http { status: 200, headers: vec![], body: page.into(), tls: false }),
        );
        let f = run(&d, &probes);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].confidence, Confidence::Likely);
        assert!(f[0].evidence.iter().any(|e| e.contains("phpinfo")));
        assert!(f[0].evidence.iter().any(|e| e.contains("FPM/FastCGI")));
    }

    #[test]
    fn not_php_means_no_findings() {
        let d = device_with_http(80, Some("lighttpd/1.4.55"), None, &["sid"], "<html></html>");
        assert!(run(&d, &ProbeResults::default()).is_empty());
    }

    #[test]
    fn probes_only_when_version_hidden() {
        let db = AdvisoryDb::embedded();
        let hidden = device_with_http(80, None, None, &["PHPSESSID"], "");
        assert_eq!(Php2Shell.probes(&hidden, &db).len(), PHPINFO_PATHS.len());
        let known = device_with_http(80, None, Some("PHP/8.2.30"), &[], "");
        assert!(Php2Shell.probes(&known, &db).is_empty());
        let none = device_with_http(80, Some("nginx"), None, &[], "");
        assert!(Php2Shell.probes(&none, &db).is_empty());
        assert!(Php2Shell.probes(&hidden, &db).iter().all(|p| p.intrusive));
    }

    #[test]
    fn prerelease_ignored() {
        let d = device_with_http(80, None, Some("PHP/8.2.0RC1"), &[], "");
        assert!(run(&d, &ProbeResults::default()).is_empty());
    }

    #[test]
    fn multiple_ports_give_multiple_findings() {
        let mut d = device_with_http(80, None, Some("PHP/8.2.30"), &[], "");
        let second = device_with_http(8080, None, Some("PHP/8.3.20"), &[], "");
        d.services.extend(second.services);
        let f = run(&d, &ProbeResults::default());
        assert_eq!(f.len(), 2);
    }
}
