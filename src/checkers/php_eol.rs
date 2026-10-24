//! End-of-life PHP. Unsupported PHP receives no security fixes at all, which
//! on an IoT device usually means it never will.

use super::*;
use crate::model::Severity;
use crate::version::cmp_branch;

/// Checker id.
pub const ID: &str = "php-eol";

/// Days before end of security support at which we start warning.
pub const WARN_DAYS: i64 = 180;

/// The PHP end-of-life checker.
pub struct PhpEol;

impl Checker for PhpEol {
    fn meta(&self) -> CheckerMeta {
        CheckerMeta {
            id: ID,
            name: "End-of-life PHP",
            description: "PHP branches that no longer receive security fixes, or will soon stop.",
            category: Category::Lifecycle,
            tags: &["php", "eol", "lifecycle"],
            uses_active_probes: false,
        }
    }

    fn evaluate(&self, input: &CheckInput) -> Vec<Finding> {
        input.php_facts().iter().filter_map(|f| assess(f, input.db, input.today)).collect()
    }
}

fn assess(f: &PhpFact, db: &AdvisoryDb, today: Date) -> Option<Finding> {
    let v = f.version.as_ref()?;
    if v.is_prerelease() {
        return None;
    }
    let branch = v.branch();
    let window = db.php_branch(&branch);
    // Unknown branch: older than everything we track = EOL; newer = no opinion.
    let (sec_end, act_end) = match window {
        Some(w) => (w.security_end()?, w.active_end()),
        None if cmp_branch(&branch, "5.6").is_lt() => (Date::parse("2018-12-31")?, None),
        None => return None,
    };
    let vendor = if f.vendor_packaged {
        " Distributions sometimes keep supporting an upstream-EOL branch with their own patches (for example Ubuntu Pro or Debian LTS), so check your vendor."
    } else {
        ""
    };
    let evid = |mut e: Vec<String>| {
        if let Some(src) = &f.version_source {
            e.insert(0, format!("PHP {v} (from {src})"));
        }
        if let Some(h) = &f.vendor_hint {
            e.push(format!("Vendor-packaging hint: {h}"));
        }
        e
    };
    let days_left = sec_end.to_days() - today.to_days();
    let conf = if f.vendor_packaged { Confidence::Possible } else { Confidence::Likely };

    if days_left < 0 {
        let years = (-days_left) as f64 / 365.25;
        return Some(
            Finding::new(ID, format!("PHP {branch} is end-of-life"), Severity::High, conf)
                .port(f.port)
                .summary(format!(
                    "PHP {branch} stopped receiving security fixes on {sec_end} ({years:.1} years ago). Every PHP vulnerability found since stays unpatched.{vendor}"
                ))
                .remediation("Upgrade to a supported PHP branch (see https://www.php.net/supported-versions.php). For an appliance, install the latest firmware or replace the device if the vendor no longer ships updates; until then keep its web interface off untrusted networks.")
                .references(&["https://www.php.net/supported-versions.php".to_string()])
                .tap(|x| x.evidence = evid(vec![format!("Security support ended {sec_end}")])),
        );
    }
    if days_left <= WARN_DAYS {
        return Some(
            Finding::new(ID, format!("PHP {branch} reaches end-of-life soon"), Severity::Low, conf)
                .port(f.port)
                .summary(format!("PHP {branch} receives security fixes only until {sec_end} ({days_left} days from now).{vendor}"))
                .remediation("Plan an upgrade to a newer PHP branch before that date.")
                .references(&["https://www.php.net/supported-versions.php".to_string()])
                .tap(|x| x.evidence = evid(vec![format!("Security support ends {sec_end}")])),
        );
    }
    if let Some(a) = act_end
        && today > a
    {
        return Some(
            Finding::new(ID, format!("PHP {branch} is in security-only support"), Severity::Info, conf)
                .port(f.port)
                .summary(format!("PHP {branch} stopped receiving bug fixes on {a} and gets security fixes only until {sec_end}."))
                .remediation("No action needed yet; plan the next upgrade.")
                .tap(|x| x.evidence = evid(vec![format!("Active support ended {a}")])),
        );
    }
    None
}

/// Tiny builder helper so findings can be finished inline.
trait Tap: Sized {
    fn tap(self, f: impl FnOnce(&mut Self)) -> Self;
}
impl Tap for Finding {
    fn tap(mut self, f: impl FnOnce(&mut Self)) -> Self {
        f(&mut self);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::super::testutil::*;
    use super::*;

    fn run(powered: &str, today: &str) -> Vec<Finding> {
        let d = device_with_http(80, None, Some(powered), &[], "");
        let db = AdvisoryDb::embedded();
        PhpEol.evaluate(&input(&d, &ProbeResults::default(), &db, today))
    }

    #[test]
    fn eol_branches_are_high() {
        for v in ["PHP/5.6.40", "PHP/7.4.33", "PHP/8.0.30", "PHP/8.1.33", "PHP/4.4.9"] {
            let f = run(v, "2026-10-24");
            assert_eq!(f.len(), 1, "{v}");
            assert_eq!(f[0].severity, Severity::High, "{v}");
            assert_eq!(f[0].confidence, Confidence::Likely);
        }
    }

    #[test]
    fn nearing_eol_is_low() {
        let f = run("PHP/8.2.35", "2026-10-24");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Low);
        assert!(f[0].summary.contains("2026-12-31"));
    }

    #[test]
    fn same_version_becomes_eol_after_the_date() {
        let f = run("PHP/8.2.35", "2027-01-02");
        assert_eq!(f[0].severity, Severity::High);
    }

    #[test]
    fn supported_branches_are_clean_or_info() {
        assert!(run("PHP/8.5.12", "2026-10-24").is_empty());
        let f = run("PHP/8.3.36", "2026-10-24");
        assert!(f.is_empty() || f[0].severity == Severity::Info);
        let f = run("PHP/8.4.27", "2026-10-24");
        assert!(f.is_empty() || f[0].severity == Severity::Info);
    }

    #[test]
    fn newer_than_known_branch_is_silent() {
        assert!(run("PHP/9.1.0", "2026-10-24").is_empty());
    }

    #[test]
    fn vendor_build_is_possible() {
        let d = device_with_http(80, Some("Apache/2.4.52 (Ubuntu)"), Some("PHP/8.1.2-1ubuntu2.14"), &[], "");
        let db = AdvisoryDb::embedded();
        let f = PhpEol.evaluate(&input(&d, &ProbeResults::default(), &db, "2026-10-24"));
        assert_eq!(f[0].confidence, Confidence::Possible);
        assert!(f[0].summary.contains("Ubuntu Pro"));
    }

    #[test]
    fn hidden_version_is_silent() {
        let d = device_with_http(80, None, None, &["PHPSESSID"], "");
        let db = AdvisoryDb::embedded();
        assert!(PhpEol.evaluate(&input(&d, &ProbeResults::default(), &db, "2026-10-24")).is_empty());
    }
}
