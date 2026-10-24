//! Exposed `phpinfo()` pages: a free reconnaissance gift to attackers (exact
//! PHP version, modules, paths, environment).

use super::*;
use crate::model::Severity;

/// Checker id.
pub const ID: &str = "php-info-exposed";

/// The phpinfo exposure checker.
pub struct PhpInfoExposed;

impl Checker for PhpInfoExposed {
    fn meta(&self) -> CheckerMeta {
        CheckerMeta {
            id: ID,
            name: "Exposed phpinfo() page",
            description: "A reachable phpinfo() page leaks the PHP version, build, paths and environment.",
            category: Category::Web,
            tags: &["php", "information-disclosure"],
            uses_active_probes: true,
        }
    }

    fn probes(&self, device: &Device, _db: &AdvisoryDb) -> Vec<Probe> {
        let mut out = Vec::new();
        for s in device.services.iter().filter(|s| s.is_web()) {
            let http = s.http.clone().unwrap_or_default();
            if php::detect(s.port, &http, None).is_some() {
                for p in PHPINFO_PATHS {
                    out.push(Probe::active(ProbeKind::http_get(s.port, p)));
                }
            }
        }
        out
    }

    fn evaluate(&self, input: &CheckInput) -> Vec<Finding> {
        let mut out = Vec::new();
        for s in input.web_services() {
            for path in PHPINFO_PATHS {
                let Some((200, _, body)) = input.probes.http(s.port, path) else { continue };
                let Some(page) = php::parse_phpinfo(body) else { continue };
                let mut f = Finding::new(ID, "phpinfo() page is publicly reachable", Severity::Medium, Confidence::Confirmed)
                    .port(s.port)
                    .summary(format!(
                        "{path} on port {} serves phpinfo(), revealing PHP {} and the server's configuration to anyone on the network.",
                        s.port, page.version
                    ))
                    .remediation("Delete the phpinfo() file (or restrict it to administrators). On an appliance, check for a firmware update that removes it.")
                    .evidence(format!("GET {path} returned 200 with a phpinfo() page"))
                    .evidence(format!("PHP {}", page.version));
                if let Some(sapi) = page.sapi {
                    f = f.evidence(format!("Server API: {sapi}"));
                }
                out.push(f);
                break; // one finding per port
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::super::testutil::*;
    use super::*;

    const PAGE: &str = "<h1>PHP Version 8.2.30</h1> phpinfo() Zend";

    #[test]
    fn detects_exposed_phpinfo() {
        let d = device_with_http(80, None, Some("PHP/8.2.30"), &[], "");
        let mut p = ProbeResults::default();
        p.insert(ProbeKind::http_get(80, "/info.php"), Ok(ProbeData::Http { status: 200, headers: vec![], body: PAGE.into(), tls: false }));
        let db = AdvisoryDb::embedded();
        let f = PhpInfoExposed.evaluate(&input(&d, &p, &db, "2026-10-24"));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].confidence, Confidence::Confirmed);
        assert_eq!(f[0].port, Some(80));
    }

    #[test]
    fn ignores_404_and_lookalikes() {
        let d = device_with_http(80, None, Some("PHP/8.2.30"), &[], "");
        let mut p = ProbeResults::default();
        p.insert(ProbeKind::http_get(80, "/info.php"), Ok(ProbeData::Http { status: 404, headers: vec![], body: PAGE.into(), tls: false }));
        p.insert(
            ProbeKind::http_get(80, "/phpinfo.php"),
            Ok(ProbeData::Http { status: 200, headers: vec![], body: "<h1>Welcome</h1>".into(), tls: false }),
        );
        p.insert(ProbeKind::http_get(80, "/pi.php"), Err("timed out".into()));
        let db = AdvisoryDb::embedded();
        assert!(PhpInfoExposed.evaluate(&input(&d, &p, &db, "2026-10-24")).is_empty());
    }

    #[test]
    fn probes_require_php_signals() {
        let db = AdvisoryDb::embedded();
        assert!(PhpInfoExposed.probes(&device_with_http(80, Some("nginx"), None, &[], ""), &db).is_empty());
        assert_eq!(PhpInfoExposed.probes(&device_with_http(80, None, Some("PHP/8.2.30"), &[], ""), &db).len(), PHPINFO_PATHS.len());
    }
}
