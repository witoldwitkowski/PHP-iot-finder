//! The checker framework.
//!
//! A checker is a small, pure judge of evidence. It never touches the network:
//!
//! 1. it *declares* what it needs ([`Checker::needs`]) and which extra requests
//!    it would like made ([`Checker::probes`]),
//! 2. the engine performs those requests under the scan's rate limits, size caps
//!    and safety rules, then
//! 3. it *evaluates* the collected evidence ([`Checker::evaluate`]) into findings.
//!
//! That keeps every checker unit-testable with a hand-built [`Device`], and keeps
//! all I/O (and therefore all the safety logic) in one audited place.
//!
//! See `docs/WRITING_CHECKERS.md` for a step-by-step guide.

pub mod conformance;
pub mod data_advisory;
pub mod mqtt_exposed;
pub mod php2shell;
pub mod php_eol;
pub mod php_info;
pub mod telnet;
pub mod upnp;

use crate::advisories::{Advisory, AdvisoryDb};
use crate::fingerprint::php::{self, PhpFact};
use crate::http::Method;
use crate::model::{Confidence, Device, Finding, Service, ServiceKind};
use crate::util::Date;
use serde::Serialize;
use std::collections::HashMap;

/// Broad grouping used in listings and the GUI.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Category {
    /// Web interface / application flaws.
    Web,
    /// Remote administration protocols (Telnet, SSH, …).
    RemoteAccess,
    /// Exposure and discovery protocols (UPnP, mDNS).
    Exposure,
    /// Software end-of-life and patch status.
    Lifecycle,
    /// Weak or default credentials.
    Credentials,
    /// Anything else.
    Other,
}

/// Static description of a checker.
#[derive(Clone, Debug, Serialize)]
pub struct CheckerMeta {
    /// Stable identifier (`--only`, `--skip`, allowlist, findings).
    pub id: &'static str,
    /// Short display name.
    pub name: &'static str,
    /// One-sentence description.
    pub description: &'static str,
    /// Category.
    pub category: Category,
    /// Free-form tags (`php`, `cve-2026-109618`, `telnet`, …).
    pub tags: &'static [&'static str],
    /// Whether this checker may send extra requests that need `--active`.
    pub uses_active_probes: bool,
}

/// Something a checker needs from the scan before it can judge.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Need {
    /// Add this TCP port to the sweep.
    Port(u16),
    /// Add this TCP port and read a banner from it.
    Banner(u16),
    /// Run SSDP/UPnP discovery.
    Ssdp,
    /// Run mDNS/DNS-SD discovery.
    Mdns,
}

/// A request the engine can make on a checker's behalf.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ProbeKind {
    /// HTTP request to a path on a given port. Only GET/HEAD/OPTIONS exist.
    Http {
        /// Target TCP port.
        port: u16,
        /// Path, starting with `/`.
        path: String,
        /// Method.
        method: Method,
    },
    /// Open a TCP connection, optionally send bytes, read up to 1 KiB.
    Tcp {
        /// Target port.
        port: u16,
        /// Bytes to send first (empty = just listen).
        send: Vec<u8>,
    },
    /// Send one UDP datagram and read one reply.
    Udp {
        /// Target port.
        port: u16,
        /// Datagram payload (max 1400 bytes).
        payload: Vec<u8>,
    },
}

impl ProbeKind {
    /// `GET path` on `port`.
    pub fn http_get(port: u16, path: &str) -> ProbeKind {
        ProbeKind::Http { port, path: path.to_string(), method: Method::Get }
    }
}

/// A probe request plus whether it needs `--active`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Probe {
    /// What to do.
    pub kind: ProbeKind,
    /// True if it goes beyond reading what the device volunteers (extra paths,
    /// payloads). Intrusive probes only run with `--active`.
    pub intrusive: bool,
}

impl Probe {
    /// A probe that only runs with `--active`.
    pub fn active(kind: ProbeKind) -> Probe {
        Probe { kind, intrusive: true }
    }
    /// A probe that is safe to run in every scan.
    pub fn passive(kind: ProbeKind) -> Probe {
        Probe { kind, intrusive: false }
    }
}

/// What a probe returned.
#[derive(Clone, Debug)]
pub enum ProbeData {
    /// HTTP response.
    Http {
        /// Status code.
        status: u16,
        /// Response headers.
        headers: Vec<(String, String)>,
        /// Body (lossy UTF-8, capped).
        body: String,
        /// Whether TLS was used.
        tls: bool,
    },
    /// Raw bytes from TCP/UDP.
    Bytes(Vec<u8>),
}

/// A borrowed view of an HTTP probe result: status, headers, body.
pub type HttpView<'a> = (u16, &'a [(String, String)], &'a str);

/// Results of all executed probes.
#[derive(Clone, Debug, Default)]
pub struct ProbeResults {
    map: HashMap<ProbeKind, Result<ProbeData, String>>,
}

impl ProbeResults {
    /// Record a result.
    pub fn insert(&mut self, k: ProbeKind, r: Result<ProbeData, String>) {
        self.map.insert(k, r);
    }
    /// Whether the probe was executed at all.
    pub fn ran(&self, k: &ProbeKind) -> bool {
        self.map.contains_key(k)
    }
    /// Result of a probe, if it ran.
    pub fn get(&self, k: &ProbeKind) -> Option<&Result<ProbeData, String>> {
        self.map.get(k)
    }
    /// A successful HTTP response for `GET path` on `port`.
    pub fn http(&self, port: u16, path: &str) -> Option<HttpView<'_>> {
        match self.map.get(&ProbeKind::http_get(port, path)) {
            Some(Ok(ProbeData::Http { status, headers, body, .. })) => Some((*status, headers.as_slice(), body.as_str())),
            _ => None,
        }
    }
    /// Bytes returned by a TCP/UDP probe.
    pub fn bytes(&self, k: &ProbeKind) -> Option<&[u8]> {
        match self.map.get(k) {
            Some(Ok(ProbeData::Bytes(b))) => Some(b),
            _ => None,
        }
    }
    /// Number of results.
    pub fn len(&self) -> usize {
        self.map.len()
    }
    /// True when empty.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

/// Everything a checker may look at.
pub struct CheckInput<'a> {
    /// The device under test.
    pub device: &'a Device,
    /// Results of executed probes.
    pub probes: &'a ProbeResults,
    /// Advisory database.
    pub db: &'a AdvisoryDb,
    /// Today's date (injectable for tests).
    pub today: Date,
    /// Whether `--active` probing was enabled.
    pub active: bool,
}

impl CheckInput<'_> {
    /// Web services on the device.
    pub fn web_services(&self) -> impl Iterator<Item = &Service> {
        self.device.services.iter().filter(|s| s.is_web())
    }

    /// Services of a given kind.
    pub fn services_of(&self, kind: ServiceKind) -> impl Iterator<Item = &Service> {
        self.device.services.iter().filter(move |s| s.kind == kind)
    }

    /// PHP evidence per port, including any `phpinfo()` pages found by probes.
    pub fn php_facts(&self) -> Vec<PhpFact> {
        php_facts(self.device, self.probes)
    }
}

/// Paths commonly serving `phpinfo()`.
pub const PHPINFO_PATHS: &[&str] = &["/phpinfo.php", "/info.php", "/php_info.php", "/pi.php", "/i.php", "/test.php"];

/// Collect PHP facts for every web port of a device.
pub fn php_facts(device: &Device, probes: &ProbeResults) -> Vec<PhpFact> {
    let mut out = Vec::new();
    for s in device.services.iter().filter(|s| s.is_web()) {
        let http = s.http.clone().unwrap_or_default();
        let page = PHPINFO_PATHS.iter().find_map(|p| match probes.http(s.port, p) {
            Some((200, _, body)) => php::parse_phpinfo(body),
            _ => None,
        });
        if let Some(mut f) = php::detect(s.port, &http, page.as_ref()) {
            if let Some(p) =
                PHPINFO_PATHS.iter().find(|p| probes.http(s.port, p).is_some_and(|(st, _, b)| st == 200 && php::parse_phpinfo(b).is_some()))
            {
                f.signals.push(format!("phpinfo() served at {p}"));
            }
            out.push(f);
        }
    }
    out
}

/// A security check.
pub trait Checker: Send + Sync {
    /// Static description.
    fn meta(&self) -> CheckerMeta;

    /// Ports, banners and discovery protocols this checker depends on.
    fn needs(&self) -> Vec<Need> {
        vec![]
    }

    /// Extra requests to make for `device`, decided from what is already known
    /// (passive enrichment has finished by the time this is called).
    fn probes(&self, _device: &Device, _db: &AdvisoryDb) -> Vec<Probe> {
        vec![]
    }

    /// Judge the evidence.
    fn evaluate(&self, input: &CheckInput) -> Vec<Finding>;
}

/// The set of enabled checkers.
pub struct Registry {
    checkers: Vec<Box<dyn Checker>>,
}

impl Registry {
    /// Every built-in checker. **Add new checkers here.**
    pub fn builtin() -> Registry {
        Registry {
            checkers: vec![
                Box::new(php2shell::Php2Shell),
                Box::new(php_eol::PhpEol),
                Box::new(php_info::PhpInfoExposed),
                Box::new(telnet::TelnetOpen),
                Box::new(upnp::UpnpExposed),
                Box::new(mqtt_exposed::MqttExposed),
                Box::new(data_advisory::DataAdvisory),
            ],
        }
    }

    /// A registry with exactly these checkers (tests, embedding).
    pub fn with(checkers: Vec<Box<dyn Checker>>) -> Registry {
        Registry { checkers }
    }

    /// Keep only checkers in `only` (if non-empty) and drop those in `skip`.
    /// Unknown ids are an error so typos are not silently ignored.
    pub fn select(mut self, only: &[String], skip: &[String]) -> Result<Registry, String> {
        let known: Vec<&str> = self.checkers.iter().map(|c| c.meta().id).collect();
        for id in only.iter().chain(skip) {
            if !known.contains(&id.as_str()) {
                return Err(format!("unknown checker '{id}'. Known checkers: {}", known.join(", ")));
            }
        }
        self.checkers.retain(|c| {
            let id = c.meta().id;
            (only.is_empty() || only.iter().any(|o| o == id)) && !skip.iter().any(|s| s == id)
        });
        Ok(self)
    }

    /// Metadata of all enabled checkers.
    pub fn list(&self) -> Vec<CheckerMeta> {
        self.checkers.iter().map(|c| c.meta()).collect()
    }

    /// Ids of enabled checkers.
    pub fn ids(&self) -> Vec<String> {
        self.checkers.iter().map(|c| c.meta().id.to_string()).collect()
    }

    /// All declared needs.
    pub fn needs(&self) -> Vec<Need> {
        let mut n: Vec<Need> = self.checkers.iter().flat_map(|c| c.needs()).collect();
        n.sort_by_key(|x| format!("{x:?}"));
        n.dedup();
        n
    }

    /// Extra ports to sweep.
    pub fn extra_ports(&self) -> Vec<u16> {
        let mut p: Vec<u16> = self
            .needs()
            .into_iter()
            .filter_map(|n| match n {
                Need::Port(p) | Need::Banner(p) => Some(p),
                _ => None,
            })
            .collect();
        p.sort_unstable();
        p.dedup();
        p
    }

    /// Ports whose banner must be read.
    pub fn banner_ports(&self) -> Vec<u16> {
        self.needs()
            .into_iter()
            .filter_map(|n| match n {
                Need::Banner(p) => Some(p),
                _ => None,
            })
            .collect()
    }

    /// Whether any checker needs the given discovery protocol.
    pub fn wants(&self, need: Need) -> bool {
        self.needs().contains(&need)
    }

    /// Probes requested for a device (deduplicated). When `active` is false the
    /// intrusive ones are dropped.
    pub fn probes_for(&self, device: &Device, db: &AdvisoryDb, active: bool) -> Vec<Probe> {
        let mut out: Vec<Probe> = Vec::new();
        for c in &self.checkers {
            for p in c.probes(device, db) {
                if (!p.intrusive || active) && !out.iter().any(|o| o.kind == p.kind) {
                    out.push(p);
                }
            }
        }
        out
    }

    /// Run every checker. A panicking checker is contained: it yields an
    /// informational "checker failed" finding instead of aborting the scan.
    pub fn evaluate(&self, input: &CheckInput) -> Vec<Finding> {
        let mut out = Vec::new();
        for c in &self.checkers {
            let meta = c.meta();
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| c.evaluate(input))) {
                Ok(mut f) => {
                    // Backstop for every plugin: nothing a device said may reach a report as a control character.
                    for x in &mut f {
                        x.title = crate::util::scrub(&x.title);
                        x.summary = crate::util::scrub(&x.summary);
                        x.remediation = crate::util::scrub(&x.remediation);
                        x.evidence.truncate(24);
                        x.evidence.iter_mut().for_each(|e| *e = crate::util::truncate(&crate::util::scrub(e), 600));
                    }
                    out.append(&mut f)
                }
                Err(_) => out.push(
                    Finding::new(meta.id, format!("Checker '{}' failed", meta.id), crate::model::Severity::Info, Confidence::Confirmed)
                        .summary("The checker panicked while evaluating this device. The scan continued; please report this."),
                ),
            }
        }
        out.sort_by(|a, b| b.rank().cmp(&a.rank()).then_with(|| a.checker.cmp(&b.checker)).then(a.port.cmp(&b.port)));
        out
    }
}

/// Shared helper: build the common parts of an advisory-derived finding.
pub fn advisory_finding(adv: &Advisory, checker_id: &str, severity: crate::model::Severity, confidence: Confidence) -> Finding {
    let mut f = Finding::new(checker_id, adv.title.clone(), severity, confidence)
        .remediation(adv.remediation.clone())
        .cves(&adv.cves)
        .references(&adv.references);
    if !adv.verified {
        f.evidence.push(UNVERIFIED_NOTE.to_string());
    }
    f
}

/// Added to findings whose advisory data has not been checked against the vendor's own advisory.
pub const UNVERIFIED_NOTE: &str =
    "Note: the advisory's version data is compiled from secondary sources and not yet verified against the vendor's own advisory.";

/// Advice appended to findings whose version evidence may be outdated by back-porting.
pub const BACKPORT_NOTE: &str = "This looks like a distribution or vendor build. Those usually back-port security fixes without changing the version number, so the device may already be patched. Check the package changelog (apt changelog <pkg> | grep CVE, or rpm -q --changelog <pkg>) or the vendor's firmware release notes before treating this as confirmed.";

#[cfg(test)]
pub(crate) mod testutil {
    //! Builders for unit-testing checkers against hand-made devices.
    use super::*;
    use crate::model::HttpInfo;

    pub fn device_with_http(port: u16, server: Option<&str>, powered_by: Option<&str>, cookies: &[&str], body: &str) -> Device {
        let mut d = Device::new("192.168.1.50".parse().unwrap());
        d.services.push(Service {
            port,
            kind: ServiceKind::Http,
            banner: None,
            http: Some(HttpInfo {
                status: 200,
                path: "/".into(),
                server: server.map(Into::into),
                powered_by: powered_by.map(Into::into),
                cookie_names: cookies.iter().map(|s| s.to_string()).collect(),
                body: body.into(),
                ..HttpInfo::default()
            }),
            note: None,
        });
        d
    }

    pub fn input<'a>(d: &'a Device, p: &'a ProbeResults, db: &'a AdvisoryDb, today: &str) -> CheckInput<'a> {
        CheckInput { device: d, probes: p, db, today: Date::parse(today).unwrap(), active: true }
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::*;
    use super::*;

    #[test]
    fn select_validates_ids() {
        assert!(Registry::builtin().select(&["nope".into()], &[]).is_err());
        let r = Registry::builtin().select(&["telnet-open".into()], &[]).unwrap();
        assert_eq!(r.ids(), vec!["telnet-open"]);
        let r = Registry::builtin().select(&[], &["telnet-open".into()]).unwrap();
        assert!(!r.ids().contains(&"telnet-open".to_string()));
    }

    #[test]
    fn needs_drive_port_selection() {
        let r = Registry::builtin();
        assert!(r.extra_ports().contains(&23));
        assert!(r.banner_ports().contains(&23));
        assert!(r.wants(Need::Ssdp));
    }

    #[test]
    fn ids_are_unique_and_kebab() {
        let ids = Registry::builtin().ids();
        let mut u = ids.clone();
        u.sort();
        u.dedup();
        assert_eq!(ids.len(), u.len());
        assert!(ids.iter().all(|i| i.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')));
    }

    #[test]
    fn intrusive_probes_need_active() {
        let r = Registry::builtin();
        let d = device_with_http(80, Some("nginx"), None, &["PHPSESSID"], "");
        let db = AdvisoryDb::embedded();
        assert!(r.probes_for(&d, &db, false).is_empty());
        let active = r.probes_for(&d, &db, true);
        assert!(!active.is_empty());
        assert!(active.iter().all(|p| p.intrusive));
        // Deduplicated.
        for (i, a) in active.iter().enumerate() {
            assert!(!active[i + 1..].iter().any(|b| b.kind == a.kind));
        }
    }

    struct Panicker;
    impl Checker for Panicker {
        fn meta(&self) -> CheckerMeta {
            CheckerMeta { id: "panicker", name: "p", description: "p", category: Category::Other, tags: &[], uses_active_probes: false }
        }
        fn evaluate(&self, _: &CheckInput) -> Vec<Finding> {
            panic!("boom")
        }
    }

    #[test]
    fn panicking_checker_is_contained() {
        let r = Registry::with(vec![Box::new(Panicker), Box::new(telnet::TelnetOpen)]);
        let d = Device::new("10.0.0.1".parse().unwrap());
        let db = AdvisoryDb::embedded();
        let p = ProbeResults::default();
        let f = r.evaluate(&input(&d, &p, &db, "2026-10-24"));
        assert_eq!(f.len(), 1);
        assert!(f[0].title.contains("failed"));
    }
}
