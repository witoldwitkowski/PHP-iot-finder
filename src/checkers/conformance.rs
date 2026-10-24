//! Conformance rules for checkers (plugins).
//!
//! Every checker, built in or written later (for example by an agent from a CVE),
//! must pass [`check`]. It is the automatic gatekeeper behind iotscan's safety
//! promises:
//!
//! * a checker never panics or hangs, whatever a device sends;
//! * the requests it asks for are small, well-formed, and *read-only*: anything
//!   beyond `GET /` or listening on a port is flagged `intrusive` (needs `--active`);
//! * requests contain nothing that looks like an exploit payload (path traversal,
//!   shell metacharacters, command or SQL injection, long overflow-style runs);
//! * findings are complete (title, summary, remediation), safe to print, and refer
//!   to ports the device really has;
//! * evaluation is deterministic.
//!
//! The payload check is a heuristic tripwire, not a proof: it exists to stop a
//! well-meaning mistake, and to make a human look at anything unusual.
//! See `docs/WRITING_CHECKERS.md`.

use super::*;
use crate::model::{HttpInfo, MdnsService, Service, ServiceKind, SsdpInfo};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::{Duration, Instant};

/// Longest a single `evaluate` or `probes` call may take.
pub const MAX_CALL: Duration = Duration::from_millis(1000);
/// Longest payload a probe may send.
pub const MAX_PAYLOAD: usize = 1400;

/// Substrings that must not appear in probe paths or payloads.
const SUSPICIOUS: &[(&str, &str)] = &[
    ("../", "path traversal"),
    ("..\\", "path traversal"),
    ("%2e%2e", "encoded path traversal"),
    ("%252e", "double-encoded traversal"),
    ("%00", "NUL injection"),
    ("\0", "NUL byte"),
    (";", "command separator"),
    ("|", "pipe"),
    ("`", "backtick"),
    ("$(", "command substitution"),
    ("&&", "command chaining"),
    ("<script", "script injection"),
    ("' or ", "SQL injection"),
    ("union select", "SQL injection"),
    ("cmd=", "command parameter"),
    ("exec(", "code execution"),
    ("system(", "code execution"),
    ("eval(", "code execution"),
    ("/bin/sh", "shell"),
    ("/bin/bash", "shell"),
    ("wget ", "download-and-run"),
    ("curl ", "download-and-run"),
    ("nc -e", "reverse shell"),
    ("passwd", "credential file"),
    ("shadow", "credential file"),
    ("${", "template/JNDI injection"),
    ("jndi:", "JNDI injection"),
];

/// Returns why `s` looks like an exploit payload, if it does. Used for URL paths and other text.
pub fn suspicious(s: &str) -> Option<&'static str> {
    let l = s.to_ascii_lowercase();
    SUSPICIOUS.iter().find(|(needle, _)| l.contains(needle)).map(|(_, why)| *why)
}

/// Like [`suspicious`] for TCP/UDP payloads. Text-like payloads get the full list; binary payloads
/// (MQTT, SNMP, …) legitimately contain NUL bytes and stray `;` or `|`, so only multi-character
/// exploit signatures apply to them.
pub fn suspicious_payload(b: &[u8]) -> Option<&'static str> {
    let printable = b.iter().filter(|&&x| x == b'\t' || x == b'\r' || x == b'\n' || (0x20..0x7f).contains(&x)).count();
    let text_like = !b.is_empty() && printable * 100 >= b.len() * 85;
    let l = String::from_utf8_lossy(b).to_ascii_lowercase();
    SUSPICIOUS
        .iter()
        .filter(|(needle, _)| *needle != "\0" && (text_like || needle.len() >= 3))
        .find(|(needle, _)| l.contains(needle))
        .map(|(_, why)| *why)
}

fn longest_run(b: &[u8]) -> usize {
    let (mut best, mut cur) = (0, 0);
    let mut prev = None;
    for &x in b {
        if Some(x) == prev {
            cur += 1;
        } else {
            cur = 1;
            prev = Some(x);
        }
        best = best.max(cur);
    }
    best
}

fn kebab(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 48
        && s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && !s.starts_with('-')
        && !s.ends_with('-')
}

fn has_control(s: &str) -> bool {
    s.chars().any(|c| c.is_control() || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'))
}

fn cve_ok(c: &str) -> bool {
    let Some(rest) = c.strip_prefix("CVE-") else { return false };
    let mut it = rest.split('-');
    let (y, n) = (it.next().unwrap_or(""), it.next().unwrap_or(""));
    it.next().is_none() && y.len() == 4 && y.chars().all(|c| c.is_ascii_digit()) && n.len() >= 4 && n.chars().all(|c| c.is_ascii_digit())
}

/// Problems with one probe request.
pub fn check_probe(p: &Probe) -> Vec<String> {
    let mut out = Vec::new();
    match &p.kind {
        ProbeKind::Http { port, path, .. } => {
            if *port == 0 {
                out.push("HTTP probe to port 0".into());
            }
            if !path.starts_with('/') || path.len() > 512 || path.contains(char::is_whitespace) || has_control(path) {
                out.push(format!(
                    "HTTP probe path {path:?} must start with '/', be at most 512 bytes, and contain no whitespace or control characters"
                ));
            }
            if let Some(why) = suspicious(path) {
                out.push(format!("HTTP probe path {path:?} looks like an exploit payload ({why})"));
            }
            if path != "/" && !p.intrusive {
                out.push(format!("HTTP probe for {path:?} must be Probe::active (only `GET /` may run without --active)"));
            }
        }
        ProbeKind::Tcp { port, send } => {
            if *port == 0 {
                out.push("TCP probe to port 0".into());
            }
            if !send.is_empty() && !p.intrusive {
                out.push("a TCP probe that sends data must be Probe::active".into());
            }
            out.extend(check_payload("TCP", send));
        }
        ProbeKind::Udp { port, payload } => {
            if *port == 0 {
                out.push("UDP probe to port 0".into());
            }
            if !p.intrusive {
                out.push("UDP probes must be Probe::active (they send unsolicited datagrams)".into());
            }
            if payload.is_empty() {
                out.push("empty UDP payload".into());
            }
            out.extend(check_payload("UDP", payload));
        }
    }
    out
}

fn check_payload(proto: &str, b: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    if b.len() > MAX_PAYLOAD {
        out.push(format!("{proto} payload is {} bytes; the limit is {MAX_PAYLOAD}", b.len()));
    }
    if longest_run(b) >= 64 {
        out.push(format!("{proto} payload contains a run of {} identical bytes (looks like a buffer-overflow pattern)", longest_run(b)));
    }
    if let Some(why) = suspicious_payload(b) {
        out.push(format!("{proto} payload looks like an exploit payload ({why})"));
    }
    out
}

/// Problems with one finding.
pub fn check_finding(meta: &CheckerMeta, dev: &Device, f: &Finding) -> Vec<String> {
    let mut out = Vec::new();
    let tag = format!("finding '{}'", f.title);
    if !kebab(&f.checker) {
        out.push(format!("{tag}: checker id {:?} must be lowercase kebab-case", f.checker));
    }
    if f.title.trim().is_empty() || f.title.len() > 140 {
        out.push(format!("{tag}: title must be 1-140 characters"));
    }
    if f.summary.trim().is_empty() {
        out.push(format!("{tag}: summary is empty"));
    }
    if f.severity >= crate::model::Severity::Low && f.remediation.trim().is_empty() {
        out.push(format!("{tag}: findings of severity low or higher need remediation advice"));
    }
    if f.evidence.len() > 24 || f.evidence.iter().any(|e| e.chars().count() > 600) {
        out.push(format!("{tag}: at most 24 evidence lines of 600 characters"));
    }
    for (name, text) in [("title", &f.title), ("summary", &f.summary), ("remediation", &f.remediation)] {
        if has_control(text) {
            out.push(format!("{tag}: {name} contains control characters"));
        }
    }
    if f.evidence.iter().any(|e| has_control(e)) {
        out.push(format!("{tag}: evidence contains control characters (untrusted device text must be sanitised)"));
    }
    for r in &f.references {
        if !(r.starts_with("https://") || r.starts_with("http://")) || has_control(r) {
            out.push(format!("{tag}: reference {r:?} must be an http(s) URL"));
        }
    }
    for c in &f.cves {
        if !cve_ok(c) {
            out.push(format!("{tag}: {c:?} is not a CVE id like CVE-2026-12345"));
        }
    }
    if let Some(p) = f.port
        && !dev.services.iter().any(|s| s.port == p)
    {
        out.push(format!("{tag}: refers to port {p}, which the device does not have open"));
    }
    if f.suppressed.is_some() {
        out.push(format!("{tag}: checkers must not set `suppressed` (the allowlist does)"));
    }
    if f.checker != meta.id && !kebab(&f.checker) {
        out.push(format!("{tag}: checker id {:?} differs from the checker's id {:?} and is not valid", f.checker, meta.id));
    }
    out
}

fn svc(port: u16, kind: ServiceKind, http: Option<HttpInfo>, banner: Option<&str>) -> Service {
    Service { port, kind, banner: banner.map(String::from), http, note: None }
}

/// Devices used for conformance: the demo network plus deliberately nasty ones.
pub fn sample_devices() -> Vec<Device> {
    let mut v: Vec<Device> = crate::demo::scans().0.devices;
    let big = "A".repeat(20_000);
    let uni = "é€😀".repeat(2_000);
    let weird = "PHP Version 99999999999999999999 phpinfo() Zend Server API <td class=\"v\"></td> \u{0}\u{1b}[2J \r\n";

    let mut hostile = Device::new("192.168.1.250".parse().expect("ip"));
    hostile.mac = Some(uni.clone());
    hostile.vendor = Some(big.clone());
    hostile.hostname = Some("\u{0}\u{1b}[31m".into());
    for (i, port) in [80u16, 443, 8080, 65535].into_iter().enumerate() {
        let http = HttpInfo {
            tls: port == 443,
            tls_version: Some(big.clone()),
            status: [200, 302, 500, 0][i],
            path: format!("/{big}"),
            server: Some(match i {
                0 => big.clone(),
                1 => uni.clone(),
                2 => "PHP/99999999999.1.1 (Ubuntu) Apache/".to_string(),
                _ => String::new(),
            }),
            powered_by: Some(match i {
                0 => format!("PHP/{}", "9".repeat(50)),
                1 => "PHP/".into(),
                2 => "PHP/7.4.33-1+deb11u1\u{0}".into(),
                _ => "PHP".into(),
            }),
            title: Some(uni.clone()),
            location: Some(format!("http://{big}/")),
            cookie_names: vec!["PHPSESSID".into(), big.clone()],
            headers: vec![("Server".into(), big.clone()), (big.clone(), String::new()), (String::new(), uni.clone())],
            body: format!("{weird}{big}{uni}<a href=\"x.php\">"),
        };
        hostile.services.push(svc(port, if port == 443 { ServiceKind::Https } else { ServiceKind::Http }, Some(http), None));
    }
    for (port, kind, banner) in [
        (21u16, ServiceKind::Ftp, Some("")),
        (22, ServiceKind::Ssh, Some("SSH-\u{0}")),
        (23, ServiceKind::Telnet, Some(big.as_str())),
        (554, ServiceKind::Rtsp, None),
        (1883, ServiceKind::Mqtt, Some(uni.as_str())),
        (9999, ServiceKind::Other, Some("\u{1b}[2J")),
    ] {
        hostile.services.push(svc(port, kind, None, banner));
    }
    hostile.mdns.push(MdnsService { instance: uni.clone(), service: big.clone(), port: 0, txt: vec![big.clone(); 50] });
    hostile.ssdp = Some(SsdpInfo {
        server: Some(big.clone()),
        targets: vec![uni.clone(); 30],
        friendly_name: Some(String::new()),
        manufacturer: Some(big.clone()),
        model: Some(uni),
        model_number: None,
    });
    v.push(hostile);

    v.push(Device::new("10.0.0.1".parse().expect("ip")));
    let mut v6 = Device::new("fe80::1".parse().expect("ip"));
    v6.services.push(svc(
        80,
        ServiceKind::Http,
        Some(HttpInfo { status: 200, powered_by: Some("PHP/7.4.33".into()), ..HttpInfo::default() }),
        None,
    ));
    v.push(v6);
    v
}

fn timed<T>(f: impl FnOnce() -> T) -> Result<(T, Duration), String> {
    let t = Instant::now();
    catch_unwind(AssertUnwindSafe(f)).map(|r| (r, t.elapsed())).map_err(|_| "panicked".to_string())
}

/// Plausible and hostile results for the probes a checker asked for.
fn probe_variants(probes: &[Probe]) -> Vec<ProbeResults> {
    let big = "B".repeat(300_000);
    let nasty = "phpinfo() PHP Version 8.2.30 Zend <h1>\u{0}\u{1b}[2J\u{202e}é€😀 ".repeat(50);
    let mut out = vec![ProbeResults::default()];
    let make = |f: &dyn Fn(&ProbeKind) -> Result<ProbeData, String>| {
        let mut r = ProbeResults::default();
        for p in probes {
            r.insert(p.kind.clone(), f(&p.kind));
        }
        r
    };
    let http = |status: u16, body: &str| ProbeData::Http {
        status,
        headers: vec![("Server".into(), "x".into())],
        body: body.to_string(),
        tls: false,
    };
    out.push(make(&|k| Ok(if matches!(k, ProbeKind::Http { .. }) { http(200, &big) } else { ProbeData::Bytes(vec![0xff; 1024]) })));
    out.push(make(&|k| Ok(if matches!(k, ProbeKind::Http { .. }) { http(200, "") } else { ProbeData::Bytes(vec![]) })));
    out.push(make(&|k| {
        Ok(if matches!(k, ProbeKind::Http { .. }) { http(200, &nasty) } else { ProbeData::Bytes(nasty.as_bytes()[..200].to_vec()) })
    }));
    out.push(make(&|k| Ok(if matches!(k, ProbeKind::Http { .. }) { http(500, "error") } else { ProbeData::Bytes(b"\0\0\0".to_vec()) })));
    out.push(make(&|_| Err("timed out".into())));
    out
}

/// Check one checker against the conformance rules. An empty list means it conforms.
pub fn check(c: &dyn Checker) -> Vec<String> {
    let mut problems: Vec<String> = Vec::new();
    let meta = c.meta();
    let id = meta.id;
    let mut add = |p: String| {
        if problems.len() < 40 {
            problems.push(format!("[{id}] {p}"));
        }
    };

    if !kebab(id) {
        add(format!("id {id:?} must be lowercase kebab-case (a-z, 0-9, -), at most 48 characters"));
    }
    if meta.name.trim().is_empty() || meta.description.trim().is_empty() {
        add("name and description must not be empty".into());
    }
    match timed(|| c.needs()) {
        Ok((needs, _)) => {
            for n in needs {
                if matches!(n, Need::Port(0) | Need::Banner(0)) {
                    add("Need on port 0".into());
                }
            }
        }
        Err(e) => add(format!("needs() {e}")),
    }

    let db = AdvisoryDb::embedded();
    let today = Date::parse("2026-10-24").expect("valid date");
    let mut saw_intrusive = false;

    for dev in sample_devices() {
        let who = dev.ip.to_string();
        let probes = match timed(|| c.probes(&dev, &db)) {
            Ok((p, took)) => {
                if took > MAX_CALL {
                    add(format!("probes() took {took:?} on {who}; the limit is {MAX_CALL:?}"));
                    return problems;
                }
                p
            }
            Err(e) => {
                add(format!("probes() {e} on {who}"));
                continue;
            }
        };
        if probes.len() > 64 {
            add(format!("probes() returned {} probes for one device; the limit is 64", probes.len()));
        }
        for p in &probes {
            saw_intrusive |= p.intrusive;
            for m in check_probe(p) {
                add(m);
            }
        }
        if !meta.uses_active_probes && probes.iter().any(|p| p.intrusive) {
            add("returns active probes but meta.uses_active_probes is false".into());
        }

        for (vi, results) in probe_variants(&probes).into_iter().enumerate() {
            let input = CheckInput { device: &dev, probes: &results, db: &db, today, active: true };
            match timed(|| c.evaluate(&input)) {
                Ok((findings, took)) => {
                    if took > MAX_CALL {
                        add(format!("evaluate() took {took:?} on {who} (probe variant {vi}); the limit is {MAX_CALL:?}"));
                        return problems;
                    }
                    for f in &findings {
                        for m in check_finding(&meta, &dev, f) {
                            add(format!("on {who}: {m}"));
                        }
                    }
                    match timed(|| c.evaluate(&input)) {
                        Ok((again, _)) if again != findings => add(format!("evaluate() is not deterministic on {who}")),
                        Err(e) => add(format!("evaluate() {e} on second call")),
                        _ => {}
                    }
                }
                Err(e) => add(format!("evaluate() {e} on {who} (probe variant {vi})")),
            }
        }
    }
    let _ = saw_intrusive;
    problems
}

impl Registry {
    /// Run the conformance rules over every checker in the registry.
    pub fn conformance(&self) -> Vec<String> {
        self.checkers.iter().flat_map(|c| check(c.as_ref())).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Severity;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn every_builtin_checker_conforms() {
        let problems = Registry::builtin().conformance();
        assert!(problems.is_empty(), "{problems:#?}");
    }

    #[test]
    fn sample_devices_are_diverse() {
        let d = sample_devices();
        assert!(d.len() >= 18);
        assert!(d.iter().any(|d| d.ip.is_ipv6()));
        assert!(d.iter().any(|d| d.services.is_empty()));
    }

    // ---- negative tests: each bad plugin must be caught ----

    struct Bad {
        id: &'static str,
        probes: Vec<Probe>,
        findings: fn(&Device) -> Vec<Finding>,
        active_meta: bool,
    }
    impl Checker for Bad {
        fn meta(&self) -> CheckerMeta {
            CheckerMeta {
                id: self.id,
                name: "bad",
                description: "bad",
                category: Category::Other,
                tags: &[],
                uses_active_probes: self.active_meta,
            }
        }
        fn probes(&self, _: &Device, _: &AdvisoryDb) -> Vec<Probe> {
            self.probes.clone()
        }
        fn evaluate(&self, i: &CheckInput) -> Vec<Finding> {
            (self.findings)(i.device)
        }
    }
    fn bad(id: &'static str, probes: Vec<Probe>, findings: fn(&Device) -> Vec<Finding>) -> Bad {
        Bad { id, probes, findings, active_meta: true }
    }
    fn none(_: &Device) -> Vec<Finding> {
        vec![]
    }
    fn expect(b: Bad, needle: &str) {
        let p = check(&b);
        assert!(p.iter().any(|m| m.contains(needle)), "expected a problem mentioning {needle:?}, got {p:#?}");
    }

    #[test]
    fn rejects_bad_ids() {
        expect(bad("Bad ID!", vec![], none), "kebab-case");
        expect(bad("", vec![], none), "kebab-case");
    }

    #[test]
    fn rejects_passive_nonroot_http_probe() {
        expect(bad("x-a", vec![Probe::passive(ProbeKind::http_get(80, "/setup.cgi"))], none), "must be Probe::active");
    }

    #[test]
    fn rejects_exploit_looking_requests() {
        for path in ["/cgi-bin/x?cmd=id", "/a;reboot", "/../../etc/x", "/x|id", "/%2e%2e/%2e%2e/etc", "/x`id`", "/${jndi:ldap://a/b}"] {
            expect(bad("x-b", vec![Probe::active(ProbeKind::http_get(80, path))], none), "exploit payload");
        }
        expect(bad("x-c", vec![Probe::active(ProbeKind::http_get(80, "/has space"))], none), "whitespace");
        expect(bad("x-d", vec![Probe::active(ProbeKind::http_get(80, "nolead"))], none), "start with '/'");
    }

    #[test]
    fn rejects_overflow_style_and_oversize_payloads() {
        expect(bad("x-e", vec![Probe::active(ProbeKind::Udp { port: 161, payload: vec![b'A'; 1000] })], none), "buffer-overflow");
        expect(
            bad("x-f", vec![Probe::active(ProbeKind::Tcp { port: 23, send: (0..2000u32).map(|i| i as u8).collect() })], none),
            "limit is 1400",
        );
        expect(
            bad("x-g", vec![Probe::passive(ProbeKind::Udp { port: 161, payload: vec![1, 2, 3] })], none),
            "UDP probes must be Probe::active",
        );
        expect(bad("x-h", vec![Probe::passive(ProbeKind::Tcp { port: 23, send: b"hello".to_vec() })], none), "must be Probe::active");
        expect(bad("x-i", vec![Probe::active(ProbeKind::Tcp { port: 0, send: vec![] })], none), "port 0");
    }

    #[test]
    fn binary_protocol_payloads_are_not_false_positives() {
        // MQTT CONNECT contains NUL bytes; SNMP-like blobs contain stray ';' and '|'.
        let mqtt = crate::checkers::mqtt_exposed::CONNECT.to_vec();
        let snmp =
            vec![0x30, 0x26, 0x02, 0x01, 0x01, 0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', 0xa0, 0x19, 0x3b, 0x7c, 0x00, 0x60, 0x00];
        for payload in [mqtt, snmp] {
            let ok = bad("x-bin", vec![Probe::active(ProbeKind::Tcp { port: 1883, send: payload })], none);
            assert!(check(&ok).is_empty(), "{:#?}", check(&ok));
        }
        // But a text request with shell syntax, or a binary blob carrying an exploit signature, is still caught.
        expect(bad("x-t1", vec![Probe::active(ProbeKind::Tcp { port: 23, send: b"GET /;reboot".to_vec() })], none), "exploit payload");
        let mut blob = vec![0x00, 0x01, 0xff, 0xfe, 0x00];
        blob.extend_from_slice(b"/bin/sh");
        blob.extend_from_slice(&[0x00, 0xff, 0x01, 0x02, 0x00, 0x9f]);
        expect(bad("x-t2", vec![Probe::active(ProbeKind::Udp { port: 161, payload: blob })], none), "shell");
        // NUL stays forbidden in URL paths.
        expect(bad("x-t3", vec![Probe::active(ProbeKind::http_get(80, "/x\0"))], none), "exploit payload");
    }

    #[test]
    fn allows_the_safe_passive_forms() {
        let ok =
            bad("x-j", vec![Probe::passive(ProbeKind::http_get(80, "/")), Probe::passive(ProbeKind::Tcp { port: 23, send: vec![] })], none);
        assert!(check(&ok).is_empty(), "{:#?}", check(&ok));
    }

    #[test]
    fn rejects_meta_that_hides_active_probes() {
        let mut b = bad("x-k", vec![Probe::active(ProbeKind::http_get(80, "/x"))], none);
        b.active_meta = false;
        expect(b, "uses_active_probes");
    }

    #[test]
    fn rejects_incomplete_or_unsafe_findings() {
        expect(bad("x-l", vec![], |_| vec![Finding::new("x-l", "t", Severity::High, Confidence::Likely).summary("s")]), "remediation");
        expect(bad("x-m", vec![], |_| vec![Finding::new("x-m", "t", Severity::Info, Confidence::Likely)]), "summary is empty");
        expect(
            bad("x-n", vec![], |_| vec![Finding::new("x-n", "t", Severity::Info, Confidence::Likely).summary("a\u{1b}[2Jb")]),
            "control characters",
        );
        expect(
            bad("x-o", vec![], |_| {
                vec![Finding::new("x-o", "t", Severity::Info, Confidence::Likely).summary("s").cves(&["CVE-26-1".to_string()])]
            }),
            "not a CVE id",
        );
        expect(
            bad("x-p", vec![], |_| {
                vec![
                    Finding::new("x-p", "t", Severity::Info, Confidence::Likely)
                        .summary("s")
                        .references(&["javascript:alert(1)".to_string()]),
                ]
            }),
            "http(s) URL",
        );
        expect(
            bad("x-q", vec![], |_| vec![Finding::new("x-q", "t", Severity::Info, Confidence::Likely).summary("s").port(31337)]),
            "does not have open",
        );
        expect(
            bad("x-r", vec![], |_| {
                let mut f = Finding::new("x-r", "t", Severity::Info, Confidence::Likely).summary("s");
                f.suppressed = Some("sneaky".into());
                vec![f]
            }),
            "must not set `suppressed`",
        );
    }

    #[test]
    fn rejects_panics_and_nondeterminism_and_slowness() {
        expect(bad("x-s", vec![], |_| panic!("boom")), "panicked");
        static N: AtomicUsize = AtomicUsize::new(0);
        expect(
            bad("x-t", vec![], |_| {
                vec![Finding::new("x-t", format!("t{}", N.fetch_add(1, Ordering::SeqCst)), Severity::Info, Confidence::Likely).summary("s")]
            }),
            "not deterministic",
        );
        expect(
            bad("x-u", vec![], |_| {
                std::thread::sleep(MAX_CALL + Duration::from_millis(200));
                vec![]
            }),
            "evaluate() took",
        );
    }

    #[test]
    fn suspicious_detector_has_no_obvious_false_positives_on_real_probes() {
        for ok in ["/", "/phpinfo.php", "/info.php", "/setup.cgi", "/api/v1/status", "/login.html?lang=en"] {
            assert!(suspicious(ok).is_none(), "{ok}");
        }
    }
}
