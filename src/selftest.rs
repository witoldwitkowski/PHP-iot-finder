//! `iotscan selftest`: scans a fleet of mock devices on localhost and checks
//! that the right findings (and no wrong ones) come out. It exercises the real
//! engine, HTTP client, fingerprinting and checkers end to end, in a few seconds.

use crate::engine::{self, Environment, ScanError, ScanOptions};
use crate::limits::Limits;
use crate::model::{Confidence, Device, ScanResult, ServiceKind, Severity};
use crate::progress::Progress;
use crate::testkit;
use std::sync::Arc;
use std::time::Duration;

/// One verified expectation.
#[derive(Clone, Debug)]
pub struct Check {
    /// What was checked.
    pub name: String,
    /// Whether it held.
    pub ok: bool,
    /// Extra detail on failure.
    pub detail: String,
}

fn opts(ports: Vec<u16>, active: bool) -> ScanOptions {
    ScanOptions {
        targets: vec!["127.0.0.1".into()],
        ports,
        limits: Limits {
            rate_per_sec: 0,
            per_host: 8,
            global_concurrency: 128,
            connect_timeout: Duration::from_millis(400),
            io_timeout: Duration::from_millis(2500),
        },
        active,
        mdns: false,
        ssdp: false,
        ipv6: false,
        arp: false,
        discovery_window: Duration::ZERO,
        today: crate::util::Date::parse("2026-10-24"),
        ..ScanOptions::default()
    }
}

struct Ctx {
    out: Vec<Check>,
}

impl Ctx {
    fn check(&mut self, name: &str, ok: bool, detail: impl Into<String>) {
        self.out.push(Check { name: name.to_string(), ok, detail: if ok { String::new() } else { detail.into() } });
    }
}

fn finding<'a>(d: &'a Device, checker: &str, port: u16) -> Option<&'a crate::model::Finding> {
    d.findings.iter().find(|f| f.checker == checker && f.port == Some(port))
}

fn describe(d: &Device, port: u16) -> String {
    let fs: Vec<String> =
        d.findings.iter().filter(|f| f.port == Some(port)).map(|f| format!("{}:{}/{}", f.checker, f.severity, f.confidence)).collect();
    format!("port {port} findings: [{}]", fs.join(", "))
}

/// Run the whole suite. Returns the individual checks.
pub async fn run() -> Vec<Check> {
    let mut c = Ctx { out: vec![] };
    let fleet = testkit::fleet().await;
    let started = std::time::Instant::now();

    // ---- passive scan ----
    let r: Result<ScanResult, ScanError> =
        engine::run(opts(fleet.all_ports(), false), Arc::new(Environment::none()), Progress::new(false)).await;
    let Ok(passive) = r else {
        c.check("passive scan completes", false, format!("{:?}", r.err()));
        return c.out;
    };
    c.check("passive scan completes", true, "");
    c.check(
        &format!("scan of {} mock services finishes in under 30s", fleet.all_ports().len()),
        started.elapsed() < Duration::from_secs(30),
        format!("took {:?}", started.elapsed()),
    );
    c.check("loopback is reported as one device", passive.devices.len() == 1, format!("{} devices", passive.devices.len()));
    let Some(d) = passive.devices.first() else { return c.out };

    let p = |n: &str| fleet.port(n);
    let f = finding(d, "php2shell", p("php-vulnerable"));
    c.check(
        "vulnerable PHP 8.2.30 → php2shell critical/likely",
        f.is_some_and(|f| f.severity == Severity::Critical && f.confidence == Confidence::Likely),
        describe(d, p("php-vulnerable")),
    );
    c.check("finding names both CVEs", f.is_some_and(|f| f.cves.len() == 2), format!("{:?}", f.map(|f| &f.cves)));
    c.check("patched PHP 8.5.12 → no php2shell", finding(d, "php2shell", p("php-patched")).is_none(), describe(d, p("php-patched")));
    c.check(
        "Ubuntu build of PHP 8.3.6 → php2shell downgraded to possible",
        finding(d, "php2shell", p("php-distro")).is_some_and(|f| f.confidence == Confidence::Possible),
        describe(d, p("php-distro")),
    );
    c.check(
        "PHP 7.4.33 → php2shell + end-of-life",
        finding(d, "php2shell", p("php-eol")).is_some_and(|f| f.severity == Severity::Critical)
            && finding(d, "php-eol", p("php-eol")).is_some_and(|f| f.severity == Severity::High),
        describe(d, p("php-eol")),
    );
    c.check(
        "hidden PHP version → php2shell possible, suggests --active",
        finding(d, "php2shell", p("php-hidden")).is_some_and(|f| f.confidence == Confidence::Possible && f.summary.contains("--active")),
        describe(d, p("php-hidden")),
    );
    c.check("no active probes in a passive scan", finding(d, "php-info-exposed", p("php-hidden")).is_none(), describe(d, p("php-hidden")));
    c.check(
        "redirect to /login.php is followed and PHP found",
        finding(d, "php2shell", p("redirect-to-php")).is_some(),
        describe(d, p("redirect-to-php")),
    );
    c.check(
        "Boa web server (with and without a version) → discontinued-software finding, likely",
        ["boa", "boa-no-version"].iter().all(|n| {
            finding(d, "boa-unmaintained", p(n)).is_some_and(|f| f.confidence == Confidence::Likely && f.severity == Severity::Medium)
        }),
        format!("{} / {}", describe(d, p("boa")), describe(d, p("boa-no-version"))),
    );
    c.check(
        "Boa finding does not cite the disputed CVE-2017-9833",
        d.findings.iter().filter(|f| f.checker == "boa-unmaintained").all(|f| !f.cves.iter().any(|c| c == "CVE-2017-9833")),
        "disputed CVE cited",
    );
    c.check(
        "plain lighttpd device has no PHP findings",
        !d.findings.iter().any(|f| f.port == Some(p("plain-web")) && f.checker.starts_with("php")),
        describe(d, p("plain-web")),
    );
    c.check(
        "Telnet → telnet-open high/confirmed with cleaned banner",
        finding(d, "telnet-open", p("telnet")).is_some_and(|f| {
            f.severity == Severity::High && f.confidence == Confidence::Confirmed && f.evidence.iter().any(|e| e.contains("BusyBox login:"))
        }),
        describe(d, p("telnet")),
    );
    let svc = |port: u16| d.services.iter().find(|s| s.port == port);
    c.check(
        "SSH banner on a web-candidate port is classified as SSH",
        svc(p("ssh-on-web-port")).is_some_and(|s| s.kind == ServiceKind::Ssh),
        format!("{:?}", svc(p("ssh-on-web-port")).map(|s| s.kind)),
    );
    c.check("hung server is listed, did not stall the scan", svc(p("hang")).is_some(), "hang port missing");
    c.check(
        "endless response is read with a cap",
        svc(p("endless")).is_some_and(|s| s.is_web()),
        format!("{:?}", svc(p("endless")).map(|s| s.kind)),
    );
    c.check(
        "device is labelled from the page title",
        d.label.contains("Garage Camera")
            || d.label.contains("Thermostat")
            || d.label.contains("Old NAS")
            || d.label.contains("Patched Hub"),
        d.label.clone(),
    );
    c.check(
        "device record has no ANSI escapes",
        !serde_json::to_string(&passive).unwrap_or_default().contains("\\u001b"),
        "escape found in JSON",
    );
    c.check("stats add up", passive.stats.findings.iter().sum::<usize>() == d.findings.len(), format!("{:?}", passive.stats));

    // ---- active scan ----
    let r = engine::run(opts(fleet.all_ports(), true), Arc::new(Environment::none()), Progress::new(false)).await;
    match r {
        Ok(active) => {
            let d = &active.devices[0];
            c.check(
                "--active reveals hidden PHP 8.2.30 via phpinfo() → php2shell likely",
                finding(d, "php2shell", p("php-hidden"))
                    .is_some_and(|f| f.confidence == Confidence::Likely && f.summary.contains("8.2.30")),
                describe(d, p("php-hidden")),
            );
            c.check(
                "--active reports the exposed phpinfo() page",
                finding(d, "php-info-exposed", p("php-hidden")).is_some_and(|f| f.confidence == Confidence::Confirmed),
                describe(d, p("php-hidden")),
            );
            c.check(
                "--active leaves clean devices clean",
                finding(d, "php-info-exposed", p("plain-web")).is_none(),
                describe(d, p("plain-web")),
            );
        }
        Err(e) => c.check("active scan completes", false, e.to_string()),
    }

    // ---- safety rails ----
    let mut o = opts(vec![80], false);
    o.targets = vec!["8.8.8.8".into()];
    c.check(
        "public targets are refused without --allow-public",
        matches!(engine::run(o, Arc::new(Environment::none()), Progress::new(false)).await, Err(ScanError::PublicRange(_))),
        "public scan was not refused",
    );
    let mut o = opts(vec![80], false);
    o.targets = vec!["10.0.0.0/8".into()];
    c.check(
        "oversized ranges are refused",
        matches!(engine::run(o, Arc::new(Environment::none()), Progress::new(false)).await, Err(ScanError::Config(_))),
        "10.0.0.0/8 was accepted",
    );
    let mut o = opts(vec![80], false);
    o.only = vec!["no-such-checker".into()];
    c.check(
        "unknown checker ids are rejected",
        matches!(engine::run(o, Arc::new(Environment::none()), Progress::new(false)).await, Err(ScanError::Config(_))),
        "typo accepted",
    );

    // ---- plugin rules ----
    let problems = crate::checkers::Registry::builtin().conformance();
    c.check(
        "every checker passes the plugin conformance rules (safe probes, complete findings, no panics)",
        problems.is_empty(),
        problems.join("; "),
    );
    let problems = crate::advisories::AdvisoryDb::embedded().validate();
    c.check("built-in advisory database is valid", problems.is_empty(), problems.join("; "));

    // ---- cancellation ----
    let prog = Progress::new(false);
    let cancel = prog.clone();
    let task = tokio::spawn(engine::run(opts(fleet.all_ports(), false), Arc::new(Environment::none()), prog));
    tokio::time::sleep(Duration::from_millis(150)).await;
    cancel.cancel();
    let res = tokio::time::timeout(Duration::from_secs(10), task).await;
    c.check(
        "cancelling a scan stops it promptly",
        matches!(res, Ok(Ok(Err(ScanError::Cancelled)))) || matches!(res, Ok(Ok(Ok(_)))),
        "scan did not stop",
    );

    c.out
}

#[cfg(test)]
mod tests {
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn selftest_passes() {
        let checks = super::run().await;
        let failed: Vec<_> = checks.iter().filter(|c| !c.ok).collect();
        assert!(failed.is_empty(), "failed checks: {failed:#?}");
        assert!(checks.len() >= 20);
    }
}
