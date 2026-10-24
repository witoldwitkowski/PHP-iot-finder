//! The worked example from docs/WRITING_CHECKERS.md, compiled and executed, to prove
//! that a checker written outside the crate works through the public API.

use iotscan::advisories::AdvisoryDb;
use iotscan::checkers::*;
use iotscan::engine::{self, Environment, ScanOptions};
use iotscan::limits::Limits;
use iotscan::model::{Confidence, Device, Finding, Severity};
use iotscan::progress::Progress;
use iotscan::testkit::{self, Route};
use std::sync::Arc;
use std::time::Duration;

pub const ID: &str = "example-camera-default-page";
pub struct ExampleCamera;

impl Checker for ExampleCamera {
    fn meta(&self) -> CheckerMeta {
        CheckerMeta {
            id: ID,
            name: "Example camera setup page exposed",
            description: "The factory setup page is reachable without a password.",
            category: Category::Web,
            tags: &["camera", "default-config"],
            uses_active_probes: true,
        }
    }

    fn needs(&self) -> Vec<Need> {
        vec![Need::Port(8080)]
    }

    fn probes(&self, device: &Device, _db: &AdvisoryDb) -> Vec<Probe> {
        device.services.iter().filter(|s| s.is_web()).map(|s| Probe::active(ProbeKind::http_get(s.port, "/setup.cgi"))).collect()
    }

    fn evaluate(&self, input: &CheckInput) -> Vec<Finding> {
        let mut out = vec![];
        for s in input.web_services() {
            if let Some((200, _headers, body)) = input.probes.http(s.port, "/setup.cgi")
                && body.contains("Camera Setup")
            {
                out.push(
                    Finding::new(ID, "Setup page is open", Severity::High, Confidence::Confirmed)
                        .port(s.port)
                        .summary("The setup page answers without a password.")
                        .evidence("GET /setup.cgi returned the setup page")
                        .remediation("Set an admin password; update the firmware."),
                );
            }
        }
        out
    }
}

fn opts(port: u16, active: bool) -> ScanOptions {
    ScanOptions {
        targets: vec!["127.0.0.1".into()],
        ports: vec![port],
        limits: Limits {
            rate_per_sec: 0,
            connect_timeout: Duration::from_millis(500),
            io_timeout: Duration::from_secs(2),
            ..Limits::default()
        },
        active,
        mdns: false,
        ssdp: false,
        ipv6: false,
        arp: false,
        discovery_window: Duration::ZERO,
        ..ScanOptions::default()
    }
}

#[tokio::test]
async fn external_checker_runs_through_the_engine() {
    let cam = testkit::http(vec![("/", Route::ok("<title>Cam</title>")), ("/setup.cgi", Route::ok("<h1>Camera Setup</h1>"))]).await;
    let reg = || Registry::with(vec![Box::new(ExampleCamera)]);

    // With --active the probe runs and the finding appears.
    let r = engine::run_with(opts(cam.port, true), Arc::new(Environment::none()), Progress::new(false), reg()).await.unwrap();
    let f = &r.devices[0].findings;
    assert_eq!(f.len(), 1, "{f:?}");
    assert_eq!(f[0].checker, ID);
    assert_eq!(f[0].confidence, Confidence::Confirmed);
    assert_eq!(r.summary.checkers, vec![ID]);

    // Without --active the intrusive probe is never made, so the checker stays silent.
    let r = engine::run_with(opts(cam.port, false), Arc::new(Environment::none()), Progress::new(false), reg()).await.unwrap();
    assert!(r.devices[0].findings.is_empty());
}

#[test]
fn the_probe_is_declared_intrusive() {
    let r = Registry::with(vec![Box::new(ExampleCamera)]);
    let db = AdvisoryDb::embedded();
    let mut d = Device::new("10.0.0.1".parse().unwrap());
    d.services.push(iotscan::model::Service { port: 80, kind: iotscan::model::ServiceKind::Http, banner: None, http: None, note: None });
    assert!(r.probes_for(&d, &db, false).is_empty());
    assert_eq!(r.probes_for(&d, &db, true).len(), 1);
    assert!(r.extra_ports().contains(&8080));
}
