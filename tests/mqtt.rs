//! MQTT end to end. Kept in its own test binary (its own process) because the broker must sit on the
//! well-known port 1883, which would otherwise show up in every concurrent scan of 127.0.0.1.

use iotscan::engine::{self, Environment, ScanOptions};
use iotscan::limits::Limits;
use iotscan::model::{Confidence, Severity};
use iotscan::progress::Progress;
use iotscan::testkit;
use std::sync::Arc;
use std::time::Duration;

fn opts(active: bool) -> ScanOptions {
    ScanOptions {
        targets: vec!["127.0.0.1".into()],
        ports: vec![1883],
        limits: Limits {
            rate_per_sec: 0,
            per_host: 8,
            global_concurrency: 128,
            connect_timeout: Duration::from_millis(500),
            io_timeout: Duration::from_millis(2000),
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

async fn scan(active: bool) -> iotscan::model::ScanResult {
    engine::run(opts(active), Arc::new(Environment::none()), Progress::new(false)).await.unwrap()
}

/// MQTT is recognised by its well-known port, so this test needs 127.0.0.1:1883; it skips if that is taken.
#[tokio::test]
async fn mqtt_broker_end_to_end() {
    // CONNACK with return code 0: the broker accepts an anonymous CONNECT.
    let Ok(_broker) = testkit::banner_at("127.0.0.1:1883", &[0x20, 0x02, 0x00, 0x00]).await else {
        eprintln!("port 1883 is in use here; skipping");
        return;
    };
    let r = scan(true).await;
    let f = r.devices[0].findings.iter().find(|f| f.checker == "mqtt-exposed").expect("mqtt finding");
    assert_eq!((f.severity, f.confidence), (Severity::High, Confidence::Confirmed));
    // Without --active nothing is sent: only the plain-text finding appears.
    let r = scan(false).await;
    let f = r.devices[0].findings.iter().find(|f| f.checker == "mqtt-exposed").expect("passive mqtt finding");
    assert_eq!(f.severity, Severity::Low);
    assert!(f.summary.contains("--active"));
}
