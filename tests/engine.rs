//! End-to-end engine tests against mock devices: many devices, TLS, IPv6, and hostile behaviour.

use iotscan::allowlist::Allowlist;
use iotscan::engine::{self, Environment, ScanError, ScanOptions};
use iotscan::limits::Limits;
use iotscan::model::{Confidence, ScanResult, ServiceKind, Severity};
use iotscan::progress::Progress;
use iotscan::testkit::{self, Route};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn opts(targets: &[&str], ports: Vec<u16>) -> ScanOptions {
    ScanOptions {
        targets: targets.iter().map(|s| s.to_string()).collect(),
        ports,
        limits: Limits {
            rate_per_sec: 0,
            per_host: 8,
            global_concurrency: 128,
            connect_timeout: Duration::from_millis(500),
            io_timeout: Duration::from_millis(2000),
        },
        mdns: false,
        ssdp: false,
        ipv6: false,
        arp: false,
        discovery_window: Duration::ZERO,
        today: iotscan::util::Date::parse("2026-10-24"),
        ..ScanOptions::default()
    }
}

async fn scan(o: ScanOptions) -> Result<ScanResult, ScanError> {
    engine::run(o, Arc::new(Environment::none()), Progress::new(false)).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn several_devices_are_told_apart() {
    // Four "devices" on 127.0.0.2-5, all listening on the same port.
    let first = testkit::http_bind("127.0.0.2:0", vec![("/", Route::ok("").header("X-Powered-By", "PHP/8.2.30"))]).await.unwrap();
    let port = first.port;
    let mut keep = vec![first];
    let versions = ["PHP/8.5.12", "PHP/7.4.33", "PHP/8.3.20"];
    for (i, v) in versions.iter().enumerate() {
        let addr = format!("127.0.0.{}:{port}", i + 3);
        keep.push(
            testkit::http_bind(&addr, vec![("/", Route::ok("<title>dev</title>").header("X-Powered-By", v))])
                .await
                .expect("same port free on loopback aliases"),
        );
    }
    let r = scan(opts(&["127.0.0.2-127.0.0.5"], vec![port])).await.unwrap();
    assert_eq!(r.devices.len(), 4);
    let by_ip = |ip: &str| r.devices.iter().find(|d| d.ip.to_string() == ip).unwrap();
    let has = |ip: &str, checker: &str| by_ip(ip).findings.iter().any(|f| f.checker == checker);
    assert!(has("127.0.0.2", "php2shell"), "8.2.30 is vulnerable");
    assert!(!has("127.0.0.3", "php2shell"), "8.5.12 is patched");
    assert!(has("127.0.0.4", "php2shell") && has("127.0.0.4", "php-eol"), "7.4.33");
    assert!(has("127.0.0.5", "php2shell"), "8.3.20 < 8.3.36");
    assert_eq!(r.stats.devices, 4);
    assert!(r.stats.findings[0] >= 3, "{:?}", r.stats);
    drop(keep);
}

#[tokio::test]
async fn ipv6_loopback_is_scanned() {
    let Ok(m) = testkit::http_bind("[::1]:0", vec![("/", Route::ok("").header("X-Powered-By", "PHP/8.2.30"))]).await else {
        eprintln!("IPv6 loopback unavailable in this environment; skipping");
        return;
    };
    let r = scan(opts(&["::1"], vec![m.port])).await.unwrap();
    assert_eq!(r.devices.len(), 1);
    assert!(r.devices[0].ip.is_ipv6());
    assert!(r.devices[0].findings.iter().any(|f| f.checker == "php2shell"));
}

#[tokio::test]
async fn https_with_self_signed_certificate() {
    use tokio_rustls::TlsAcceptor;
    let ck = rcgen::generate_simple_self_signed(vec!["iot.local".to_string()]).unwrap();
    let cert = rustls::pki_types::CertificateDer::from(ck.cert.der().to_vec());
    let key = rustls::pki_types::PrivateKeyDer::try_from(ck.signing_key.serialize_der()).unwrap();
    let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(cfg));
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            let a = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(mut t) = a.accept(s).await {
                    let mut b = [0u8; 2048];
                    let _ = t.read(&mut b).await;
                    let body = "<title>Secure Hub</title>";
                    let _ = t
                        .write_all(
                            format!("HTTP/1.0 200 OK\r\nX-Powered-By: PHP/8.4.20\r\nContent-Length: {}\r\n\r\n{body}", body.len())
                                .as_bytes(),
                        )
                        .await;
                    let _ = t.shutdown().await;
                }
            });
        }
    });
    let r = scan(opts(&["127.0.0.1"], vec![port])).await.unwrap();
    let svc = &r.devices[0].services[0];
    assert_eq!(svc.kind, ServiceKind::Https, "{svc:?}");
    assert!(svc.http.as_ref().unwrap().tls_version.is_some());
    assert_eq!(svc.http.as_ref().unwrap().title.as_deref(), Some("Secure Hub"));
    assert!(r.devices[0].findings.iter().any(|f| f.checker == "php2shell" && f.confidence == Confidence::Likely));
}

#[tokio::test]
async fn hostile_text_is_neutralised_everywhere() {
    let evil = "\x1b[2J\x1b[31mPWNED\x1b[0m\x07\u{202e}";
    let m = testkit::http(vec![(
        "/",
        Route::ok(&format!("<title>{evil} Camera\r\nInjected: line</title>"))
            .header("Server", &format!("nginx/1.2 {evil}"))
            .header("X-Powered-By", "PHP/8.2.30"),
    )])
    .await;
    let r = scan(opts(&["127.0.0.1"], vec![m.port])).await.unwrap();
    let json = serde_json::to_string(&r).unwrap();
    assert!(
        !json.contains("\\u001b") && !json.contains("\\u0007") && !json.contains("\\u202e"),
        "control characters leaked into JSON: {json}"
    );
    let term = iotscan::report::terminal::render(&r, None, &iotscan::report::terminal::Opts { color: false, ..Default::default() });
    assert!(!term.contains('\x1b') && !term.contains('\x07'), "terminal output contains escapes");
    let html = iotscan::report::html::render(&r, None);
    assert!(!html.contains('\x1b'));
    assert!(r.devices[0].label.contains("Camera"), "label should still be useful: {}", r.devices[0].label);
}

#[tokio::test]
async fn redirect_loops_terminate() {
    let m = testkit::http(vec![
        ("/", Route::ok("").status(302).header("Location", "/a")),
        ("/a", Route::ok("").status(302).header("Location", "/b")),
        ("/b", Route::ok("").status(302).header("Location", "/a")),
    ])
    .await;
    let start = std::time::Instant::now();
    let r = scan(opts(&["127.0.0.1"], vec![m.port])).await.unwrap();
    assert!(start.elapsed() < Duration::from_secs(10));
    assert!(r.devices[0].services[0].is_web());
}

#[tokio::test]
async fn off_host_redirects_are_not_followed() {
    // If the scanner followed this it would try to reach 192.0.2.1 (a documentation address).
    let m = testkit::http(vec![("/", Route::ok("").status(302).header("Location", "http://192.0.2.1/phpinfo.php"))]).await;
    let start = std::time::Instant::now();
    let r = scan(opts(&["127.0.0.1"], vec![m.port])).await.unwrap();
    assert!(start.elapsed() < Duration::from_secs(5));
    let http = r.devices[0].services[0].http.as_ref().unwrap();
    assert_eq!(http.status, 302);
    assert_eq!(http.location.as_deref(), Some("http://192.0.2.1/phpinfo.php"));
}

#[tokio::test]
async fn trickling_server_cannot_stall_the_scan() {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            tokio::spawn(async move {
                let mut b = [0u8; 1024];
                let _ = s.read(&mut b).await;
                for byte in b"HTTP/1.0 200 OK\r\nServer: slow\r\n\r\nbody body body".iter().cycle().take(400) {
                    if s.write_all(&[*byte]).await.is_err() {
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            });
        }
    });
    let start = std::time::Instant::now();
    let r = scan(opts(&["127.0.0.1"], vec![port])).await.unwrap();
    assert!(start.elapsed() < Duration::from_secs(12), "took {:?}", start.elapsed());
    assert_eq!(r.devices.len(), 1);
}

#[tokio::test]
async fn reset_connections_do_not_break_the_scan() {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            drop(s); // close immediately
        }
    });
    let r = scan(opts(&["127.0.0.1"], vec![port])).await.unwrap();
    assert_eq!(r.devices[0].services.len(), 1);
    assert_eq!(r.devices[0].services[0].kind, ServiceKind::Other);
}

#[tokio::test]
async fn allowlist_suppresses_and_counts() {
    let m = testkit::http(vec![("/", Route::ok("").header("X-Powered-By", "PHP/8.2.30"))]).await;
    let mut o = opts(&["127.0.0.1"], vec![m.port]);
    o.allowlist = Allowlist::parse("[[allow]]\ndevice='127.0.0.1'\nchecker='php2shell'\nreason='verified patched by vendor'\n").unwrap();
    let r = scan(o).await.unwrap();
    let f = r.devices[0].findings.iter().find(|f| f.checker == "php2shell").unwrap();
    assert_eq!(f.suppressed.as_deref(), Some("verified patched by vendor"));
    assert_eq!(r.stats.suppressed, 1);
    assert_eq!(r.count_at_least(Severity::Critical), 0, "suppressed findings do not count");
}

#[tokio::test]
async fn only_and_skip_select_checkers() {
    let m = testkit::http(vec![("/", Route::ok("").header("X-Powered-By", "PHP/7.4.33"))]).await;
    let mut o = opts(&["127.0.0.1"], vec![m.port]);
    o.only = vec!["php-eol".into()];
    let r = scan(o).await.unwrap();
    assert!(r.devices[0].findings.iter().all(|f| f.checker == "php-eol"));
    assert_eq!(r.summary.checkers, vec!["php-eol"]);
    let mut o = opts(&["127.0.0.1"], vec![m.port]);
    o.skip = vec!["php2shell".into()];
    let r = scan(o).await.unwrap();
    assert!(r.devices[0].findings.iter().all(|f| f.checker != "php2shell"));
}

#[tokio::test]
async fn extra_advisory_file_adds_a_checker_without_code() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("adv.toml");
    std::fs::write(
        &f,
        r#"
[[advisory]]
id = "boa-abandoned"
product = "boa"
title = "Boa web server is abandoned"
severity = "high"
cves = ["CVE-2017-9833"]
summary = "Boa has had no releases since 2005."
remediation = "Replace the device firmware."
[[advisory.affected]]
from = "0.0"
"#,
    )
    .unwrap();
    let m = testkit::http(vec![("/", Route::ok("<title>Cam</title>").header("Server", "Boa/0.94.14rc21"))]).await;
    let mut o = opts(&["127.0.0.1"], vec![m.port]);
    o.advisories = Some(f);
    let r = scan(o).await.unwrap();
    let f = r.devices[0].findings.iter().find(|f| f.checker == "boa-abandoned").expect("data-driven finding");
    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.cves, vec!["CVE-2017-9833"]);
}

#[tokio::test]
async fn scope_rules() {
    assert!(matches!(scan(opts(&["1.1.1.1"], vec![80])).await, Err(ScanError::PublicRange(_))));
    assert!(matches!(scan(opts(&["192.168.0.0/16"], vec![80])).await, Err(ScanError::Config(_))), "65k hosts exceeds the default cap");
    assert!(matches!(scan(opts(&["not-an-ip"], vec![80])).await, Err(ScanError::Config(_))));
    // Mixed private+public is refused as a whole.
    assert!(matches!(scan(opts(&["10.0.0.1", "8.8.8.8"], vec![80])).await, Err(ScanError::PublicRange(_))));
    // allow_public lets it through (against an unreachable documentation address, with a tiny timeout).
    let mut o = opts(&["192.0.2.1"], vec![9]);
    o.allow_public = true;
    o.limits.connect_timeout = Duration::from_millis(100);
    assert!(scan(o).await.is_ok());
}

#[tokio::test]
async fn progress_is_reported() {
    let m = testkit::http(vec![("/", Route::ok(""))]).await;
    let p = Progress::new(false);
    let r = engine::run(opts(&["127.0.0.1"], vec![m.port]), Arc::new(Environment::none()), p.clone()).await.unwrap();
    assert_eq!(r.devices.len(), 1);
    let s = p.snapshot();
    assert_eq!(s.phase, "Done");
    assert_eq!(s.devices_found, 1);
    assert!(s.log.iter().any(|l| l.contains("device")));
}

#[test]
fn local_only_classification_for_auto_targets() {
    // Auto-detection skips interfaces whose addresses are not private (e.g. documentation or public ranges).
    use iotscan::scope::Target;
    assert!(!Target::parse("192.0.2.0/24").unwrap().is_local_only());
    assert!(!Target::parse("100.64.0.0/24").unwrap().is_local_only());
    assert!(Target::parse("192.168.1.0/24").unwrap().is_local_only());
    assert!(Target::parse("10.1.0.0/16").unwrap().is_local_only());
}
