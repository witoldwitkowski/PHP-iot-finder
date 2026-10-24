//! Security and lifecycle tests for the local web GUI, over real sockets.

use iotscan::cli::GuiArgs;
use iotscan::engine::Environment;
use iotscan::gui::Server;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

struct Harness {
    port: u16,
    token: String,
    _dir: tempfile::TempDir,
    app: Arc<iotscan::gui::api::App>,
}

async fn start(demo: bool) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let args = GuiArgs {
        port: 0,
        no_open: true,
        history_dir: Some(dir.path().join("hist")),
        advisories: None,
        allowlist: None,
        no_arp: true,
        demo,
    };
    let srv = Server::prepare(listener, args, Arc::new(Environment::none())).unwrap();
    let port: u16 = srv.url.split(':').nth(2).unwrap().split('/').next().unwrap().parse().unwrap();
    let token = srv.url.split("t=").nth(1).unwrap().to_string();
    let app = srv.app.clone();
    tokio::spawn(srv.run(false));
    Harness { port, token, _dir: dir, app }
}

struct Resp {
    status: u16,
    headers: String,
    body: String,
}

impl Resp {
    fn header(&self, name: &str) -> Option<String> {
        self.headers
            .lines()
            .find_map(|l| l.split_once(':').filter(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.trim().to_string()))
    }
    fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.body).unwrap_or_else(|e| panic!("bad json {e}: {}", self.body))
    }
}

async fn raw(port: u16, request: &[u8]) -> Resp {
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    s.write_all(request).await.unwrap();
    let _ = s.shutdown().await; // half-close: we are done sending
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut buf)).await;
    let text = String::from_utf8_lossy(&buf).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let status = head.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    Resp { status, headers: head.to_string(), body: body.to_string() }
}

impl Harness {
    async fn get(&self, path: &str, cookie: bool) -> Resp {
        let c = if cookie { format!("Cookie: iotscan_token={}\r\n", self.token) } else { String::new() };
        raw(self.port, format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n{c}\r\n", self.port).as_bytes()).await
    }
    async fn post(&self, path: &str, body: &str) -> Resp {
        raw(
            self.port,
            format!(
                "POST {path} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nCookie: iotscan_token={}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                self.port,
                self.token,
                body.len()
            )
            .as_bytes(),
        )
        .await
    }
}

#[tokio::test]
async fn token_gate() {
    let h = start(true).await;
    // No token: the page and the API are locked.
    let r = h.get("/", false).await;
    assert_eq!(r.status, 401);
    assert!(!r.body.contains("iotscan-app"));
    assert_eq!(h.get("/api/state", false).await.status, 401);
    assert_eq!(h.get("/app.js", false).await.status, 401);
    // Wrong token.
    let r = raw(h.port, format!("GET /?t=wrong HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n", h.port).as_bytes()).await;
    assert_eq!(r.status, 401);
    let r = raw(h.port, format!("GET /api/state HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nCookie: iotscan_token=wrong\r\n\r\n", h.port).as_bytes())
        .await;
    assert_eq!(r.status, 401);
    // Right token: redirect + HttpOnly SameSite=Strict cookie.
    let r = raw(h.port, format!("GET /?t={} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n", h.token, h.port).as_bytes()).await;
    assert_eq!(r.status, 303);
    let cookie = r.header("set-cookie").unwrap();
    assert!(cookie.contains("HttpOnly") && cookie.contains("SameSite=Strict") && cookie.contains(&h.token));
    assert_eq!(r.header("location").as_deref(), Some("/"));
    // With the cookie everything works.
    assert_eq!(h.get("/", true).await.status, 200);
    assert_eq!(h.get("/app.js", true).await.status, 200);
    assert_eq!(h.get("/ui.css", true).await.status, 200);
    assert_eq!(h.get("/api/state", true).await.status, 200);
    // Header token also works (scripts, tests).
    let r =
        raw(h.port, format!("GET /api/state HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nX-Iotscan-Token: {}\r\n\r\n", h.port, h.token).as_bytes())
            .await;
    assert_eq!(r.status, 200);
}

#[tokio::test]
async fn dns_rebinding_is_blocked() {
    let h = start(true).await;
    for host in ["evil.example", "evil.example:80", "127.0.0.1", "127.0.0.1:1", "localhost", "[::1]:80"] {
        let r =
            raw(h.port, format!("GET /api/state HTTP/1.1\r\nHost: {host}\r\nCookie: iotscan_token={}\r\n\r\n", h.token).as_bytes()).await;
        assert_eq!(r.status, 421, "Host: {host}");
    }
    let r = raw(
        h.port,
        format!("GET /api/state HTTP/1.1\r\nHost: localhost:{}\r\nCookie: iotscan_token={}\r\n\r\n", h.port, h.token).as_bytes(),
    )
    .await;
    assert_eq!(r.status, 200, "localhost is allowed");
    let r = raw(h.port, b"GET /api/state HTTP/1.0\r\n\r\n").await;
    assert_eq!(r.status, 421, "missing Host");
}

#[tokio::test]
async fn csrf_protection() {
    let h = start(true).await;
    let base = |extra: &str, body: &str| {
        format!(
            "POST /api/cancel HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nCookie: iotscan_token={}\r\n{extra}Content-Length: {}\r\n\r\n{body}",
            h.port,
            h.token,
            body.len()
        )
    };
    // A cross-site HTML form can only send these content types.
    for ct in ["text/plain", "application/x-www-form-urlencoded", "multipart/form-data; boundary=x"] {
        let r = raw(h.port, base(&format!("Content-Type: {ct}\r\n"), "{}").as_bytes()).await;
        assert_eq!(r.status, 415, "{ct}");
    }
    let r = raw(h.port, base("Content-Type: application/json\r\n", "{}").as_bytes()).await;
    assert_eq!(r.status, 200);
    let r = raw(h.port, base("Content-Type: application/json\r\nOrigin: https://evil.example\r\n", "{}").as_bytes()).await;
    assert_eq!(r.status, 403);
    let r = raw(h.port, base("Content-Type: application/json\r\nSec-Fetch-Site: cross-site\r\n", "{}").as_bytes()).await;
    assert_eq!(r.status, 403);
    let r = raw(h.port, base(&format!("Content-Type: application/json\r\nOrigin: http://127.0.0.1:{}\r\n", h.port), "{}").as_bytes()).await;
    assert_eq!(r.status, 200);
}

#[tokio::test]
async fn security_headers_present() {
    let h = start(true).await;
    let r = h.get("/", true).await;
    let csp = r.header("content-security-policy").unwrap();
    assert!(csp.contains("default-src 'none'") && csp.contains("script-src 'self'") && csp.contains("frame-ancestors 'none'"));
    assert!(!csp.contains("unsafe-inline") && !csp.contains("unsafe-eval"));
    assert_eq!(r.header("x-content-type-options").as_deref(), Some("nosniff"));
    assert_eq!(r.header("referrer-policy").as_deref(), Some("no-referrer"));
    assert_eq!(r.header("cache-control").as_deref(), Some("no-store"));
    assert_eq!(r.header("x-frame-options").as_deref(), Some("DENY"));
}

#[tokio::test]
async fn frontend_never_uses_innerhtml() {
    // The page's XSS safety rests on never parsing device text as markup.
    let js = include_str!("../assets/app.js");
    for banned in ["innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"] {
        assert!(!js.contains(banned), "app.js must not use {banned}");
    }
}

#[tokio::test]
async fn malformed_and_oversized_requests() {
    let h = start(true).await;
    assert_eq!(raw(h.port, b"garbage\r\n\r\n").await.status, 400);
    assert_eq!(raw(h.port, b"").await.status, 400);
    let big = format!("GET / HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nX-Big: {}\r\n\r\n", h.port, "a".repeat(40_000));
    assert_eq!(raw(h.port, big.as_bytes()).await.status, 413);
    let body = "x".repeat(100_000);
    let r = raw(
        h.port,
        format!("POST /api/scan HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nCookie: iotscan_token={}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}", h.port, h.token, body.len()).as_bytes(),
    )
    .await;
    assert_eq!(r.status, 413);
    let r = raw(h.port, format!("POST /api/scan HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nTransfer-Encoding: chunked\r\n\r\n", h.port).as_bytes())
        .await;
    assert!(matches!(r.status, 400 | 401));
    // Unknown routes and methods.
    assert_eq!(h.get("/nope", true).await.status, 404);
    assert_eq!(h.get("/api/nope", true).await.status, 404);
    let r = raw(
        h.port,
        format!("DELETE /api/state HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nCookie: iotscan_token={}\r\n\r\n", h.port, h.token).as_bytes(),
    )
    .await;
    assert_eq!(r.status, 405);
}

#[tokio::test]
async fn path_traversal_in_history_names() {
    let h = start(true).await;
    for p in [
        "/api/history/../../etc/passwd",
        "/api/history/%2e%2e%2fetc%2fpasswd",
        "/api/history/scan-../../x.json",
        "/api/history//etc/passwd",
    ] {
        let r = h.get(p, true).await;
        assert_eq!(r.status, 404, "{p}");
        assert!(!r.body.contains("root:"), "{p}");
    }
}

#[tokio::test]
async fn demo_mode_serves_data_and_refuses_scans() {
    let h = start(true).await;
    let s = h.get("/api/state", true).await.json();
    assert_eq!(s["demo"], true);
    assert_eq!(s["running"], false);
    assert_eq!(s["has_result"], true);
    let r = h.get("/api/result", true).await.json();
    assert!(r["result"]["devices"].as_array().unwrap().len() >= 15);
    assert!(r["diff"]["new_devices"].as_array().unwrap().len() == 1);
    let resp = h.post("/api/scan", "{}").await;
    assert_eq!(resp.status, 409);
    // Downloads.
    let html = h.get("/api/report.html", true).await;
    assert_eq!(html.status, 200);
    assert!(html.body.starts_with("<!doctype html>"));
    assert!(html.header("content-disposition").unwrap().contains("attachment"));
    let json = h.get("/api/result.json", true).await;
    assert!(serde_json::from_str::<serde_json::Value>(&json.body).is_ok());
    // Checkers list.
    let c = h.get("/api/checkers", true).await.json();
    assert!(c.as_array().unwrap().iter().any(|x| x["id"] == "php2shell"));
}

#[tokio::test]
async fn public_ranges_need_explicit_confirmation() {
    let h = start(false).await;
    let r = h.post("/api/scan", r#"{"targets":["8.8.8.0/30"]}"#).await;
    assert_eq!(r.status, 400);
    assert_eq!(r.json()["error"], "public");
    assert_eq!(r.json()["targets"][0], "8.8.8.0/30");
    // Bad input is rejected, not crashed on.
    assert_eq!(h.post("/api/scan", "not json").await.status, 400);
    assert_eq!(h.post("/api/scan", r#"{"targets":["nope"]}"#).await.status, 400);
    assert_eq!(h.post("/api/scan", r#"{"ports":"99999"}"#).await.status, 400);
    let many = format!(r#"{{"targets":[{}]}}"#, vec!["\"10.0.0.1\""; 40].join(","));
    assert_eq!(h.post("/api/scan", &many).await.status, 400);
    let s = h.get("/api/state", true).await.json();
    assert_eq!(s["running"], false, "rejected requests must not start scans");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn full_scan_lifecycle_with_history_and_diff() {
    let h = start(false).await;
    let fleet = iotscan::testkit::fleet().await;
    let ports = fleet.all_ports().iter().map(u16::to_string).collect::<Vec<_>>().join(",");
    let body =
        format!(r#"{{"targets":["127.0.0.1"],"ports":"{ports}","active":true,"fast":true,"no_mdns":true,"no_ssdp":true,"no_ipv6":true}}"#);

    let r = h.post("/api/scan", &body).await;
    assert_eq!(r.status, 202, "{}", r.body);
    // A second scan while one is running is refused.
    let again = h.post("/api/scan", &body).await;
    assert!(again.status == 409 || again.status == 202);

    let first = wait_for_result(&h).await;
    let devices = first["result"]["devices"].as_array().unwrap();
    assert_eq!(devices.len(), 1);
    let findings = devices[0]["findings"].as_array().unwrap();
    assert!(findings.iter().any(|f| f["checker"] == "php2shell" && f["severity"] == "critical"));
    assert!(findings.iter().any(|f| f["checker"] == "telnet-open"));
    assert!(first["saved_as"].is_string(), "scan must be saved to history");

    let hist = h.get("/api/history", true).await.json();
    assert_eq!(hist.as_array().unwrap().len(), 1);
    let name = hist[0]["name"].as_str().unwrap().to_string();
    let old = h.get(&format!("/api/history/{name}"), true).await;
    assert_eq!(old.status, 200);

    // Second scan: identical network → diff exists and reports no change.
    let r = h.post("/api/scan", &body).await;
    assert_eq!(r.status, 202);
    let second = wait_for_result(&h).await;
    assert!(second["diff"].is_object(), "second scan must carry a diff");
    assert_eq!(second["diff"]["new_devices"].as_array().unwrap().len(), 0);
    assert_eq!(h.get("/api/history", true).await.json().as_array().unwrap().len(), 2);

    // The HTML report reflects the result and escapes content.
    let html = h.get("/api/report.html", true).await;
    assert!(html.body.contains("PHP2Shell"));
    drop(h.app);
}

async fn wait_for_result(h: &Harness) -> serde_json::Value {
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    loop {
        tokio::time::sleep(Duration::from_millis(300)).await;
        let s = h.get("/api/state", true).await.json();
        if s["running"] == false {
            assert!(s["error"].is_null(), "scan failed: {}", s["error"]);
            break;
        }
        assert!(std::time::Instant::now() < deadline, "scan did not finish in 60s");
    }
    h.get("/api/result", true).await.json()
}

#[tokio::test]
async fn cancel_and_quit() {
    let h = start(false).await;
    let fleet = iotscan::testkit::fleet().await;
    let ports = fleet.all_ports().iter().map(u16::to_string).collect::<Vec<_>>().join(",");
    let body = format!(r#"{{"targets":["127.0.0.1"],"ports":"{ports}","no_mdns":true,"no_ssdp":true,"no_ipv6":true}}"#);
    assert_eq!(h.post("/api/scan", &body).await.status, 202);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(h.post("/api/cancel", "{}").await.status, 200);
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        let s = h.get("/api/state", true).await.json();
        if s["running"] == false {
            break;
        }
        assert!(std::time::Instant::now() < deadline, "cancel did not stop the scan");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert_eq!(h.post("/api/quit", "{}").await.status, 200);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        TcpStream::connect(("127.0.0.1", h.port)).await.is_err() || raw(h.port, b"GET / HTTP/1.0\r\n\r\n").await.status == 0,
        "server should stop accepting"
    );
}
