//! Mock IoT devices on localhost, used by `iotscan selftest` and the test suite.
//!
//! Every mock listens on `127.0.0.1` on an ephemeral port and mimics a real
//! device behaviour: vulnerable and patched PHP banners, distribution builds,
//! hidden versions with a reachable `phpinfo()`, Telnet, hangs, garbage, huge
//! bodies and redirect loops.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

/// One HTTP route.
#[derive(Clone, Debug)]
pub struct Route {
    /// Status code.
    pub status: u16,
    /// Extra headers.
    pub headers: Vec<(String, String)>,
    /// Body.
    pub body: String,
}

impl Route {
    /// 200 with a body.
    pub fn ok(body: &str) -> Route {
        Route { status: 200, headers: vec![], body: body.to_string() }
    }
    /// Add a header.
    pub fn header(mut self, k: &str, v: &str) -> Route {
        self.headers.push((k.to_string(), v.to_string()));
        self
    }
    /// Set the status.
    pub fn status(mut self, s: u16) -> Route {
        self.status = s;
        self
    }
}

/// A running mock device.
pub struct Mock {
    /// Listening port.
    pub port: u16,
    task: JoinHandle<()>,
}

impl Drop for Mock {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn read_request(s: &mut tokio::net::TcpStream) -> Option<String> {
    let mut buf = vec![0u8; 4096];
    let mut n = 0;
    loop {
        match tokio::time::timeout(Duration::from_secs(2), s.read(&mut buf[n..])).await {
            Ok(Ok(0)) | Err(_) | Ok(Err(_)) => return None,
            Ok(Ok(k)) => {
                n += k;
                if buf[..n].windows(4).any(|w| w == b"\r\n\r\n") || n == buf.len() {
                    return Some(String::from_utf8_lossy(&buf[..n]).into_owned());
                }
            }
        }
    }
}

/// Serve fixed routes over plain HTTP. Unknown paths get a bare 404.
pub async fn http(routes: Vec<(&str, Route)>) -> Mock {
    http_bind("127.0.0.1:0", routes).await.expect("bind mock")
}

/// Like [`http`], on a chosen address (for multi-device tests on 127.0.0.x or ::1).
pub async fn http_bind(bind: &str, routes: Vec<(&str, Route)>) -> std::io::Result<Mock> {
    let map: Arc<HashMap<String, Route>> = Arc::new(routes.into_iter().map(|(p, r)| (p.to_string(), r)).collect());
    let l = TcpListener::bind(bind).await?;
    let port = l.local_addr()?.port();
    let task = tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            let map = map.clone();
            tokio::spawn(async move {
                let Some(req) = read_request(&mut s).await else { return };
                let path = req.split_whitespace().nth(1).unwrap_or("/").split('?').next().unwrap_or("/").to_string();
                let route = map.get(&path).cloned().unwrap_or(Route { status: 404, headers: vec![], body: "not found".into() });
                let mut out = format!("HTTP/1.0 {} X\r\nContent-Length: {}\r\n", route.status, route.body.len());
                for (k, v) in &route.headers {
                    out.push_str(&format!("{k}: {v}\r\n"));
                }
                out.push_str("\r\n");
                out.push_str(&route.body);
                let _ = s.write_all(out.as_bytes()).await;
                let _ = s.shutdown().await;
            });
        }
    });
    Ok(Mock { port, task })
}

/// A TCP service that sends `banner` on connect, then closes.
pub async fn banner(banner: &[u8]) -> Mock {
    let banner = banner.to_vec();
    let l = TcpListener::bind("127.0.0.1:0").await.expect("bind mock");
    let port = l.local_addr().expect("addr").port();
    let task = tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            let b = banner.clone();
            tokio::spawn(async move {
                let _ = s.write_all(&b).await;
                tokio::time::sleep(Duration::from_millis(100)).await;
            });
        }
    });
    Mock { port, task }
}

/// Accepts connections and never says anything (a hung embedded web server).
pub async fn hang() -> Mock {
    let l = TcpListener::bind("127.0.0.1:0").await.expect("bind mock");
    let port = l.local_addr().expect("addr").port();
    let task = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((s, _)) = l.accept().await {
            held.push(s);
        }
    });
    Mock { port, task }
}

/// Streams an endless response body (tests size caps).
pub async fn endless() -> Mock {
    let l = TcpListener::bind("127.0.0.1:0").await.expect("bind mock");
    let port = l.local_addr().expect("addr").port();
    let task = tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            tokio::spawn(async move {
                let _ = read_request(&mut s).await;
                let _ = s.write_all(b"HTTP/1.0 200 OK\r\nServer: endless\r\n\r\n").await;
                let chunk = vec![b'A'; 64 * 1024];
                for _ in 0..2000 {
                    if s.write_all(&chunk).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    Mock { port, task }
}

/// A PHP phpinfo() page for the given version.
pub fn phpinfo_page(version: &str) -> String {
    format!(
        "<html><head><title>phpinfo()</title></head><body><table><tr class=\"h\"><td><h1 class=\"p\">PHP Version {version}</h1></td></tr></table><table><tr><td class=\"e\">Server API </td><td class=\"v\">FPM/FastCGI </td></tr></table><p>This program makes use of the Zend Scripting Language Engine</p></body></html>"
    )
}

/// The standard fleet used by the selftest.
pub struct Fleet {
    /// Name → port.
    pub ports: Vec<(&'static str, u16)>,
    _mocks: Vec<Mock>,
}

impl Fleet {
    /// Port of a named mock.
    pub fn port(&self, name: &str) -> u16 {
        self.ports.iter().find(|(n, _)| *n == name).map(|(_, p)| *p).unwrap_or_else(|| panic!("no mock named {name}"))
    }

    /// All ports, for `--ports`.
    pub fn all_ports(&self) -> Vec<u16> {
        let mut p: Vec<u16> = self.ports.iter().map(|(_, p)| *p).collect();
        p.sort_unstable();
        p
    }
}

/// Start the standard fleet.
pub async fn fleet() -> Fleet {
    let mut ports = Vec::new();
    let mut mocks = Vec::new();
    let mut add = |name: &'static str, m: Mock| {
        ports.push((name, m.port));
        mocks.push(m);
    };

    add(
        "php-vulnerable",
        http(vec![(
            "/",
            Route::ok("<html><title>Garage Camera</title></html>").header("Server", "nginx/1.24.0").header("X-Powered-By", "PHP/8.2.30"),
        )])
        .await,
    );
    add(
        "php-patched",
        http(vec![(
            "/",
            Route::ok("<html><title>Patched Hub</title></html>").header("Server", "nginx").header("X-Powered-By", "PHP/8.5.12"),
        )])
        .await,
    );
    add(
        "php-distro",
        http(vec![(
            "/",
            Route::ok("<html></html>").header("Server", "Apache/2.4.58 (Ubuntu)").header("X-Powered-By", "PHP/8.3.6-0ubuntu0.24.04.12"),
        )])
        .await,
    );
    add(
        "php-eol",
        http(vec![(
            "/",
            Route::ok("<html><title>Old NAS</title></html>").header("Server", "Apache/2.4.10").header("X-Powered-By", "PHP/7.4.33"),
        )])
        .await,
    );
    add(
        "php-hidden",
        http(vec![
            (
                "/",
                Route::ok("<html><a href=\"login.php\">login</a></html>")
                    .header("Server", "nginx")
                    .header("Set-Cookie", "PHPSESSID=abc123; path=/"),
            ),
            ("/phpinfo.php", Route::ok(&phpinfo_page("8.2.30"))),
        ])
        .await,
    );
    add("plain-web", http(vec![("/", Route::ok("<html><title>Thermostat</title></html>").header("Server", "lighttpd/1.4.66"))]).await);
    add(
        "redirect-to-php",
        http(vec![
            ("/", Route::ok("").status(302).header("Location", "/login.php")),
            ("/login.php", Route::ok("<html>login</html>").header("X-Powered-By", "PHP/7.4.33")),
        ])
        .await,
    );
    add(
        "telnet",
        banner(&[
            0xFF, 0xFD, 0x18, 0xFF, 0xFD, 0x20, b'B', b'u', b's', b'y', b'B', b'o', b'x', b' ', b'l', b'o', b'g', b'i', b'n', b':', b' ',
        ])
        .await,
    );
    add("hang", hang().await);
    add("ssh-on-web-port", banner(b"SSH-2.0-dropbear_2022.83\r\n").await);
    add("endless", endless().await);
    Fleet { ports, _mocks: mocks }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn fleet_starts_and_serves() {
        let f = fleet().await;
        assert!(f.all_ports().len() >= 10);
        let t = crate::http::Timeouts { connect: Duration::from_millis(500), total: Duration::from_secs(2) };
        let addr: std::net::SocketAddr = format!("127.0.0.1:{}", f.port("php-vulnerable")).parse().unwrap();
        let r = crate::http::fetch(addr, false, &crate::http::Request::get("/"), t).await.unwrap();
        assert_eq!(r.header("x-powered-by"), Some("PHP/8.2.30"));
        let r = crate::http::fetch(addr, false, &crate::http::Request::get("/nope"), t).await.unwrap();
        assert_eq!(r.status, 404);
    }
}
