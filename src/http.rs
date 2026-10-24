//! A deliberately small HTTP/1.0 client for fingerprinting devices.
//!
//! Safety properties:
//! * only `GET`, `HEAD` and `OPTIONS` can be sent,
//! * response heads and bodies are size-capped and the whole exchange has a deadline,
//! * TLS verification is off (see [`crate::tlsconf`]) and nothing sensitive is ever sent,
//! * everything stored from the response is sanitised.

use crate::model::HttpInfo;
use crate::util::{contains_ci, lossy, sanitize};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{Instant, timeout, timeout_at};

/// Maximum size of a response head we will buffer.
pub const MAX_HEAD: usize = 16 * 1024;
/// Default body cap for the front-page fetch.
pub const DEFAULT_BODY: usize = 64 * 1024;
/// Largest body cap any probe may ask for.
pub const MAX_BODY: usize = 256 * 1024;

/// HTTP methods the scanner is allowed to use.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Method {
    /// GET
    Get,
    /// HEAD
    Head,
    /// OPTIONS
    Options,
}

impl Method {
    fn as_str(self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Head => "HEAD",
            Method::Options => "OPTIONS",
        }
    }
}

/// A request to send.
#[derive(Clone, Debug)]
pub struct Request {
    /// Method.
    pub method: Method,
    /// Absolute path and query, must start with `/`.
    pub path: String,
    /// Extra headers (validated against CR/LF injection).
    pub headers: Vec<(String, String)>,
    /// Maximum body bytes to read.
    pub max_body: usize,
}

impl Request {
    /// A plain `GET path`.
    pub fn get(path: &str) -> Request {
        Request { method: Method::Get, path: path.to_string(), headers: vec![], max_body: DEFAULT_BODY }
    }
}

/// Errors from an HTTP exchange.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpError {
    /// TCP connection failed or timed out.
    Connect(String),
    /// Deadline elapsed before a response head arrived.
    Timeout,
    /// TLS handshake failed.
    Tls(String),
    /// The peer did not speak HTTP.
    NotHttp(String),
    /// The request itself was invalid.
    BadRequest(String),
    /// I/O error mid-exchange.
    Io(String),
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpError::Connect(e) => write!(f, "connect failed: {e}"),
            HttpError::Timeout => f.write_str("timed out"),
            HttpError::Tls(e) => write!(f, "TLS error: {e}"),
            HttpError::NotHttp(e) => write!(f, "not HTTP: {e}"),
            HttpError::BadRequest(e) => write!(f, "bad request: {e}"),
            HttpError::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}
impl std::error::Error for HttpError {}

/// A parsed response.
#[derive(Clone, Debug, Default)]
pub struct Response {
    /// Status code.
    pub status: u16,
    /// Headers in order (raw values, lossily decoded).
    pub headers: Vec<(String, String)>,
    /// Body bytes read (possibly truncated).
    pub body: Vec<u8>,
    /// Whether the body was cut at the cap.
    pub truncated: bool,
    /// Whether TLS was used.
    pub tls: bool,
    /// Negotiated TLS version.
    pub tls_version: Option<String>,
}

impl Response {
    /// First header with this name (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
    /// All headers with this name.
    pub fn headers_all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> {
        self.headers.iter().filter(move |(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

/// Connection settings.
#[derive(Clone, Copy, Debug)]
pub struct Timeouts {
    /// TCP connect timeout.
    pub connect: Duration,
    /// Deadline for the whole exchange after connecting.
    pub total: Duration,
}

fn validate_request(req: &Request) -> Result<(), HttpError> {
    if !req.path.starts_with('/') || req.path.len() > 512 {
        return Err(HttpError::BadRequest("path must start with '/' and be at most 512 bytes".into()));
    }
    let bad = |s: &str| s.bytes().any(|b| b < 0x20 || b == 0x7f || b == b' ' && false) || s.contains(['\r', '\n']);
    if bad(&req.path) || req.path.contains(' ') {
        return Err(HttpError::BadRequest("path contains control characters or spaces".into()));
    }
    for (k, v) in &req.headers {
        if k.is_empty() || k.contains([':', ' ', '\r', '\n']) || bad(v) {
            return Err(HttpError::BadRequest(format!("invalid header '{k}'")));
        }
    }
    if req.max_body > MAX_BODY {
        return Err(HttpError::BadRequest("body cap too large".into()));
    }
    Ok(())
}

/// Send one request and read the response.
pub async fn fetch(addr: SocketAddr, use_tls: bool, req: &Request, t: Timeouts) -> Result<Response, HttpError> {
    validate_request(req)?;
    let stream = match timeout(t.connect, TcpStream::connect(addr)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(HttpError::Connect(e.kind().to_string())),
        Err(_) => return Err(HttpError::Connect("timed out".into())),
    };
    let _ = stream.set_nodelay(true);
    let deadline = Instant::now() + t.total;
    let host = match addr.ip() {
        std::net::IpAddr::V4(a) => a.to_string(),
        std::net::IpAddr::V6(a) => format!("[{a}]"),
    };
    if use_tls {
        let connector = tokio_rustls::TlsConnector::from(crate::tlsconf::client_config());
        let name = rustls::pki_types::ServerName::IpAddress(addr.ip().into());
        let tls = match timeout_at(deadline, connector.connect(name, stream)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(HttpError::Tls(e.to_string())),
            Err(_) => return Err(HttpError::Tls("handshake timed out".into())),
        };
        let version = tls.get_ref().1.protocol_version().map(|v| format!("{v:?}"));
        let mut resp = exchange(tls, &host, req, deadline).await?;
        resp.tls = true;
        resp.tls_version = version;
        Ok(resp)
    } else {
        exchange(stream, &host, req, deadline).await
    }
}

async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
    mut s: S,
    host: &str,
    req: &Request,
    deadline: Instant,
) -> Result<Response, HttpError> {
    let mut out = format!(
        "{} {} HTTP/1.0\r\nHost: {}\r\nUser-Agent: iotscan/{} (local network audit)\r\nAccept: */*\r\nConnection: close\r\n",
        req.method.as_str(),
        req.path,
        host,
        env!("CARGO_PKG_VERSION")
    );
    for (k, v) in &req.headers {
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    out.push_str("\r\n");
    match timeout_at(deadline, async {
        s.write_all(out.as_bytes()).await?;
        s.flush().await
    })
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(HttpError::Io(e.kind().to_string())),
        Err(_) => return Err(HttpError::Timeout),
    }

    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    let mut head: Option<Head> = None;
    let cap_total = MAX_HEAD + req.max_body;
    let mut eof = false;
    let mut timed_out = false;
    loop {
        if head.is_none() {
            match parse_head(&buf)? {
                Some(h) => head = Some(h),
                None if buf.len() > MAX_HEAD => return Err(HttpError::NotHttp("response head too large".into())),
                None => {}
            }
        }
        if let Some((_, _, off)) = &head
            && (buf.len().saturating_sub(*off) >= req.max_body || req.method == Method::Head)
        {
            break;
        }
        if eof || buf.len() >= cap_total {
            break;
        }
        match timeout_at(deadline, s.read(&mut chunk)).await {
            Ok(Ok(0)) => eof = true,
            Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
            Ok(Err(e)) => {
                // A reset after the head was received still leaves us a usable response.
                if head.is_none() && buf.is_empty() {
                    return Err(HttpError::Io(e.kind().to_string()));
                }
                eof = true;
            }
            Err(_) => {
                timed_out = true;
                break;
            }
        }
    }
    if head.is_none() {
        head = parse_head(&buf)?;
    }
    let Some((status, headers, off)) = head else {
        return Err(if timed_out || buf.is_empty() && !eof {
            HttpError::Timeout
        } else if buf.is_empty() {
            HttpError::NotHttp("connection closed without a response".into())
        } else {
            HttpError::NotHttp("no HTTP response head".into())
        });
    };
    let mut body = buf[off.min(buf.len())..].to_vec();
    let chunked = headers.iter().any(|(k, v)| k.eq_ignore_ascii_case("transfer-encoding") && contains_ci(v, "chunked"));
    if chunked {
        body = dechunk(&body);
    }
    let truncated = body.len() > req.max_body;
    body.truncate(req.max_body);
    Ok(Response { status, headers, body, truncated, tls: false, tls_version: None })
}

/// Status code, headers, and the offset where the body starts.
type Head = (u16, Vec<(String, String)>, usize);

/// Parse the status line and headers. `Ok(None)` means more bytes are needed.
fn parse_head(buf: &[u8]) -> Result<Option<Head>, HttpError> {
    if buf.is_empty() {
        return Ok(None);
    }
    // Reject early if the first bytes cannot start an HTTP response.
    let probe = &buf[..buf.len().min(5)];
    if !b"HTTP/".starts_with(probe) && !probe.starts_with(b"HTTP/") {
        return Err(HttpError::NotHttp(format!("unexpected bytes: {:?}", lossy(probe, 5))));
    }
    let mut hdrs = [httparse::EMPTY_HEADER; 64];
    let mut r = httparse::Response::new(&mut hdrs);
    // Embedded devices often emit malformed header lines; skip those instead of discarding the whole response.
    let mut cfg = httparse::ParserConfig::default();
    cfg.ignore_invalid_headers_in_responses(true);
    match cfg.parse_response(&mut r, buf) {
        Ok(httparse::Status::Complete(off)) => {
            let status = r.code.unwrap_or(0);
            let headers = r.headers.iter().map(|h| (h.name.to_string(), String::from_utf8_lossy(h.value).into_owned())).collect();
            Ok(Some((status, headers, off)))
        }
        Ok(httparse::Status::Partial) => Ok(None),
        Err(e) => Err(HttpError::NotHttp(format!("malformed response: {e}"))),
    }
}

/// Lenient chunked-transfer decoder; stops quietly at the first malformed chunk.
pub fn dechunk(mut data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(nl) = data.iter().position(|&b| b == b'\n') {
        let line = String::from_utf8_lossy(&data[..nl]);
        let size_str = line.trim().split(';').next().unwrap_or("");
        let Ok(size) = usize::from_str_radix(size_str, 16) else { break };
        data = &data[nl + 1..];
        if size == 0 {
            break;
        }
        let take = size.min(data.len());
        out.extend_from_slice(&data[..take]);
        if take < size {
            break;
        }
        data = &data[take..];
        // Skip the CRLF after the chunk.
        if data.starts_with(b"\r\n") {
            data = &data[2..];
        } else if data.starts_with(b"\n") {
            data = &data[1..];
        }
        if out.len() > MAX_HEAD + MAX_BODY {
            break;
        }
    }
    out
}

/// Pull the page `<title>` out of an HTML body.
pub fn extract_title(body: &str) -> Option<String> {
    let lower = body.to_ascii_lowercase();
    let start = lower.find("<title")?;
    let gt = lower[start..].find('>')? + start + 1;
    let end = lower[gt..].find("</title")? + gt;
    let t = sanitize(&body[gt..end], 120);
    if t.is_empty() { None } else { Some(t) }
}

/// Headers worth keeping on a device record.
const KEEP_HEADERS: &[&str] = &[
    "server",
    "x-powered-by",
    "content-type",
    "www-authenticate",
    "x-generator",
    "x-aspnet-version",
    "via",
    "x-frame-options",
    "strict-transport-security",
    "content-security-policy",
    "location",
    "x-php-version",
];

/// Convert a raw response into the stored [`HttpInfo`].
pub fn to_info(resp: &Response, path: &str) -> HttpInfo {
    let mut info = HttpInfo {
        tls: resp.tls,
        tls_version: resp.tls_version.clone(),
        status: resp.status,
        path: sanitize(path, 200),
        ..HttpInfo::default()
    };
    for (k, v) in &resp.headers {
        let lk = k.to_ascii_lowercase();
        if lk == "set-cookie" {
            let name = v.split('=').next().unwrap_or("").trim();
            let name = sanitize(name, 64);
            if !name.is_empty() && !info.cookie_names.contains(&name) && info.cookie_names.len() < 16 {
                info.cookie_names.push(name);
            }
        } else if KEEP_HEADERS.contains(&lk.as_str()) && info.headers.len() < 24 {
            info.headers.push((sanitize(k, 48), sanitize(v, 200)));
        }
    }
    info.server = resp.header("server").map(|v| sanitize(v, 200));
    info.powered_by = resp.header("x-powered-by").map(|v| sanitize(v, 200));
    info.location = resp.header("location").map(|v| sanitize(v, 200));
    let body = String::from_utf8_lossy(&resp.body);
    info.title = extract_title(&body);
    // Keep a sanitised-for-matching copy of the body (control chars become spaces).
    info.body = body.chars().map(|c| if c.is_control() && c != '\n' && c != '\t' && c != '\r' { ' ' } else { c }).collect();
    info
}

/// Resolve a redirect `Location` into a same-host path, or `None` if it leaves the device.
pub fn same_host_path(location: &str, addr: SocketAddr, tls: bool) -> Option<String> {
    let loc = location.trim();
    if loc.starts_with('/') && !loc.starts_with("//") {
        return Some(loc.to_string());
    }
    let (scheme, rest) = loc.split_once("://")?;
    let https = match scheme.to_ascii_lowercase().as_str() {
        "http" => false,
        "https" => true,
        _ => return None,
    };
    if https != tls {
        return None; // never silently change scheme
    }
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let default_port = if https { 443 } else { 80 };
    let (host, port) = split_authority(authority, default_port)?;
    if host.parse::<std::net::IpAddr>().ok()? == addr.ip() && port == addr.port() { Some(path.to_string()) } else { None }
}

fn split_authority(a: &str, default_port: u16) -> Option<(String, u16)> {
    let a = a.rsplit('@').next()?;
    if let Some(rest) = a.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        let port = match tail.strip_prefix(':') {
            Some(p) => p.parse().ok()?,
            None => default_port,
        };
        return Some((host.to_string(), port));
    }
    match a.rsplit_once(':') {
        Some((h, p)) => Some((h.to_string(), p.parse().ok()?)),
        None => Some((a.to_string(), default_port)),
    }
}

/// Fetch `/` (following up to `max_redirects` same-host redirects) and return the final response.
pub async fn fetch_following(
    addr: SocketAddr,
    use_tls: bool,
    first: &Request,
    t: Timeouts,
    max_redirects: usize,
) -> Result<(Response, String), HttpError> {
    let mut req = first.clone();
    let mut hops = 0;
    loop {
        let resp = fetch(addr, use_tls, &req, t).await?;
        if (300..400).contains(&resp.status)
            && hops < max_redirects
            && let Some(next) = resp.header("location").and_then(|l| same_host_path(l, addr, use_tls))
            && next != req.path
        {
            hops += 1;
            req.path = next;
            continue;
        }
        return Ok((resp, req.path));
    }
}

/// Shared handle type used by tests and the engine.
pub type SharedTls = Arc<rustls::ClientConfig>;

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    const T: Timeouts = Timeouts { connect: Duration::from_millis(500), total: Duration::from_millis(800) };

    async fn serve_once(payload: Vec<u8>, hang_after: bool) -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = l.accept().await {
                let mut tmp = [0u8; 2048];
                let _ = timeout(Duration::from_millis(300), s.read(&mut tmp)).await;
                let _ = s.write_all(&payload).await;
                if hang_after {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }
        });
        addr
    }

    #[tokio::test]
    async fn parses_a_normal_response() {
        let a = serve_once(
            b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.58 (Ubuntu) PHP/8.2.30\r\nX-Powered-By: PHP/8.2.30\r\nSet-Cookie: PHPSESSID=abc; path=/\r\n\r\n<html><title>My Camera</title></html>".to_vec(),
            false,
        )
        .await;
        let r = fetch(a, false, &Request::get("/"), T).await.unwrap();
        assert_eq!(r.status, 200);
        let info = to_info(&r, "/");
        assert_eq!(info.title.as_deref(), Some("My Camera"));
        assert_eq!(info.powered_by.as_deref(), Some("PHP/8.2.30"));
        assert_eq!(info.cookie_names, vec!["PHPSESSID".to_string()]);
        assert!(!info.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("set-cookie")), "cookie values must not be stored");
    }

    #[tokio::test]
    async fn rejects_non_http() {
        let a = serve_once(b"SSH-2.0-dropbear\r\n".to_vec(), false).await;
        let e = fetch(a, false, &Request::get("/"), T).await.unwrap_err();
        assert!(matches!(e, HttpError::NotHttp(_)), "{e:?}");
    }

    #[tokio::test]
    async fn caps_body_size() {
        let mut p = b"HTTP/1.0 200 OK\r\n\r\n".to_vec();
        p.extend(std::iter::repeat_n(b'A', 3_000_000));
        let a = serve_once(p, false).await;
        let mut req = Request::get("/");
        req.max_body = 10_000;
        let r = fetch(a, false, &req, T).await.unwrap();
        assert_eq!(r.body.len(), 10_000);
        assert!(r.truncated);
    }

    #[tokio::test]
    async fn timeout_when_server_never_answers() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a = l.local_addr().unwrap();
        tokio::spawn(async move {
            let _s = l.accept().await;
            tokio::time::sleep(Duration::from_secs(5)).await;
        });
        let start = std::time::Instant::now();
        let e = fetch(a, false, &Request::get("/"), T).await.unwrap_err();
        assert_eq!(e, HttpError::Timeout);
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    #[tokio::test]
    async fn slow_server_after_head_returns_partial() {
        let a = serve_once(b"HTTP/1.0 200 OK\r\nServer: x\r\n\r\npartial".to_vec(), true).await;
        let r = fetch(a, false, &Request::get("/"), T).await.unwrap();
        assert_eq!(r.body, b"partial");
    }

    #[tokio::test]
    async fn oversized_head_is_rejected() {
        let mut p = b"HTTP/1.1 200 OK\r\nX-Junk: ".to_vec();
        p.extend(std::iter::repeat_n(b'a', 100_000));
        let a = serve_once(p, false).await;
        assert!(fetch(a, false, &Request::get("/"), T).await.is_err());
    }

    #[tokio::test]
    async fn connect_refused_is_reported() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a = l.local_addr().unwrap();
        drop(l);
        assert!(matches!(fetch(a, false, &Request::get("/"), T).await, Err(HttpError::Connect(_))));
    }

    #[tokio::test]
    async fn rejects_header_injection() {
        let a: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let mut r = Request::get("/ok");
        r.headers.push(("X-A".into(), "b\r\nInjected: 1".into()));
        assert!(matches!(fetch(a, false, &r, T).await, Err(HttpError::BadRequest(_))));
        let r = Request::get("/a b");
        assert!(matches!(fetch(a, false, &r, T).await, Err(HttpError::BadRequest(_))));
        let r = Request::get("noslash");
        assert!(matches!(fetch(a, false, &r, T).await, Err(HttpError::BadRequest(_))));
    }

    #[tokio::test]
    async fn malformed_header_lines_are_skipped_not_fatal() {
        let a = serve_once(
            b"HTTP/1.0 200 OK\r\nServer: ok\r\nX-Bad: va\x1blue\r\nBroken line without colon\r\nX-Powered-By: PHP/8.2.30\r\n\r\nhi"
                .to_vec(),
            false,
        )
        .await;
        let r = fetch(a, false, &Request::get("/"), T).await.unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.header("x-powered-by"), Some("PHP/8.2.30"));
        assert_eq!(r.body, b"hi");
    }

    #[test]
    fn dechunks() {
        assert_eq!(dechunk(b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"), b"hello world");
        assert_eq!(dechunk(b"zz\r\nbad"), b"");
        assert_eq!(dechunk(b"10\r\nshort"), b"short");
        assert!(dechunk(b"").is_empty());
    }

    #[test]
    fn titles() {
        assert_eq!(extract_title("<HTML><TITLE>  A\n B </TITLE>").as_deref(), Some("A B"));
        assert_eq!(extract_title("<title>\x1b[31mred</title>").as_deref(), Some("[31mred"));
        assert_eq!(extract_title("no title"), None);
        assert_eq!(extract_title("<title>unterminated"), None);
    }

    #[test]
    fn redirect_rules() {
        let a: SocketAddr = "192.168.1.5:80".parse().unwrap();
        assert_eq!(same_host_path("/login.php", a, false).as_deref(), Some("/login.php"));
        assert_eq!(same_host_path("http://192.168.1.5/x", a, false).as_deref(), Some("/x"));
        assert_eq!(same_host_path("http://192.168.1.5:80/x", a, false).as_deref(), Some("/x"));
        assert_eq!(same_host_path("http://evil.example/x", a, false), None);
        assert_eq!(same_host_path("http://192.168.1.6/x", a, false), None);
        assert_eq!(same_host_path("https://192.168.1.5/x", a, false), None);
        assert_eq!(same_host_path("//192.168.1.5/x", a, false), None);
        assert_eq!(same_host_path("ftp://192.168.1.5/x", a, false), None);
    }

    #[test]
    fn headers_are_sanitized() {
        let r = Response { status: 200, headers: vec![("Server".into(), "evil\x1b[2Jbox".into())], ..Response::default() };
        let info = to_info(&r, "/");
        assert!(!info.server.unwrap().contains('\x1b'));
    }
}
