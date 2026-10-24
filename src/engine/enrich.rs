//! Service identification: what is actually listening on each open port?

use super::sweep::{Scopes, sockaddr};
use crate::http::{self, Request, Timeouts};
use crate::limits::NetCtx;
use crate::model::{Service, ServiceKind};
use crate::ports;
use crate::util::sanitize;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::time::{Duration, timeout};

/// Remove Telnet option negotiation (IAC sequences) and non-printable bytes.
pub fn strip_telnet(data: &[u8]) -> String {
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0;
    while i < data.len() {
        if data[i] == 0xFF {
            // IAC <cmd> [<opt>]: commands 251-254 carry an option byte; SB..SE blocks are rare, skip simply.
            i += match data.get(i + 1) {
                Some(251..=254) => 3,
                Some(_) => 2,
                None => 1,
            };
            continue;
        }
        out.push(data[i]);
        i += 1;
    }
    sanitize(&String::from_utf8_lossy(&out), 120)
}

/// Decide the service kind from the port and what it said first.
pub fn classify_banner(port: u16, data: &[u8]) -> (ServiceKind, Option<String>) {
    let text = String::from_utf8_lossy(&data[..data.len().min(512)]);
    let banner = |s: &str| {
        let b = sanitize(s, 120);
        if b.is_empty() { None } else { Some(b) }
    };
    if text.starts_with("SSH-") {
        return (ServiceKind::Ssh, banner(&text));
    }
    if text.starts_with("RTSP/") {
        return (ServiceKind::Rtsp, banner(&text));
    }
    if text.starts_with("220") && (text.to_ascii_lowercase().contains("ftp") || port == 21) {
        return (ServiceKind::Ftp, banner(&text));
    }
    if matches!(port, 23 | 2323) || (data.first() == Some(&0xFF) && matches!(data.get(1), Some(251..=254))) {
        let t = strip_telnet(data);
        return (ServiceKind::Telnet, if t.is_empty() { None } else { Some(t) });
    }
    match port {
        22 => (ServiceKind::Ssh, banner(&text)),
        21 => (ServiceKind::Ftp, banner(&text)),
        554 => (ServiceKind::Rtsp, banner(&text)),
        1883 | 8883 => (ServiceKind::Mqtt, None),
        _ => (ServiceKind::Other, banner(&text)),
    }
}

/// Connect and read whatever the service volunteers.
async fn read_banner(ctx: &NetCtx, scopes: &Scopes, ip: IpAddr, port: u16) -> Result<Vec<u8>, String> {
    let Some(_permit) = ctx.permit(ip).await else { return Err("cancelled".into()) };
    let addr = sockaddr(ip, port, scopes);
    let mut s = match timeout(ctx.limits.connect_timeout, TcpStream::connect(addr)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(e.kind().to_string()),
        Err(_) => return Err("connect timed out".into()),
    };
    let mut buf = vec![0u8; 512];
    match timeout(Duration::from_millis(1500), s.read(&mut buf)).await {
        Ok(Ok(n)) => {
            buf.truncate(n);
            Ok(buf)
        }
        Ok(Err(e)) => Err(e.kind().to_string()),
        Err(_) => Ok(Vec::new()), // silent service: fine, open is still open
    }
}

fn timeouts(ctx: &NetCtx) -> Timeouts {
    Timeouts { connect: ctx.limits.connect_timeout, total: ctx.limits.io_timeout }
}

/// Try to talk HTTP(S) to a port. Returns the service on success.
async fn try_web(ctx: &NetCtx, scopes: &Scopes, ip: IpAddr, port: u16, tls: bool) -> Result<Service, http::HttpError> {
    let _permit = ctx.permit(ip).await.ok_or_else(|| http::HttpError::Io("cancelled".into()))?;
    let addr = sockaddr(ip, port, scopes);
    let (resp, path) = http::fetch_following(addr, tls, &Request::get("/"), timeouts(ctx), 2).await?;
    let info = http::to_info(&resp, &path);
    Ok(Service { port, kind: if tls { ServiceKind::Https } else { ServiceKind::Http }, banner: None, http: Some(info), note: None })
}

/// Identify one open port.
pub async fn identify_port(ctx: &NetCtx, scopes: &Scopes, ip: IpAddr, port: u16, banner_ports: &[u16]) -> Service {
    let mut note = None;
    if ports::is_web_candidate(port) && !banner_ports.contains(&port) {
        let order: [bool; 2] = if ports::TLS_FIRST.contains(&port) { [true, false] } else { [false, true] };
        for tls in order {
            match try_web(ctx, scopes, ip, port, tls).await {
                Ok(s) => return s,
                Err(e) => {
                    // Only keep the most informative failure.
                    if !matches!(e, http::HttpError::Connect(_)) {
                        note = Some(format!("{}: {e}", if tls { "HTTPS" } else { "HTTP" }));
                    }
                }
            }
            if ctx.is_cancelled() {
                break;
            }
        }
    }
    // Not (recognisably) a web service: read a banner.
    let (kind, banner) = match read_banner(ctx, scopes, ip, port).await {
        Ok(data) => classify_banner(port, &data),
        Err(e) => {
            note.get_or_insert(e);
            classify_banner(port, &[])
        }
    };
    Service { port, kind, banner, http: None, note }
}

/// Identify every open port of a host concurrently (the per-host permit limit
/// still applies) and return the services in port order.
pub async fn identify_host(ctx: Arc<NetCtx>, scopes: Arc<Scopes>, ip: IpAddr, open: Vec<u16>, banner_ports: Arc<Vec<u16>>) -> Vec<Service> {
    let mut set = tokio::task::JoinSet::new();
    for p in open {
        let (ctx, scopes, bp) = (ctx.clone(), scopes.clone(), banner_ports.clone());
        set.spawn(async move { identify_port(&ctx, &scopes, ip, p, &bp).await });
    }
    let mut out = Vec::new();
    while let Some(r) = set.join_next().await {
        if let Ok(s) = r {
            out.push(s);
        }
    }
    out.sort_by_key(|s| s.port);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn telnet_negotiation_is_stripped() {
        let data = [0xFF, 0xFD, 0x18, 0xFF, 0xFD, 0x20, b'l', b'o', b'g', b'i', b'n', b':', b' '];
        assert_eq!(strip_telnet(&data), "login:");
        assert_eq!(strip_telnet(&[0xFF]), "");
        assert_eq!(strip_telnet(&[0xFF, 0xFA]), "");
    }

    #[test]
    fn banner_classification() {
        assert_eq!(classify_banner(22, b"SSH-2.0-dropbear_2019.78\r\n").0, ServiceKind::Ssh);
        assert_eq!(classify_banner(2222, b"SSH-2.0-OpenSSH_9.6").0, ServiceKind::Ssh);
        assert_eq!(classify_banner(21, b"220 ProFTPD Server ready").0, ServiceKind::Ftp);
        assert_eq!(classify_banner(554, b"RTSP/1.0 200 OK").0, ServiceKind::Rtsp);
        assert_eq!(classify_banner(554, b"").0, ServiceKind::Rtsp);
        assert_eq!(classify_banner(23, b"").0, ServiceKind::Telnet);
        assert_eq!(classify_banner(8023, &[0xFF, 0xFD, 0x01]).0, ServiceKind::Telnet);
        assert_eq!(classify_banner(1883, b"").0, ServiceKind::Mqtt);
        assert_eq!(classify_banner(9999, b"hello").0, ServiceKind::Other);
        let (_, b) = classify_banner(9999, b"\x1b[31mred\x1b[0m");
        assert!(!b.unwrap().contains('\x1b'));
    }

    #[test]
    fn classify_never_panics() {
        let mut x: u64 = 7;
        for _ in 0..5000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let n = (x % 64) as usize;
            let data: Vec<u8> = (0..n).map(|i| (x >> (i % 48)) as u8).collect();
            let _ = classify_banner((x % 65535) as u16, &data);
            let _ = strip_telnet(&data);
        }
    }
}
