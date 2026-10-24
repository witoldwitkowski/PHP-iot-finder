//! Executes the probes that checkers asked for, under the scan's limits.

use super::sweep::{Scopes, sockaddr};
use crate::checkers::{Probe, ProbeData, ProbeKind, ProbeResults};
use crate::http::{self, Request, Timeouts};
use crate::limits::NetCtx;
use crate::model::{Service, ServiceKind};
use crate::util::lossy;
use std::net::IpAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::{Duration, timeout};

/// Largest body a probe may read.
pub const PROBE_BODY: usize = 160 * 1024;
/// Largest payload we send.
pub const MAX_SEND: usize = 1400;

/// Run all probes for one device.
pub async fn run_probes(ctx: &NetCtx, scopes: &Scopes, ip: IpAddr, services: &[Service], probes: &[Probe]) -> ProbeResults {
    let mut results = ProbeResults::default();
    for p in probes {
        if ctx.is_cancelled() {
            break;
        }
        let r = run_one(ctx, scopes, ip, services, &p.kind).await;
        results.insert(p.kind.clone(), r);
    }
    results
}

async fn run_one(ctx: &NetCtx, scopes: &Scopes, ip: IpAddr, services: &[Service], kind: &ProbeKind) -> Result<ProbeData, String> {
    let _permit = ctx.permit(ip).await.ok_or("cancelled")?;
    match kind {
        ProbeKind::Http { port, path, method } => {
            let svc = services.iter().find(|s| s.port == *port && s.is_web()).ok_or("no web service on that port")?;
            let tls = svc.kind == ServiceKind::Https;
            let mut req = Request { method: *method, path: path.clone(), headers: vec![], max_body: PROBE_BODY };
            req.max_body = PROBE_BODY;
            let t = Timeouts { connect: ctx.limits.connect_timeout, total: ctx.limits.io_timeout };
            let r = http::fetch(sockaddr(ip, *port, scopes), tls, &req, t).await.map_err(|e| e.to_string())?;
            let body: String = String::from_utf8_lossy(&r.body)
                .chars()
                .map(|c| if c.is_control() && !matches!(c, '\n' | '\t' | '\r') { ' ' } else { c })
                .collect();
            Ok(ProbeData::Http {
                status: r.status,
                headers: r.headers.iter().take(40).map(|(k, v)| (crate::util::sanitize(k, 64), crate::util::sanitize(v, 300))).collect(),
                body,
                tls: r.tls,
            })
        }
        ProbeKind::Tcp { port, send } => {
            if send.len() > MAX_SEND {
                return Err("payload too large".into());
            }
            let mut s = match timeout(ctx.limits.connect_timeout, TcpStream::connect(sockaddr(ip, *port, scopes))).await {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => return Err(e.kind().to_string()),
                Err(_) => return Err("connect timed out".into()),
            };
            if !send.is_empty() {
                timeout(Duration::from_secs(2), s.write_all(send))
                    .await
                    .map_err(|_| "write timed out")?
                    .map_err(|e| e.kind().to_string())?;
            }
            let mut buf = vec![0u8; 1024];
            let n = match timeout(Duration::from_millis(1500), s.read(&mut buf)).await {
                Ok(Ok(n)) => n,
                Ok(Err(e)) => return Err(e.kind().to_string()),
                Err(_) => 0,
            };
            buf.truncate(n);
            Ok(ProbeData::Bytes(buf))
        }
        ProbeKind::Udp { port, payload } => {
            if payload.len() > MAX_SEND {
                return Err("payload too large".into());
            }
            let bind = if ip.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
            let sock = UdpSocket::bind(bind).await.map_err(|e| e.kind().to_string())?;
            let dst = sockaddr(ip, *port, scopes);
            sock.send_to(payload, dst).await.map_err(|e| e.kind().to_string())?;
            let mut buf = vec![0u8; 1500];
            loop {
                match timeout(Duration::from_millis(1500), sock.recv_from(&mut buf)).await {
                    Ok(Ok((n, from))) if from.ip() == ip => {
                        buf.truncate(n);
                        return Ok(ProbeData::Bytes(buf));
                    }
                    Ok(Ok(_)) => continue, // ignore datagrams from other hosts
                    Ok(Err(e)) => return Err(e.kind().to_string()),
                    Err(_) => return Err("no reply".into()),
                }
            }
        }
    }
}

/// Convenience for checkers' tests: text of a probe response body.
pub fn body_text(d: &ProbeData, max: usize) -> String {
    match d {
        ProbeData::Http { body, .. } => body.chars().take(max).collect(),
        ProbeData::Bytes(b) => lossy(b, max),
    }
}
