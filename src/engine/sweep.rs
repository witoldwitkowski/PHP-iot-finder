//! TCP connect sweep: the unprivileged way of finding hosts and open ports.
//!
//! A connection that is *refused* still proves the host is alive, so closed
//! ports contribute to host discovery too.

use crate::limits::NetCtx;
use crate::scope::Target;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tokio::time::{Instant, timeout};

/// Interface scope ids for link-local IPv6 addresses.
pub type Scopes = HashMap<Ipv6Addr, u32>;

/// Build a socket address, attaching the scope id for IPv6 link-local hosts.
pub fn sockaddr(ip: IpAddr, port: u16, scopes: &Scopes) -> SocketAddr {
    match ip {
        IpAddr::V6(a) => SocketAddr::V6(SocketAddrV6::new(a, port, 0, scopes.get(&a).copied().unwrap_or(0))),
        IpAddr::V4(a) => SocketAddr::new(IpAddr::V4(a), port),
    }
}

/// Result of probing one port.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortState {
    /// Connection accepted.
    Open,
    /// Connection actively refused (host is alive).
    Refused,
    /// No answer.
    NoAnswer,
}

/// Probe one TCP port. `None` means the scan was cancelled.
pub async fn probe_port(ctx: &NetCtx, scopes: &Scopes, ip: IpAddr, port: u16) -> Option<PortState> {
    let _permit = ctx.permit(ip).await?;
    let addr = sockaddr(ip, port, scopes);
    Some(match timeout(ctx.limits.connect_timeout, TcpStream::connect(addr)).await {
        Ok(Ok(_s)) => PortState::Open,
        Ok(Err(e)) if matches!(e.kind(), std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::ConnectionReset) => PortState::Refused,
        _ => PortState::NoAnswer,
    })
}

/// Result for one host.
#[derive(Clone, Debug, Default)]
pub struct HostSweep {
    /// Open ports.
    pub open: Vec<u16>,
    /// Whether the host proved it is alive.
    pub alive: bool,
}

/// Lets the sweep abandon on-link hosts that never answered ARP.
pub struct EarlyExit {
    on_link: Vec<Target>,
    cache: Mutex<(Option<Instant>, HashSet<IpAddr>)>,
}

impl EarlyExit {
    /// Build from the local subnets.
    pub fn new(on_link: Vec<Target>) -> EarlyExit {
        EarlyExit { on_link, cache: Mutex::new((None, HashSet::new())) }
    }

    /// True when `ip` is on a local subnet but the kernel has no ARP entry for
    /// it after several probes, i.e. nobody is home.
    pub fn looks_dead(&self, ip: IpAddr) -> bool {
        if !self.on_link.iter().any(|t| t.contains(ip)) {
            return false;
        }
        let mut c = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        let stale = c.0.is_none_or(|t| t.elapsed() > Duration::from_millis(400));
        if stale {
            c.1 = crate::discovery::neigh::read().into_iter().map(|n| IpAddr::V4(n.ip)).collect();
            c.0 = Some(Instant::now());
        }
        !c.1.contains(&ip)
    }
}

/// Number of ports tried before the early-exit check applies.
pub const EARLY_AFTER: usize = 6;

/// Sweep all `ports` on one host with at most `window` probes in flight.
pub async fn sweep_host(
    ctx: Arc<NetCtx>,
    scopes: Arc<Scopes>,
    ip: IpAddr,
    ports: Arc<Vec<u16>>,
    early: Option<Arc<EarlyExit>>,
) -> HostSweep {
    let window = ctx.limits.per_host.max(1);
    let mut out = HostSweep::default();
    let mut set: JoinSet<(u16, Option<PortState>)> = JoinSet::new();
    let mut next = 0usize;
    let mut done = 0usize;
    loop {
        while set.len() < window && next < ports.len() {
            let (ctx, scopes, port) = (ctx.clone(), scopes.clone(), ports[next]);
            next += 1;
            set.spawn(async move { (port, probe_port(&ctx, &scopes, ip, port).await) });
        }
        let Some(res) = set.join_next().await else { break };
        let Ok((port, state)) = res else { continue };
        done += 1;
        match state {
            Some(PortState::Open) => {
                out.open.push(port);
                out.alive = true;
            }
            Some(PortState::Refused) => out.alive = true,
            Some(PortState::NoAnswer) => {}
            None => break, // cancelled
        }
        if !out.alive
            && done >= EARLY_AFTER
            && let Some(e) = &early
            && e.looks_dead(ip)
        {
            break;
        }
    }
    out.open.sort_unstable();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::Limits;
    use std::sync::atomic::AtomicBool;
    use tokio::net::TcpListener;

    fn ctx() -> Arc<NetCtx> {
        let l = Limits { rate_per_sec: 0, connect_timeout: Duration::from_millis(300), ..Limits::default() };
        Arc::new(NetCtx::new(l, Arc::new(AtomicBool::new(false))))
    }

    #[tokio::test]
    async fn finds_open_and_refused() {
        let open = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let open_port = open.local_addr().unwrap().port();
        let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let closed_port = closed.local_addr().unwrap().port();
        drop(closed);
        tokio::spawn(async move { while open.accept().await.is_ok() {} });
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let r = sweep_host(ctx(), Arc::new(Scopes::new()), ip, Arc::new(vec![open_port, closed_port]), None).await;
        assert_eq!(r.open, vec![open_port]);
        assert!(r.alive);
    }

    #[tokio::test]
    async fn refused_only_still_alive() {
        let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let p = closed.local_addr().unwrap().port();
        drop(closed);
        let r = sweep_host(ctx(), Arc::new(Scopes::new()), "127.0.0.1".parse().unwrap(), Arc::new(vec![p]), None).await;
        assert!(r.open.is_empty());
        assert!(r.alive);
    }

    #[tokio::test]
    async fn cancelled_scan_stops() {
        let cancel = Arc::new(AtomicBool::new(true));
        let c = Arc::new(NetCtx::new(Limits::default(), cancel));
        let r = sweep_host(c, Arc::new(Scopes::new()), "127.0.0.1".parse().unwrap(), Arc::new(vec![80, 443]), None).await;
        assert!(r.open.is_empty() && !r.alive);
    }

    #[test]
    fn early_exit_ignores_off_link_hosts() {
        let e = EarlyExit::new(vec![Target::parse("192.168.77.0/24").unwrap()]);
        assert!(!e.looks_dead("10.1.2.3".parse().unwrap()));
    }

    #[test]
    fn v6_scope_attached() {
        let mut s = Scopes::new();
        let a: Ipv6Addr = "fe80::1".parse().unwrap();
        s.insert(a, 3);
        match sockaddr(IpAddr::V6(a), 80, &s) {
            SocketAddr::V6(v) => assert_eq!(v.scope_id(), 3),
            _ => panic!(),
        }
    }
}
