//! IPv6 neighbour discovery by multicast echo to `ff02::1` (all nodes on the link).
//!
//! Uses unprivileged ICMPv6 datagram sockets (`net.ipv4.ping_group_range`), so
//! no root is required on Ubuntu's default configuration.

use socket2::{Domain, Protocol, Socket, Type};
use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::Instant;

/// An IPv6 host that answered on a link.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Host {
    /// Address (usually link-local).
    pub ip: Ipv6Addr,
    /// Interface index it answered on (needed to connect to link-local addresses).
    pub scope: u32,
}

/// Build an ICMPv6 echo request (the kernel fills id and checksum on datagram sockets).
pub fn echo_request(seq: u16) -> Vec<u8> {
    let mut p = vec![128, 0, 0, 0, 0, 0];
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(b"iotscan");
    p
}

/// True if `buf` starts with an ICMPv6 echo reply.
pub fn is_echo_reply(buf: &[u8]) -> bool {
    buf.first() == Some(&129)
}

/// Probe each `(ifindex)` for IPv6 neighbours. `own` addresses are excluded.
pub async fn discover(ifindexes: &[u32], own: &[Ipv6Addr], window: Duration) -> (Vec<Host>, Vec<String>) {
    let mut hosts: Vec<Host> = Vec::new();
    let mut warnings = Vec::new();
    for &idx in ifindexes {
        match probe_iface(idx, window).await {
            Ok(found) => {
                for h in found {
                    if !own.contains(&h.ip) && !hosts.contains(&h) {
                        hosts.push(h);
                    }
                }
            }
            Err(e) => warnings.push(format!("IPv6 neighbour discovery on interface {idx}: {e}")),
        }
    }
    (hosts, warnings)
}

async fn probe_iface(ifindex: u32, window: Duration) -> Result<Vec<Host>, String> {
    let s = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::ICMPV6))
        .map_err(|e| format!("cannot open ICMPv6 socket ({e}); check net.ipv4.ping_group_range"))?;
    s.set_multicast_if_v6(ifindex).map_err(|e| e.to_string())?;
    s.set_multicast_hops_v6(1).map_err(|e| e.to_string())?;
    s.set_nonblocking(true).map_err(|e| e.to_string())?;
    let sock = UdpSocket::from_std(s.into()).map_err(|e| e.to_string())?;
    let dst = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1), 0, 0, ifindex));
    for seq in 1..=2u16 {
        sock.send_to(&echo_request(seq), dst).await.map_err(|e| e.to_string())?;
    }
    let end = Instant::now() + window;
    let mut out = Vec::new();
    let mut buf = [0u8; 1500];
    while let Ok(Ok((n, src))) = tokio::time::timeout_at(end, sock.recv_from(&mut buf)).await {
        if !is_echo_reply(&buf[..n]) {
            continue;
        }
        if let IpAddr::V6(ip) = src.ip() {
            let h = Host { ip, scope: ifindex };
            if !out.contains(&h) && out.len() < 1024 {
                out.push(h);
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn echo_packet() {
        let p = echo_request(7);
        assert_eq!(p[0], 128);
        assert_eq!(&p[6..8], &[0, 7]);
        assert!(!is_echo_reply(&p));
        assert!(is_echo_reply(&[129, 0, 0, 0]));
        assert!(!is_echo_reply(&[]));
    }
}
