//! Ways of finding devices: TCP sweep, neighbour table, raw ARP, mDNS, SSDP, ICMPv6.

pub mod arp;
pub mod icmp6;
pub mod mdns;
pub mod neigh;
pub mod ssdp;

use socket2::{Domain, Protocol, Socket, Type};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use tokio::net::UdpSocket;

/// Create a non-blocking UDP socket bound to `iface_ip:0` that sends multicast out of that interface.
pub(crate) fn multicast_socket_v4(iface_ip: Ipv4Addr) -> std::io::Result<UdpSocket> {
    let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    s.bind(&SocketAddr::V4(SocketAddrV4::new(iface_ip, 0)).into())?;
    // These can fail on loopback or odd interfaces; unicast probing still works.
    let _ = s.set_multicast_if_v4(&iface_ip);
    let _ = s.set_multicast_ttl_v4(255);
    let _ = s.set_multicast_loop_v4(false);
    s.set_nonblocking(true)?;
    UdpSocket::from_std(s.into())
}
