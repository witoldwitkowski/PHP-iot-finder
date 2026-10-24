//! Optional raw ARP sweep (needs `CAP_NET_RAW`).
//!
//! Without the capability the scanner still learns MAC addresses from the
//! kernel's ARP cache (see [`super::neigh`]). The raw sweep is faster and finds
//! hosts that silently drop TCP and ICMP. Sockets are opened *before* the async
//! runtime starts and privileges are dropped immediately afterwards (see
//! [`crate::privsep`]).

use crate::sys;
use crate::util::parse_mac;
use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::os::fd::OwnedFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// A raw ARP socket bound to one interface.
pub struct ArpSocket {
    /// Interface name.
    pub iface: String,
    /// Kernel interface index.
    pub ifindex: i32,
    /// Our MAC on that interface.
    pub mac: [u8; 6],
    /// Our IPv4 address on that interface.
    pub ip: Ipv4Addr,
    /// The subnet this socket sweeps.
    pub target: crate::scope::Target,
    fd: OwnedFd,
}

/// Build a 42-byte Ethernet+ARP "who-has" frame.
pub fn build_request(src_mac: &[u8; 6], src_ip: Ipv4Addr, target: Ipv4Addr) -> [u8; 42] {
    let mut f = [0u8; 42];
    f[0..6].copy_from_slice(&[0xff; 6]); // dst: broadcast
    f[6..12].copy_from_slice(src_mac); // src
    f[12..14].copy_from_slice(&[0x08, 0x06]); // ethertype ARP
    f[14..16].copy_from_slice(&[0x00, 0x01]); // hw type: ethernet
    f[16..18].copy_from_slice(&[0x08, 0x00]); // proto: IPv4
    f[18] = 6; // hw len
    f[19] = 4; // proto len
    f[20..22].copy_from_slice(&[0x00, 0x01]); // op: request
    f[22..28].copy_from_slice(src_mac); // sender hw
    f[28..32].copy_from_slice(&src_ip.octets()); // sender ip
    // target hw (32..38) stays zero
    f[38..42].copy_from_slice(&target.octets());
    f
}

/// Parse an ARP reply frame into (sender IP, sender MAC).
pub fn parse_reply(frame: &[u8]) -> Option<(Ipv4Addr, [u8; 6])> {
    if frame.len() < 42 || frame[12..14] != [0x08, 0x06] {
        return None;
    }
    // hw type ethernet, proto IPv4, sizes 6/4, op = reply
    if frame[14..16] != [0, 1] || frame[16..18] != [8, 0] || frame[18] != 6 || frame[19] != 4 || frame[20..22] != [0, 2] {
        return None;
    }
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&frame[22..28]);
    let ip = Ipv4Addr::new(frame[28], frame[29], frame[30], frame[31]);
    if ip.is_unspecified() || mac == [0; 6] || mac == [0xff; 6] {
        return None;
    }
    Some((ip, mac))
}

impl ArpSocket {
    /// Open a socket for `iface` with address `ip`. Needs `CAP_NET_RAW`.
    pub fn open(iface: &str, ip: Ipv4Addr, target: crate::scope::Target) -> std::io::Result<ArpSocket> {
        let base = format!("/sys/class/net/{iface}");
        let ifindex: i32 =
            std::fs::read_to_string(format!("{base}/ifindex"))?.trim().parse().map_err(|_| std::io::Error::other("bad ifindex"))?;
        let mac = parse_mac(std::fs::read_to_string(format!("{base}/address"))?.trim())
            .ok_or_else(|| std::io::Error::other("bad interface MAC"))?;
        if mac == [0; 6] {
            return Err(std::io::Error::other("interface has no hardware address"));
        }
        let fd = sys::open_arp_socket(ifindex)?;
        Ok(ArpSocket { iface: iface.to_string(), ifindex, mac, ip, target, fd })
    }

    /// Blocking sweep: ask every address in `targets` who it is and collect replies.
    /// Runs on a blocking thread; `pps` paces the requests.
    pub fn sweep(&self, targets: &[Ipv4Addr], pps: u32, listen: Duration, cancel: &AtomicBool) -> Vec<(Ipv4Addr, [u8; 6])> {
        let mut found: BTreeMap<Ipv4Addr, [u8; 6]> = BTreeMap::new();
        let mut buf = [0u8; 2048];
        let gap = Duration::from_secs_f64(1.0 / pps.max(1) as f64);
        let _ = sys::set_recv_timeout(&self.fd, 1);
        for t in targets {
            if cancel.load(Ordering::Relaxed) {
                return found.into_iter().collect();
            }
            if *t == self.ip {
                continue;
            }
            let _ = sys::send_frame(&self.fd, self.ifindex, &build_request(&self.mac, self.ip, *t));
            let until = Instant::now() + gap;
            while Instant::now() < until {
                match sys::recv_frame(&self.fd, &mut buf) {
                    Ok(Some(n)) => {
                        if let Some((ip, mac)) = parse_reply(&buf[..n]) {
                            found.insert(ip, mac);
                        }
                    }
                    _ => break,
                }
            }
        }
        let _ = sys::set_recv_timeout(&self.fd, 100);
        let end = Instant::now() + listen;
        while Instant::now() < end && !cancel.load(Ordering::Relaxed) {
            match sys::recv_frame(&self.fd, &mut buf) {
                Ok(Some(n)) => {
                    if let Some((ip, mac)) = parse_reply(&buf[..n]) {
                        found.insert(ip, mac);
                    }
                }
                Ok(None) => {}
                Err(_) => break,
            }
        }
        found.remove(&self.ip);
        found.into_iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_layout() {
        let mac = [0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee];
        let f = build_request(&mac, "192.168.1.2".parse().unwrap(), "192.168.1.9".parse().unwrap());
        assert_eq!(f.len(), 42);
        assert_eq!(&f[0..6], &[0xff; 6]);
        assert_eq!(&f[6..12], &mac);
        assert_eq!(&f[12..14], &[0x08, 0x06]);
        assert_eq!(&f[20..22], &[0, 1]);
        assert_eq!(&f[28..32], &[192, 168, 1, 2]);
        assert_eq!(&f[38..42], &[192, 168, 1, 9]);
    }

    #[test]
    fn reply_parse() {
        let mut f = build_request(&[2, 1, 1, 1, 1, 1], "192.168.1.9".parse().unwrap(), "192.168.1.2".parse().unwrap());
        // Turn it into a reply: op=2.
        f[21] = 2;
        let (ip, mac) = parse_reply(&f).unwrap();
        assert_eq!(ip, "192.168.1.9".parse::<Ipv4Addr>().unwrap());
        assert_eq!(mac, [2, 1, 1, 1, 1, 1]);
    }

    #[test]
    fn rejects_requests_garbage_and_short() {
        let req = build_request(&[2, 1, 1, 1, 1, 1], "192.168.1.9".parse().unwrap(), "192.168.1.2".parse().unwrap());
        assert!(parse_reply(&req).is_none(), "requests are not replies");
        assert!(parse_reply(&[0u8; 10]).is_none());
        assert!(parse_reply(&[]).is_none());
        let mut bad = req;
        bad[21] = 2;
        bad[12] = 0x86;
        assert!(parse_reply(&bad).is_none());
        let mut zero = req;
        zero[21] = 2;
        zero[28..32].copy_from_slice(&[0, 0, 0, 0]);
        assert!(parse_reply(&zero).is_none());
    }

    #[test]
    fn random_frames_never_panic() {
        let mut x: u64 = 88172645463325252;
        for _ in 0..20_000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let len = (x % 80) as usize;
            let buf: Vec<u8> = (0..len).map(|i| (x >> (i % 56)) as u8).collect();
            let _ = parse_reply(&buf);
        }
    }
}
