//! The kernel neighbour (ARP) cache. After a TCP sweep, every host that
//! answered ARP appears here with its MAC, even if it ignored our SYNs. This
//! needs no privileges.

use crate::util::{fmt_mac, parse_mac};
use std::net::{IpAddr, Ipv4Addr};

/// One complete ARP cache entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Neighbor {
    /// IPv4 address.
    pub ip: Ipv4Addr,
    /// MAC (lowercase, colon separated).
    pub mac: String,
    /// Interface name.
    pub iface: String,
}

/// Parse the text of `/proc/net/arp`.
pub fn parse(text: &str) -> Vec<Neighbor> {
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 6 {
            continue;
        }
        let (Ok(ip), flags, mac, iface) = (cols[0].parse::<Ipv4Addr>(), cols[2], cols[3], cols[5]) else { continue };
        // Flag 0x2 = ATF_COM: the entry is resolved. Incomplete entries have no usable MAC.
        let Some(fl) = flags.strip_prefix("0x").and_then(|f| u32::from_str_radix(f, 16).ok()) else { continue };
        if fl & 0x2 == 0 || mac == "00:00:00:00:00:00" {
            continue;
        }
        let Some(m) = parse_mac(mac) else { continue };
        out.push(Neighbor { ip, mac: fmt_mac(&m), iface: iface.chars().take(32).collect() });
    }
    out
}

/// Read the live ARP cache; empty on non-Linux systems or errors.
pub fn read() -> Vec<Neighbor> {
    std::fs::read_to_string("/proc/net/arp").map(|t| parse(&t)).unwrap_or_default()
}

/// Neighbours as `(IpAddr, mac)` pairs.
pub fn pairs(n: &[Neighbor]) -> Vec<(IpAddr, String)> {
    n.iter().map(|x| (IpAddr::V4(x.ip), x.mac.clone())).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "IP address       HW type     Flags       HW address            Mask     Device\n\
192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:01     *        eth0\n\
192.168.1.20     0x1         0x0         00:00:00:00:00:00     *        eth0\n\
192.168.1.21     0x1         0x6         aa:bb:cc:dd:ee:21     *        eth0\n\
192.168.1.22     0x1         0x2         AA-BB-CC-DD-EE-22     *        wlan0\n\
garbage line\n\
999.1.1.1        0x1         0x2         aa:bb:cc:dd:ee:99     *        eth0\n";

    #[test]
    fn parses_complete_entries_only() {
        let n = parse(SAMPLE);
        let ips: Vec<String> = n.iter().map(|x| x.ip.to_string()).collect();
        assert_eq!(ips, vec!["192.168.1.1", "192.168.1.21", "192.168.1.22"]);
        assert_eq!(n[0].mac, "aa:bb:cc:dd:ee:01");
        assert_eq!(n[2].iface, "wlan0");
    }

    #[test]
    fn empty_and_header_only() {
        assert!(parse("").is_empty());
        assert!(parse("IP address HW type Flags HW address Mask Device\n").is_empty());
    }
}
