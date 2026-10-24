//! Target parsing, address classification and local-subnet detection.
//!
//! The scanner is meant for networks you own. Everything outside private,
//! link-local, unique-local and loopback space is classified as *public* and
//! needs an explicit confirmation before it is scanned.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Default cap on the number of addresses in one scan.
pub const DEFAULT_MAX_HOSTS: usize = 4096;

/// One parsed target specification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    /// A single address.
    Addr(IpAddr),
    /// An IPv4 CIDR block (`192.168.1.0/24`).
    V4Net {
        /// First address of the block.
        base: u32,
        /// Prefix length 0-32.
        prefix: u8,
    },
    /// An inclusive IPv4 range (`192.168.1.10-192.168.1.50`).
    V4Range {
        /// First address.
        start: u32,
        /// Last address.
        end: u32,
    },
}

/// Error from parsing or expanding targets.
#[derive(Debug, PartialEq, Eq)]
pub struct ScopeError(pub String);

impl fmt::Display for ScopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for ScopeError {}

fn err<T>(s: impl Into<String>) -> Result<T, ScopeError> {
    Err(ScopeError(s.into()))
}

impl Target {
    /// Parse `1.2.3.4`, `1.2.3.0/24`, `1.2.3.4-1.2.3.9`, `1.2.3.4-9` or an IPv6 address.
    pub fn parse(spec: &str) -> Result<Target, ScopeError> {
        let spec = spec.trim();
        if spec.is_empty() {
            return err("empty target");
        }
        if let Some((ip, len)) = spec.split_once('/') {
            let ip: Ipv4Addr = ip.parse().map_err(|_| ScopeError(format!("invalid CIDR address in '{spec}'")))?;
            let prefix: u8 = len.parse().map_err(|_| ScopeError(format!("invalid prefix length in '{spec}'")))?;
            if prefix > 32 {
                return err(format!("prefix length out of range in '{spec}'"));
            }
            let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
            return Ok(Target::V4Net { base: u32::from(ip) & mask, prefix });
        }
        if let Some((a, b)) = spec.split_once('-') {
            let start: Ipv4Addr = a.trim().parse().map_err(|_| ScopeError(format!("invalid range start in '{spec}'")))?;
            let end: Ipv4Addr = if let Ok(full) = b.trim().parse::<Ipv4Addr>() {
                full
            } else if let Ok(last) = b.trim().parse::<u8>() {
                let o = start.octets();
                Ipv4Addr::new(o[0], o[1], o[2], last)
            } else {
                return err(format!("invalid range end in '{spec}'"));
            };
            let (s, e) = (u32::from(start), u32::from(end));
            if e < s {
                return err(format!("range end is before start in '{spec}'"));
            }
            return Ok(Target::V4Range { start: s, end: e });
        }
        let ip: IpAddr = spec.parse().map_err(|_| ScopeError(format!("'{spec}' is not an IP address, CIDR block or range")))?;
        Ok(Target::Addr(ip))
    }

    /// Number of addresses this target expands to.
    pub fn len(&self) -> u64 {
        match self {
            Target::Addr(_) => 1,
            Target::V4Net { prefix, .. } => hosts_in_prefix(*prefix),
            Target::V4Range { start, end } => (*end as u64) - (*start as u64) + 1,
        }
    }

    /// True when the target is empty (never, kept for clippy symmetry).
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// First and last IPv4 address scanned, or `None` for IPv6.
    fn v4_bounds(&self) -> Option<(u32, u32)> {
        match self {
            Target::Addr(IpAddr::V4(a)) => Some((u32::from(*a), u32::from(*a))),
            Target::Addr(IpAddr::V6(_)) => None,
            Target::V4Net { base, prefix } => {
                let size = 1u64 << (32 - *prefix as u64);
                let last = *base as u64 + size - 1;
                if *prefix >= 31 {
                    Some((*base, last as u32))
                } else {
                    // Skip network and broadcast addresses.
                    Some((base.saturating_add(1), (last - 1) as u32))
                }
            }
            Target::V4Range { start, end } => Some((*start, *end)),
        }
    }

    /// True if `ip` lies inside the target.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self, ip) {
            (Target::Addr(a), b) => *a == b,
            (_, IpAddr::V4(v4)) => {
                let x = u32::from(v4);
                self.v4_bounds().is_some_and(|(s, e)| x >= s && x <= e)
            }
            _ => false,
        }
    }

    /// Whether every address in the target is private/local.
    pub fn is_local_only(&self) -> bool {
        match self {
            Target::Addr(ip) => is_local_scope(*ip),
            _ => match self.v4_bounds() {
                Some((s, e)) => {
                    is_local_scope(IpAddr::V4(Ipv4Addr::from(s))) && is_local_scope(IpAddr::V4(Ipv4Addr::from(e))) && range_is_local(s, e)
                }
                None => false,
            },
        }
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Target::Addr(a) => write!(f, "{a}"),
            Target::V4Net { base, prefix } => write!(f, "{}/{}", Ipv4Addr::from(*base), prefix),
            Target::V4Range { start, end } => write!(f, "{}-{}", Ipv4Addr::from(*start), Ipv4Addr::from(*end)),
        }
    }
}

fn hosts_in_prefix(prefix: u8) -> u64 {
    let size = 1u64 << (32 - prefix as u64);
    if prefix >= 31 { size } else { size - 2 }
}

/// A range is local only if it does not straddle private and public space.
fn range_is_local(s: u32, e: u32) -> bool {
    const BLOCKS: [(u32, u32); 5] = [
        (0x0A00_0000, 0x0AFF_FFFF), // 10/8
        (0xAC10_0000, 0xAC1F_FFFF), // 172.16/12
        (0xC0A8_0000, 0xC0A8_FFFF), // 192.168/16
        (0xA9FE_0000, 0xA9FE_FFFF), // 169.254/16
        (0x7F00_0000, 0x7FFF_FFFF), // 127/8
    ];
    BLOCKS.iter().any(|&(bs, be)| s >= bs && e <= be)
}

/// True for loopback, RFC 1918, link-local and IPv6 unique-local/link-local addresses.
pub fn is_local_scope(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => a.is_private() || a.is_loopback() || a.is_link_local(),
        IpAddr::V6(a) => is_v6_local(&a),
    }
}

fn is_v6_local(a: &Ipv6Addr) -> bool {
    let seg = a.segments();
    a.is_loopback() || (seg[0] & 0xfe00) == 0xfc00 || (seg[0] & 0xffc0) == 0xfe80
}

/// The set of targets for a scan.
#[derive(Clone, Debug, Default)]
pub struct Scope {
    /// Parsed targets.
    pub targets: Vec<Target>,
}

impl Scope {
    /// Parse a list of target specs.
    pub fn parse(specs: &[String]) -> Result<Scope, ScopeError> {
        let mut targets = Vec::new();
        for s in specs {
            for part in s.split(',').map(str::trim).filter(|p| !p.is_empty()) {
                targets.push(Target::parse(part)?);
            }
        }
        if targets.is_empty() {
            return err("no targets given");
        }
        Ok(Scope { targets })
    }

    /// Total number of addresses (duplicates counted).
    pub fn size(&self) -> u64 {
        self.targets.iter().map(Target::len).sum()
    }

    /// Targets that include non-local addresses.
    pub fn public_targets(&self) -> Vec<String> {
        self.targets.iter().filter(|t| !t.is_local_only()).map(|t| t.to_string()).collect()
    }

    /// True if `ip` is within any target.
    pub fn contains(&self, ip: IpAddr) -> bool {
        self.targets.iter().any(|t| t.contains(ip))
    }

    /// Expand to a deduplicated, sorted address list, failing above `max_hosts`.
    pub fn expand(&self, max_hosts: usize) -> Result<Vec<IpAddr>, ScopeError> {
        let total = self.size();
        if total > max_hosts as u64 {
            return err(format!(
                "targets expand to {total} addresses, above the limit of {max_hosts}; narrow the range or raise --max-hosts"
            ));
        }
        let mut v4: Vec<u32> = Vec::new();
        let mut other: Vec<IpAddr> = Vec::new();
        for t in &self.targets {
            match t {
                Target::Addr(IpAddr::V6(a)) => other.push(IpAddr::V6(*a)),
                t => {
                    if let Some((s, e)) = t.v4_bounds() {
                        v4.extend(s..=e);
                    }
                }
            }
        }
        v4.sort_unstable();
        v4.dedup();
        other.sort();
        other.dedup();
        let mut out: Vec<IpAddr> = v4.into_iter().map(|x| IpAddr::V4(Ipv4Addr::from(x))).collect();
        out.extend(other);
        Ok(out)
    }
}

/// An IPv4 subnet attached to a local interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalNet {
    /// Interface name.
    pub iface: String,
    /// Our address on that interface.
    pub addr: Ipv4Addr,
    /// Prefix length of the interface.
    pub prefix: u8,
    /// The target actually scanned (may be narrowed to a /24).
    pub target: Target,
    /// Set when the real subnet was larger than we scan.
    pub narrowed: bool,
}

fn is_virtual_iface(name: &str) -> bool {
    ["lo", "docker", "veth", "br-", "virbr", "lxcbr", "lxdbr", "cni", "flannel", "cali", "tun", "tap", "wg", "tailscale", "zt"]
        .iter()
        .any(|p| name == *p || (p.len() > 1 && name.starts_with(p)))
}

/// Pure helper: narrow a (addr, prefix) to the block we will scan.
pub fn subnet_target(addr: Ipv4Addr, prefix: u8, max_hosts: usize) -> (Target, bool) {
    let mut p = prefix.clamp(8, 32);
    let mut narrowed = p != prefix;
    while hosts_in_prefix(p) > max_hosts as u64 && p < 30 {
        p += 1;
        narrowed = true;
    }
    if prefix > 30 {
        // /31 and /32 links: just scan the block as configured.
        let mask = if prefix == 32 { u32::MAX } else { u32::MAX << (32 - prefix) };
        return (Target::V4Net { base: u32::from(addr) & mask, prefix }, false);
    }
    let mask = u32::MAX << (32 - p);
    (Target::V4Net { base: u32::from(addr) & mask, prefix: p }, narrowed)
}

/// Detect the IPv4 subnets of physical-looking, non-loopback interfaces.
pub fn local_subnets(max_hosts: usize, only_iface: Option<&str>) -> Vec<LocalNet> {
    let mut out: Vec<LocalNet> = Vec::new();
    let Ok(ifaces) = if_addrs::get_if_addrs() else {
        return out;
    };
    for ifa in ifaces {
        if ifa.is_loopback() {
            continue;
        }
        if let Some(want) = only_iface {
            if ifa.name != want {
                continue;
            }
        } else if is_virtual_iface(&ifa.name) {
            continue;
        }
        if let if_addrs::IfAddr::V4(v4) = &ifa.addr {
            if v4.ip.is_link_local() || v4.ip.is_unspecified() {
                continue;
            }
            let prefix = u32::from(v4.netmask).count_ones() as u8;
            let (target, narrowed) = subnet_target(v4.ip, prefix, max_hosts);
            let net = LocalNet { iface: ifa.name.clone(), addr: v4.ip, prefix, target, narrowed };
            if !out.iter().any(|o| o.target == net.target) {
                out.push(net);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn parse_forms() {
        assert_eq!(Target::parse("192.168.1.7").unwrap(), Target::Addr(ip("192.168.1.7")));
        assert_eq!(Target::parse("192.168.1.77/24").unwrap().to_string(), "192.168.1.0/24");
        assert_eq!(Target::parse("10.0.0.5-10.0.0.9").unwrap().len(), 5);
        assert_eq!(Target::parse("10.0.0.5-9").unwrap().len(), 5);
        assert!(Target::parse("10.0.0.9-5").is_err());
        assert!(Target::parse("10.0.0.0/33").is_err());
        assert!(Target::parse("example.com").is_err());
        assert!(Target::parse("").is_err());
        assert!(Target::parse("fe80::1").is_ok());
    }

    #[test]
    fn expand_skips_network_and_broadcast() {
        let s = Scope::parse(&["192.168.1.0/24".into()]).unwrap();
        let hosts = s.expand(4096).unwrap();
        assert_eq!(hosts.len(), 254);
        assert_eq!(hosts[0], ip("192.168.1.1"));
        assert_eq!(*hosts.last().unwrap(), ip("192.168.1.254"));
    }

    #[test]
    fn expand_small_prefixes_and_dedup() {
        assert_eq!(Scope::parse(&["10.0.0.1/32".into()]).unwrap().expand(10).unwrap().len(), 1);
        assert_eq!(Scope::parse(&["10.0.0.0/31".into()]).unwrap().expand(10).unwrap().len(), 2);
        let s = Scope::parse(&["10.0.0.1,10.0.0.1,10.0.0.2".into()]).unwrap();
        assert_eq!(s.expand(10).unwrap().len(), 2);
    }

    #[test]
    fn expand_enforces_limit() {
        let s = Scope::parse(&["10.0.0.0/16".into()]).unwrap();
        assert!(s.expand(4096).unwrap_err().0.contains("limit"));
        assert_eq!(s.expand(70_000).unwrap().len(), 65_534);
    }

    #[test]
    fn classification() {
        for a in ["10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.0.1", "169.254.1.1", "127.0.0.1", "fe80::1", "fd12::1", "::1"] {
            assert!(is_local_scope(ip(a)), "{a}");
        }
        for a in ["8.8.8.8", "172.32.0.1", "100.64.0.1", "1.1.1.1", "2001:4860::1", "192.169.0.1"] {
            assert!(!is_local_scope(ip(a)), "{a}");
        }
    }

    #[test]
    fn public_targets_detected() {
        let s = Scope::parse(&["192.168.1.0/24".into(), "8.8.8.0/24".into(), "10.0.0.1-10.0.0.9".into()]).unwrap();
        assert_eq!(s.public_targets(), vec!["8.8.8.0/24".to_string()]);
        // A range that straddles private and public space is public.
        let s = Scope::parse(&["10.255.255.250-11.0.0.5".into()]).unwrap();
        assert_eq!(s.public_targets().len(), 1);
        // The whole internet is public.
        assert_eq!(Scope::parse(&["0.0.0.0/0".into()]).unwrap().public_targets().len(), 1);
    }

    #[test]
    fn contains_works() {
        let s = Scope::parse(&["192.168.1.0/24".into(), "10.0.0.5".into()]).unwrap();
        assert!(s.contains(ip("192.168.1.9")));
        assert!(!s.contains(ip("192.168.2.9")));
        assert!(!s.contains(ip("192.168.1.255")), "broadcast excluded");
        assert!(s.contains(ip("10.0.0.5")));
    }

    #[test]
    fn narrowing() {
        let (t, narrowed) = subnet_target("192.168.50.20".parse().unwrap(), 16, 4096);
        assert!(narrowed);
        assert_eq!(t.to_string(), "192.168.48.0/20");
        assert!(t.len() <= 4096);
        let (t, narrowed) = subnet_target("192.168.1.20".parse().unwrap(), 24, 4096);
        assert!(!narrowed);
        assert_eq!(t.to_string(), "192.168.1.0/24");
    }

    #[test]
    fn virtual_ifaces_skipped() {
        assert!(is_virtual_iface("docker0"));
        assert!(is_virtual_iface("veth1234"));
        assert!(is_virtual_iface("lo"));
        assert!(!is_virtual_iface("eth0"));
        assert!(!is_virtual_iface("wlp3s0"));
        assert!(!is_virtual_iface("enp0s31f6"));
    }
}
