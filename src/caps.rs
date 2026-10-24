//! Linux capability introspection (no unsafe, reads `/proc/self/status`).

/// `CAP_NET_RAW` bit number.
pub const CAP_NET_RAW: u32 = 13;

/// Parse the `CapEff` line of `/proc/<pid>/status`.
pub fn parse_cap_eff(status: &str) -> Option<u64> {
    status.lines().find_map(|l| l.strip_prefix("CapEff:").and_then(|v| u64::from_str_radix(v.trim(), 16).ok()))
}

/// True if the effective set contains `cap`.
pub fn has_cap(eff: u64, cap: u32) -> bool {
    cap < 64 && eff & (1u64 << cap) != 0
}

/// Whether this process can open raw sockets right now.
pub fn can_raw() -> bool {
    std::fs::read_to_string("/proc/self/status").ok().and_then(|s| parse_cap_eff(&s)).is_some_and(|e| has_cap(e, CAP_NET_RAW))
}

/// The command a user should run to grant the capability to a binary.
pub fn setcap_hint(exe: &str) -> String {
    format!("sudo setcap cap_net_raw+ep {exe}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_status() {
        let s = "Name:\tx\nCapInh:\t0000000000000000\nCapPrm:\t0000000000002000\nCapEff:\t0000000000002000\nCapBnd:\t000001ffffffffff\n";
        let e = parse_cap_eff(s).unwrap();
        assert!(has_cap(e, CAP_NET_RAW));
        assert!(!has_cap(e, 12));
        assert_eq!(parse_cap_eff("nothing here"), None);
        assert!(!has_cap(0, CAP_NET_RAW));
        assert!(has_cap(0x000001fffeffffff, CAP_NET_RAW));
        assert!(!has_cap(u64::MAX, 64));
    }

    #[test]
    fn hint() {
        assert_eq!(setcap_hint("/usr/bin/iotscan"), "sudo setcap cap_net_raw+ep /usr/bin/iotscan");
    }
}
