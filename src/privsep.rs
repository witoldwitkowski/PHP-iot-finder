//! Privilege separation.
//!
//! iotscan runs fine as an ordinary user. If it has been given `CAP_NET_RAW`
//! (`setcap cap_net_raw+ep`) or is started as root, it uses that privilege for
//! exactly one thing: opening raw ARP sockets. This happens in [`init`], which
//! must run **before the async runtime starts** (while the process is still
//! single-threaded), after which every capability is dropped for good and a root
//! process also drops to an unprivileged user. All parsing of untrusted network
//! data therefore happens without privileges.

use crate::caps;
use crate::discovery::arp::ArpSocket;
use crate::scope::LocalNet;
use crate::sys;

/// Outcome of privileged start-up.
pub struct Privileges {
    /// Opened raw ARP sockets, one per local subnet.
    pub arp: Vec<ArpSocket>,
    /// Human-readable notes (shown as warnings).
    pub notes: Vec<String>,
    /// Whether `CAP_NET_RAW` was available at start.
    pub raw_capable: bool,
    /// Whether the process started as root.
    pub was_root: bool,
}

/// Pick the unprivileged identity to drop to when started as root (`sudo`).
///
/// Returns `(uid, gid, from_sudo)`; `from_sudo` says the identity names a real user whose home we may use.
pub fn drop_target(sudo_uid: Option<&str>, sudo_gid: Option<&str>) -> (u32, u32, bool) {
    let parse = |s: Option<&str>| s.and_then(|v| v.parse::<u32>().ok()).filter(|n| *n != 0);
    match (parse(sudo_uid), parse(sudo_gid)) {
        (Some(u), Some(g)) => (u, g, true),
        (Some(u), None) => (u, u, true),
        _ => (65534, 65534, false), // nobody
    }
}

/// Look up a user's home directory in `/etc/passwd` text.
pub fn home_from_passwd(passwd: &str, uid: u32) -> Option<String> {
    passwd.lines().find_map(|l| {
        let f: Vec<&str> = l.split(':').collect();
        (f.len() >= 6 && f[2].parse::<u32>().ok() == Some(uid)).then(|| f[5].to_string())
    })
}

/// Open raw sockets if possible, then drop every privilege. Call once, before
/// starting threads. `will_exec_helpers` is true for the GUI, which launches the
/// user's browser.
pub fn init(want_arp: bool, nets: &[LocalNet], will_exec_helpers: bool) -> Result<Privileges, String> {
    let raw_capable = caps::can_raw();
    let was_root = sys::euid() == 0;
    let mut p = Privileges { arp: vec![], notes: vec![], raw_capable, was_root };

    if want_arp && raw_capable {
        for n in nets {
            match ArpSocket::open(&n.iface, n.addr, n.target.clone()) {
                Ok(s) => p.arp.push(s),
                Err(e) => p.notes.push(format!("raw ARP on {} unavailable: {e}", n.iface)),
            }
        }
    }
    // Without CAP_NET_RAW iotscan still works (kernel ARP cache); `iotscan doctor` explains how to enable the raw sweep.

    if was_root {
        let (uid, gid, from_sudo) = drop_target(std::env::var("SUDO_UID").ok().as_deref(), std::env::var("SUDO_GID").ok().as_deref());
        if from_sudo {
            // `sudo` keeps root's HOME; the invoking user's config and history live in their own.
            if let Ok(passwd) = std::fs::read_to_string("/etc/passwd")
                && let Some(h) = home_from_passwd(&passwd, uid)
            {
                crate::paths::set_home_override(h.into());
            }
        }
        sys::drop_to_user(uid, gid).map_err(|e| format!("refusing to continue as root: could not drop privileges: {e}"))?;
        p.notes.push(format!("started as root: dropped to uid {uid} after opening sockets (prefer: setcap instead of sudo)"));
    }
    // Capabilities are per-thread; we are still single-threaded here, so no thread can inherit them.
    // `no_new_privs` is inherited by children; skip it when we will launch a (possibly snap-packaged) browser.
    let _ = sys::drop_all_capabilities(!will_exec_helpers);
    Ok(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drop_target_choices() {
        assert_eq!(drop_target(Some("1000"), Some("1000")), (1000, 1000, true));
        assert_eq!(drop_target(Some("1000"), None), (1000, 1000, true));
        assert_eq!(drop_target(None, None), (65534, 65534, false));
        assert_eq!(drop_target(Some("0"), Some("0")), (65534, 65534, false), "never 'drop' to root");
        assert_eq!(drop_target(Some("abc"), Some("5")), (65534, 65534, false));
    }

    #[test]
    fn passwd_lookup() {
        let p = "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000:Alice:/home/alice:/bin/bash\nbad line\n";
        assert_eq!(home_from_passwd(p, 1000).as_deref(), Some("/home/alice"));
        assert_eq!(home_from_passwd(p, 0).as_deref(), Some("/root"));
        assert_eq!(home_from_passwd(p, 7), None);
    }
}
