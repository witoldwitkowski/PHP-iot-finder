//! The only module in the crate that contains `unsafe` code.
//!
//! It wraps a handful of Linux syscalls needed for the optional raw-ARP sweep
//! and for dropping privileges afterwards. Each wrapper is tiny, documents its
//! safety argument, and returns an `io::Result`.

#![allow(unsafe_code)]

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

/// `ETH_P_ARP` in host order.
pub const ETH_P_ARP: u16 = 0x0806;

/// Open a raw `AF_PACKET` socket that only receives ARP frames on `ifindex`.
/// Requires `CAP_NET_RAW`.
pub fn open_arp_socket(ifindex: i32) -> io::Result<OwnedFd> {
    // SAFETY: socket() has no memory-safety preconditions; the returned fd is
    // checked and immediately wrapped in an OwnedFd, which closes it on drop.
    let raw = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW | libc::SOCK_CLOEXEC, (ETH_P_ARP).to_be() as i32) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw` is a valid, owned file descriptor we just created.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };

    // SAFETY: sockaddr_ll is plain-old-data; zeroed is a valid initial state.
    let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    addr.sll_family = libc::AF_PACKET as u16;
    addr.sll_protocol = ETH_P_ARP.to_be();
    addr.sll_ifindex = ifindex;
    // SAFETY: `addr` outlives the call and the length matches its type.
    let rc = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            &addr as *const libc::sockaddr_ll as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

/// Set the receive timeout on a socket.
pub fn set_recv_timeout(fd: &OwnedFd, ms: u64) -> io::Result<()> {
    let tv = libc::timeval { tv_sec: (ms / 1000) as _, tv_usec: ((ms % 1000) * 1000) as _ };
    // SAFETY: `tv` is a valid timeval for the duration of the call.
    let rc = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const libc::timeval as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if rc < 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
}

/// Send one Ethernet frame out of `ifindex`.
pub fn send_frame(fd: &OwnedFd, ifindex: i32, frame: &[u8]) -> io::Result<usize> {
    // SAFETY: zeroed sockaddr_ll is valid POD.
    let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    addr.sll_family = libc::AF_PACKET as u16;
    addr.sll_protocol = ETH_P_ARP.to_be();
    addr.sll_ifindex = ifindex;
    addr.sll_halen = 6;
    addr.sll_addr[..6].copy_from_slice(&[0xff; 6]);
    // SAFETY: `frame` and `addr` are valid for the lengths passed.
    let n = unsafe {
        libc::sendto(
            fd.as_raw_fd(),
            frame.as_ptr() as *const libc::c_void,
            frame.len(),
            0,
            &addr as *const libc::sockaddr_ll as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if n < 0 { Err(io::Error::last_os_error()) } else { Ok(n as usize) }
}

/// Receive one frame; honours the socket's receive timeout.
/// Returns `Ok(None)` on timeout.
pub fn recv_frame(fd: &OwnedFd, buf: &mut [u8]) -> io::Result<Option<usize>> {
    // SAFETY: `buf` is valid for writes of `buf.len()` bytes.
    let n = unsafe { libc::recv(fd.as_raw_fd(), buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
    if n >= 0 {
        return Ok(Some(n as usize));
    }
    let e = io::Error::last_os_error();
    match e.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted => Ok(None),
        _ => Err(e),
    }
}

/// Effective user id.
pub fn euid() -> u32 {
    // SAFETY: geteuid() cannot fail and has no preconditions.
    unsafe { libc::geteuid() }
}

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

/// Permanently give up every capability on the *calling thread* and, when
/// `no_new_privs` is set, forbid gaining privileges through exec (inherited by
/// children, so it is skipped when we must launch desktop helpers such as a
/// snap-packaged browser). Must be called while the process is still
/// single-threaded so that no later thread inherits capabilities.
pub fn drop_all_capabilities(no_new_privs: bool) -> io::Result<()> {
    // Best effort: clear ambient set and shrink the bounding set (needs CAP_SETPCAP; failures are fine).
    // SAFETY: prctl with these constant arguments has no pointer parameters.
    unsafe {
        libc::prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_CLEAR_ALL as libc::c_ulong, 0, 0, 0);
        for cap in 0..64 {
            if libc::prctl(libc::PR_CAPBSET_READ, cap as libc::c_ulong, 0, 0, 0) < 0 {
                break;
            }
            libc::prctl(libc::PR_CAPBSET_DROP, cap as libc::c_ulong, 0, 0, 0);
        }
    }
    let mut hdr = CapHeader { version: LINUX_CAPABILITY_VERSION_3, pid: 0 };
    let data = [CapData { effective: 0, permitted: 0, inheritable: 0 }; 2];
    // SAFETY: hdr and data are valid #[repr(C)] structs matching the kernel ABI for version 3
    // (one header, two data elements) and live for the duration of the call.
    let rc = unsafe { libc::syscall(libc::SYS_capset, &mut hdr as *mut CapHeader, data.as_ptr()) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    if no_new_privs {
        // SAFETY: constant-argument prctl.
        let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1 as libc::c_ulong, 0, 0, 0) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Switch from root to an unprivileged user/group (irreversibly).
pub fn drop_to_user(uid: u32, gid: u32) -> io::Result<()> {
    // SAFETY: setgroups with size 0 ignores the pointer; the set*id calls take plain integers.
    unsafe {
        if libc::setgroups(0, std::ptr::null()) < 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::setresgid(gid, gid, gid) < 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::setresuid(uid, uid, uid) < 0 {
            return Err(io::Error::last_os_error());
        }
        // Verify the drop is irreversible.
        if uid != 0 && libc::setuid(0) == 0 {
            return Err(io::Error::other("privilege drop did not stick"));
        }
    }
    Ok(())
}

/// Number of capabilities in the effective set (for tests/diagnostics).
pub fn effective_caps_raw() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| s.lines().find_map(|l| l.strip_prefix("CapEff:").and_then(|v| u64::from_str_radix(v.trim(), 16).ok())))
        .unwrap_or(0)
}

/// Width of the terminal attached to stdout, if any.
pub fn terminal_width() -> Option<usize> {
    // SAFETY: winsize is plain-old-data and TIOCGWINSZ fills it; the pointer is valid for the call.
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut ws as *mut libc::winsize) };
    (rc == 0 && ws.ws_col > 0).then_some(ws.ws_col as usize)
}
