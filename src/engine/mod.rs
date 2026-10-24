//! The scan engine: discovery → identification → probes → checks.
//!
//! All network I/O in the program happens here (and in the discovery modules it
//! drives), under one [`NetCtx`] that enforces concurrency caps, a global rate
//! limit and cancellation. Checkers only see the collected evidence.

pub mod enrich;
pub mod probes;
pub mod sweep;

use crate::advisories::AdvisoryDb;
use crate::allowlist::Allowlist;
use crate::checkers::{CheckInput, Need, Registry, php_facts};
use crate::discovery::mdns::MdnsDevice;
use crate::discovery::{arp::ArpSocket, icmp6, mdns, neigh, ssdp};
use crate::fingerprint::{identify, php::PhpDetection};
use crate::http::Timeouts;
use crate::limits::{Limits, NetCtx};
use crate::model::*;
use crate::progress::Progress;
use crate::scope::{self, Scope, Target};
use crate::util::{self, Date, fmt_mac, parse_mac};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use sweep::{EarlyExit, Scopes};
use tokio::task::JoinSet;

/// Privileged resources prepared before the runtime started.
#[derive(Default)]
pub struct Environment {
    /// Raw ARP sockets (empty without `CAP_NET_RAW`).
    pub arp: Vec<ArpSocket>,
    /// Start-up notes surfaced as warnings.
    pub notes: Vec<String>,
}

impl Environment {
    /// No privileged resources (the normal, unprivileged case, and tests).
    pub fn none() -> Environment {
        Environment::default()
    }
}

impl From<crate::privsep::Privileges> for Environment {
    fn from(p: crate::privsep::Privileges) -> Self {
        Environment { arp: p.arp, notes: p.notes }
    }
}

/// Everything configurable about a scan.
#[derive(Clone)]
pub struct ScanOptions {
    /// Target specs; empty or `auto` means the local subnets.
    pub targets: Vec<String>,
    /// Ports to sweep (checker-requested ports are added).
    pub ports: Vec<u16>,
    /// Politeness limits.
    pub limits: Limits,
    /// Enable intrusive (extra-request) probes.
    pub active: bool,
    /// Use mDNS.
    pub mdns: bool,
    /// Use SSDP.
    pub ssdp: bool,
    /// Discover IPv6 neighbours.
    pub ipv6: bool,
    /// Use raw ARP when sockets are available.
    pub arp: bool,
    /// Refuse to expand beyond this many addresses.
    pub max_hosts: usize,
    /// Only use this interface for auto-detection and multicast.
    pub iface: Option<String>,
    /// Permit non-private targets.
    pub allow_public: bool,
    /// Run only these checkers.
    pub only: Vec<String>,
    /// Skip these checkers.
    pub skip: Vec<String>,
    /// Extra advisory file.
    pub advisories: Option<PathBuf>,
    /// Suppressions.
    pub allowlist: Allowlist,
    /// Multicast listen window.
    pub discovery_window: Duration,
    /// Override "today" (tests).
    pub today: Option<Date>,
}

impl Default for ScanOptions {
    fn default() -> Self {
        ScanOptions {
            targets: vec![],
            ports: crate::ports::default_ports(),
            limits: Limits::default(),
            active: false,
            mdns: true,
            ssdp: true,
            ipv6: true,
            arp: true,
            max_hosts: scope::DEFAULT_MAX_HOSTS,
            iface: None,
            allow_public: false,
            only: vec![],
            skip: vec![],
            advisories: None,
            allowlist: Allowlist::default(),
            discovery_window: Duration::from_millis(3000),
            today: None,
        }
    }
}

/// Why a scan could not run.
#[derive(Debug)]
pub enum ScanError {
    /// Bad target/port/checker configuration.
    Config(String),
    /// Targets include public addresses and `allow_public` is off.
    PublicRange(Vec<String>),
    /// Cancelled by the user.
    Cancelled,
}

impl std::fmt::Display for ScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanError::Config(e) => f.write_str(e),
            ScanError::PublicRange(r) => write!(
                f,
                "these targets are outside private address space: {}. Scanning networks you do not own may be illegal; pass --allow-public to confirm you are authorised",
                r.join(", ")
            ),
            ScanError::Cancelled => f.write_str("scan cancelled"),
        }
    }
}
impl std::error::Error for ScanError {}

/// Draft of a device while evidence from different sources is merged.
#[derive(Default)]
struct Draft {
    mac: Option<String>,
    via: BTreeSet<&'static str>,
    open: BTreeSet<u16>,
    mdns: Option<MdnsDevice>,
    ssdp: Option<SsdpInfo>,
    other_ips: Vec<IpAddr>,
}

/// Minutes a full sweep would take at the given rate, if it is long enough to be worth mentioning.
pub fn estimate_minutes(hosts: usize, ports: usize, rate: u32) -> Option<u64> {
    if rate == 0 {
        return None;
    }
    let mins = (hosts as u64 * ports as u64) / rate as u64 / 60;
    (mins >= 3).then_some(mins)
}

/// Derive the MAC from a modified-EUI-64 IPv6 interface identifier, if it is one.
pub fn mac_from_eui64(ip: Ipv6Addr) -> Option<String> {
    let o = ip.octets();
    if o[11] == 0xff && o[12] == 0xfe { Some(fmt_mac(&[o[8] ^ 0x02, o[9], o[10], o[13], o[14], o[15]])) } else { None }
}

fn own_addresses() -> HashSet<IpAddr> {
    if_addrs::get_if_addrs().map(|v| v.into_iter().map(|i| i.ip()).collect()).unwrap_or_default()
}

/// Run a complete scan with the built-in checkers (filtered by `opts.only` / `opts.skip`).
pub async fn run(opts: ScanOptions, env: Arc<Environment>, progress: Arc<Progress>) -> Result<ScanResult, ScanError> {
    let registry = Registry::builtin().select(&opts.only, &opts.skip).map_err(ScanError::Config)?;
    run_with(opts, env, progress, registry).await
}

/// Run a complete scan with an explicit set of checkers (embedding, tests).
pub async fn run_with(
    opts: ScanOptions,
    env: Arc<Environment>,
    progress: Arc<Progress>,
    registry: Registry,
) -> Result<ScanResult, ScanError> {
    let t0 = Instant::now();
    let started = util::now_rfc3339();
    let today = opts.today.unwrap_or_else(Date::today);
    let mut warnings: Vec<String> = env.notes.clone();

    // ---- configuration -------------------------------------------------
    let (db, mut w) = AdvisoryDb::load(opts.advisories.as_deref());
    warnings.append(&mut w);

    let auto = opts.targets.is_empty() || opts.targets.iter().any(|t| t == "auto");
    let locals = scope::local_subnets(opts.max_hosts, opts.iface.as_deref());
    let mut specs: Vec<String> = opts.targets.iter().filter(|t| *t != "auto").cloned().collect();
    if auto {
        if locals.is_empty() {
            return Err(ScanError::Config(
                "no usable network interface found for auto-detection; pass a target such as 192.168.1.0/24".into(),
            ));
        }
        let mut usable = 0;
        let mut skipped: Vec<String> = Vec::new();
        for n in &locals {
            // Auto-detection only ever picks private networks; public addressing needs an explicit, confirmed target.
            if !n.target.is_local_only() && !opts.allow_public {
                warnings.push(format!(
                    "interface {} has non-private addressing ({}); skipped. Name it as a target and confirm with --allow-public if you are authorised to scan it",
                    n.iface, n.target
                ));
                skipped.push(format!("{} ({})", n.iface, n.target));
                continue;
            }
            usable += 1;
            specs.push(n.target.to_string());
            if n.narrowed {
                warnings.push(format!(
                    "interface {} is /{} ({}); scanning only {} to stay under {} addresses (use --max-hosts to widen)",
                    n.iface, n.prefix, n.addr, n.target, opts.max_hosts
                ));
            }
        }
        if usable == 0 {
            return Err(ScanError::Config(format!(
                "none of this machine's networks are private (skipped: {}); pass a target explicitly, for example 192.168.1.0/24",
                skipped.join(", ")
            )));
        }
    }
    let scope = Scope::parse(&specs).map_err(|e| ScanError::Config(e.to_string()))?;
    let public = scope.public_targets();
    if !public.is_empty() && !opts.allow_public {
        return Err(ScanError::PublicRange(public));
    }
    let mut hosts = scope.expand(opts.max_hosts).map_err(|e| ScanError::Config(e.to_string()))?;
    if auto {
        let own = own_addresses();
        hosts.retain(|h| !own.contains(h));
    }

    let mut ports = opts.ports.clone();
    ports.extend(registry.extra_ports());
    ports.sort_unstable();
    ports.dedup();
    crate::ports::order_by_popularity(&mut ports);
    let banner_ports = registry.banner_ports();

    let cancel = progress.cancel_flag();
    let ctx = Arc::new(NetCtx::new(opts.limits.clone(), cancel));
    let check_cancel = || if progress.is_cancelled() { Err(ScanError::Cancelled) } else { Ok(()) };

    let want_mdns = opts.mdns || registry.wants(Need::Mdns);
    let want_ssdp = opts.ssdp || registry.wants(Need::Ssdp);
    let iface_v4: Vec<Ipv4Addr> = {
        let all = scope::local_subnets(65536, opts.iface.as_deref());
        all.iter().map(|n| n.addr).collect()
    };
    let window = opts.discovery_window;

    progress.log(format!("{} address(es), {} port(s), {} checker(s)", hosts.len(), ports.len(), registry.ids().len()));
    if let Some(mins) = estimate_minutes(hosts.len(), ports.len(), opts.limits.rate_per_sec) {
        let note = format!(
            "{} probes at {}/s will take roughly {mins} minutes; use --fast or fewer ports/addresses to shorten it",
            hosts.len() * ports.len(),
            opts.limits.rate_per_sec
        );
        progress.log(note.clone());
        warnings.push(note);
    }

    // ---- multicast discovery runs alongside everything else --------------
    let mdns_task = (want_mdns && !window.is_zero()).then(|| {
        let cfg = mdns::Config { window, ifaces: iface_v4.clone(), unicast_targets: vec![] };
        tokio::spawn(async move { mdns::discover(&cfg).await })
    });
    let ssdp_task = (want_ssdp && !window.is_zero()).then(|| {
        let cfg = ssdp::Config { window, ifaces: iface_v4.clone(), unicast_targets: vec![] };
        let t = Timeouts { connect: opts.limits.connect_timeout, total: opts.limits.io_timeout };
        tokio::spawn(async move {
            let (replies, warns) = ssdp::discover(&cfg).await;
            (ssdp::describe(&replies, t).await, warns)
        })
    });

    // ---- link-layer discovery --------------------------------------------
    progress.phase("Looking for devices", 0);
    let mut drafts: BTreeMap<IpAddr, Draft> = BTreeMap::new();
    let mut scopes: Scopes = Scopes::new();
    let mut arp_covered: Vec<Target> = Vec::new();
    let mut raw_arp_used = false;

    if opts.arp && !env.arp.is_empty() {
        let mut tasks = Vec::new();
        for (i, sock) in env.arp.iter().enumerate() {
            let targets: Vec<Ipv4Addr> = hosts
                .iter()
                .filter_map(|h| match h {
                    IpAddr::V4(a) if sock.target.contains(*h) => Some(*a),
                    _ => None,
                })
                .collect();
            if targets.is_empty() {
                continue;
            }
            arp_covered.push(sock.target.clone());
            let (env, cancel) = (env.clone(), progress.cancel_flag());
            let pps = if opts.limits.rate_per_sec == 0 { 2000 } else { opts.limits.rate_per_sec.max(200) };
            tasks.push(tokio::task::spawn_blocking(move || env.arp[i].sweep(&targets, pps, Duration::from_millis(1500), &cancel)));
        }
        for t in tasks {
            if let Ok(found) = t.await {
                raw_arp_used = true;
                for (ip, mac) in found {
                    let d = drafts.entry(IpAddr::V4(ip)).or_default();
                    d.mac = Some(fmt_mac(&mac));
                    d.via.insert("arp");
                }
            }
        }
        progress.log(format!("raw ARP sweep found {} host(s)", drafts.len()));
    }
    check_cancel()?;

    if opts.ipv6 && auto {
        let nets = if_addrs::get_if_addrs().unwrap_or_default();
        let mut idx: Vec<u32> = nets
            .iter()
            .filter(|i| !i.is_loopback() && matches!(i.addr, if_addrs::IfAddr::V6(ref a) if (a.ip.segments()[0] & 0xffc0) == 0xfe80))
            .filter(|i| opts.iface.as_ref().is_none_or(|w| *w == i.name))
            .filter_map(|i| i.index)
            .collect();
        idx.sort_unstable();
        idx.dedup();
        let own6: Vec<Ipv6Addr> = nets.iter().filter_map(|i| if let IpAddr::V6(a) = i.ip() { Some(a) } else { None }).collect();
        if !idx.is_empty() {
            let (found, mut w) = icmp6::discover(&idx, &own6, Duration::from_millis(1500)).await;
            warnings.append(&mut w);
            for h in found {
                scopes.insert(h.ip, h.scope);
                let d = drafts.entry(IpAddr::V6(h.ip)).or_default();
                d.mac = mac_from_eui64(h.ip);
                d.via.insert("icmp6");
            }
        }
    }
    check_cancel()?;

    // ---- TCP sweep -------------------------------------------------------
    let arp_alive: HashSet<IpAddr> = drafts.iter().filter(|(_, d)| d.via.contains("arp")).map(|(ip, _)| *ip).collect();
    let mut sweep_list: Vec<IpAddr> =
        hosts.iter().copied().filter(|h| !(arp_covered.iter().any(|t| t.contains(*h)) && !arp_alive.contains(h))).collect();
    sweep_list.extend(drafts.keys().filter(|k| k.is_ipv6() && !hosts.contains(k)).copied());
    sweep_list.sort();
    sweep_list.dedup();

    progress.phase("Scanning ports", sweep_list.len());
    let early = (arp_covered.is_empty()).then(|| Arc::new(EarlyExit::new(locals.iter().map(|n| n.target.clone()).collect())));
    let scopes_arc = Arc::new(scopes.clone());
    let ports_arc = Arc::new(ports.clone());
    let mut set: JoinSet<(IpAddr, sweep::HostSweep)> = JoinSet::new();
    for ip in sweep_list.iter().copied() {
        let (ctx, sc, pa, early) = (ctx.clone(), scopes_arc.clone(), ports_arc.clone(), early.clone());
        set.spawn(async move { (ip, sweep::sweep_host(ctx, sc, ip, pa, early).await) });
    }
    while let Some(res) = set.join_next().await {
        progress.tick();
        if let Ok((ip, hs)) = res
            && (hs.alive || !hs.open.is_empty())
        {
            let d = drafts.entry(ip).or_default();
            d.via.insert("tcp");
            d.open.extend(hs.open);
        }
        if progress.is_cancelled() {
            set.abort_all();
        }
    }
    check_cancel()?;

    // Hosts the kernel resolved via ARP (even if they ignored every probe).
    let neighbors: HashMap<Ipv4Addr, String> = neigh::read().into_iter().map(|n| (n.ip, n.mac)).collect();
    for h in &hosts {
        if let IpAddr::V4(a) = h
            && let Some(mac) = neighbors.get(a)
        {
            let d = drafts.entry(*h).or_default();
            if d.mac.is_none() {
                d.mac = Some(mac.clone());
            }
            if !d.via.contains("arp") {
                d.via.insert("arp-cache");
            }
        }
    }

    // ---- collect multicast results ----------------------------------------
    if let Some(t) = mdns_task
        && let Ok((devs, mut w)) = t.await
    {
        warnings.append(&mut w);
        for m in devs {
            if scope.contains(m.ip) || (auto && !m.ip.is_ipv4()) {
                let d = drafts.entry(m.ip).or_default();
                d.via.insert("mdns");
                d.mdns = Some(m);
            }
        }
    }
    if let Some(t) = ssdp_task
        && let Ok((info, mut w)) = t.await
    {
        warnings.append(&mut w);
        for (ip, s) in info {
            if scope.contains(ip) {
                let d = drafts.entry(ip).or_default();
                d.via.insert("ssdp");
                d.ssdp = Some(s);
            }
        }
    }
    check_cancel()?;

    // ---- merge IPv6 drafts into their IPv4 twins ---------------------------
    let v6_keys: Vec<IpAddr> = drafts.keys().filter(|k| k.is_ipv6()).copied().collect();
    for k in v6_keys {
        let IpAddr::V6(v6) = k else { continue };
        let target = drafts
            .iter()
            .find(|(ip, d)| {
                ip.is_ipv4()
                    && (d.mdns.as_ref().is_some_and(|m| m.other_ips.contains(&k))
                        || (d.mac.is_some() && d.mac == drafts.get(&k).and_then(|x| x.mac.clone()).or_else(|| mac_from_eui64(v6))))
            })
            .map(|(ip, _)| *ip);
        if let Some(t) = target
            && let Some(v) = drafts.remove(&k)
        {
            let d = drafts.get_mut(&t).expect("target exists");
            d.other_ips.push(k);
            d.open.extend(v.open);
            d.via.extend(v.via);
        }
    }
    // Drop out-of-scope hosts (multicast replies from outside the targets).
    drafts.retain(|ip, _| scope.contains(*ip) || (ip.is_ipv6() && auto));

    // ---- build devices ----------------------------------------------------
    let mut devices: Vec<Device> = drafts
        .into_iter()
        .map(|(ip, d)| {
            let mut dev = Device::new(ip);
            dev.mac = d.mac;
            dev.vendor = dev.mac.as_deref().and_then(parse_mac).and_then(|m| crate::oui::vendor(&m));
            dev.discovered_via = d.via.iter().map(|s| s.to_string()).collect();
            dev.other_ips = d.other_ips;
            if let Some(m) = d.mdns {
                dev.hostname = m.hostname;
                for o in m.other_ips {
                    if !dev.other_ips.contains(&o) {
                        dev.other_ips.push(o);
                    }
                }
                dev.mdns = m.services;
            }
            dev.ssdp = d.ssdp;
            dev.services =
                d.open.iter().map(|&p| Service { port: p, kind: ServiceKind::Other, banner: None, http: None, note: None }).collect();
            dev
        })
        .collect();
    progress.set_live(devices.clone());
    progress.log(format!("found {} device(s)", devices.len()));

    // ---- identify services, probe, check -----------------------------------
    progress.phase("Identifying services", devices.len());
    let scopes_arc = Arc::new(scopes);
    let banner_ports = Arc::new(banner_ports);
    let mut idset: JoinSet<(usize, Vec<Service>)> = JoinSet::new();
    for (i, dev) in devices.iter().enumerate() {
        let (ctx, sc, bp, ip) = (ctx.clone(), scopes_arc.clone(), banner_ports.clone(), dev.ip);
        let open = dev.open_ports();
        idset.spawn(async move { (i, enrich::identify_host(ctx, sc, ip, open, bp).await) });
    }
    while let Some(r) = idset.join_next().await {
        progress.tick();
        if let Ok((i, services)) = r {
            devices[i].services = services;
            identify::apply(&mut devices[i]);
            progress.set_live(devices.clone());
        }
        if progress.is_cancelled() {
            idset.abort_all();
        }
    }
    check_cancel()?;

    progress.phase("Running checks", devices.len());
    let registry = Arc::new(registry);
    let db = Arc::new(db);
    let mut ckset: JoinSet<(usize, Vec<Finding>, Option<PhpDetection>)> = JoinSet::new();
    for (i, dev) in devices.iter().enumerate() {
        let (ctx, sc, reg, db, dev, active) = (ctx.clone(), scopes_arc.clone(), registry.clone(), db.clone(), dev.clone(), opts.active);
        ckset.spawn(async move {
            let wanted = reg.probes_for(&dev, &db, active);
            let probes = probes::run_probes(&ctx, &sc, dev.ip, &dev.services, &wanted).await;
            let input = CheckInput { device: &dev, probes: &probes, db: &db, today, active };
            let findings = reg.evaluate(&input);
            let facts = php_facts(&dev, &probes);
            (i, findings, (!facts.is_empty()).then_some(PhpDetection { facts }))
        });
    }
    while let Some(r) = ckset.join_next().await {
        progress.tick();
        if let Ok((i, findings, php)) = r {
            devices[i].findings = findings;
            devices[i].php = php;
            identify::apply(&mut devices[i]);
        }
        if progress.is_cancelled() {
            ckset.abort_all();
        }
    }
    check_cancel()?;

    // ---- finish ----------------------------------------------------------
    opts.allowlist.apply(&mut devices, today);
    devices.sort_by_key(|d| (d.ip.is_ipv6(), d.ip));
    let mut result = ScanResult {
        schema_version: SCHEMA_VERSION,
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        started,
        finished: util::now_rfc3339(),
        summary: ScanSummary { targets: specs, ports, active: opts.active, raw_arp: raw_arp_used, checkers: registry.ids() },
        devices,
        warnings,
        stats: Stats { addresses_scanned: hosts.len(), duration_secs: t0.elapsed().as_secs_f64(), ..Stats::default() },
    };
    result.recount();
    result.stats.duration_secs = (t0.elapsed().as_secs_f64() * 10.0).round() / 10.0;
    progress.set_live(result.devices.clone());
    progress.phase("Done", 0);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duration_estimate() {
        assert_eq!(estimate_minutes(254, 30, 400), None);
        assert_eq!(estimate_minutes(254, 4096, 400), Some(43));
        assert_eq!(estimate_minutes(254, 4096, 0), None);
    }

    #[test]
    fn eui64_mac() {
        let ip: Ipv6Addr = "fe80::0211:22ff:fe33:4455".parse().unwrap();
        assert_eq!(mac_from_eui64(ip).as_deref(), Some("00:11:22:33:44:55"));
        let random: Ipv6Addr = "fe80::1234:5678:9abc:def0".parse().unwrap();
        assert_eq!(mac_from_eui64(random), None);
    }
}
