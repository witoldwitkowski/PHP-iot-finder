//! mDNS / DNS-SD discovery. Smart-home gear announces itself here even when
//! it ignores port probes: Chromecasts, HomeKit accessories, printers, NAS boxes.

use crate::dns::{self, Message, RData};
use crate::model::MdnsService;
use crate::scope::is_local_scope;
use crate::util::sanitize;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::time::Instant;

const MDNS_V4: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251)), 5353);
const META: &str = "_services._dns-sd._udp.local";

/// Service types queried in the first round (the meta-query reveals the rest).
const COMMON: &[&str] = &[
    "_http._tcp.local",
    "_https._tcp.local",
    "_googlecast._tcp.local",
    "_airplay._tcp.local",
    "_raop._tcp.local",
    "_hap._tcp.local",
    "_homekit._tcp.local",
    "_ipp._tcp.local",
    "_printer._tcp.local",
    "_smb._tcp.local",
    "_ssh._tcp.local",
    "_workstation._tcp.local",
    "_device-info._tcp.local",
    "_spotify-connect._tcp.local",
    "_hue._tcp.local",
    "_esphomelib._tcp.local",
    "_mqtt._tcp.local",
    "_matter._tcp.local",
    "_rtsp._tcp.local",
];

/// A device learned from mDNS.
#[derive(Clone, Debug, PartialEq)]
pub struct MdnsDevice {
    /// Primary address (IPv4 preferred).
    pub ip: IpAddr,
    /// Other addresses announced for the same host.
    pub other_ips: Vec<IpAddr>,
    /// Hostname without `.local`.
    pub hostname: Option<String>,
    /// Announced services.
    pub services: Vec<MdnsService>,
}

/// Discovery settings.
#[derive(Clone, Debug)]
pub struct Config {
    /// How long to listen in total.
    pub window: Duration,
    /// Local IPv4 addresses to send from (one socket each).
    pub ifaces: Vec<Ipv4Addr>,
    /// Extra unicast destinations (used by tests and for known hosts).
    pub unicast_targets: Vec<SocketAddr>,
}

/// Run discovery. Returns devices plus non-fatal warnings.
pub async fn discover(cfg: &Config) -> (Vec<MdnsDevice>, Vec<String>) {
    let mut tasks = Vec::new();
    for ip in &cfg.ifaces {
        let (ip, window, extra) = (*ip, cfg.window, cfg.unicast_targets.clone());
        tasks.push(tokio::spawn(async move { run_iface(ip, window, extra).await }));
    }
    if cfg.ifaces.is_empty() && !cfg.unicast_targets.is_empty() {
        let (window, extra) = (cfg.window, cfg.unicast_targets.clone());
        tasks.push(tokio::spawn(async move { run_iface(Ipv4Addr::UNSPECIFIED, window, extra).await }));
    }
    let mut msgs: Vec<(IpAddr, Message)> = Vec::new();
    let mut warnings = Vec::new();
    for t in tasks {
        match t.await {
            Ok(Ok(mut m)) => msgs.append(&mut m),
            Ok(Err(e)) => warnings.push(format!("mDNS: {e}")),
            Err(_) => warnings.push("mDNS task failed".to_string()),
        }
    }
    (assemble(&msgs), warnings)
}

async fn run_iface(iface: Ipv4Addr, window: Duration, extra: Vec<SocketAddr>) -> Result<Vec<(IpAddr, Message)>, String> {
    let sock = super::multicast_socket_v4(iface).map_err(|e| format!("socket on {iface}: {e}"))?;
    let end = Instant::now() + window;
    let mid = Instant::now() + window / 2;
    let mut got: Vec<(IpAddr, Message)> = Vec::new();

    let mut questions: Vec<(&str, u16)> = vec![(META, dns::T_PTR)];
    questions.extend(COMMON.iter().map(|s| (*s, dns::T_PTR)));
    // Several small packets are friendlier to weak responders than one big one.
    for chunk in questions.chunks(6) {
        let pkt = dns::build_query(chunk, true);
        let _ = sock.send_to(&pkt, MDNS_V4).await;
        for t in &extra {
            let _ = sock.send_to(&pkt, t).await;
        }
    }

    let mut buf = vec![0u8; 9000];
    let mut second_round = false;
    let mut seen_types: HashSet<String> = COMMON.iter().map(|s| s.to_string()).collect();
    let mut packets = 0usize;
    loop {
        let now = Instant::now();
        if now >= end || packets > 4000 {
            break;
        }
        if !second_round && now >= mid {
            second_round = true;
            let types = learned_types(&got, &mut seen_types);
            for chunk in types.chunks(6) {
                let qs: Vec<(&str, u16)> = chunk.iter().map(|s| (s.as_str(), dns::T_PTR)).collect();
                let pkt = dns::build_query(&qs, true);
                let _ = sock.send_to(&pkt, MDNS_V4).await;
                for t in &extra {
                    let _ = sock.send_to(&pkt, t).await;
                }
            }
        }
        let deadline = if second_round { end } else { mid.min(end) };
        match tokio::time::timeout_at(deadline, sock.recv_from(&mut buf)).await {
            Ok(Ok((n, src))) => {
                packets += 1;
                if !is_local_scope(src.ip()) && !src.ip().is_loopback() {
                    continue;
                }
                if let Ok(m) = dns::parse(&buf[..n])
                    && m.is_response()
                {
                    got.push((src.ip(), m));
                }
            }
            Ok(Err(_)) => break,
            Err(_) => {}
        }
    }
    Ok(got)
}

fn learned_types(got: &[(IpAddr, Message)], seen: &mut HashSet<String>) -> Vec<String> {
    let mut out = Vec::new();
    for (_, m) in got {
        for r in &m.records {
            if r.name.eq_ignore_ascii_case(META)
                && let RData::Ptr(t) = &r.data
            {
                let t = t.to_ascii_lowercase();
                if t.starts_with('_') && seen.insert(t.clone()) && out.len() < 60 {
                    out.push(t);
                }
            }
        }
    }
    out
}

fn host_label(h: &str) -> String {
    let h = h.trim_end_matches('.');
    let h = h.strip_suffix(".local").unwrap_or(h);
    sanitize(h, 80)
}

/// Combine response packets into per-device records. Pure; used by tests.
pub fn assemble(msgs: &[(IpAddr, Message)]) -> Vec<MdnsDevice> {
    let mut host_ips: HashMap<String, Vec<IpAddr>> = HashMap::new();
    let mut srv: HashMap<String, (u16, String, IpAddr)> = HashMap::new();
    let mut txt: HashMap<String, Vec<String>> = HashMap::new();
    let mut ptr_owner: HashMap<String, String> = HashMap::new();

    for (src, m) in msgs {
        for r in &m.records {
            let name = r.name.to_ascii_lowercase();
            match &r.data {
                RData::A(a) => push_unique(host_ips.entry(name).or_default(), IpAddr::V4(*a)),
                RData::Aaaa(a) => push_unique(host_ips.entry(name).or_default(), IpAddr::V6(*a)),
                RData::Srv { port, target } => {
                    srv.insert(name, (*port, target.to_ascii_lowercase(), *src));
                }
                RData::Txt(t) => {
                    txt.insert(name, t.clone());
                }
                RData::Ptr(inst) if !name.eq_ignore_ascii_case(META) => {
                    ptr_owner.insert(inst.to_ascii_lowercase(), name);
                }
                _ => {}
            }
        }
    }

    let mut by_ip: BTreeMap<IpAddr, MdnsDevice> = BTreeMap::new();
    // Hosts with addresses, with or without services.
    for (host, ips) in &host_ips {
        let Some(primary) = ips.iter().find(|i| i.is_ipv4()).or(ips.first()) else { continue };
        if !is_local_scope(*primary) && !primary.is_loopback() {
            continue;
        }
        ensure(&mut by_ip, *primary, Some(host), ips);
    }

    // Services.
    for (inst_lc, (port, target, src)) in &srv {
        let ips = host_ips.get(target).cloned().unwrap_or_default();
        let primary = ips.iter().find(|i| i.is_ipv4()).or(ips.first()).copied().unwrap_or(*src);
        ensure(&mut by_ip, primary, Some(target), &ips);
        let svc_type = service_type_of(inst_lc, ptr_owner.get(inst_lc));
        let instance = instance_label(inst_lc, &svc_type);
        let mut txt_items: Vec<String> =
            txt.get(inst_lc).map(|t| t.iter().filter(|s| !s.is_empty()).take(8).map(|s| sanitize(s, 80)).collect()).unwrap_or_default();
        txt_items.truncate(8);
        let d = by_ip.get_mut(&primary).expect("ensured above");
        let svc = MdnsService { instance, service: svc_type, port: *port, txt: txt_items };
        if !d.services.contains(&svc) && d.services.len() < 32 {
            d.services.push(svc);
        }
    }

    let mut out: Vec<MdnsDevice> = by_ip.into_values().collect();
    for d in &mut out {
        d.services.sort_by(|a, b| (&a.service, &a.instance).cmp(&(&b.service, &b.instance)));
    }
    out
}

fn ensure(by_ip: &mut BTreeMap<IpAddr, MdnsDevice>, ip: IpAddr, host: Option<&str>, others: &[IpAddr]) {
    let d = by_ip.entry(ip).or_insert_with(|| MdnsDevice { ip, other_ips: vec![], hostname: None, services: vec![] });
    if d.hostname.is_none() {
        d.hostname = host.map(host_label).filter(|h| !h.is_empty());
    }
    for o in others {
        if *o != ip {
            push_unique(&mut d.other_ips, *o);
        }
    }
}

fn push_unique(v: &mut Vec<IpAddr>, ip: IpAddr) {
    if !v.contains(&ip) && v.len() < 8 {
        v.push(ip);
    }
}

/// `My TV._googlecast._tcp.local` → `_googlecast._tcp`.
fn service_type_of(instance_lc: &str, ptr_owner: Option<&String>) -> String {
    if let Some(i) = instance_lc.find("._") {
        let t = &instance_lc[i + 1..];
        return t.trim_end_matches(".local").trim_end_matches('.').to_string();
    }
    ptr_owner.map(|p| p.trim_end_matches(".local").to_string()).unwrap_or_default()
}

fn instance_label(instance_lc: &str, svc_type: &str) -> String {
    let suffix = format!(".{svc_type}.local");
    let base = instance_lc.strip_suffix(&suffix).unwrap_or(instance_lc);
    sanitize(base, 80)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::Record;

    fn rec(name: &str, rtype: u16, data: RData) -> Record {
        Record { name: name.into(), rtype, data }
    }

    fn msg(records: Vec<Record>) -> Message {
        Message { id: 0, flags: 0x8400, questions: vec![], records }
    }

    #[test]
    fn assembles_a_chromecast() {
        let src: IpAddr = "192.168.1.9".parse().unwrap();
        let m = msg(vec![
            rec("_googlecast._tcp.local", dns::T_PTR, RData::Ptr("Living Room TV._googlecast._tcp.local".into())),
            rec("Living Room TV._googlecast._tcp.local", dns::T_SRV, RData::Srv { port: 8009, target: "Chromecast-abc.local".into() }),
            rec("Living Room TV._googlecast._tcp.local", dns::T_TXT, RData::Txt(vec!["md=Chromecast".into(), "ve=05".into()])),
            rec("Chromecast-abc.local", dns::T_A, RData::A("192.168.1.9".parse().unwrap())),
            rec("Chromecast-abc.local", dns::T_AAAA, RData::Aaaa("fe80::1234".parse().unwrap())),
        ]);
        let devs = assemble(&[(src, m)]);
        assert_eq!(devs.len(), 1);
        let d = &devs[0];
        assert_eq!(d.ip, src);
        assert_eq!(d.hostname.as_deref(), Some("chromecast-abc"));
        assert_eq!(d.other_ips.len(), 1);
        assert_eq!(d.services.len(), 1);
        assert_eq!(d.services[0].service, "_googlecast._tcp");
        assert_eq!(d.services[0].instance, "living room tv");
        assert_eq!(d.services[0].port, 8009);
        assert!(d.services[0].txt.contains(&"md=Chromecast".to_string()));
    }

    #[test]
    fn falls_back_to_packet_source_when_no_address_record() {
        let src: IpAddr = "192.168.1.20".parse().unwrap();
        let m = msg(vec![rec("Printer._ipp._tcp.local", dns::T_SRV, RData::Srv { port: 631, target: "printer.local".into() })]);
        let devs = assemble(&[(src, m)]);
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].ip, src);
        assert_eq!(devs[0].services[0].service, "_ipp._tcp");
    }

    #[test]
    fn ignores_public_addresses() {
        let m = msg(vec![rec("evil.local", dns::T_A, RData::A("8.8.8.8".parse().unwrap()))]);
        assert!(assemble(&[("192.168.1.2".parse().unwrap(), m)]).is_empty());
    }

    #[test]
    fn hostile_text_is_sanitized() {
        let src: IpAddr = "192.168.1.9".parse().unwrap();
        let m = msg(vec![
            rec("x\x1b[31m._http._tcp.local", dns::T_SRV, RData::Srv { port: 80, target: "h.local".into() }),
            rec("h.local", dns::T_A, RData::A("192.168.1.9".parse().unwrap())),
        ]);
        let devs = assemble(&[(src, m)]);
        assert!(!devs[0].services[0].instance.contains('\x1b'));
    }

    #[test]
    fn learns_service_types_once() {
        let m = msg(vec![
            rec(META, dns::T_PTR, RData::Ptr("_foo._tcp.local".into())),
            rec(META, dns::T_PTR, RData::Ptr("_http._tcp.local".into())),
            rec(META, dns::T_PTR, RData::Ptr("not-a-service".into())),
        ]);
        let mut seen: HashSet<String> = COMMON.iter().map(|s| s.to_string()).collect();
        let t = learned_types(&[("192.168.1.2".parse().unwrap(), m)], &mut seen);
        assert_eq!(t, vec!["_foo._tcp.local".to_string()]);
    }

    #[tokio::test]
    async fn end_to_end_against_unicast_responder() {
        use tokio::net::UdpSocket;
        let responder = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let raddr = responder.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            if let Ok((_, from)) = responder.recv_from(&mut buf).await {
                // Respond with a hand-built packet: A record for host.local.
                let mut p = vec![0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0];
                for l in ["host", "local"] {
                    p.push(l.len() as u8);
                    p.extend_from_slice(l.as_bytes());
                }
                p.push(0);
                p.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 10, 0, 4, 127, 0, 0, 1]);
                let _ = responder.send_to(&p, from).await;
            }
        });
        let cfg = Config { window: Duration::from_millis(600), ifaces: vec![Ipv4Addr::LOCALHOST], unicast_targets: vec![raddr] };
        let (devs, _w) = discover(&cfg).await;
        assert_eq!(devs.len(), 1, "{devs:?}");
        assert_eq!(devs[0].hostname.as_deref(), Some("host"));
    }
}
