//! SSDP / UPnP discovery. Routers, TVs, media players and many cameras answer
//! an `M-SEARCH`, usually with a description document naming the model.

use crate::http::{self, Request, Timeouts};
use crate::model::SsdpInfo;
use crate::scope::is_local_scope;
use crate::util::sanitize;
use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::time::Instant;

const SSDP_V4: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(239, 255, 255, 250)), 1900);

/// One SSDP reply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reply {
    /// Responder address.
    pub ip: IpAddr,
    /// `SERVER` header.
    pub server: Option<String>,
    /// `ST` (search target) or `NT`.
    pub st: Option<String>,
    /// `USN`.
    pub usn: Option<String>,
    /// `LOCATION` URL of the description document.
    pub location: Option<String>,
}

/// Discovery settings.
#[derive(Clone, Debug)]
pub struct Config {
    /// Listen window.
    pub window: Duration,
    /// Local addresses to send from.
    pub ifaces: Vec<Ipv4Addr>,
    /// Extra unicast destinations (tests, known hosts).
    pub unicast_targets: Vec<SocketAddr>,
}

/// Build an `M-SEARCH` request.
pub fn msearch(st: &str) -> Vec<u8> {
    format!("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: {st}\r\nUSER-AGENT: iotscan/{}\r\n\r\n", env!("CARGO_PKG_VERSION")).into_bytes()
}

/// Parse an SSDP reply or NOTIFY datagram.
pub fn parse_reply(buf: &[u8], src: IpAddr) -> Option<Reply> {
    let text = String::from_utf8_lossy(&buf[..buf.len().min(4096)]);
    let mut lines = text.split('\n').map(|l| l.trim_end_matches('\r'));
    let first = lines.next()?;
    if !(first.starts_with("HTTP/1.") || first.starts_with("NOTIFY ")) {
        return None;
    }
    let mut h: HashMap<String, String> = HashMap::new();
    for l in lines {
        if l.is_empty() {
            break;
        }
        if let Some((k, v)) = l.split_once(':') {
            h.entry(k.trim().to_ascii_lowercase()).or_insert_with(|| v.trim().to_string());
        }
    }
    let get = |k: &str, max: usize| h.get(k).map(|v| sanitize(v, max)).filter(|v| !v.is_empty());
    Some(Reply {
        ip: src,
        server: get("server", 160),
        st: get("st", 120).or_else(|| get("nt", 120)),
        usn: get("usn", 200),
        location: h.get("location").map(|v| v.chars().take(300).collect()),
    })
}

/// Run discovery.
pub async fn discover(cfg: &Config) -> (Vec<Reply>, Vec<String>) {
    let mut tasks = Vec::new();
    let mut ifaces = cfg.ifaces.clone();
    if ifaces.is_empty() && !cfg.unicast_targets.is_empty() {
        ifaces.push(Ipv4Addr::UNSPECIFIED);
    }
    for ip in ifaces {
        let (window, extra) = (cfg.window, cfg.unicast_targets.clone());
        tasks.push(tokio::spawn(async move { run_iface(ip, window, extra).await }));
    }
    let mut replies = Vec::new();
    let mut warnings = Vec::new();
    for t in tasks {
        match t.await {
            Ok(Ok(mut r)) => replies.append(&mut r),
            Ok(Err(e)) => warnings.push(format!("SSDP: {e}")),
            Err(_) => warnings.push("SSDP task failed".into()),
        }
    }
    (replies, warnings)
}

async fn run_iface(iface: Ipv4Addr, window: Duration, extra: Vec<SocketAddr>) -> Result<Vec<Reply>, String> {
    let sock = super::multicast_socket_v4(iface).map_err(|e| format!("socket on {iface}: {e}"))?;
    let end = Instant::now() + window;
    for st in ["ssdp:all", "upnp:rootdevice"] {
        let pkt = msearch(st);
        let _ = sock.send_to(&pkt, SSDP_V4).await;
        for t in &extra {
            let _ = sock.send_to(&pkt, t).await;
        }
    }
    let mut out = Vec::new();
    let mut buf = vec![0u8; 4096];
    let mut n_packets = 0;
    loop {
        if Instant::now() >= end || n_packets > 4000 {
            break;
        }
        match tokio::time::timeout_at(end, sock.recv_from(&mut buf)).await {
            Ok(Ok((n, src))) => {
                n_packets += 1;
                if !is_local_scope(src.ip()) && !src.ip().is_loopback() {
                    continue;
                }
                if let Some(r) = parse_reply(&buf[..n], src.ip()) {
                    out.push(r);
                }
            }
            Ok(Err(_)) => break,
            Err(_) => break,
        }
    }
    Ok(out)
}

/// Pull `<tag>text</tag>` out of an XML document (first occurrence, no entity handling beyond a few basics).
pub fn xml_tag(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&format!("</{tag}>"))? + start;
    let raw =
        xml[start..end].replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&apos;", "'");
    let t = sanitize(&raw, 120);
    if t.is_empty() { None } else { Some(t) }
}

/// Parse a UPnP device description.
pub fn parse_description(xml: &str) -> SsdpInfo {
    SsdpInfo {
        server: None,
        targets: xml_tag(xml, "deviceType").into_iter().collect(),
        friendly_name: xml_tag(xml, "friendlyName"),
        manufacturer: xml_tag(xml, "manufacturer"),
        model: xml_tag(xml, "modelName"),
        model_number: xml_tag(xml, "modelNumber"),
    }
}

/// Validate a `LOCATION` URL. Only `http://<responder-ip>[:port]/path` is accepted,
/// so a hostile device cannot make the scanner fetch arbitrary URLs (SSRF).
pub fn location_target(location: &str, responder: IpAddr) -> Option<(SocketAddr, String)> {
    let rest = location.strip_prefix("http://")?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, "/".to_string()),
    };
    if authority.contains('@') {
        return None;
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if !h.contains(']') || h.ends_with(']') => (h.trim_matches(['[', ']']), p.parse::<u16>().ok()?),
        _ => (authority.trim_matches(['[', ']']), 80),
    };
    let ip: IpAddr = host.parse().ok()?;
    if ip != responder || path.len() > 300 || port == 0 {
        return None;
    }
    Some((SocketAddr::new(ip, port), path))
}

/// Merge replies per responder and fetch each device description once.
pub async fn describe(replies: &[Reply], t: Timeouts) -> BTreeMap<IpAddr, SsdpInfo> {
    let mut out: BTreeMap<IpAddr, SsdpInfo> = BTreeMap::new();
    let mut loc: BTreeMap<IpAddr, String> = BTreeMap::new();
    for r in replies {
        let e = out.entry(r.ip).or_default();
        if e.server.is_none() {
            e.server = r.server.clone();
        }
        if let Some(st) = &r.st
            && !e.targets.contains(st)
            && e.targets.len() < 12
        {
            e.targets.push(st.clone());
        }
        if let Some(l) = &r.location {
            loc.entry(r.ip).or_insert_with(|| l.clone());
        }
    }
    for (ip, l) in loc {
        let Some((addr, path)) = location_target(&l, ip) else { continue };
        let mut req = Request::get(&path);
        req.max_body = 64 * 1024;
        if let Ok(resp) = http::fetch(addr, false, &req, t).await
            && resp.status == 200
        {
            let d = parse_description(&String::from_utf8_lossy(&resp.body));
            let e = out.entry(ip).or_default();
            e.friendly_name = d.friendly_name;
            e.manufacturer = d.manufacturer;
            e.model = d.model;
            e.model_number = d.model_number;
            for dt in d.targets {
                if !e.targets.contains(&dt) {
                    e.targets.push(dt);
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const REPLY: &[u8] = b"HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nLOCATION: http://192.168.1.1:5000/rootDesc.xml\r\nSERVER: Linux/5.4 UPnP/1.1 MiniUPnPd/2.2.1\r\nST: upnp:rootdevice\r\nUSN: uuid:abc::upnp:rootdevice\r\n\r\n";

    #[test]
    fn parses_reply() {
        let r = parse_reply(REPLY, "192.168.1.1".parse().unwrap()).unwrap();
        assert_eq!(r.server.as_deref(), Some("Linux/5.4 UPnP/1.1 MiniUPnPd/2.2.1"));
        assert_eq!(r.st.as_deref(), Some("upnp:rootdevice"));
        assert_eq!(r.location.as_deref(), Some("http://192.168.1.1:5000/rootDesc.xml"));
    }

    #[test]
    fn rejects_non_ssdp() {
        assert!(parse_reply(b"GET / HTTP/1.1\r\n\r\n", "1.1.1.1".parse().unwrap()).is_none());
        assert!(parse_reply(b"", "1.1.1.1".parse().unwrap()).is_none());
        assert!(parse_reply(&[0xff; 100], "1.1.1.1".parse().unwrap()).is_none());
    }

    #[test]
    fn parses_notify() {
        let n = b"NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nNT: urn:schemas-upnp-org:device:MediaServer:1\r\nUSN: uuid:x\r\nLOCATION: http://192.168.1.4:80/d.xml\r\n\r\n";
        let r = parse_reply(n, "192.168.1.4".parse().unwrap()).unwrap();
        assert_eq!(r.st.as_deref(), Some("urn:schemas-upnp-org:device:MediaServer:1"));
    }

    #[test]
    fn location_ssrf_guard() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        assert!(location_target("http://192.168.1.1:5000/rootDesc.xml", ip).is_some());
        assert!(location_target("http://192.168.1.1/d.xml", ip).is_some());
        // Someone else's address: refuse (SSRF to another host/internal service).
        assert!(location_target("http://192.168.1.99:80/d.xml", ip).is_none());
        assert!(location_target("http://169.254.169.254/latest/meta-data", ip).is_none());
        assert!(location_target("http://evil.example/d.xml", ip).is_none());
        assert!(location_target("https://192.168.1.1/d.xml", ip).is_none());
        assert!(location_target("http://user@192.168.1.1/d.xml", ip).is_none());
        assert!(location_target("file:///etc/passwd", ip).is_none());
    }

    #[test]
    fn description_parsing() {
        let xml = "<root><device><deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType><friendlyName>Home &amp; Router</friendlyName><manufacturer>Acme</manufacturer><modelName>RT-1</modelName><modelNumber>v2</modelNumber></device></root>";
        let d = parse_description(xml);
        assert_eq!(d.friendly_name.as_deref(), Some("Home & Router"));
        assert_eq!(d.manufacturer.as_deref(), Some("Acme"));
        assert_eq!(d.model.as_deref(), Some("RT-1"));
        assert_eq!(d.targets.len(), 1);
        assert!(parse_description("<junk").friendly_name.is_none());
    }

    #[tokio::test]
    async fn end_to_end_unicast_with_description() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpListener, UdpSocket};
        let http_l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let http_port = http_l.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = http_l.accept().await {
                let mut b = [0u8; 1024];
                let _ = s.read(&mut b).await;
                let body = "<root><device><friendlyName>Test Gateway</friendlyName><manufacturer>Acme</manufacturer></device></root>";
                let _ = s.write_all(format!("HTTP/1.0 200 OK\r\nContent-Length: {}\r\n\r\n{}", body.len(), body).as_bytes()).await;
            }
        });
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let uaddr = udp.local_addr().unwrap();
        tokio::spawn(async move {
            let mut b = [0u8; 1024];
            while let Ok((_, from)) = udp.recv_from(&mut b).await {
                let r = format!(
                    "HTTP/1.1 200 OK\r\nLOCATION: http://127.0.0.1:{http_port}/d.xml\r\nSERVER: Test/1.0\r\nST: upnp:rootdevice\r\n\r\n"
                );
                let _ = udp.send_to(r.as_bytes(), from).await;
            }
        });
        let cfg = Config { window: Duration::from_millis(500), ifaces: vec![Ipv4Addr::LOCALHOST], unicast_targets: vec![uaddr] };
        let (replies, _) = discover(&cfg).await;
        assert!(!replies.is_empty());
        let t = Timeouts { connect: Duration::from_millis(500), total: Duration::from_secs(2) };
        let info = describe(&replies, t).await;
        let d = info.get(&"127.0.0.1".parse().unwrap()).unwrap();
        assert_eq!(d.friendly_name.as_deref(), Some("Test Gateway"));
        assert_eq!(d.server.as_deref(), Some("Test/1.0"));
    }
}
