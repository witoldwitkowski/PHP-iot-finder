//! Port lists and port-spec parsing.

/// Ports that commonly serve web admin pages on IoT devices.
pub const WEB_PORTS: &[u16] = &[80, 81, 82, 443, 5000, 5001, 8000, 8008, 8080, 8081, 8088, 8090, 8443, 8888, 9000, 9090];

/// Non-web services worth knowing about on IoT devices.
pub const OTHER_PORTS: &[u16] = &[
    21,   // FTP
    22,   // SSH
    23,   // Telnet
    554,  // RTSP (cameras)
    1883, // MQTT
    2323, // alternate Telnet used by many botnets
    5555, // Android Debug Bridge
    7547, // TR-069
    8883, // MQTT over TLS
];

/// Ports on which we try TLS before plain HTTP.
pub const TLS_FIRST: &[u16] = &[443, 4443, 5001, 8443, 9443, 10443];

/// Default port list: web ports plus the non-web ones.
pub fn default_ports() -> Vec<u16> {
    let mut v: Vec<u16> = WEB_PORTS.iter().chain(OTHER_PORTS).copied().collect();
    v.sort_unstable();
    v.dedup();
    v
}

/// Ports that are probed with HTTP (everything in [`WEB_PORTS`] plus any
/// user-supplied port that is not a known non-web service).
pub fn is_web_candidate(port: u16) -> bool {
    WEB_PORTS.contains(&port) || !OTHER_PORTS.contains(&port)
}

/// Most-likely-first ordering, so that early-exit logic and slow hosts see the
/// ports that matter first.
pub fn order_by_popularity(ports: &mut [u16]) {
    const FIRST: &[u16] = &[80, 443, 22, 23, 8080, 8443, 554, 8000, 81, 8081, 21, 1883, 5000];
    ports.sort_by_key(|p| (FIRST.iter().position(|f| f == p).unwrap_or(usize::MAX), *p));
}

/// Parse a port spec: `80,443,8000-8100`, or the keywords `default`, `web`, `top`.
pub fn parse_ports(spec: &str) -> Result<Vec<u16>, String> {
    let mut out: Vec<u16> = Vec::new();
    for part in spec.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        match part {
            "default" | "top" => out.extend(default_ports()),
            "web" => out.extend(WEB_PORTS),
            _ => {
                if let Some((a, b)) = part.split_once('-') {
                    let a: u16 = a.trim().parse().map_err(|_| format!("bad port '{a}'"))?;
                    let b: u16 = b.trim().parse().map_err(|_| format!("bad port '{b}'"))?;
                    if a == 0 || b < a {
                        return Err(format!("bad port range '{part}'"));
                    }
                    if (b - a) as usize >= 4096 {
                        return Err(format!("port range '{part}' is larger than 4096 ports"));
                    }
                    out.extend(a..=b);
                } else {
                    let p: u16 = part.parse().map_err(|_| format!("bad port '{part}'"))?;
                    if p == 0 {
                        return Err("port 0 is not valid".into());
                    }
                    out.push(p);
                }
            }
        }
    }
    if out.is_empty() {
        return Err("no ports given".into());
    }
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse() {
        assert_eq!(parse_ports("80,443").unwrap(), vec![80, 443]);
        assert_eq!(parse_ports("8000-8002,80,80").unwrap(), vec![80, 8000, 8001, 8002]);
        assert!(parse_ports("0").is_err());
        assert!(parse_ports("70000").is_err());
        assert!(parse_ports("90-80").is_err());
        assert!(parse_ports("1-60000").is_err());
        assert!(parse_ports("").is_err());
        assert!(parse_ports("web").unwrap().contains(&8080));
        assert!(parse_ports("default").unwrap().contains(&23));
    }

    #[test]
    fn web_candidates() {
        assert!(is_web_candidate(80));
        assert!(is_web_candidate(12345));
        assert!(!is_web_candidate(22));
        assert!(!is_web_candidate(23));
    }

    #[test]
    fn popularity_order() {
        let mut p = vec![9000, 23, 80, 5, 443];
        order_by_popularity(&mut p);
        assert_eq!(p, vec![80, 443, 23, 5, 9000]);
    }

    #[test]
    fn default_is_sorted_unique() {
        let d = default_ports();
        let mut s = d.clone();
        s.sort_unstable();
        s.dedup();
        assert_eq!(d, s);
    }
}
