//! Synthetic demo data (`iotscan gui --demo`): a plausible home network, with
//! findings produced by the real checkers, so the interface can be explored
//! without scanning anything.

use crate::advisories::AdvisoryDb;
use crate::checkers::{CheckInput, ProbeData, ProbeKind, ProbeResults, Registry};
use crate::fingerprint::{identify, php::PhpDetection};
use crate::model::*;
use crate::testkit::phpinfo_page;
use crate::util::{self, Date, parse_mac};

struct Spec {
    octet: u8,
    mac: &'static str,
    hostname: Option<&'static str>,
    mdns: &'static [(&'static str, &'static str, u16, &'static [&'static str])],
    ssdp: Option<(&'static str, &'static str, &'static str)>,
    web: &'static [(u16, bool, &'static str, &'static str, &'static str, &'static str)], // port, tls, server, powered_by, title, cookie
    other: &'static [(u16, ServiceKind, &'static str)],
    phpinfo_at: Option<(u16, &'static str)>,
}

const SPECS: &[Spec] = &[
    Spec {
        octet: 1,
        mac: "2c:fd:a1:10:00:01",
        hostname: Some("rt-ax88u"),
        mdns: &[],
        ssdp: Some(("Home router", "ASUSTeK", "RT-AX88U")),
        web: &[(80, false, "httpd/2.0", "", "ASUS Router Login", ""), (443, true, "httpd/2.0", "", "ASUS Router Login", "")],
        other: &[],
        phpinfo_at: None,
    },
    Spec {
        octet: 20,
        mac: "04:03:12:5a:11:20",
        hostname: None,
        mdns: &[],
        ssdp: None,
        web: &[(80, false, "App-webs/", "PHP/7.4.33", "Network Camera", "PHPSESSID")],
        other: &[(23, ServiceKind::Telnet, "\u{0}login: "), (554, ServiceKind::Rtsp, "")],
        phpinfo_at: None,
    },
    Spec {
        octet: 21,
        mac: "3c:ef:8c:70:00:21",
        hostname: None,
        mdns: &[],
        ssdp: None,
        web: &[(80, false, "nginx", "PHP/8.2.30", "Driveway camera", "")],
        other: &[(554, ServiceKind::Rtsp, "")],
        phpinfo_at: None,
    },
    Spec {
        octet: 30,
        mac: "84:25:db:33:00:30",
        hostname: Some("samsung-tv"),
        mdns: &[("Living room TV", "_airplay._tcp", 7000, &["model=UE55AU8000"])],
        ssdp: Some(("Living room TV", "Samsung Electronics", "UE55AU8000")),
        web: &[],
        other: &[],
        phpinfo_at: None,
    },
    Spec {
        octet: 31,
        mac: "f4:f5:d8:44:00:31",
        hostname: Some("nest-hub"),
        mdns: &[("Kitchen display", "_googlecast._tcp", 8009, &["md=Nest Hub", "ve=05"])],
        ssdp: None,
        web: &[],
        other: &[],
        phpinfo_at: None,
    },
    Spec {
        octet: 40,
        mac: "00:11:32:aa:00:40",
        hostname: Some("diskstation"),
        mdns: &[("DiskStation", "_smb._tcp", 445, &[])],
        ssdp: None,
        web: &[
            (5000, false, "Apache/2.4.57 (Debian)", "PHP/8.2.7-1~deb12u1", "Synology DiskStation", "PHPSESSID"),
            (5001, true, "Apache/2.4.57 (Debian)", "PHP/8.2.7-1~deb12u1", "Synology DiskStation", ""),
        ],
        other: &[(22, ServiceKind::Ssh, "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3")],
        phpinfo_at: None,
    },
    Spec {
        octet: 41,
        mac: "00:01:e6:55:00:41",
        hostname: Some("npi5a1b2c"),
        mdns: &[("HP LaserJet M404", "_ipp._tcp", 631, &["ty=HP LaserJet M404n"])],
        ssdp: None,
        web: &[(80, false, "HP HTTP Server", "", "HP LaserJet M404n", ""), (443, true, "HP HTTP Server", "", "HP LaserJet M404n", "")],
        other: &[],
        phpinfo_at: None,
    },
    Spec {
        octet: 50,
        mac: "08:3a:f2:66:00:50",
        hostname: Some("tasmota-plug"),
        mdns: &[],
        ssdp: None,
        web: &[(80, false, "Tasmota", "", "Tasmota - Hallway plug", "")],
        other: &[],
        phpinfo_at: None,
    },
    Spec { octet: 51, mac: "44:61:32:77:00:51", hostname: None, mdns: &[], ssdp: None, web: &[], other: &[], phpinfo_at: None },
    Spec {
        octet: 52,
        mac: "00:17:88:88:00:52",
        hostname: Some("philips-hue"),
        mdns: &[("Hue Bridge", "_hue._tcp", 443, &["bridgeid=001788fffe880052"])],
        ssdp: Some(("Hue Bridge", "Signify", "BSB002")),
        web: &[
            (80, false, "nginx", "", "hue personal wireless lighting", ""),
            (443, true, "nginx", "", "hue personal wireless lighting", ""),
        ],
        other: &[],
        phpinfo_at: None,
    },
    Spec {
        octet: 60,
        mac: "54:2a:1b:99:00:60",
        hostname: Some("sonos-move"),
        mdns: &[("Garden Sonos", "_spotify-connect._tcp", 1400, &[])],
        ssdp: Some(("Garden Sonos", "Sonos, Inc.", "Move")),
        web: &[],
        other: &[],
        phpinfo_at: None,
    },
    Spec {
        octet: 70,
        mac: "d8:3a:dd:12:00:70",
        hostname: Some("raspberrypi"),
        mdns: &[("raspberrypi", "_ssh._tcp", 22, &[])],
        ssdp: None,
        web: &[(80, false, "Apache/2.4.62 (Raspbian)", "PHP/8.2.28-1~deb12u1", "Pi-hole Admin", "PHPSESSID")],
        other: &[(22, ServiceKind::Ssh, "SSH-2.0-OpenSSH_9.2p1 Raspbian-2+deb12u5")],
        phpinfo_at: None,
    },
    Spec {
        octet: 71,
        mac: "10:d0:7a:41:00:71",
        hostname: None,
        mdns: &[],
        ssdp: None,
        web: &[(80, false, "Boa/0.94.14rc21", "", "IP Baby Monitor", "")],
        other: &[(23, ServiceKind::Telnet, "BusyBox login: ")],
        phpinfo_at: None,
    },
    Spec { octet: 80, mac: "6e:5b:1c:00:00:80", hostname: None, mdns: &[], ssdp: None, web: &[], other: &[], phpinfo_at: None },
    Spec {
        octet: 90,
        mac: "b0:95:8e:aa:00:90",
        hostname: None,
        mdns: &[],
        ssdp: None,
        web: &[(80, false, "nginx", "", "Video Doorbell", "PHPSESSID")],
        other: &[],
        phpinfo_at: Some((80, "8.2.30")),
    },
    Spec {
        octet: 100,
        mac: "a4:83:e7:21:00:64",
        hostname: Some("workbook"),
        mdns: &[("Workbook", "_workstation._tcp", 9, &[])],
        ssdp: None,
        web: &[],
        other: &[],
        phpinfo_at: None,
    },
];

fn build(octet_filter: impl Fn(u8) -> bool) -> Vec<Device> {
    let db = AdvisoryDb::embedded();
    let registry = Registry::builtin();
    let today = Date::parse("2026-10-24").expect("valid date");
    let mut out = Vec::new();
    for s in SPECS.iter().filter(|s| octet_filter(s.octet)) {
        let mut d = Device::new(format!("192.168.1.{}", s.octet).parse().expect("ip"));
        let mac = if s.mac.split(':').count() == 6 && s.mac.len() == 17 { s.mac.to_string() } else { "a4:83:e7:21:00:64".to_string() };
        d.mac = Some(mac.clone());
        d.vendor = parse_mac(&mac).and_then(|m| crate::oui::vendor(&m));
        d.hostname = s.hostname.map(String::from);
        d.discovered_via = vec!["tcp".into(), "arp".into()];
        for (instance, service, port, txt) in s.mdns {
            d.mdns.push(MdnsService {
                instance: instance.to_string(),
                service: service.to_string(),
                port: *port,
                txt: txt.iter().map(|t| t.to_string()).collect(),
            });
            d.via("mdns");
        }
        if let Some((name, mf, model)) = s.ssdp {
            d.ssdp = Some(SsdpInfo {
                server: Some("Linux/5.4 UPnP/1.1 MiniUPnPd/2.2.1".into()),
                targets: vec!["upnp:rootdevice".into()],
                friendly_name: Some(name.into()),
                manufacturer: Some(mf.into()),
                model: Some(model.into()),
                model_number: None,
            });
            d.via("ssdp");
        }
        for (port, tls, server, powered, title, cookie) in s.web {
            let mut http = HttpInfo {
                tls: *tls,
                tls_version: tls.then(|| "TLSv1_3".to_string()),
                status: 200,
                path: "/".into(),
                ..HttpInfo::default()
            };
            if !server.is_empty() {
                http.server = Some(server.to_string());
            }
            if !powered.is_empty() {
                http.powered_by = Some(powered.to_string());
            }
            http.title = Some(title.to_string());
            if !cookie.is_empty() {
                http.cookie_names.push(cookie.to_string());
            }
            d.services.push(Service {
                port: *port,
                kind: if *tls { ServiceKind::Https } else { ServiceKind::Http },
                banner: None,
                http: Some(http),
                note: None,
            });
        }
        for (port, kind, banner) in s.other {
            let b = banner.replace('\u{0}', "");
            d.services.push(Service { port: *port, kind: *kind, banner: (!b.is_empty()).then_some(b), http: None, note: None });
        }
        d.services.sort_by_key(|x| x.port);
        let mut probes = ProbeResults::default();
        if let Some((port, version)) = s.phpinfo_at {
            probes.insert(
                ProbeKind::http_get(port, "/info.php"),
                Ok(ProbeData::Http { status: 200, headers: vec![], body: phpinfo_page(version), tls: false }),
            );
        }
        identify::apply(&mut d);
        let input = CheckInput { device: &d, probes: &probes, db: &db, today, active: true };
        d.findings = registry.evaluate(&input);
        let facts = crate::checkers::php_facts(&d, &probes);
        if !facts.is_empty() {
            d.php = Some(PhpDetection { facts });
        }
        identify::apply(&mut d);
        out.push(d);
    }
    out
}

fn wrap(devices: Vec<Device>, started: &str, targets: &str) -> ScanResult {
    let mut r = ScanResult {
        schema_version: SCHEMA_VERSION,
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        started: started.to_string(),
        finished: started.to_string(),
        summary: ScanSummary {
            targets: vec![targets.to_string()],
            ports: crate::ports::default_ports(),
            active: true,
            raw_arp: false,
            checkers: Registry::builtin().ids(),
        },
        devices,
        warnings: vec!["Demo data: nothing here was scanned.".to_string()],
        stats: Stats { addresses_scanned: 254, duration_secs: 14.2, ..Stats::default() },
    };
    r.recount();
    r
}

/// The current demo scan and an earlier one to diff against.
pub fn scans() -> (ScanResult, ScanResult) {
    let now = wrap(build(|_| true), &util::now_rfc3339(), "192.168.1.0/24");
    let mut earlier_devices = build(|o| o != 71);
    // Last week: the doorbell's phpinfo() page had not been found yet, and an old tablet was around.
    for d in &mut earlier_devices {
        if d.ip.to_string().ends_with(".90") {
            d.findings.clear();
        }
    }
    let mut tablet = Device::new("192.168.1.99".parse().expect("ip"));
    tablet.mac = Some("a4:83:e7:21:00:99".into());
    tablet.label = "Old tablet".into();
    earlier_devices.push(tablet);
    let earlier = wrap(earlier_devices, "2026-10-17T19:02:11Z", "192.168.1.0/24");
    (now, earlier)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demo_has_realistic_findings() {
        let (now, earlier) = scans();
        assert!(now.devices.len() >= 15);
        assert!(now.stats.findings[0] >= 2, "critical findings: {:?}", now.stats.findings);
        assert!(now.devices.iter().any(|d| d.findings.iter().any(|f| f.checker == "telnet-open")));
        assert!(now.devices.iter().any(|d| d.findings.iter().any(|f| f.confidence == Confidence::Possible)));
        let diff = crate::diff::compare(&earlier, &now);
        assert_eq!(diff.new_devices.len(), 1);
        assert_eq!(diff.missing_devices.len(), 1);
        assert!(!diff.changed.is_empty());
    }

    #[test]
    fn demo_labels_are_sensible() {
        let (now, _) = scans();
        assert!(now.devices.iter().all(|d| !d.label.is_empty()));
        assert!(now.devices.iter().any(|d| d.kind == "camera"));
        assert!(now.devices.iter().any(|d| d.kind == "router"));
    }
}
