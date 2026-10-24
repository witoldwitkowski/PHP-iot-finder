//! Human-friendly labels and device-type guesses.

use crate::model::Device;
use crate::util::truncate;

/// Keyword rules, checked in order against a lowercase description of the device.
const RULES: &[(&str, &[&str])] = &[
    (
        "camera",
        &[
            "camera",
            "ipcam",
            "ip cam",
            "dvr",
            "nvr",
            "hikvision",
            "dahua",
            "reolink",
            "foscam",
            "amcrest",
            "axis communications",
            "wyze",
            "ring ",
            "arlo",
            "onvif",
            "_rtsp",
        ],
    ),
    ("printer", &["printer", "_ipp", "_printer", "laserjet", "officejet", "epson", "brother", "pixma", "xerox", "_pdl-datastream"]),
    (
        "router",
        &[
            "router",
            "internetgatewaydevice",
            "gateway",
            "openwrt",
            "routeros",
            "mikrotik",
            "tp-link",
            "netgear",
            "ubiquiti",
            "unifi",
            "fritz",
            "asuswrt",
            "dd-wrt",
            "miniupnpd",
            "access point",
        ],
    ),
    ("nas", &["synology", "diskstation", "qnap", "nas ", "readynas", "western digital", "my cloud", "truenas", "_smb"]),
    (
        "tv",
        &[
            "bravia",
            "webos",
            "roku",
            "chromecast",
            "_googlecast",
            "_airplay",
            "tizen",
            "smart tv",
            "samsung tv",
            "lg tv",
            "appletv",
            "mediarenderer",
            "vizio",
        ],
    ),
    ("speaker", &["sonos", "echo", "homepod", "_raop", "spotify", "bose", "speaker", "alexa"]),
    (
        "smart-home",
        &[
            "philips hue",
            "_hue",
            "_hap",
            "homekit",
            "zigbee",
            "tuya",
            "esphome",
            "_esphomelib",
            "shelly",
            "tasmota",
            "espressif",
            "smartthings",
            "_matter",
            "wemo",
            "tp-link smart",
            "sonoff",
            "lifx",
            "nest",
            "ecobee",
            "thermostat",
            "bulb",
            "plug",
        ],
    ),
    ("computer", &["_workstation", "_device-info", "windows", "ubuntu", "macbook", "_ssh"]),
];

fn haystack(d: &Device) -> String {
    let mut s = String::new();
    let mut add = |x: &str| {
        s.push_str(&x.to_ascii_lowercase());
        s.push(' ');
    };
    if let Some(v) = &d.vendor {
        add(v);
    }
    if let Some(h) = &d.hostname {
        add(h);
    }
    for m in &d.mdns {
        add(&m.service);
        add(&m.instance);
        for t in &m.txt {
            add(t);
        }
    }
    if let Some(u) = &d.ssdp {
        for x in [&u.server, &u.friendly_name, &u.manufacturer, &u.model].into_iter().flatten() {
            add(x);
        }
        for t in &u.targets {
            add(t);
        }
    }
    for svc in &d.services {
        if let Some(h) = &svc.http {
            for x in [&h.title, &h.server].into_iter().flatten() {
                add(x);
            }
            if let Some(a) = h.header("www-authenticate") {
                add(a);
            }
        }
        match svc.port {
            554 => add("_rtsp"),
            631 | 9100 => add("printer"),
            1883 | 8883 => add("mqtt"),
            _ => {}
        }
    }
    s
}

/// Guess a device type.
pub fn guess_kind(d: &Device) -> String {
    let h = haystack(d);
    for (kind, words) in RULES {
        if words.iter().any(|w| h.contains(w)) {
            return (*kind).to_string();
        }
    }
    "unknown".to_string()
}

fn generic_title(t: &str) -> bool {
    let l = t.to_ascii_lowercase();
    [
        "index of",
        "401",
        "403",
        "404",
        "unauthorized",
        "forbidden",
        "not found",
        "welcome to nginx",
        "apache2",
        "it works",
        "login",
        "document",
        "untitled",
        "home",
    ]
    .iter()
    .any(|g| l == *g || l.starts_with(g))
}

/// Pick the most informative description of the device.
pub fn label(d: &Device) -> String {
    if let Some(u) = &d.ssdp {
        match (&u.friendly_name, &u.manufacturer, &u.model) {
            (Some(f), _, Some(m)) if !f.contains(m.as_str()) => return truncate(&format!("{f} ({m})"), 70),
            (Some(f), _, _) => return truncate(f, 70),
            (None, Some(mf), Some(m)) => return truncate(&format!("{mf} {m}"), 70),
            _ => {}
        }
    }
    if let Some(m) = d.mdns.iter().find(|m| !m.instance.is_empty() && m.service != "_device-info._tcp" && m.service != "_workstation._tcp")
    {
        let model = m.txt.iter().find_map(|t| t.strip_prefix("md=").or_else(|| t.strip_prefix("model=")));
        return truncate(
            &match model {
                Some(md) => format!("{} ({md})", m.instance),
                None => m.instance.clone(),
            },
            70,
        );
    }
    if let Some(h) = &d.hostname {
        return truncate(h, 70);
    }
    for s in &d.services {
        if let Some(t) = s.http.as_ref().and_then(|h| h.title.as_ref())
            && !generic_title(t)
        {
            return truncate(t, 70);
        }
    }
    match (&d.vendor, d.kind.as_str()) {
        (Some(v), "unknown") if v != "Private/randomized address" => truncate(&format!("{v} device"), 70),
        (Some(v), k) if v != "Private/randomized address" => truncate(&format!("{v} {k}"), 70),
        (_, k) if k != "unknown" && !k.is_empty() => k.to_string(),
        _ => "Unidentified device".to_string(),
    }
}

/// Fill `kind` and `label` on a device.
pub fn apply(d: &mut Device) {
    d.kind = guess_kind(d);
    d.label = label(d);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{HttpInfo, MdnsService, Service, ServiceKind, SsdpInfo};

    fn dev() -> Device {
        Device::new("192.168.1.9".parse().unwrap())
    }

    #[test]
    fn camera_by_vendor_and_port() {
        let mut d = dev();
        d.vendor = Some("Hangzhou Hikvision Digital Technology".into());
        apply(&mut d);
        assert_eq!(d.kind, "camera");
        assert!(d.label.contains("Hikvision"));
    }

    #[test]
    fn ssdp_label_wins() {
        let mut d = dev();
        d.ssdp = Some(SsdpInfo { friendly_name: Some("Living Room".into()), model: Some("Bravia X90".into()), ..SsdpInfo::default() });
        apply(&mut d);
        assert_eq!(d.label, "Living Room (Bravia X90)");
        assert_eq!(d.kind, "tv");
    }

    #[test]
    fn mdns_label_with_model() {
        let mut d = dev();
        d.mdns.push(MdnsService {
            instance: "Kitchen display".into(),
            service: "_googlecast._tcp".into(),
            port: 8009,
            txt: vec!["md=Nest Hub".into()],
        });
        apply(&mut d);
        assert_eq!(d.label, "Kitchen display (Nest Hub)");
        assert_eq!(d.kind, "tv");
    }

    #[test]
    fn http_title_used_unless_generic() {
        let mut d = dev();
        d.services.push(Service {
            port: 80,
            kind: ServiceKind::Http,
            banner: None,
            http: Some(HttpInfo { title: Some("Garage Door Controller".into()), ..HttpInfo::default() }),
            note: None,
        });
        apply(&mut d);
        assert_eq!(d.label, "Garage Door Controller");
        d.services[0].http.as_mut().unwrap().title = Some("Login".into());
        d.vendor = Some("Acme".into());
        apply(&mut d);
        assert_eq!(d.label, "Acme device");
    }

    #[test]
    fn fallback() {
        let mut d = dev();
        apply(&mut d);
        assert_eq!(d.label, "Unidentified device");
        assert_eq!(d.kind, "unknown");
        d.vendor = Some("Private/randomized address".into());
        apply(&mut d);
        assert_eq!(d.label, "Unidentified device");
    }
}
