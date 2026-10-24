//! UPnP/SSDP answering on the LAN. Not a vulnerability by itself, but UPnP
//! lets software on the network open ports in the router and is rarely needed.

use super::*;
use crate::model::Severity;

/// Checker id.
pub const ID: &str = "upnp-exposed";

/// The UPnP checker.
pub struct UpnpExposed;

impl Checker for UpnpExposed {
    fn meta(&self) -> CheckerMeta {
        CheckerMeta {
            id: ID,
            name: "UPnP / SSDP enabled",
            description: "Devices answering UPnP discovery widen the attack surface (port forwarding, SSDP abuse).",
            category: Category::Exposure,
            tags: &["upnp", "ssdp", "exposure"],
            uses_active_probes: false,
        }
    }

    fn needs(&self) -> Vec<Need> {
        vec![Need::Ssdp]
    }

    fn evaluate(&self, input: &CheckInput) -> Vec<Finding> {
        let Some(s) = &input.device.ssdp else { return vec![] };
        let is_router = input.device.kind == "router";
        let mut f = Finding::new(ID, "UPnP is enabled", if is_router { Severity::Low } else { Severity::Info }, Confidence::Confirmed)
            .summary(if is_router {
                "The router answers UPnP discovery. UPnP lets any program on your network ask the router to open ports to the internet without a password."
            } else {
                "The device answers UPnP/SSDP discovery. Services like this are rarely needed on IoT devices and add attack surface."
            })
            .remediation(if is_router {
                "Disable UPnP in the router's settings unless an application you use depends on it, and review the router's existing port forwards."
            } else {
                "Disable UPnP on the device if it has the option; otherwise keep it on an isolated network."
            })
            .evidence("Replied to an SSDP M-SEARCH");
        if let Some(sv) = &s.server {
            f = f.evidence(format!("SERVER: {sv}"));
        }
        if let Some(m) = &s.model {
            f = f.evidence(format!("Model: {m}"));
        }
        vec![f]
    }
}

#[cfg(test)]
mod tests {
    use super::super::testutil::*;
    use super::*;
    use crate::model::SsdpInfo;

    #[test]
    fn flags_ssdp_devices() {
        let mut d = Device::new("192.168.1.1".parse().unwrap());
        d.kind = "router".into();
        d.ssdp = Some(SsdpInfo { server: Some("Linux/5.4 UPnP/1.1 MiniUPnPd/2.2.1".into()), ..SsdpInfo::default() });
        let db = AdvisoryDb::embedded();
        let f = UpnpExposed.evaluate(&input(&d, &ProbeResults::default(), &db, "2026-10-24"));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Low);
        d.kind = "tv".into();
        let f = UpnpExposed.evaluate(&input(&d, &ProbeResults::default(), &db, "2026-10-24"));
        assert_eq!(f[0].severity, Severity::Info);
    }

    #[test]
    fn silent_without_ssdp() {
        let d = Device::new("192.168.1.1".parse().unwrap());
        let db = AdvisoryDb::embedded();
        assert!(UpnpExposed.evaluate(&input(&d, &ProbeResults::default(), &db, "2026-10-24")).is_empty());
    }
}
