//! Telnet exposed on the network. Telnet sends everything, including
//! passwords, in cleartext and is the classic entry point for IoT botnets.

use super::*;
use crate::model::Severity;

/// Checker id.
pub const ID: &str = "telnet-open";

/// The Telnet checker.
pub struct TelnetOpen;

impl Checker for TelnetOpen {
    fn meta(&self) -> CheckerMeta {
        CheckerMeta {
            id: ID,
            name: "Telnet service exposed",
            description: "An open Telnet port: cleartext remote shell, a favourite of IoT botnets.",
            category: Category::RemoteAccess,
            tags: &["telnet", "cleartext", "botnet"],
            uses_active_probes: false,
        }
    }

    fn needs(&self) -> Vec<Need> {
        vec![Need::Banner(23), Need::Banner(2323)]
    }

    fn evaluate(&self, input: &CheckInput) -> Vec<Finding> {
        input
            .services_of(ServiceKind::Telnet)
            .map(|s| {
                let mut f = Finding::new(ID, "Telnet is enabled", Severity::High, Confidence::Confirmed)
                    .port(s.port)
                    .summary(format!(
                        "Port {} accepts Telnet connections. Telnet is unencrypted and frequently protected only by default passwords; attackers scan the internet for it constantly.",
                        s.port
                    ))
                    .remediation("Disable Telnet in the device's settings and use SSH or the vendor app instead. If it cannot be disabled, update the firmware, change default passwords, and keep the device on an isolated network.")
                    .evidence(format!("TCP port {} is open and speaks Telnet", s.port));
                if let Some(b) = &s.banner {
                    f = f.evidence(format!("Banner: {b}"));
                }
                f
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::super::testutil::*;
    use super::*;
    use crate::model::Service;

    #[test]
    fn flags_telnet() {
        let mut d = Device::new("192.168.1.9".parse().unwrap());
        d.services.push(Service { port: 23, kind: ServiceKind::Telnet, banner: Some("BusyBox login:".into()), http: None, note: None });
        let db = AdvisoryDb::embedded();
        let f = TelnetOpen.evaluate(&input(&d, &ProbeResults::default(), &db, "2026-10-24"));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].confidence, Confidence::Confirmed);
        assert!(f[0].evidence.iter().any(|e| e.contains("BusyBox")));
    }

    #[test]
    fn ignores_other_services() {
        let mut d = Device::new("192.168.1.9".parse().unwrap());
        d.services.push(Service { port: 22, kind: ServiceKind::Ssh, banner: None, http: None, note: None });
        let db = AdvisoryDb::embedded();
        assert!(TelnetOpen.evaluate(&input(&d, &ProbeResults::default(), &db, "2026-10-24")).is_empty());
    }
}
