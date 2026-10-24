//! Comparing two scans: what appeared, vanished or changed.

use crate::model::{Confidence, Device, Finding, ScanResult, Severity};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

/// A compact reference to a device.
#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct DeviceRef {
    /// Stable identity (MAC or IP).
    pub identity: String,
    /// Address.
    pub ip: String,
    /// Description.
    pub label: String,
    /// MAC, if known.
    pub mac: Option<String>,
    /// Open ports.
    pub ports: Vec<u16>,
    /// Worst active severity.
    pub worst: Option<Severity>,
}

/// A compact reference to a finding.
#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct FindingRef {
    /// Checker id.
    pub checker: String,
    /// Title.
    pub title: String,
    /// Severity.
    pub severity: Severity,
    /// Confidence.
    pub confidence: Confidence,
    /// Port.
    pub port: Option<u16>,
}

impl From<&Finding> for FindingRef {
    fn from(f: &Finding) -> Self {
        FindingRef { checker: f.checker.clone(), title: f.title.clone(), severity: f.severity, confidence: f.confidence, port: f.port }
    }
}

/// A finding whose severity or confidence changed.
#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct FindingChange {
    /// The finding now.
    pub finding: FindingRef,
    /// Severity before.
    pub was_severity: Severity,
    /// Confidence before.
    pub was_confidence: Confidence,
}

/// Changes to one device present in both scans.
#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct DeviceDiff {
    /// The device.
    pub device: DeviceRef,
    /// Previous address when it changed.
    pub previous_ip: Option<String>,
    /// Ports that opened.
    pub opened_ports: Vec<u16>,
    /// Ports that closed.
    pub closed_ports: Vec<u16>,
    /// Findings that appeared.
    pub new_findings: Vec<FindingRef>,
    /// Findings that went away.
    pub resolved_findings: Vec<FindingRef>,
    /// Findings whose rating changed.
    pub changed_findings: Vec<FindingChange>,
}

impl DeviceDiff {
    fn is_empty(&self) -> bool {
        self.previous_ip.is_none()
            && self.opened_ports.is_empty()
            && self.closed_ports.is_empty()
            && self.new_findings.is_empty()
            && self.resolved_findings.is_empty()
            && self.changed_findings.is_empty()
    }
}

/// The difference between two scans.
#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct Diff {
    /// Start time of the earlier scan.
    pub previous: String,
    /// Start time of the later scan.
    pub current: String,
    /// Devices only in the later scan.
    pub new_devices: Vec<DeviceRef>,
    /// Devices only in the earlier scan.
    pub missing_devices: Vec<DeviceRef>,
    /// Devices present in both with changes.
    pub changed: Vec<DeviceDiff>,
}

fn dref(d: &Device) -> DeviceRef {
    DeviceRef {
        identity: d.identity(),
        ip: d.ip.to_string(),
        label: d.label.clone(),
        mac: d.mac.clone(),
        ports: d.open_ports(),
        worst: d.worst().map(|f| f.severity),
    }
}

fn active_map(d: &Device) -> BTreeMap<String, &Finding> {
    d.active_findings().map(|f| (f.key(), f)).collect()
}

/// Compare `old` to `new`.
pub fn compare(old: &ScanResult, new: &ScanResult) -> Diff {
    let mut used_old: BTreeSet<usize> = BTreeSet::new();
    let mut new_devices = Vec::new();
    let mut changed = Vec::new();

    for nd in &new.devices {
        // Prefer a MAC match (survives DHCP changes) and, among equal MACs, the same address;
        // then fall back to an address match.
        let by_mac = nd.mac.as_ref().and_then(|m| {
            let cands = || old.devices.iter().enumerate().filter(|(i, o)| !used_old.contains(i) && o.mac.as_ref() == Some(m));
            cands().find(|(_, o)| o.ip == nd.ip).or_else(|| cands().next())
        });
        let found = by_mac.or_else(|| {
            old.devices
                .iter()
                .enumerate()
                .find(|(i, o)| !used_old.contains(i) && o.ip == nd.ip && (o.mac.is_none() || nd.mac.is_none() || o.mac == nd.mac))
        });
        let Some((oi, od)) = found else {
            new_devices.push(dref(nd));
            continue;
        };
        used_old.insert(oi);

        let (old_ports, new_ports) = (od.open_ports(), nd.open_ports());
        let (om, nm) = (active_map(od), active_map(nd));
        let mut dd = DeviceDiff {
            device: dref(nd),
            previous_ip: (od.ip != nd.ip).then(|| od.ip.to_string()),
            opened_ports: new_ports.iter().filter(|p| !old_ports.contains(p)).copied().collect(),
            closed_ports: old_ports.iter().filter(|p| !new_ports.contains(p)).copied().collect(),
            new_findings: nm.iter().filter(|(k, _)| !om.contains_key(*k)).map(|(_, f)| (*f).into()).collect(),
            resolved_findings: om.iter().filter(|(k, _)| !nm.contains_key(*k)).map(|(_, f)| (*f).into()).collect(),
            changed_findings: nm
                .iter()
                .filter_map(|(k, f)| {
                    let o = om.get(k)?;
                    (o.severity != f.severity || o.confidence != f.confidence).then(|| FindingChange {
                        finding: (*f).into(),
                        was_severity: o.severity,
                        was_confidence: o.confidence,
                    })
                })
                .collect(),
        };
        dd.new_findings.sort_by_key(|f| std::cmp::Reverse((f.severity, f.confidence)));
        if !dd.is_empty() {
            changed.push(dd);
        }
    }
    let missing_devices = old.devices.iter().enumerate().filter(|(i, _)| !used_old.contains(i)).map(|(_, d)| dref(d)).collect();
    Diff { previous: old.started.clone(), current: new.started.clone(), new_devices, missing_devices, changed }
}

impl Diff {
    /// True when anything changed.
    pub fn has_changes(&self) -> bool {
        !(self.new_devices.is_empty() && self.missing_devices.is_empty() && self.changed.is_empty())
    }

    /// Number of findings that appeared on any device (including new devices).
    pub fn new_finding_count(&self, new: &ScanResult) -> usize {
        let on_changed: usize = self.changed.iter().map(|c| c.new_findings.len()).sum();
        let on_new: usize = new
            .devices
            .iter()
            .filter(|d| self.new_devices.iter().any(|n| n.identity == d.identity()))
            .map(|d| d.active_findings().count())
            .sum();
        on_changed + on_new
    }

    /// One-line English summary.
    pub fn summary(&self) -> String {
        if !self.has_changes() {
            return "No changes since the previous scan.".to_string();
        }
        let mut parts = Vec::new();
        let n = |n: usize, one: &str, many: &str| format!("{n} {}", if n == 1 { one } else { many });
        if !self.new_devices.is_empty() {
            parts.push(n(self.new_devices.len(), "new device", "new devices"));
        }
        if !self.missing_devices.is_empty() {
            parts.push(format!("{} gone", n(self.missing_devices.len(), "device", "devices")));
        }
        let nf: usize = self.changed.iter().map(|c| c.new_findings.len()).sum();
        let rf: usize = self.changed.iter().map(|c| c.resolved_findings.len()).sum();
        let op: usize = self.changed.iter().map(|c| c.opened_ports.len()).sum();
        if nf > 0 {
            parts.push(n(nf, "new finding", "new findings"));
        }
        if rf > 0 {
            parts.push(n(rf, "resolved finding", "resolved findings"));
        }
        if op > 0 {
            parts.push(format!("{} newly open", n(op, "port", "ports")));
        }
        if parts.is_empty() {
            parts.push(format!("{} changed", n(self.changed.len(), "device", "devices")));
        }
        format!("Since the previous scan: {}.", parts.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{SCHEMA_VERSION, ScanSummary, Service, ServiceKind, Stats};

    fn scan(devs: Vec<Device>) -> ScanResult {
        ScanResult {
            schema_version: SCHEMA_VERSION,
            tool_version: "t".into(),
            started: "2026-10-24T00:00:00Z".into(),
            finished: "2026-10-24T00:01:00Z".into(),
            summary: ScanSummary::default(),
            devices: devs,
            warnings: vec![],
            stats: Stats::default(),
        }
    }

    fn dev(ip: &str, mac: Option<&str>, ports: &[u16], findings: &[(&str, Severity)]) -> Device {
        let mut d = Device::new(ip.parse().unwrap());
        d.mac = mac.map(Into::into);
        d.label = format!("dev {ip}");
        for p in ports {
            d.services.push(Service { port: *p, kind: ServiceKind::Other, banner: None, http: None, note: None });
        }
        for (c, s) in findings {
            d.findings.push(Finding::new(c, "t", *s, Confidence::Likely).port(ports.first().copied().unwrap_or(0)));
        }
        d
    }

    #[test]
    fn identical_scans_have_no_changes() {
        let a = scan(vec![dev("192.168.1.2", Some("aa:aa:aa:aa:aa:01"), &[80], &[("x", Severity::Low)])]);
        let d = compare(&a, &a.clone());
        assert!(!d.has_changes());
        assert_eq!(d.summary(), "No changes since the previous scan.");
    }

    #[test]
    fn new_and_missing_devices() {
        let old =
            scan(vec![dev("192.168.1.2", Some("aa:aa:aa:aa:aa:01"), &[80], &[]), dev("192.168.1.3", Some("aa:aa:aa:aa:aa:02"), &[], &[])]);
        let new = scan(vec![
            dev("192.168.1.2", Some("aa:aa:aa:aa:aa:01"), &[80], &[]),
            dev("192.168.1.9", Some("aa:aa:aa:aa:aa:09"), &[23], &[("telnet-open", Severity::High)]),
        ]);
        let d = compare(&old, &new);
        assert_eq!(d.new_devices.len(), 1);
        assert_eq!(d.new_devices[0].ip, "192.168.1.9");
        assert_eq!(d.new_devices[0].worst, Some(Severity::High));
        assert_eq!(d.missing_devices.len(), 1);
        assert_eq!(d.missing_devices[0].ip, "192.168.1.3");
        assert_eq!(d.new_finding_count(&new), 1);
        assert!(d.summary().contains("1 new device"));
    }

    #[test]
    fn dhcp_change_is_tracked_by_mac() {
        let old = scan(vec![dev("192.168.1.2", Some("aa:aa:aa:aa:aa:01"), &[80], &[])]);
        let new = scan(vec![dev("192.168.1.77", Some("aa:aa:aa:aa:aa:01"), &[80], &[])]);
        let d = compare(&old, &new);
        assert!(d.new_devices.is_empty() && d.missing_devices.is_empty());
        assert_eq!(d.changed[0].previous_ip.as_deref(), Some("192.168.1.2"));
    }

    #[test]
    fn port_and_finding_changes() {
        let old = scan(vec![dev(
            "192.168.1.2",
            Some("aa:aa:aa:aa:aa:01"),
            &[80, 23],
            &[("telnet-open", Severity::High), ("php2shell", Severity::Critical)],
        )]);
        let mut nd =
            dev("192.168.1.2", Some("aa:aa:aa:aa:aa:01"), &[80, 8080], &[("php2shell", Severity::High), ("php-eol", Severity::High)]);
        for f in &mut nd.findings {
            f.port = Some(80);
        }
        let mut od = old.devices[0].clone();
        for f in &mut od.findings {
            f.port = Some(80);
        }
        let d = compare(&scan(vec![od]), &scan(vec![nd]));
        let c = &d.changed[0];
        assert_eq!(c.opened_ports, vec![8080]);
        assert_eq!(c.closed_ports, vec![23]);
        assert_eq!(c.new_findings.len(), 1);
        assert_eq!(c.new_findings[0].checker, "php-eol");
        assert_eq!(c.resolved_findings.len(), 1);
        assert_eq!(c.resolved_findings[0].checker, "telnet-open");
        assert_eq!(c.changed_findings.len(), 1);
        assert_eq!(c.changed_findings[0].was_severity, Severity::Critical);
    }

    #[test]
    fn suppressed_findings_are_invisible() {
        let old = scan(vec![dev("192.168.1.2", None, &[80], &[])]);
        let mut nd = dev("192.168.1.2", None, &[80], &[("x", Severity::High)]);
        nd.findings[0].suppressed = Some("ok".into());
        assert!(!compare(&old, &scan(vec![nd])).has_changes());
    }

    #[test]
    fn devices_sharing_a_mac_are_matched_by_address() {
        // One NIC answering for two addresses (aliases, proxy ARP).
        let old =
            scan(vec![dev("192.168.1.2", Some("aa:aa:aa:aa:aa:01"), &[80], &[]), dev("192.168.1.3", Some("aa:aa:aa:aa:aa:01"), &[], &[])]);
        let new =
            scan(vec![dev("192.168.1.3", Some("aa:aa:aa:aa:aa:01"), &[], &[]), dev("192.168.1.2", Some("aa:aa:aa:aa:aa:01"), &[80], &[])]);
        let d = compare(&old, &new);
        assert!(!d.has_changes(), "{d:?}");
    }

    #[test]
    fn two_devices_swapping_ips_are_matched_by_mac() {
        let old =
            scan(vec![dev("192.168.1.2", Some("aa:aa:aa:aa:aa:01"), &[], &[]), dev("192.168.1.3", Some("aa:aa:aa:aa:aa:02"), &[], &[])]);
        let new =
            scan(vec![dev("192.168.1.2", Some("aa:aa:aa:aa:aa:02"), &[], &[]), dev("192.168.1.3", Some("aa:aa:aa:aa:aa:01"), &[], &[])]);
        let d = compare(&old, &new);
        assert!(d.new_devices.is_empty() && d.missing_devices.is_empty());
        assert_eq!(d.changed.len(), 2);
    }
}
