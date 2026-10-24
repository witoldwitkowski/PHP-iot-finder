//! Data model shared by discovery, checkers, reports and the GUI.
//!
//! Everything here is `serde`-serialisable so scans can be saved, diffed and
//! rendered. All text that originated on the network has been passed through
//! [`crate::util::sanitize`] before it is stored.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Current JSON schema version of [`ScanResult`].
pub const SCHEMA_VERSION: u32 = 1;

/// How bad a finding is if it is real.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Informational only.
    Info,
    /// Low.
    Low,
    /// Medium.
    Medium,
    /// High.
    High,
    /// Critical.
    Critical,
}

impl Severity {
    /// Lowercase name.
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    /// Parse from a case-insensitive name.
    pub fn parse(s: &str) -> Option<Severity> {
        match s.trim().to_ascii_lowercase().as_str() {
            "info" | "informational" => Some(Severity::Info),
            "low" => Some(Severity::Low),
            "medium" | "moderate" => Some(Severity::Medium),
            "high" => Some(Severity::High),
            "critical" => Some(Severity::Critical),
            _ => None,
        }
    }

    /// All severities, most severe first.
    pub const ALL_DESC: [Severity; 5] = [Severity::Critical, Severity::High, Severity::Medium, Severity::Low, Severity::Info];
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How sure the checker is that the finding applies to this device.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    /// A weak or indirect signal; the device may well be fine (for example the
    /// version is hidden, or a distribution may have back-ported the fix).
    Possible,
    /// Good evidence: an authoritative version in the affected range with no
    /// sign of vendor back-porting.
    Likely,
    /// Directly observed (an open port, an exposed page, a verified behaviour).
    Confirmed,
}

impl Confidence {
    /// Lowercase name.
    pub fn as_str(self) -> &'static str {
        match self {
            Confidence::Possible => "possible",
            Confidence::Likely => "likely",
            Confidence::Confirmed => "confirmed",
        }
    }

    /// Lower the confidence one step (never below `Possible`).
    pub fn lowered(self) -> Confidence {
        match self {
            Confidence::Confirmed => Confidence::Likely,
            _ => Confidence::Possible,
        }
    }
}

impl std::fmt::Display for Confidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One security issue on one device.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Finding {
    /// Id of the checker that produced it (stable; used by the allowlist).
    pub checker: String,
    /// Short human title.
    pub title: String,
    /// Severity if real.
    pub severity: Severity,
    /// Confidence that it applies.
    pub confidence: Confidence,
    /// What was found and why it matters.
    pub summary: String,
    /// The observations that led to this conclusion.
    #[serde(default)]
    pub evidence: Vec<String>,
    /// What to do about it.
    #[serde(default)]
    pub remediation: String,
    /// CVE ids.
    #[serde(default)]
    pub cves: Vec<String>,
    /// Links to advisories.
    #[serde(default)]
    pub references: Vec<String>,
    /// TCP/UDP port the finding is about, if specific.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// Set when an allowlist entry suppresses this finding (the reason).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suppressed: Option<String>,
}

impl Finding {
    /// Start building a finding.
    pub fn new(checker: &str, title: impl Into<String>, severity: Severity, confidence: Confidence) -> Finding {
        Finding {
            checker: checker.to_string(),
            title: title.into(),
            severity,
            confidence,
            summary: String::new(),
            evidence: vec![],
            remediation: String::new(),
            cves: vec![],
            references: vec![],
            port: None,
            suppressed: None,
        }
    }

    /// Set the summary.
    pub fn summary(mut self, s: impl Into<String>) -> Self {
        self.summary = s.into();
        self
    }
    /// Add one evidence line.
    pub fn evidence(mut self, s: impl Into<String>) -> Self {
        self.evidence.push(s.into());
        self
    }
    /// Set the remediation text.
    pub fn remediation(mut self, s: impl Into<String>) -> Self {
        self.remediation = s.into();
        self
    }
    /// Set the CVE list.
    pub fn cves(mut self, c: &[String]) -> Self {
        self.cves = c.to_vec();
        self
    }
    /// Set the reference list.
    pub fn references(mut self, r: &[String]) -> Self {
        self.references = r.to_vec();
        self
    }
    /// Attach a port.
    pub fn port(mut self, p: u16) -> Self {
        self.port = Some(p);
        self
    }

    /// Identity used to match findings across scans.
    pub fn key(&self) -> String {
        format!("{}|{}", self.checker, self.port.map(|p| p.to_string()).unwrap_or_default())
    }

    /// Sort rank: higher is more urgent (severity first, then confidence).
    pub fn rank(&self) -> (Severity, Confidence) {
        (self.severity, self.confidence)
    }
}

/// What kind of service was identified on a port.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ServiceKind {
    /// Plain HTTP.
    Http,
    /// HTTP over TLS.
    Https,
    /// Telnet.
    Telnet,
    /// SSH.
    Ssh,
    /// FTP.
    Ftp,
    /// RTSP (cameras).
    Rtsp,
    /// MQTT.
    Mqtt,
    /// Open port, not identified.
    Other,
}

/// Summary of one HTTP(S) response.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct HttpInfo {
    /// Whether TLS was used.
    pub tls: bool,
    /// Negotiated TLS version, when TLS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_version: Option<String>,
    /// Final status code.
    pub status: u16,
    /// Path of the final response (after same-host redirects).
    pub path: String,
    /// `Server` header.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    /// `X-Powered-By` header.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub powered_by: Option<String>,
    /// `<title>` of the page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// `Location` header of the final response, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    /// Cookie names set by the server (values are never stored).
    #[serde(default)]
    pub cookie_names: Vec<String>,
    /// Selected response headers (name, sanitised value).
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    /// Start of the body, sanitised, for fingerprinting. Not serialised.
    #[serde(skip)]
    pub body: String,
}

impl HttpInfo {
    /// Case-insensitive header lookup.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

/// One open port on a device.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Service {
    /// TCP port.
    pub port: u16,
    /// Identified kind.
    pub kind: ServiceKind,
    /// First bytes the service sent (sanitised), for non-HTTP services.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub banner: Option<String>,
    /// HTTP details.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http: Option<HttpInfo>,
    /// Note on why enrichment was partial (timeout, TLS failure, …).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl Service {
    /// True for HTTP and HTTPS services.
    pub fn is_web(&self) -> bool {
        matches!(self.kind, ServiceKind::Http | ServiceKind::Https)
    }
}

/// A service announced over mDNS/DNS-SD.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct MdnsService {
    /// Instance name, e.g. `Living Room TV`.
    pub instance: String,
    /// Service type, e.g. `_googlecast._tcp`.
    pub service: String,
    /// Port.
    pub port: u16,
    /// Selected TXT key=value pairs (sanitised).
    #[serde(default)]
    pub txt: Vec<String>,
}

/// UPnP/SSDP description of a device.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct SsdpInfo {
    /// `SERVER` header.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    /// Advertised search targets / device types.
    #[serde(default)]
    pub targets: Vec<String>,
    /// `friendlyName` from the device description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub friendly_name: Option<String>,
    /// `manufacturer`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manufacturer: Option<String>,
    /// `modelName`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// `modelNumber`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_number: Option<String>,
}

/// A device on the network.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Device {
    /// Primary address.
    pub ip: IpAddr,
    /// Additional addresses learned for the same device (e.g. IPv6 via mDNS).
    #[serde(default)]
    pub other_ips: Vec<IpAddr>,
    /// MAC address (lowercase, colon separated) when learned from the local link.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    /// Vendor from the MAC prefix.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    /// Hostname from mDNS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// Best human description, e.g. `Hikvision IP camera`.
    #[serde(default)]
    pub label: String,
    /// Guessed device type (`camera`, `router`, `printer`, …).
    #[serde(default)]
    pub kind: String,
    /// How the device was discovered (`tcp`, `arp-cache`, `arp`, `mdns`, `ssdp`, `icmp6`).
    #[serde(default)]
    pub discovered_via: Vec<String>,
    /// Open services.
    #[serde(default)]
    pub services: Vec<Service>,
    /// mDNS services.
    #[serde(default)]
    pub mdns: Vec<MdnsService>,
    /// SSDP details.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssdp: Option<SsdpInfo>,
    /// PHP detection summary, if PHP was seen.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub php: Option<crate::fingerprint::php::PhpDetection>,
    /// Findings from all checkers.
    #[serde(default)]
    pub findings: Vec<Finding>,
}

impl Device {
    /// A bare device with only an address.
    pub fn new(ip: IpAddr) -> Device {
        Device {
            ip,
            other_ips: vec![],
            mac: None,
            vendor: None,
            hostname: None,
            label: String::new(),
            kind: String::new(),
            discovered_via: vec![],
            services: vec![],
            mdns: vec![],
            ssdp: None,
            php: None,
            findings: vec![],
        }
    }

    /// Stable identity across scans: MAC if known, otherwise the IP.
    pub fn identity(&self) -> String {
        self.mac.clone().unwrap_or_else(|| self.ip.to_string())
    }

    /// Record a discovery method once.
    pub fn via(&mut self, how: &str) {
        if !self.discovered_via.iter().any(|v| v == how) {
            self.discovered_via.push(how.to_string());
        }
    }

    /// Open ports, ascending.
    pub fn open_ports(&self) -> Vec<u16> {
        let mut p: Vec<u16> = self.services.iter().map(|s| s.port).collect();
        p.sort_unstable();
        p
    }

    /// Findings that are not suppressed.
    pub fn active_findings(&self) -> impl Iterator<Item = &Finding> {
        self.findings.iter().filter(|f| f.suppressed.is_none())
    }

    /// Highest severity among active findings.
    pub fn worst(&self) -> Option<&Finding> {
        self.active_findings().max_by_key(|f| f.rank())
    }
}

/// Counters for the summary line.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Stats {
    /// Addresses probed.
    pub addresses_scanned: usize,
    /// Devices found.
    pub devices: usize,
    /// Open services found.
    pub services: usize,
    /// Active (non-suppressed) findings by severity: critical, high, medium, low, info.
    pub findings: [usize; 5],
    /// Suppressed findings.
    pub suppressed: usize,
    /// Wall-clock seconds.
    pub duration_secs: f64,
}

/// Summary of the options a scan ran with (recorded for reproducibility).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ScanSummary {
    /// Targets as given.
    pub targets: Vec<String>,
    /// Ports probed.
    pub ports: Vec<u16>,
    /// Whether `--active` probes were enabled.
    pub active: bool,
    /// Whether the raw ARP sweep was used.
    pub raw_arp: bool,
    /// Checkers that ran.
    pub checkers: Vec<String>,
}

/// Complete result of one scan.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScanResult {
    /// JSON schema version.
    pub schema_version: u32,
    /// iotscan version.
    pub tool_version: String,
    /// Start time (RFC 3339).
    pub started: String,
    /// Finish time (RFC 3339).
    pub finished: String,
    /// Options used.
    pub summary: ScanSummary,
    /// Devices found.
    pub devices: Vec<Device>,
    /// Non-fatal problems (privilege missing, multicast blocked, …).
    #[serde(default)]
    pub warnings: Vec<String>,
    /// Counters.
    pub stats: Stats,
}

impl ScanResult {
    /// Recompute `stats` from `devices`.
    pub fn recount(&mut self) {
        self.stats.devices = self.devices.len();
        self.stats.services = self.devices.iter().map(|d| d.services.len()).sum();
        self.stats.findings = [0; 5];
        self.stats.suppressed = 0;
        for d in &self.devices {
            for f in &d.findings {
                if f.suppressed.is_some() {
                    self.stats.suppressed += 1;
                } else {
                    let idx = match f.severity {
                        Severity::Critical => 0,
                        Severity::High => 1,
                        Severity::Medium => 2,
                        Severity::Low => 3,
                        Severity::Info => 4,
                    };
                    self.stats.findings[idx] += 1;
                }
            }
        }
    }

    /// Highest active severity across all devices.
    pub fn worst_severity(&self) -> Option<Severity> {
        self.devices.iter().flat_map(|d| d.active_findings()).map(|f| f.severity).max()
    }

    /// Count of active findings at or above `min`.
    pub fn count_at_least(&self, min: Severity) -> usize {
        self.devices.iter().flat_map(|d| d.active_findings()).filter(|f| f.severity >= min).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Confidence::Confirmed > Confidence::Likely);
        assert_eq!(Confidence::Confirmed.lowered(), Confidence::Likely);
        assert_eq!(Confidence::Possible.lowered(), Confidence::Possible);
        assert_eq!(Severity::parse("HIGH"), Some(Severity::High));
        assert_eq!(Severity::parse("x"), None);
    }

    #[test]
    fn finding_key_and_rank() {
        let f = Finding::new("php2shell", "t", Severity::High, Confidence::Likely).port(80);
        assert_eq!(f.key(), "php2shell|80");
        assert_eq!(f.rank(), (Severity::High, Confidence::Likely));
    }

    #[test]
    fn json_roundtrip() {
        let mut d = Device::new("192.168.1.5".parse().unwrap());
        d.findings.push(Finding::new("x", "t", Severity::Low, Confidence::Possible));
        let s = serde_json::to_string(&d).unwrap();
        let back: Device = serde_json::from_str(&s).unwrap();
        assert_eq!(back.findings.len(), 1);
        assert_eq!(back.identity(), "192.168.1.5");
    }
}
