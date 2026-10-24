//! Coloured terminal report.

use super::{CONFIDENCE_LEGEND, confidence_words, marker};
use crate::diff::Diff;
use crate::model::{Device, Finding, ScanResult, Severity};
use crate::util::truncate;

/// Rendering options.
#[derive(Clone, Copy, Debug)]
pub struct Opts {
    /// Emit ANSI colours.
    pub color: bool,
    /// Terminal width in columns.
    pub width: usize,
    /// Show evidence lines and low/info findings in full.
    pub verbose: bool,
    /// Include suppressed findings.
    pub show_suppressed: bool,
}

impl Default for Opts {
    fn default() -> Self {
        Opts { color: false, width: 100, verbose: false, show_suppressed: false }
    }
}

struct Style {
    on: bool,
}

impl Style {
    fn wrap(&self, code: &str, s: &str) -> String {
        if self.on { format!("\x1b[{code}m{s}\x1b[0m") } else { s.to_string() }
    }
    fn bold(&self, s: &str) -> String {
        self.wrap("1", s)
    }
    fn dim(&self, s: &str) -> String {
        self.wrap("2", s)
    }
    fn sev(&self, sev: Severity, s: &str) -> String {
        let code = match sev {
            Severity::Critical => "1;97;41",
            Severity::High => "1;31",
            Severity::Medium => "1;33",
            Severity::Low => "36",
            Severity::Info => "2",
        };
        self.wrap(code, s)
    }
}

/// Wrap `text` to `width` columns with a hanging `indent`.
pub fn wrap(text: &str, width: usize, indent: usize) -> String {
    let width = width.max(indent + 20);
    let pad = " ".repeat(indent);
    let mut out = String::new();
    let mut line = String::new();
    for word in text.split_whitespace() {
        if !line.is_empty() && indent + line.chars().count() + 1 + word.chars().count() > width {
            out.push_str(&pad);
            out.push_str(&line);
            out.push('\n');
            line.clear();
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    if !line.is_empty() {
        out.push_str(&pad);
        out.push_str(&line);
        out.push('\n');
    }
    out
}

fn sev_tag(st: &Style, sev: Severity) -> String {
    st.sev(sev, &format!(" {} {} ", marker(sev), sev.as_str().to_uppercase()))
}

fn ports_text(d: &Device) -> String {
    let p = d.open_ports();
    if p.is_empty() { "-".into() } else { p.iter().map(u16::to_string).collect::<Vec<_>>().join(" ") }
}

/// Render a full report.
pub fn render(r: &ScanResult, diff: Option<&Diff>, o: &Opts) -> String {
    let st = Style { on: o.color };
    let mut out = String::new();
    let w = o.width.clamp(60, 200);

    out.push_str(&format!(
        "{}  {}\n",
        st.bold(&format!("iotscan {}", r.tool_version)),
        st.dim(&format!(
            "{} · {} device{} · {:.1}s{}",
            r.summary.targets.join(", "),
            r.devices.len(),
            if r.devices.len() == 1 { "" } else { "s" },
            r.stats.duration_secs,
            if r.summary.active { " · active probes on" } else { "" }
        ))
    ));
    for warn in &r.warnings {
        out.push_str(&st.dim(&format!("  note: {warn}\n")));
    }
    out.push('\n');

    // ---- device table ----
    let mut devices: Vec<&Device> = r.devices.iter().collect();
    devices.sort_by(|a, b| {
        let ra = a.worst().map(|f| f.rank());
        let rb = b.worst().map(|f| f.rank());
        rb.cmp(&ra).then(a.ip.cmp(&b.ip))
    });
    let name_w = (w.saturating_sub(15 + 19 + 20 + 14 + 6)).clamp(14, 44);
    out.push_str(&st.bold("DEVICES"));
    out.push('\n');
    out.push_str(&st.dim(&format!("{:<15} {:<19} {:<name_w$} {:<20} {}\n", "ADDRESS", "MAC", "DEVICE", "OPEN PORTS", "RISK")));
    for d in &devices {
        let risk = match d.worst() {
            Some(f) => st.sev(f.severity, &format!("{} {}", marker(f.severity), f.severity.as_str())),
            None => st.dim("– none"),
        };
        out.push_str(&format!(
            "{:<15} {:<19} {:<name_w$} {:<20} {}\n",
            d.ip,
            d.mac.as_deref().unwrap_or("-"),
            truncate(if d.label.is_empty() { "Unidentified device" } else { &d.label }, name_w),
            truncate(&ports_text(d), 20),
            risk
        ));
    }
    if devices.is_empty() {
        out.push_str("No devices found. Check the target range, or that you are on the same network.\n");
    }
    out.push('\n');

    // ---- findings ----
    let with_findings: Vec<&Device> =
        devices.iter().copied().filter(|d| d.findings.iter().any(|f| f.suppressed.is_none() || o.show_suppressed)).collect();
    let total_active: usize = r.stats.findings.iter().sum();
    if with_findings.is_empty() {
        out.push_str(&format!("{}\n\n", st.bold("No findings. Nothing needs attention.")));
    } else {
        out.push_str(&format!(
            "{}  {}\n\n",
            st.bold("FINDINGS"),
            st.dim(&format!(
                "{} on {} device{}{}",
                total_active,
                with_findings.len(),
                if with_findings.len() == 1 { "" } else { "s" },
                if r.stats.suppressed > 0 { format!(" · {} suppressed by allowlist", r.stats.suppressed) } else { String::new() }
            ))
        ));
        for d in with_findings {
            out.push_str(&format!(
                "{}  {}\n",
                st.bold(&d.ip.to_string()),
                st.dim(&format!(
                    "{}{}",
                    if d.label.is_empty() { "Unidentified device" } else { &d.label },
                    d.mac.as_ref().map(|m| format!(" · {m}")).unwrap_or_default()
                ))
            ));
            let mut fs: Vec<&Finding> = d.findings.iter().filter(|f| f.suppressed.is_none() || o.show_suppressed).collect();
            fs.sort_by_key(|f| std::cmp::Reverse(f.rank()));
            for f in fs {
                out.push_str(&finding_block(&st, f, w, o));
            }
            out.push('\n');
        }
    }

    // ---- changes ----
    if let Some(d) = diff {
        out.push_str(&st.bold("CHANGES"));
        out.push_str(&format!("  {}\n", st.dim(&d.summary())));
        let sev_of = |s: Option<Severity>| s.map(|s| format!(" [{}]", s.as_str())).unwrap_or_default();
        for n in &d.new_devices {
            out.push_str(&format!("  + new device  {:<15} {}{}\n", n.ip, truncate(&n.label, 40), sev_of(n.worst)));
        }
        for n in &d.missing_devices {
            out.push_str(&format!("  - gone         {:<15} {}\n", n.ip, truncate(&n.label, 40)));
        }
        for c in &d.changed {
            out.push_str(&format!("  ~ changed      {:<15} {}\n", c.device.ip, truncate(&c.device.label, 40)));
            if let Some(p) = &c.previous_ip {
                out.push_str(&format!("      address changed from {p}\n"));
            }
            for p in &c.opened_ports {
                out.push_str(&format!("      port {p} newly open\n"));
            }
            for p in &c.closed_ports {
                out.push_str(&format!("      port {p} closed\n"));
            }
            for f in &c.new_findings {
                out.push_str(&format!("      new: {} {} ({})\n", marker(f.severity), f.title, confidence_words(f.confidence)));
            }
            for f in &c.resolved_findings {
                out.push_str(&format!("      resolved: {}\n", f.title));
            }
            for f in &c.changed_findings {
                out.push_str(&format!(
                    "      rating changed: {} ({} {} → {} {})\n",
                    f.finding.title,
                    f.was_severity,
                    confidence_words(f.was_confidence),
                    f.finding.severity,
                    confidence_words(f.finding.confidence)
                ));
            }
        }
        out.push('\n');
    }

    // ---- summary + hints ----
    let s = &r.stats.findings;
    out.push_str(&format!(
        "{} critical · {} high · {} medium · {} low · {} info\n",
        st.sev(Severity::Critical, &s[0].to_string()),
        st.sev(Severity::High, &s[1].to_string()),
        st.sev(Severity::Medium, &s[2].to_string()),
        st.sev(Severity::Low, &s[3].to_string()),
        st.sev(Severity::Info, &s[4].to_string()),
    ));
    if r.devices.iter().flat_map(|d| &d.findings).any(|f| f.summary.contains("--active")) && !r.summary.active {
        out.push_str(&wrap(
            "Tip: some versions are hidden. Re-run with --active to look for exposed phpinfo() pages that would reveal them.",
            w,
            0,
        ));
    }
    if total_active > 0 {
        out.push_str(&st.dim(&wrap(&format!("Confidence: {CONFIDENCE_LEGEND}."), w, 0)));
    }
    out
}

fn finding_block(st: &Style, f: &Finding, w: usize, o: &Opts) -> String {
    let mut out = String::new();
    let port = f.port.map(|p| format!(" · port {p}")).unwrap_or_default();
    let cves = if f.cves.is_empty() { String::new() } else { format!(" · {}", f.cves.join(", ")) };
    let sup = f.suppressed.as_ref().map(|r| format!(" · suppressed: {r}")).unwrap_or_default();
    out.push_str(&format!("  {} {}\n", sev_tag(st, f.severity), st.bold(&f.title)));
    out.push_str(&st.dim(&format!("      {}{}{}{}\n", confidence_words(f.confidence), port, cves, sup)));
    if f.severity >= Severity::Low || o.verbose {
        out.push_str(&wrap(&f.summary, w, 6));
    }
    if o.verbose || f.severity >= Severity::High {
        for e in f.evidence.iter().take(if o.verbose { 12 } else { 4 }) {
            out.push_str(&st.dim(&wrap(&format!("• {e}"), w, 6)));
        }
    }
    if !f.remediation.is_empty() && (f.severity >= Severity::Low || o.verbose) {
        out.push_str(&format!("      {} ", st.bold("Fix:")));
        let fix = wrap(&f.remediation, w, 6);
        out.push_str(fix.trim_start());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Confidence, SCHEMA_VERSION, ScanSummary, Service, ServiceKind, Stats};

    fn sample() -> ScanResult {
        let mut d = Device::new("192.168.1.50".parse().unwrap());
        d.mac = Some("aa:bb:cc:dd:ee:ff".into());
        d.label = "Garage camera".into();
        d.services.push(Service { port: 80, kind: ServiceKind::Http, banner: None, http: None, note: None });
        d.findings.push(
            Finding::new("php2shell", "PHP2Shell: unauthenticated remote code execution in PHP", Severity::Critical, Confidence::Likely)
                .port(80)
                .summary("PHP 8.2.30 is older than the patched release 8.2.35.")
                .evidence("X-Powered-By: PHP/8.2.30")
                .remediation("Upgrade PHP to 8.2.35 or newer.")
                .cves(&["CVE-2026-109618".to_string()]),
        );
        let mut quiet = Device::new("192.168.1.9".parse().unwrap());
        quiet.label = "Thermostat".into();
        let mut r = ScanResult {
            schema_version: SCHEMA_VERSION,
            tool_version: "0.1.0".into(),
            started: "2026-10-24T00:00:00Z".into(),
            finished: "2026-10-24T00:00:05Z".into(),
            summary: ScanSummary { targets: vec!["192.168.1.0/24".into()], ..ScanSummary::default() },
            devices: vec![quiet, d],
            warnings: vec![],
            stats: Stats::default(),
        };
        r.recount();
        r
    }

    #[test]
    fn plain_output_has_no_escapes_and_key_facts() {
        let t = render(&sample(), None, &Opts::default());
        assert!(!t.contains('\x1b'));
        assert!(t.contains("192.168.1.50"));
        assert!(t.contains("Garage camera"));
        assert!(t.contains("CRITICAL"));
        assert!(t.contains("likely"));
        assert!(t.contains("CVE-2026-109618"));
        assert!(t.contains("Fix: Upgrade PHP to 8.2.35"));
        assert!(t.contains("1 critical"));
        // Riskiest device first.
        assert!(t.find("192.168.1.50").unwrap() < t.find("192.168.1.9 ").unwrap());
    }

    #[test]
    fn colour_output_has_escapes() {
        let t = render(&sample(), None, &Opts { color: true, ..Opts::default() });
        assert!(t.contains("\x1b["));
    }

    #[test]
    fn hostile_text_cannot_inject_escapes_via_wrapping() {
        // Sanitising happens at ingest; this verifies the renderer itself adds nothing unexpected.
        let t = render(&sample(), None, &Opts::default());
        assert_eq!(t.matches('\x1b').count(), 0);
    }

    #[test]
    fn suppressed_hidden_unless_requested() {
        let mut r = sample();
        r.devices[1].findings[0].suppressed = Some("accepted".into());
        r.recount();
        let t = render(&r, None, &Opts::default());
        assert!(t.contains("No findings"));
        let t = render(&r, None, &Opts { show_suppressed: true, ..Opts::default() });
        assert!(t.contains("suppressed: accepted"));
    }

    #[test]
    fn empty_result() {
        let mut r = sample();
        r.devices.clear();
        r.recount();
        let t = render(&r, None, &Opts::default());
        assert!(t.contains("No devices found"));
    }

    #[test]
    fn wrap_respects_width() {
        let w = wrap("one two three four five six seven eight nine ten", 24, 4);
        assert!(w.lines().all(|l| l.chars().count() <= 24), "{w}");
        assert!(w.lines().all(|l| l.starts_with("    ")));
        assert_eq!(wrap("", 40, 2), "");
    }

    #[test]
    fn narrow_terminals_do_not_panic() {
        for width in [0, 10, 40, 60, 500] {
            let _ = render(&sample(), None, &Opts { width, ..Opts::default() });
        }
    }
}
