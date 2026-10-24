//! Standalone, self-contained HTML report (no scripts, no external requests).

use super::{CONFIDENCE_LEGEND, confidence_words};
use crate::diff::Diff;
use crate::model::{Device, Finding, ScanResult, Severity};
use crate::util::html_escape as esc;

static CSS: &str = include_str!("../../assets/ui.css");

/// Inline SVG marker; shape differs per severity.
pub fn svg_marker(s: Severity) -> &'static str {
    match s {
        Severity::Critical => r#"<svg viewBox="0 0 10 10" aria-hidden="true"><path d="M5 0l5 5-5 5-5-5z" fill="currentColor"/></svg>"#,
        Severity::High => r#"<svg viewBox="0 0 10 10" aria-hidden="true"><path d="M5 .5l5 9H0z" fill="currentColor"/></svg>"#,
        Severity::Medium => {
            r#"<svg viewBox="0 0 10 10" aria-hidden="true"><rect x="1" y="1" width="8" height="8" rx="1.2" fill="currentColor"/></svg>"#
        }
        Severity::Low => r#"<svg viewBox="0 0 10 10" aria-hidden="true"><circle cx="5" cy="5" r="4.5" fill="currentColor"/></svg>"#,
        Severity::Info => {
            r#"<svg viewBox="0 0 10 10" aria-hidden="true"><circle cx="5" cy="5" r="3.7" fill="none" stroke="currentColor" stroke-width="1.6"/></svg>"#
        }
    }
}

fn chip(s: Severity) -> String {
    format!(r#"<span class="chip {0}">{1}{0}</span>"#, s.as_str(), svg_marker(s))
}

fn conf(c: crate::model::Confidence) -> String {
    format!(r#"<span class="conf {0}" title="{1}">{0}</span>"#, confidence_words(c), esc(CONFIDENCE_LEGEND))
}

fn safe_link(url: &str) -> String {
    if url.starts_with("https://") || url.starts_with("http://") {
        format!(r#"<a href="{0}" rel="noopener noreferrer">{0}</a>"#, esc(url))
    } else {
        esc(url)
    }
}

/// HTML for one finding card.
pub fn finding_card(f: &Finding) -> String {
    let mut h = String::new();
    h.push_str(&format!(r#"<article class="fcard {}{}">"#, f.severity.as_str(), if f.suppressed.is_some() { " suppressed" } else { "" }));
    h.push_str(&format!(r#"<div class="row">{} {}"#, chip(f.severity), conf(f.confidence)));
    if let Some(p) = f.port {
        h.push_str(&format!(r#"<span class="port">port {p}</span>"#));
    }
    for c in &f.cves {
        h.push_str(&format!(r#"<span class="port">{}</span>"#, esc(c)));
    }
    h.push_str("</div>");
    h.push_str(&format!("<h4>{}</h4><p>{}</p>", esc(&f.title), esc(&f.summary)));
    if let Some(r) = &f.suppressed {
        h.push_str(&format!(r#"<p><strong>Suppressed:</strong> {}</p>"#, esc(r)));
    }
    if !f.evidence.is_empty() {
        h.push_str("<ul>");
        for e in &f.evidence {
            h.push_str(&format!("<li>{}</li>", esc(e)));
        }
        h.push_str("</ul>");
    }
    if !f.remediation.is_empty() {
        h.push_str(&format!(r#"<div class="fix"><b>What to do</b>{}</div>"#, esc(&f.remediation)));
    }
    if !f.references.is_empty() {
        h.push_str(r#"<div class="refs">"#);
        for r in &f.references {
            h.push_str(&safe_link(r));
        }
        h.push_str("</div>");
    }
    h.push_str("</article>");
    h
}

fn tile_ip(d: &Device) -> String {
    match d.ip {
        std::net::IpAddr::V4(a) => format!(".{}", a.octets()[3]),
        std::net::IpAddr::V6(a) => format!("…{:x}", a.segments()[7]),
    }
}

fn tile_class(d: &Device) -> String {
    match d.worst() {
        Some(f) => format!("{}{}", f.severity.as_str(), if f.severity >= Severity::Medium { " tripped" } else { "" }),
        None => String::new(),
    }
}

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// Render the whole report.
pub fn render(r: &ScanResult, diff: Option<&Diff>) -> String {
    let attention: Vec<&Device> = r.devices.iter().filter(|d| d.worst().is_some_and(|f| f.severity >= Severity::Medium)).collect();
    let headline = if r.devices.is_empty() {
        "No devices found.".to_string()
    } else if attention.is_empty() {
        format!("{}. Nothing needs attention.", plural(r.devices.len(), "device", "devices"))
    } else {
        format!(
            "{}. {} {}.",
            plural(r.devices.len(), "device", "devices"),
            attention.len(),
            if attention.len() == 1 { "needs attention" } else { "need attention" }
        )
    };

    let mut devices: Vec<(usize, &Device)> = r.devices.iter().enumerate().collect();
    devices.sort_by(|a, b| b.1.worst().map(|f| f.rank()).cmp(&a.1.worst().map(|f| f.rank())).then(a.1.ip.cmp(&b.1.ip)));

    let mut h = String::with_capacity(32 * 1024);
    h.push_str("<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">");
    h.push_str("<meta name=\"referrer\" content=\"no-referrer\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; img-src data:\">");
    h.push_str(&format!("<title>iotscan report · {}</title><style>{}</style></head><body>", esc(&r.started), CSS));
    h.push_str(r#"<div class="wrap">"#);

    // hero
    h.push_str(&format!(
        r#"<header class="hero"><div><h1>{}</h1><p>Scanned {} on {} in {:.1} seconds{}.</p>"#,
        esc(&headline),
        esc(&r.summary.targets.join(", ")),
        esc(&r.started),
        r.stats.duration_secs,
        if r.summary.active { " with active probes" } else { "" }
    ));
    if let Some(d) = diff {
        h.push_str(&format!(r#"<div class="delta">{}</div>"#, esc(&d.summary())));
    }
    h.push_str("</div><div class=\"tally\">");
    for (i, s) in Severity::ALL_DESC.iter().enumerate() {
        let n = r.stats.findings[i];
        if n > 0 {
            h.push_str(&format!(r#"<span class="chip {0}">{1}{2} {0}</span>"#, s.as_str(), svg_marker(*s), n));
        }
    }
    h.push_str("</div></header>");

    // board
    h.push_str(r#"<section class="board" aria-label="Devices"><div class="board-head"><h2>Your network</h2><div class="legend">"#);
    h.push_str(r#"<span><i class="chip ok" style="padding:2px 6px">ok</i> no findings</span><span>lever down = needs attention</span></div></div><div class="rail">"#);
    for (i, d) in &devices {
        let new = diff.is_some_and(|x| x.new_devices.iter().any(|n| n.identity == d.identity()));
        let n = d.active_findings().count();
        h.push_str(&format!(
            r##"<a class="tile {cls}{new}" href="#dev-{i}" title="{ip}" style="text-decoration:none"><span class="lever"></span><span class="ip">{tip}</span><span class="name">{name}</span>{badge}</a>"##,
            cls = tile_class(d),
            new = if new { " new" } else { "" },
            ip = esc(&d.ip.to_string()),
            tip = esc(&tile_ip(d)),
            name = esc(if d.label.is_empty() { "Unidentified device" } else { &d.label }),
            badge = if n > 0 { format!(r#"<span class="badge">{n}</span>"#) } else { String::new() },
        ));
    }
    h.push_str("</div></section>");

    // attention
    h.push_str(r#"<div class="stack" style="margin-top:20px">"#);
    h.push_str(r#"<section class="sec"><header><h2>Needs attention</h2></header><div class="body">"#);
    let mut any = false;
    for (i, d) in &devices {
        for f in d.active_findings().filter(|f| f.severity >= Severity::Medium) {
            any = true;
            h.push_str(&format!(
                r##"<ul class="att"><li><a href="#dev-{i}" style="display:grid;gap:4px;padding:12px 18px;color:inherit;text-decoration:none"><span class="t">{t}</span><span class="m">{c} {k} <span class="mono">{ip}</span> {l}</span></a></li></ul>"##,
                t = esc(&f.title),
                c = chip(f.severity),
                k = conf(f.confidence),
                ip = esc(&d.ip.to_string()),
                l = esc(&d.label),
            ));
        }
    }
    if !any {
        h.push_str(r#"<div class="empty"><strong>All clear</strong>No medium, high or critical findings.</div>"#);
    }
    h.push_str("</div></section>");

    // devices
    h.push_str(r#"<section class="sec"><header><h2>All devices</h2></header><div class="body">"#);
    for (i, d) in &devices {
        let worst = d.worst().map(|f| chip(f.severity)).unwrap_or_else(|| r#"<span class="chip ok">ok</span>"#.to_string());
        h.push_str(&format!(
            r##"<details class="dev" id="dev-{i}"><summary>{worst}<span class="sum-name">{name}<small class="mono">{ip}{mac}</small></span><span class="ports">{ports}</span></summary><div class="panel-body">"##,
            name = esc(if d.label.is_empty() { "Unidentified device" } else { &d.label }),
            ip = esc(&d.ip.to_string()),
            mac = d.mac.as_ref().map(|m| format!(" · {}", esc(m))).unwrap_or_default(),
            ports = d.open_ports().iter().map(|p| format!(r#"<span class="port">{p}</span>"#)).collect::<String>(),
        ));
        h.push_str(r#"<dl class="kv">"#);
        let mut row = |k: &str, v: String| {
            if !v.is_empty() {
                h.push_str(&format!("<dt>{}</dt><dd>{}</dd>", esc(k), v));
            }
        };
        row("Type", esc(&d.kind));
        row("Vendor", d.vendor.as_deref().map(esc).unwrap_or_default());
        row("Hostname", d.hostname.as_deref().map(esc).unwrap_or_default());
        row("Other addresses", d.other_ips.iter().map(|i| esc(&i.to_string())).collect::<Vec<_>>().join(", "));
        row("Found by", esc(&d.discovered_via.join(", ")));
        for s in &d.services {
            let mut t = format!("{:?}", s.kind).to_lowercase();
            if let Some(hh) = &s.http {
                t.push_str(&format!(" · HTTP {}", hh.status));
                if let Some(sv) = &hh.server {
                    t.push_str(&format!(" · {sv}"));
                }
                if let Some(ti) = &hh.title {
                    t.push_str(&format!(" · “{ti}”"));
                }
            }
            if let Some(b) = &s.banner {
                t.push_str(&format!(" · {b}"));
            }
            row(&format!("Port {}", s.port), esc(&t));
        }
        h.push_str("</dl>");
        if d.findings.is_empty() {
            h.push_str(r#"<p style="margin-top:14px;color:var(--ink-2)">No findings.</p>"#);
        } else {
            h.push_str(r#"<div style="margin-top:14px">"#);
            let mut fs: Vec<&Finding> = d.findings.iter().collect();
            fs.sort_by_key(|f| std::cmp::Reverse(f.rank()));
            for f in fs {
                h.push_str(&finding_card(f));
            }
            h.push_str("</div>");
        }
        h.push_str("</div></details>");
    }
    h.push_str("</div></section>");

    // changes
    if let Some(d) = diff {
        h.push_str(&format!(r#"<section class="sec"><header><h2>Changes since the previous scan</h2></header><div class="body"><p style="padding:12px 18px">{}</p>"#, esc(&d.summary())));
        h.push_str(r#"<ul style="margin:0;padding:0 18px 14px 36px">"#);
        for n in &d.new_devices {
            h.push_str(&format!("<li>New device <span class=\"mono\">{}</span> {}</li>", esc(&n.ip), esc(&n.label)));
        }
        for n in &d.missing_devices {
            h.push_str(&format!("<li>Gone: <span class=\"mono\">{}</span> {}</li>", esc(&n.ip), esc(&n.label)));
        }
        for c in &d.changed {
            for f in &c.new_findings {
                h.push_str(&format!("<li>New on <span class=\"mono\">{}</span>: {}</li>", esc(&c.device.ip), esc(&f.title)));
            }
            for f in &c.resolved_findings {
                h.push_str(&format!("<li>Resolved on <span class=\"mono\">{}</span>: {}</li>", esc(&c.device.ip), esc(&f.title)));
            }
            for p in &c.opened_ports {
                h.push_str(&format!("<li>Port {} opened on <span class=\"mono\">{}</span></li>", p, esc(&c.device.ip)));
            }
        }
        h.push_str("</ul></div></section>");
    }
    h.push_str("</div>");
    for w in &r.warnings {
        h.push_str(&format!(r#"<div class="notice" style="margin-top:14px">{}</div>"#, esc(w)));
    }
    h.push_str(&format!(r#"<p class="foot">Confidence: {} Generated by iotscan {}.</p>"#, esc(CONFIDENCE_LEGEND), esc(&r.tool_version)));
    h.push_str("</div></body></html>\n");
    h
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Confidence, SCHEMA_VERSION, ScanSummary, Stats};

    fn sample(label: &str, title: &str) -> ScanResult {
        let mut d = Device::new("192.168.1.50".parse().unwrap());
        d.label = label.into();
        d.mac = Some("aa:bb:cc:dd:ee:ff".into());
        d.findings.push(
            Finding::new("x", title, Severity::Critical, Confidence::Likely)
                .summary(format!("summary {title}"))
                .evidence(format!("ev {title}"))
                .remediation(format!("fix {title}"))
                .references(&["https://example.com/a".to_string(), "javascript:alert(1)".to_string()]),
        );
        let mut r = ScanResult {
            schema_version: SCHEMA_VERSION,
            tool_version: "0.1.0".into(),
            started: "2026-10-24T00:00:00Z".into(),
            finished: "2026-10-24T00:00:05Z".into(),
            summary: ScanSummary { targets: vec!["192.168.1.0/24".into()], ..ScanSummary::default() },
            devices: vec![d],
            warnings: vec!["be careful <b>".into()],
            stats: Stats::default(),
        };
        r.recount();
        r
    }

    #[test]
    fn contains_expected_structure() {
        let h = render(&sample("Garage camera", "Bad bug"), None);
        assert!(h.starts_with("<!doctype html>"));
        assert!(h.contains("1 device. 1 needs attention."));
        assert!(h.contains("Garage camera"));
        assert!(h.contains("class=\"tile critical tripped\""));
        assert!(h.contains("Bad bug"));
        assert!(h.contains("What to do"));
        assert!(!h.contains("<script"), "report must stay script-free");
    }

    #[test]
    fn escapes_hostile_content() {
        let evil = "<img src=x onerror=alert(1)>\"'&";
        let h = render(&sample(evil, evil), None);
        assert!(!h.contains("<img src=x"));
        assert!(h.contains("&lt;img src=x onerror=alert(1)&gt;"));
        // Dangerous URL schemes are not turned into links.
        assert!(!h.contains("href=\"javascript:"));
        assert!(h.contains("href=\"https://example.com/a\""));
        // Warnings are escaped too.
        assert!(h.contains("be careful &lt;b&gt;"));
    }

    #[test]
    fn empty_and_clean_scans() {
        let mut r = sample("x", "y");
        r.devices.clear();
        r.recount();
        assert!(render(&r, None).contains("No devices found."));
        let mut r = sample("x", "y");
        r.devices[0].findings.clear();
        r.recount();
        let h = render(&r, None);
        assert!(h.contains("Nothing needs attention"));
        assert!(h.contains("All clear"));
    }

    #[test]
    fn has_strict_csp() {
        let h = render(&sample("a", "b"), None);
        assert!(h.contains("default-src 'none'"));
    }
}
