# Adding a checker

iotscan is built so that a new vulnerability is usually a few lines. There are
two routes. Pick the simplest one that fits.

**Fastest path:** give an agent the CVE (see [CVE_INTAKE.md](CVE_INTAKE.md)). It uses the
`checker-author` agent and the `add-checker`, `cve-research` and `network-probe-safety`
skills in `.claude/`, scaffolds with `scripts/new-checker.py`, and must pass
`scripts/verify.sh` before it is done. The rest of this page is the manual route.

Every checker is automatically held to the **conformance rules**
(`src/checkers/conformance.rs`, run by `cargo test` and `iotscan selftest`): small read-only
probes (anything beyond `GET /` is `Probe::active`), no exploit-looking requests, complete and
printable findings, no panics or slow calls on hostile devices, deterministic results.

## Route 1: data only (no code)

If the vulnerable software announces its version in an HTTP `Server` or
`X-Powered-By` header (`Server: lighttpd/1.4.55`), add an advisory to
`data/advisories.toml` (built in) or to `~/.config/iotscan/advisories.toml`
(yours, merged on top, no rebuild needed):

```toml
[[advisory]]
id          = "lighttpd-2026-001"      # unique, a-z 0-9 - _
product     = "lighttpd"               # lowercase name before the "/" in the banner
title       = "lighttpd mod_x buffer overflow"
severity    = "high"                   # info | low | medium | high | critical
cves        = ["CVE-2026-00001"]
published   = "2026-11-02"
summary     = "What it is and why it matters, one or two sentences."
remediation = "Upgrade to 1.4.70 or later."
references  = ["https://example.org/advisory"]
verified    = false      # true only if you read the vendor's own advisory
notes       = ["Where the data came from, the date, and what is unconfirmed."]   # required when verified = false

[[advisory.affected]]
branch = "1.4"        # only versions on 1.4.x ...
fixed  = "1.4.70"     # ... below 1.4.70 are affected

# A product that was never fixed:
# [[advisory.affected]]
# from = "0.0"
```

Check it with `iotscan advisories --file my.toml`. Findings from the generic
`data-advisory` checker get **likely** confidence, or **possible** when the
banner names a distribution (Debian, Ubuntu, …) because those back-port fixes.

## Route 2: a Rust checker

Use this when you need more than a banner: other protocols, extra requests,
page content, several signals combined.

A checker is a **pure judge of evidence**. It cannot open sockets. It says what
it needs, optionally asks the engine to make extra requests, and then evaluates
what came back. The engine does all I/O under the scan's rate limits, size caps
and safety rules, so a checker can never hammer a device or read unbounded data.

```rust
// src/checkers/example.rs
use super::*;
use crate::model::Severity;

pub const ID: &str = "example-camera-default-page";
pub struct ExampleCamera;

impl Checker for ExampleCamera {
    fn meta(&self) -> CheckerMeta {
        CheckerMeta {
            id: ID,
            name: "Example camera setup page exposed",
            description: "The factory setup page is reachable without a password.",
            category: Category::Web,
            tags: &["camera", "default-config"],
            uses_active_probes: true,       // true if probes() returns intrusive probes
        }
    }

    // Ports/protocols to include in the scan (optional).
    fn needs(&self) -> Vec<Need> { vec![Need::Port(8080)] }

    // Extra requests, chosen from what is already known about the device (optional).
    fn probes(&self, device: &Device, _db: &AdvisoryDb) -> Vec<Probe> {
        device.services.iter().filter(|s| s.is_web()).map(|s|
            Probe::active(ProbeKind::http_get(s.port, "/setup.cgi"))   // runs only with --active
        ).collect()
    }

    fn evaluate(&self, input: &CheckInput) -> Vec<Finding> {
        let mut out = vec![];
        for s in input.web_services() {
            if let Some((200, _headers, body)) = input.probes.http(s.port, "/setup.cgi") {
                if body.contains("Camera Setup") {
                    out.push(
                        Finding::new(ID, "Setup page is open", Severity::High, Confidence::Confirmed)
                            .port(s.port)
                            .summary("The setup page answers without a password.")
                            .evidence("GET /setup.cgi returned the setup page")
                            .remediation("Set an admin password; update the firmware."),
                    );
                }
            }
        }
        out
    }
}
```

Register it in two places:

1. `src/checkers/mod.rs`: add `pub mod example;` and one line in
   `Registry::builtin()`: `Box::new(example::ExampleCamera),`
2. Write tests in the same file with the helpers in
   `checkers::testutil` (`device_with_http`, `input`). No network needed:

```rust
#[cfg(test)]
mod tests {
    use super::super::testutil::*;
    use super::*;

    #[test]
    fn flags_open_setup_page() {
        let d = device_with_http(80, None, None, &[], "");
        let mut probes = ProbeResults::default();
        probes.insert(ProbeKind::http_get(80, "/setup.cgi"),
            Ok(ProbeData::Http { status: 200, headers: vec![], body: "Camera Setup".into(), tls: false }));
        let db = AdvisoryDb::embedded();
        assert_eq!(ExampleCamera.evaluate(&input(&d, &probes, &db, "2026-11-01")).len(), 1);
    }
}
```

Then add a mock device to `src/testkit.rs` and an expectation to
`src/selftest.rs` so `iotscan selftest` covers it end to end.

### What a checker can ask for

| Need | Effect |
| --- | --- |
| `Need::Port(p)` | adds TCP port `p` to the sweep |
| `Need::Banner(p)` | adds `p` and reads the service banner |
| `Need::Ssdp` / `Need::Mdns` | makes sure that discovery runs |

| Probe (`ProbeKind`) | What the engine does |
| --- | --- |
| `Http { port, path, method }` | one GET/HEAD/OPTIONS, body capped at 160 KiB |
| `Tcp { port, send }` | connect, optionally send up to 1400 bytes, read up to 1 KiB |
| `Udp { port, payload }` | one datagram, one reply (replies from other hosts are ignored) |

`Probe::passive(..)` runs in every scan; `Probe::active(..)` only with
`--active`. Use `active` for anything beyond reading what the device volunteers
(extra paths, payloads). Never craft a probe that could crash a device or
trigger a memory-corruption bug: iotscan's promise is that it does not.

### What a checker can look at

`CheckInput` gives you the `Device` (MAC, vendor, mDNS and SSDP data, services
with HTTP headers/title/cookie names/body sample/TLS version, banners), the probe
results, the advisory database, today's date, and helpers such as
`input.php_facts()`.

### Choosing confidence

* **Confirmed**: you observed it directly (an open port, a reachable page).
* **Likely**: strong evidence, such as an authoritative version in the affected range.
* **Possible**: weak or indirect. Use it whenever a vendor may have back-ported a
  fix (`Version::looks_vendor_packaged()`, `distro_hint()`), or the signal is only
  circumstantial. Add `BACKPORT_NOTE` to the summary in that case.

### Don'ts

* No I/O inside `evaluate` or `probes`.
* Treat every string as hostile (it came from the network). The engine has
  already stripped control characters, but never build HTML from it; the report
  and GUI escape for you.
* Do not report a vulnerability you only suspect as `Likely`.

## Asking Claude to do it

You can hand the work over with a prompt like this:

> A new vulnerability came out: **<name / CVE>**. Affected: **<product and versions>**,
> fixed in **<versions>**. It shows up as **<banner / page / open port / protocol>**.
> Please research it, add a checker (data-only if a banner is enough), tests, and a
> selftest scenario, and tell me about any places where the evidence is weak.
