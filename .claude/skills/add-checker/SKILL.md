---
name: add-checker
description: Turn a CVE id, advisory URL or vulnerability description into a tested, safe iotscan checker (plugin). Use whenever the user gives a CVE or advisory and wants iotscan to detect it on home-network IoT devices, or asks for "the next checker".
---

# Add a checker to iotscan from a CVE

Input: a CVE id, advisory link, or a description. Output: a merged-ready change
that adds detection to iotscan, with tests, provenance, and an honest account of
how strong the evidence is. Work through the steps in order; do not skip the
research or the verification gate.

Related skills (load them): `cve-research` (how to research and record sources) and
`network-probe-safety` (what a probe may and may not do). The hard rules below
come from them and from `docs/SECURITY.md`.

## Hard rules

1. **Never ship an exploit.** No payload that triggers the vulnerable code path,
   no memory-corruption input, no authentication bypass, no credential guessing,
   no write/state-changing request, no fuzzing, no denial-of-service. Detection
   uses what a device *volunteers* (banners, headers, pages, protocol greetings)
   or one minimal, read-only, protocol-legal request. If the only way to *confirm*
   the bug is to trigger it, say so and detect by **version/exposure with
   `Confidence::Possible`/`Likely`**, never `Confirmed`.
2. **Evidence decides confidence.** `Confirmed` = observed directly; `Likely` =
   authoritative version in range and no vendor back-port signal; `Possible` =
   hidden version, distro/vendor build, or circumstantial. When in doubt, lower it.
3. **Checkers cannot do I/O.** They declare `needs()`/`probes()` and judge results.
   Anything beyond `GET /` or listening on a port is `Probe::active`.
4. **Data over code.** If a banner version identifies the product, add a TOML
   advisory (`scripts/new-checker.py data`), not Rust.
5. **Provenance is part of the deliverable.** Unverified data says `verified = false`
   with `notes`; findings then carry a note. Never mark `verified = true` unless
   you read the vendor's own advisory.
6. **No silent scope creep.** Change only what the new checker needs.

## Steps

### 1. Research (skill: `cve-research`)
Collect: affected product/versions per branch, first fixed versions, what the
flaw allows, exploitation status, vendor/distro back-port practice, EOL branches,
and — most important — **what a remote scanner can observe**. Write
`docs/research/<CVE-ID>.md` from `docs/research/_TEMPLATE.md` (sources with dates,
conflicts between sources, decisions).

### 2. Decide the route

| Observation available | Route |
| --- | --- |
| Version in `Server` / `X-Powered-By` banner identifies the product | **Data-only advisory.** `scripts/new-checker.py data …` |
| Open port / service greeting is the issue (Telnet, MQTT, FTP, RTSP …) | **Rust checker** with `Need::Port/Banner`, passive |
| A specific page/response reveals version or exposure | **Rust checker** + `Probe::active(ProbeKind::http_get(..))` |
| A protocol exchange (UDP/TCP) with a tiny legal request reveals it | **Rust checker** + `Probe::active(Tcp/Udp)`; see `network-probe-safety` |
| Needs a trigger, credentials, or timing to confirm | **No active detection.** Version/exposure finding at `Possible`, explain in the research note |
| Product never reveals a version | Say so; detection may be impossible. Do not invent signals. |

New fingerprints (extracting a version from somewhere new) belong in
`src/fingerprint/`, with tests.

### 3. Scaffold
```sh
scripts/new-checker.py data --id <kebab-id> --product <banner-name> --title ... --severity ... \
    --cve CVE-YYYY-NNNN --published YYYY-MM-DD --summary ... --remediation ... \
    --reference <url> --affected branch=X.Y,fixed=X.Y.Z   # repeat; or from=0.0 for never fixed
scripts/new-checker.py rust --id <kebab-id> --name "..." --description "..." --category web|remote-access|exposure|lifecycle|credentials|other \
    [--port N] [--banner-port N] [--ssdp] [--mdns] [--active]
```
The scaffold is intentionally incomplete (`TODO(agent)` markers, a placeholder test that
panics). `scripts/verify.sh` fails until every marker is gone.

### 4. Implement
* Data route: complete the `notes`, check `iotscan advisories` shows it.
* Rust route: follow `docs/WRITING_CHECKERS.md`. Reuse helpers: `advisory_finding`,
  `BACKPORT_NOTE`, `php_facts`, `Version::looks_vendor_packaged`, `distro_hint`.
  Truncate and never trust device text; keep summaries plain and actionable
  (what it is, why it matters, what to do).

**Edit safely.** `cargo fmt` reflows code, so a scripted find-and-replace written before formatting can
silently match nothing. Make edits with the Edit tool (it fails loudly), or assert in your script that
the pattern was found, and confirm each new scenario or test actually ran (for example
`iotscan selftest | grep <your scenario>`; the check count should go up). A green gate that never ran
your test proves nothing.

### 5. Test (all of these)
* Unit tests: affected, fixed/clean, vendor-packaged (lower confidence),
  hidden/unknown version, hostile/oversized input, boundary versions (the exact fixed version).
* A mock device in `src/testkit.rs` (add to `fleet()`), and a scenario in
  `src/selftest.rs` asserting the finding (and its confidence) and a clean sibling with none.
* If you added probes: assert they are not made without `--active`.
* The conformance rules run automatically (`iotscan selftest`, `cargo test`); fix what they report
  rather than relaxing them.

### 6. Verify
```sh
scripts/verify.sh        # fmt, clippy -D warnings, all tests, selftest, advisories, audit/deny if installed
```
Must end with `ALL CHECKS PASSED`. If a failure looks unrelated, say so with evidence; do not skip or weaken tests.

### 7. Document and report
* `CHANGELOG.md` entry; `docs/research/<CVE-ID>.md` complete.
* If a user-visible behaviour changed, update `README.md` / `man/iotscan.1`.
* Final message to the user: what was added (ids, files), how it detects, **confidence
  and its limits**, what was not verified or conflicted between sources, anything
  you refused to do for safety and why, and how to run it (`iotscan --only <id>`).

## Definition of done
- [ ] research note with ≥2 independent sources (primary preferred) and conflicts recorded
- [ ] detection route justified; no exploit-like request exists
- [ ] data/advisory or checker added, `verified` honest, `notes` filled
- [ ] unit tests + mock device + selftest scenario
- [ ] `scripts/verify.sh` → ALL CHECKS PASSED
- [ ] changelog + report to the user with caveats
