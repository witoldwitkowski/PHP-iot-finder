# From CVE to checker

You give an agent a CVE; it returns a tested, safe checker and an honest report.

## Ask for it

In Claude Code, from the repository root:

> Use the **checker-author** agent to add a checker for **CVE-2026-XXXXX**.

or, without the agent:

> Follow the **add-checker** skill for CVE-2026-XXXXX.

Optional context that helps: the product and version range you care about, a link to the
advisory, and how the device shows up on your network (banner, port, page).

You can also open an issue with the **New CVE checker** template; an agent can pick it up from there.

## What the agent does

1. **Researches** (skill `cve-research`): affected/fixed versions, back-port practice, exploitation status,
   and what a remote read-only scanner can observe. Writes `docs/research/<CVE>.md`, including conflicts
   between sources and what stays unverified.
2. **Chooses the route**: a TOML advisory when a banner version identifies the product; otherwise a Rust
   checker. If the flaw can only be confirmed by exploiting it, it does **not** do that: it reports the
   limit and ships a version/exposure finding at `possible`/`likely` confidence.
3. **Scaffolds and implements** with `scripts/new-checker.py`, following `network-probe-safety`.
4. **Tests**: unit tests, a mock device and an end-to-end `selftest` scenario.
5. **Gates** on `scripts/verify.sh`: formatting, `clippy -D warnings`, the whole test suite, the self-test,
   advisory validation, dependency audit. It also runs the **conformance rules** on every checker
   (safe, small, read-only probes; complete findings; no panics; deterministic), so a bad plugin cannot pass.
6. **Reports**: what was added, how it detects, confidence and limits, unresolved questions.

## What you review
* `docs/research/<CVE>.md`: are the sources right? Mark the advisory `verified = true` once you (or the agent)
  have read the vendor's own advisory.
* The probes (if any): are you comfortable that none could harm a device?
* The confidence rules: would a patched Debian/Ubuntu box be reported as `possible`, not `likely`?

## Guarantees the framework gives you
| Guarantee | Enforced by |
| --- | --- |
| No exploit-like request | conformance rules (path/payload tripwires, size limits, intrusive flagging) |
| Nothing beyond `GET /` without `--active` | conformance + engine |
| A hostile device cannot crash a checker | conformance (hostile samples) + panic containment in the registry |
| Device text cannot inject into terminal/HTML | ingest sanitising, scrub backstop, escaping, CSP |
| Politeness | engine limits (per-device 2, global rate, deadlines, size caps) |
| Honest data provenance | `verified`/`notes` + a note on every finding from unverified data |

The tripwires are heuristics, not proofs. They catch mistakes and force a human look at anything
unusual; they are not a substitute for reading the probe.
