# iotscan: guide for agents

iotscan is a safe, extensible vulnerability scanner for home IoT networks (Rust, one static
binary, CLI + local web GUI). Read `README.md` for the product and `docs/ARCHITECTURE.md` for the layout.

## Commands
```sh
scripts/verify.sh            # the gate: fmt, clippy -D warnings, all tests, selftest, advisories, audit/deny
scripts/verify.sh --quick    # unit tests only
cargo run -- selftest        # end-to-end against mock devices (includes plugin conformance rules)
cargo run -- checkers        # list checkers
cargo run -- advisories      # validate the advisory database
./scripts/build-dist.sh      # static x86_64 + aarch64 packages in dist/
```

## Adding a vulnerability checker (the main recurring task)
Use the `checker-author` agent or the `add-checker` skill. In short: research → decide data-only vs
Rust → `scripts/new-checker.py` → implement → tests + mock device + selftest scenario → `scripts/verify.sh`.
Details: `docs/WRITING_CHECKERS.md`, `docs/CVE_INTAKE.md`.

## Invariants (do not break)
* **No exploits, ever.** Probes are read-only, small, protocol-legal. Anything beyond `GET /` or listening
  is `Probe::active`. No credential guessing, no state changes, no fuzzing. Enforced by `checkers::conformance`.
* **Checkers do no I/O.** They declare `needs()`/`probes()` and judge `CheckInput`. All I/O is in `src/engine/`
  under `NetCtx` limits (per-device 2, global rate, deadlines, size caps).
* **Device text is hostile.** Sanitise at ingest (`util::sanitize`), never panic on it, never put it into HTML/shell.
  The GUI front-end must never use `innerHTML` (a test enforces it).
* **Confidence is honest.** Confirmed = observed; Likely = good evidence; Possible = weak or back-port-able.
* **Unsafe code lives only in `src/sys.rs`.** `#![deny(unsafe_code)]` elsewhere.
* **Privileges:** none needed; optional `CAP_NET_RAW` is used once, before threads start, then dropped (`src/privsep.rs`).
* **Provenance:** advisory data is `verified = false` with `notes` unless the vendor's own advisory was read.
* Never weaken or delete tests/conformance rules to get green.

## Layout cheatsheet
`src/checkers/` plugins · `src/fingerprint/` version/product extraction · `src/engine/` scan pipeline ·
`src/discovery/` ARP, mDNS, SSDP, ICMPv6 · `src/gui/` + `assets/` web GUI · `src/report/` outputs ·
`data/advisories.toml` vulnerability data · `src/testkit.rs` mock devices · `src/selftest.rs` e2e scenarios ·
`tests/` integration tests · `docs/research/` per-CVE research notes.

## Style
Match surrounding code; `cargo fmt` (max_width 140); clippy clean; plain, non-hyped wording in user-facing text;
sentence case; no new dependencies without a reason (the dependency audit runs in CI).
