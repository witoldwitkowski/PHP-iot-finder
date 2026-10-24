# Architecture

```
main.rs ─ cli.rs ─ app.rs ──────────────► commands (scan, gui, diff, history, doctor, selftest …)
                    │
         privsep.rs (before any thread starts: open raw ARP sockets, drop all privileges)
                    │
                engine/ ──────────────────────────────────────────────────────────────┐
   scope.rs  ► targets, private/public classification, local subnets                  │
   discovery/ ► neigh (ARP cache) · arp (raw, optional) · mdns · ssdp · icmp6           │
   engine/sweep.rs   ► TCP connect sweep (refused ⇒ alive), early exit for dead hosts  │
   engine/enrich.rs  ► identify services: HTTP(S) fetch + redirects, banners           │
   fingerprint/      ► php versions/phpinfo, Server banners, device labels             │
   checkers/         ► pure judges: needs() · probes() · evaluate() ─► Findings        │
   engine/probes.rs  ► executes the probes checkers asked for (only with limits)       │
   limits.rs         ► per-host + global concurrency, rate limit, cancellation         │
                    └──────────────────────────────────────────────────────────────────┘
   model.rs  Device / Service / Finding / ScanResult (serde)
   diff.rs · history.rs · allowlist.rs · advisories.rs (+ data/advisories.toml)
   report/ (terminal, html) · gui/ (server, api) + assets/{index.html,app.js,ui.css}
   testkit.rs · selftest.rs · demo.rs
```

## Scan pipeline

1. **Configuration**: targets → `Scope` (refuse public without confirmation, cap size);
   checker needs → extra ports/banners; advisory database + user overlay.
2. **Link-layer**: raw ARP sweep (if sockets were opened) and IPv6 multicast echo.
   For ARP-covered subnets only hosts that answered are swept.
3. **TCP sweep**: per host, ports in popularity order, `per_host` in flight. On-link
   hosts that never appear in the ARP cache are abandoned after 6 ports.
4. **Merge**: ARP cache MACs, mDNS names/services, SSDP descriptions; IPv6 twins are
   merged by EUI-64 MAC or mDNS addresses. Vendor from the OUI table.
5. **Identify**: each open port is fetched/banner-read concurrently; `identify.rs`
   chooses a label and kind.
6. **Probe + check**: `Registry::probes_for` (intrusive probes only with `--active`),
   `run_probes`, then `Registry::evaluate` (panic-contained). PHP evidence is
   collected once (`php_facts`) and shared by the PHP checkers.
7. **Finish**: allowlist, sort, statistics; the CLI/GUI then diff against history.

## Why checkers cannot do I/O

All network access happens in `engine/`, under `NetCtx` permits. A checker only
returns *requests* (`Probe`) and judges *results*, so adding a checker cannot
weaken the scanner's politeness or safety guarantees, and every checker is
testable with a hand-built `Device`.

## Extension points

| To add … | Touch |
| --- | --- |
| a banner-identifiable vulnerability | `data/advisories.toml` (or the user file) |
| a new check | `src/checkers/<name>.rs` + one line in `Registry::builtin()` |
| a new probe type | `ProbeKind` in `checkers/mod.rs` + `engine/probes.rs` |
| a new discovery method | `src/discovery/` + engine merge step |
| a new output | `src/report/` |
