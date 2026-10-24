# Changelog

## 0.1.0

* Network discovery: TCP sweep, ARP cache, optional raw ARP (`CAP_NET_RAW`), mDNS, SSDP, IPv6.
* Checkers: PHP2Shell (CVE-2026-109618/109619), end-of-life PHP, exposed phpinfo(), Telnet, UPnP,
  and a data-driven advisory checker.
* Confidence levels, allowlist, scan history and diffing.
* Terminal, JSON and HTML reports; local web GUI (`iotscan gui`).
* `selftest` and `doctor` commands, man page, static x86_64 and aarch64 builds, `.deb` packages.

## Unreleased

* Plugin conformance rules (`checkers::conformance`) run on every checker by `cargo test` and `iotscan selftest`.
* Advisories carry provenance (`verified`, `notes`); findings from unverified data say so.
* New advisory `boa-unmaintained` (discontinued Boa web server; `any_version` advisories and version-less banner matching).
  CVE-2017-9833 is deliberately not cited: it is disputed. See `docs/research/boa-unmaintained.md`.
* New checker `mqtt-exposed`: plain-text MQTT brokers, and with `--active` whether they accept anonymous
  connections (one 14-byte CONNECT, no subscribe/publish). See `docs/research/mqtt-exposed.md`.
* `scripts/new-checker.py` scaffolder, `scripts/verify.sh` gate, `CLAUDE.md`, the `checker-author` agent and the
  `add-checker`, `cve-research`, `network-probe-safety` skills, `docs/CVE_INTAKE.md`, `docs/research/`.
