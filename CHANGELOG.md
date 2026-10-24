# Changelog

## 0.1.0

* Network discovery: TCP sweep, ARP cache, optional raw ARP (`CAP_NET_RAW`), mDNS, SSDP, IPv6.
* Checkers: PHP2Shell (CVE-2026-109618/109619), end-of-life PHP, exposed phpinfo(), Telnet, UPnP,
  and a data-driven advisory checker.
* Confidence levels, allowlist, scan history and diffing.
* Terminal, JSON and HTML reports; local web GUI (`iotscan gui`).
* `selftest` and `doctor` commands, man page, static x86_64 and aarch64 builds, `.deb` packages.
