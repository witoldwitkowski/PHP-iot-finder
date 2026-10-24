# Security notes

iotscan connects to, and parses data from, devices that may be compromised or
hostile. It is designed so that a hostile device can waste a little time and
nothing more.

## Threat model

| Threat | Mitigation |
| --- | --- |
| Memory-safety bugs in parsers | Entire crate is safe Rust except `src/sys.rs` (a few syscall wrappers, each with a safety comment). `#![deny(unsafe_code)]` everywhere else. |
| Parser panics on hostile input | HTTP head via `httparse`; hand-written DNS/ARP/SSDP/banner parsers are bounds-checked and fuzz-tested with random inputs; a panicking *checker* is contained. |
| Giant or endless responses | Head ≤ 16 KiB, body ≤ 64 KiB (160 KiB for probes), whole exchange has a deadline, banners ≤ 512 B, DNS packets ≤ 9000 B with record/jump caps. |
| Slow-loris / hung devices | Per-exchange deadlines; the scan always finishes. |
| Terminal escape injection (`\x1b[2J…`) | Every string from the network passes through `util::sanitize` before it is stored: control and bidi characters become spaces. Verified in `tests/engine.rs`. |
| HTML/JS injection in reports and GUI | Reports escape all text and carry a `default-src 'none'` CSP; the GUI front-end never builds markup from strings (`tests/gui.rs` forbids `innerHTML` & co.). |
| SSRF via a device (redirects, UPnP `LOCATION`) | Redirects are followed only to the same IP/port/scheme; SSDP description URLs only if the host equals the announcing address. |
| Request smuggling into devices | Only `GET/HEAD/OPTIONS`; path and header values rejected if they contain CR/LF/space. |
| Fragile devices crashing | Per-device and global concurrency caps, global rate limit, small timeouts, no retries. |
| Scanning someone else's network by accident | Public ranges need `--allow-public` or an interactive `yes`; large ranges are capped (`--max-hosts`). |
| Privilege misuse | No privileges needed. Optional `CAP_NET_RAW` is used before any thread starts to open ARP sockets, then all capabilities are dropped (and root drops to the invoking user), plus `no_new_privs` except in GUI mode, where a browser must be launched (snap-packaged Firefox needs a setuid helper). `doctor` shows `CapEff=0` after start-up. |
| Local attackers / malicious web pages hitting the GUI | Loopback bind; 128-bit random token (cookie `HttpOnly; SameSite=Strict`); `Host` check (DNS rebinding); JSON content-type + same-origin `Origin`/`Sec-Fetch-Site` for POSTs (CSRF); strict CSP, `nosniff`, `no-referrer`, `no-store`, frame denial; bounded request sizes; max 32 connections. |
| Leaking scan results | Result files and history are mode 0600/0700. |
| Supply chain | Few dependencies (pure Rust except `ring` for TLS); `Cargo.lock` committed; `cargo audit` and `cargo deny` in CI; Dependabot. |

## Deliberate trade-offs

* **TLS certificates are not verified.** IoT devices use self-signed
  certificates; iotscan only reads what they say and sends nothing sensitive.
* **Banners are claims.** A device can lie about its version. Findings carry a
  confidence level for exactly this reason.
* **Discovery is visible.** ARP, mDNS and SSDP probes are ordinary network
  traffic; intrusion detection may notice a scan.

## Reporting problems

Open an issue on the repository. Do not include scan results that identify
your network.
