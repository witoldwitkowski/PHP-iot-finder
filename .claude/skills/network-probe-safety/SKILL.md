---
name: network-probe-safety
description: Rules and patterns for writing safe network probes and parsers in iotscan - what requests a checker may ask for, how to treat hostile responses, protocol-specific safe probes (HTTP, TCP banners, UDP, MQTT, RTSP, SNMP, UPnP, mDNS), and politeness limits. Use when a checker needs anything beyond reading what a device volunteers.
---

# Network probe safety

iotscan talks to cheap, fragile, possibly compromised devices. A probe that
crashes a camera or leaks into the wider network is a bug. These rules are
enforced where possible by `checkers::conformance` (run by `cargo test` and
`iotscan selftest`); the rest is judgement.

## What a checker may ask for

| Request | Allowed | Flag |
| --- | --- | --- |
| Open a port and read the greeting | yes | passive |
| `GET /` (the engine already does this) | yes | passive |
| `GET/HEAD/OPTIONS <other path>` | yes | `Probe::active` |
| TCP: send a small, protocol-legal, read-only message | yes | `Probe::active` |
| UDP: one small datagram, unicast, to the device | yes | `Probe::active` |
| POST/PUT/DELETE, any state change, login attempts, default credentials | **no** (needs explicit user approval and a design review) | – |
| Payloads that trigger a bug, fuzzing, oversized/malformed inputs | **never** | – |
| Broadcast/multicast beyond the built-in mDNS/SSDP, spoofed sources, amplification | **never** | – |

Limits: payload ≤ 1400 bytes; no run of ≥ 64 identical bytes; paths ≤ 512 bytes
without whitespace/control characters; ≤ 64 probes per device; HTTP bodies are
capped at 160 KiB, TCP reads at 1 KiB, UDP replies at 1500 bytes. The engine
adds per-device concurrency (2), a global rate limit, and deadlines — never
bypass them or add retries/loops.

## Hostile data rules (every byte of a response is attacker-controlled)

* Never `unwrap`/index/slice on device data; use `get`, `strip_prefix`, `split_once`, char-aware helpers.
  Multi-byte characters will land on your slice boundaries.
* Bound everything: lengths, counts, recursion, loops. Truncate before storing or printing
  (`util::truncate`, `util::sanitize`). Evidence lines ≤ 600 chars.
* Parse with the existing safe helpers: `Version::parse`, `products::parse_banner`,
  `php::parse_phpinfo`, `http::extract_title`, `dns::parse`.
* Treat a version string as a *claim*. Vendors back-port fixes; devices lie. → confidence.
* Never build HTML/shell/URLs from device text. Reports escape; checkers shouldn't pass text onward.
* Never follow a URL a device hands you unless host == the device (see `ssdp::location_target`).

## Protocol patterns (read-only, minimal)

* **HTTP** — headers (`Server`, `X-Powered-By`, `WWW-Authenticate`, cookies), `<title>`, a known
  page that prints a version (`/phpinfo.php`, `/about`, `/status`). Same-host redirects only.
* **Telnet/FTP/SSH/SMTP** — read the greeting; do not log in. Banner → product/version.
* **MQTT (1883/8883)** — passive: port open ⇒ broker present. Active: send a 14-byte CONNECT
  (clean session, empty client id, no credentials) and read the CONNACK; return code 0 means anonymous
  access is accepted, 4/5 means authentication is enforced. Do not subscribe or publish.
* **RTSP (554)** — `OPTIONS * RTSP/1.0` + `CSeq`; read the `Server` header. Do not `DESCRIBE` with credentials.
* **SNMP (UDP 161)** — a single v2c GET of `sysDescr.0` with the community `public` identifies devices; it is a
  *credential-like* probe: treat as `Probe::active`, document it, and never try other communities.
* **UPnP/SSDP** — use the built-in discovery; description XML only from the announcing address.
* **mDNS** — built-in; add service types to the query list rather than new sockets.
* **TLS** — the engine connects without verification (devices are self-signed). Don't send secrets.
* **IPv6** — link-local addresses need a scope id; the engine handles it. Don't build socket addresses yourself.

If a protocol isn't listed, find the smallest request that makes the device announce
the property you need, write down why it is safe in the research note, and mark it active.

## Before you finish
* `cargo test` (includes conformance) and `iotscan selftest` pass.
* The mock device in `testkit` behaves like the real one, **including a hostile variant**
  (huge banner, control characters, truncated reply).
* You can state, in one sentence, why no request could harm the device.
