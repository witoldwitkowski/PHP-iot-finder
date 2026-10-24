# MQTT broker exposure (no CVE: a configuration risk)

*Researched: 2026-10-24. Researcher: Claude (second end-to-end run of the `add-checker` workflow, Rust route). Checker: `mqtt-exposed` (Rust, passive + one active probe).*

## Summary
MQTT brokers (Mosquitto, EMQX, hub-embedded brokers) carry smart-home traffic. Brokers that accept
connections without credentials let anyone on the network read messages and publish commands; port 1883
is unencrypted. There is no CVE: this is a misconfiguration class, included to exercise the Rust-checker
route (active TCP probe, conformance rules).

## Sources
| # | Source | Kind | Date read | Established |
| - | ------ | ---- | --------- | ----------- |
| 1 | EMQX docs "MQTT Client Error Codes" (search result) | broker vendor docs | 2026-10-24 | connection succeeds only with return code 0 |
| 2 | Microsoft `MqttV311ConnectReturnCode` enum docs (search result) | vendor API docs | 2026-10-24 | codes 1 unacceptable protocol version, 2 identifier rejected, 3 server unavailable, 4 bad credentials, 5 not authorized |
| 3 | Mosquitto `mqtt_protocol.h` (search result) | reference implementation | 2026-10-24 | same six CONNACK values |

Could not be reached: docs.oasis-open.org (the normative MQTT 3.1.1 specification; DNS blocked here).
The CONNECT byte layout and the rule that a zero-length ClientId is only allowed with CleanSession=1
come from the implementer's memory of the spec (section 3.1) and are **not re-verified**.

## Decisions
| Return code | Meaning | Finding |
| ----------- | ------- | ------- |
| 0 | accepted without credentials | **High**, confirmed: anonymous access |
| 4, 5 | credentials required | Low, confirmed: plain-text broker |
| 1, 2, 3, other | cannot tell (e.g. broker rejects empty client ids) | Low, "not determined"; never alarming |
| no reply / not CONNACK | | Low: plain-text broker reachable |

## What a remote scanner can observe
Port 1883 open (service identified as MQTT by port). The broker's answer to one CONNECT.

## Detection decision
Passive finding for any 1883 broker; `--active` sends exactly one 14-byte MQTT 3.1.1 CONNECT (clean session,
empty client id, no username/password) and reads the CONNACK. **Not done:** no SUBSCRIBE, no PUBLISH, no
credential guessing, no other ports; 8883 (TLS) is deliberately not flagged. The probe is `Probe::active`
and passes the conformance rules (small, read-only, flagged intrusive).

## Limits
* The engine recognises MQTT by port 1883, so the end-to-end test binds 127.0.0.1:1883 and is skipped if
  that port is busy; `iotscan selftest` does not cover this checker (it must not bind a well-known port on
  your machine). Unit tests cover every reply.
* A broker on a non-standard port is not detected.
* A real broker logs the anonymous CONNECT attempt; some alert on it.

## Open questions
* Re-verify the CONNECT layout and ClientId rule against the OASIS specification.
