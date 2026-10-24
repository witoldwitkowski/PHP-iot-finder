//! MQTT brokers on the home network.
//!
//! MQTT carries the commands and sensor readings of many smart-home systems. A broker that
//! accepts connections without credentials lets anyone on the network read every message and
//! publish commands; a plain-text broker exposes passwords to anyone who can sniff the network.
//!
//! Passive: a service on TCP 1883 that the engine identified as MQTT is reported as a plain-text
//! broker. With `--active` the checker also sends one minimal MQTT 3.1.1 CONNECT (clean session,
//! empty client id, **no credentials**) and reads the CONNACK. It never subscribes or publishes.
//! Port 8883 (MQTT over TLS) is deliberately not flagged. Research notes: docs/research/mqtt-exposed.md

use super::*;
use crate::model::Severity;

/// Checker id.
pub const ID: &str = "mqtt-exposed";

/// The plain-text MQTT port.
pub const MQTT_PORT: u16 = 1883;

/// MQTT 3.1.1 CONNECT: protocol "MQTT" level 4, clean session, keep-alive 60 s, empty client id,
/// no username or password. 14 bytes, read-only.
pub const CONNECT: [u8; 14] = [0x10, 0x0C, 0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04, 0x02, 0x00, 0x3C, 0x00, 0x00];

/// The MQTT exposure checker.
pub struct MqttExposed;

fn connect_probe(port: u16) -> ProbeKind {
    ProbeKind::Tcp { port, send: CONNECT.to_vec() }
}

/// What a CONNACK told us.
#[derive(Debug, PartialEq, Eq)]
enum Reply {
    Accepted,
    AuthRequired(u8),
    Inconclusive(u8),
    NotMqtt,
}

fn parse_connack(b: &[u8]) -> Reply {
    // CONNACK: type 0x20, remaining length 2, session-present flags, return code.
    match b {
        [0x20, 0x02, _, 0, ..] => Reply::Accepted,
        [0x20, 0x02, _, rc @ (4 | 5), ..] => Reply::AuthRequired(*rc),
        [0x20, 0x02, _, rc, ..] => Reply::Inconclusive(*rc),
        _ => Reply::NotMqtt,
    }
}

impl Checker for MqttExposed {
    fn meta(&self) -> CheckerMeta {
        CheckerMeta {
            id: ID,
            name: "MQTT broker exposed",
            description: "A plain-text MQTT broker is reachable; with --active, whether it accepts anonymous connections.",
            category: Category::Exposure,
            tags: &["mqtt", "iot", "exposure", "cleartext"],
            uses_active_probes: true,
        }
    }

    fn needs(&self) -> Vec<Need> {
        vec![Need::Port(MQTT_PORT)]
    }

    fn probes(&self, device: &Device, _db: &AdvisoryDb) -> Vec<Probe> {
        device
            .services
            .iter()
            .filter(|s| s.kind == ServiceKind::Mqtt && s.port == MQTT_PORT)
            .map(|s| Probe::active(connect_probe(s.port)))
            .collect()
    }

    fn evaluate(&self, input: &CheckInput) -> Vec<Finding> {
        let mut out = Vec::new();
        for s in input.services_of(ServiceKind::Mqtt).filter(|s| s.port == MQTT_PORT) {
            let reply = input.probes.bytes(&connect_probe(s.port)).map(parse_connack);
            let fix = "Require authentication (a username and password, or client certificates) and TLS on the broker (port 8883), and \
                       keep it off untrusted networks: bind it to localhost or an isolated IoT VLAN. If the broker lives inside a hub or \
                       appliance, look for a firmware update and disable the broker if you do not use it.";
            let base = |sev: Severity, title: &str| Finding::new(ID, title, sev, Confidence::Confirmed).port(s.port).remediation(fix);
            let listening = format!("TCP port {} is open and identified as MQTT", s.port);
            out.push(match reply {
                Some(Reply::Accepted) => base(Severity::High, "MQTT broker accepts anonymous connections")
                    .summary(format!(
                        "The MQTT broker on port {} accepted a connection with no username or password. Anyone on the network can read the messages your smart-home \
                         devices exchange and send commands to them.",
                        s.port
                    ))
                    .evidence(listening)
                    .evidence("CONNACK return code 0 (accepted) in reply to a CONNECT without credentials"),
                Some(Reply::AuthRequired(rc)) => base(Severity::Low, "MQTT broker uses plain text (authentication is required)")
                    .summary(format!(
                        "The MQTT broker on port {} requires credentials but is not encrypted, so passwords and messages can be read by anyone who can observe the network.",
                        s.port
                    ))
                    .evidence(listening)
                    .evidence(format!("CONNACK return code {rc} (credentials required) in reply to a CONNECT without credentials")),
                Some(Reply::Inconclusive(rc)) => base(Severity::Low, "Plain-text MQTT broker (anonymous access not determined)")
                    .summary(format!(
                        "The MQTT broker on port {} is not encrypted. It answered the anonymous test with return code {rc}, which does not show whether anonymous access is allowed.",
                        s.port
                    ))
                    .evidence(listening)
                    .evidence(format!("CONNACK return code {rc}")),
                Some(Reply::NotMqtt) | None => {
                    let hint = if input.active {
                        "The broker did not answer the anonymous test with a CONNACK."
                    } else {
                        "Re-run with --active to test whether it accepts anonymous connections."
                    };
                    base(Severity::Low, "Plain-text MQTT broker is reachable")
                        .summary(format!("An MQTT broker is listening on port {} without encryption. {hint}", s.port))
                        .evidence(listening)
                }
            });
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::super::testutil::*;
    use super::*;
    use crate::model::Service;

    fn broker(port: u16) -> Device {
        let mut d = Device::new("192.168.1.60".parse().unwrap());
        d.services.push(Service { port, kind: ServiceKind::Mqtt, banner: None, http: None, note: None });
        d
    }

    fn run(d: &Device, reply: Option<&[u8]>, active: bool) -> Vec<Finding> {
        let mut probes = ProbeResults::default();
        if let Some(r) = reply {
            probes.insert(connect_probe(1883), Ok(ProbeData::Bytes(r.to_vec())));
        }
        let db = AdvisoryDb::embedded();
        let mut i = input(d, &probes, &db, "2026-10-24");
        i.active = active;
        MqttExposed.evaluate(&i)
    }

    #[test]
    fn connect_packet_is_well_formed() {
        assert_eq!(CONNECT.len(), 2 + CONNECT[1] as usize, "remaining length matches");
        assert_eq!(CONNECT[0], 0x10, "CONNECT packet type");
        assert_eq!(&CONNECT[2..8], &[0, 4, b'M', b'Q', b'T', b'T']);
        assert_eq!(CONNECT[8], 4, "protocol level 3.1.1");
        assert_eq!(CONNECT[9], 0x02, "clean session only: no username, password or will flags");
        assert_eq!(&CONNECT[12..], &[0, 0], "empty client id");
    }

    #[test]
    fn anonymous_access_is_high_and_confirmed() {
        let f = run(&broker(1883), Some(&[0x20, 0x02, 0x00, 0x00]), true);
        assert_eq!(f.len(), 1);
        assert_eq!((f[0].severity, f[0].confidence, f[0].port), (Severity::High, Confidence::Confirmed, Some(1883)));
        assert!(f[0].title.contains("anonymous"));
    }

    #[test]
    fn authentication_enforced_is_low() {
        for rc in [4u8, 5] {
            let f = run(&broker(1883), Some(&[0x20, 0x02, 0x00, rc]), true);
            assert_eq!(f[0].severity, Severity::Low, "rc {rc}");
            assert!(f[0].title.contains("authentication is required"));
        }
    }

    #[test]
    fn other_return_codes_are_inconclusive_not_alarming() {
        for rc in [1u8, 2, 3, 99] {
            let f = run(&broker(1883), Some(&[0x20, 0x02, 0x01, rc]), true);
            assert_eq!(f[0].severity, Severity::Low, "rc {rc}");
            assert!(f[0].title.contains("not determined"));
        }
    }

    #[test]
    fn no_probe_or_garbage_reports_a_plain_text_broker() {
        let f = run(&broker(1883), None, false);
        assert_eq!(f[0].severity, Severity::Low);
        assert!(f[0].summary.contains("--active"));
        let g = run(&broker(1883), Some(b"HTTP/1.1 400"), true);
        assert!(g[0].summary.contains("did not answer"));
        for junk in [&[][..], &[0x20][..], &[0x20, 0x02][..], &[0xff; 64][..]] {
            assert_eq!(run(&broker(1883), Some(junk), true)[0].severity, Severity::Low);
        }
    }

    #[test]
    fn only_plain_mqtt_on_1883_is_flagged() {
        assert!(run(&broker(8883), None, true).is_empty(), "MQTT over TLS is the good configuration");
        let mut d = broker(1883);
        d.services[0].kind = ServiceKind::Http;
        assert!(run(&d, None, true).is_empty());
        assert!(run(&Device::new("10.0.0.1".parse().unwrap()), None, true).is_empty());
    }

    #[test]
    fn probe_is_active_and_only_for_1883() {
        let db = AdvisoryDb::embedded();
        let p = MqttExposed.probes(&broker(1883), &db);
        assert_eq!(p.len(), 1);
        assert!(p[0].intrusive, "sending a CONNECT needs --active");
        assert_eq!(p[0].kind, connect_probe(1883));
        assert!(MqttExposed.probes(&broker(8883), &db).is_empty());
        assert!(MqttExposed.needs().contains(&Need::Port(1883)));
    }
}
