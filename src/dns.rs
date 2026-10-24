//! Minimal, bounds-checked DNS wire-format encoder/decoder for mDNS.
//!
//! The decoder treats every byte as hostile: it never indexes out of range,
//! caps compression-pointer hops, label/name lengths and record counts, and
//! returns `Err` instead of panicking on malformed input.

use std::net::{Ipv4Addr, Ipv6Addr};

/// Record type A.
pub const T_A: u16 = 1;
/// Record type PTR.
pub const T_PTR: u16 = 12;
/// Record type TXT.
pub const T_TXT: u16 = 16;
/// Record type AAAA.
pub const T_AAAA: u16 = 28;
/// Record type SRV.
pub const T_SRV: u16 = 33;
/// Record type ANY.
pub const T_ANY: u16 = 255;

const MAX_RECORDS: usize = 512;
const MAX_NAME: usize = 255;
const MAX_JUMPS: usize = 32;

/// Decoder failure.
#[derive(Debug, PartialEq, Eq)]
pub struct DnsError(pub &'static str);

impl std::fmt::Display for DnsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for DnsError {}

/// Decoded record data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RData {
    /// IPv4 address.
    A(Ipv4Addr),
    /// IPv6 address.
    Aaaa(Ipv6Addr),
    /// Pointer to another name.
    Ptr(String),
    /// Service location.
    Srv {
        /// Target port.
        port: u16,
        /// Target host name.
        target: String,
    },
    /// TXT strings.
    Txt(Vec<String>),
    /// Anything else.
    Other,
}

/// One resource record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// Owner name.
    pub name: String,
    /// Record type.
    pub rtype: u16,
    /// Decoded data.
    pub data: RData,
}

/// A decoded message (answers, authority and additional merged).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Message {
    /// Transaction id.
    pub id: u16,
    /// Header flags.
    pub flags: u16,
    /// Question names and types.
    pub questions: Vec<(String, u16)>,
    /// All resource records.
    pub records: Vec<Record>,
}

impl Message {
    /// True for responses (QR bit set).
    pub fn is_response(&self) -> bool {
        self.flags & 0x8000 != 0
    }
}

/// Build an mDNS query. When `unicast` is set the QU bit asks responders to
/// reply directly to us instead of multicasting.
pub fn build_query(questions: &[(&str, u16)], unicast: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&[0, 0, 0, 0]); // id, flags
    out.extend_from_slice(&(questions.len() as u16).to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    for (name, qtype) in questions {
        encode_name(&mut out, name);
        out.extend_from_slice(&qtype.to_be_bytes());
        let class: u16 = if unicast { 0x8001 } else { 0x0001 };
        out.extend_from_slice(&class.to_be_bytes());
    }
    out
}

fn encode_name(out: &mut Vec<u8>, name: &str) {
    for label in name.trim_end_matches('.').split('.') {
        let b = label.as_bytes();
        let n = b.len().min(63);
        if n == 0 {
            continue;
        }
        out.push(n as u8);
        out.extend_from_slice(&b[..n]);
    }
    out.push(0);
}

fn be16(buf: &[u8], at: usize) -> Result<u16, DnsError> {
    let b = buf.get(at..at + 2).ok_or(DnsError("truncated"))?;
    Ok(u16::from_be_bytes([b[0], b[1]]))
}

/// Read a (possibly compressed) name starting at `start`. Returns the name and
/// the offset just past the name's first encoding.
fn read_name(buf: &[u8], start: usize) -> Result<(String, usize), DnsError> {
    let mut name = String::new();
    let mut pos = start;
    let mut end: Option<usize> = None;
    let mut jumps = 0;
    loop {
        let len = *buf.get(pos).ok_or(DnsError("truncated name"))? as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        match len & 0xC0 {
            0x00 => {
                let label = buf.get(pos + 1..pos + 1 + len).ok_or(DnsError("truncated label"))?;
                if !name.is_empty() {
                    name.push('.');
                }
                name.push_str(&String::from_utf8_lossy(label));
                if name.len() > MAX_NAME {
                    return Err(DnsError("name too long"));
                }
                pos += 1 + len;
            }
            0xC0 => {
                let lo = *buf.get(pos + 1).ok_or(DnsError("truncated pointer"))? as usize;
                let target = ((len & 0x3F) << 8) | lo;
                if end.is_none() {
                    end = Some(pos + 2);
                }
                jumps += 1;
                if jumps > MAX_JUMPS {
                    return Err(DnsError("too many compression jumps"));
                }
                pos = target;
            }
            _ => return Err(DnsError("unsupported label type")),
        }
    }
    Ok((name, end.unwrap_or(pos)))
}

fn read_record(buf: &[u8], pos: usize) -> Result<(Record, usize), DnsError> {
    let (name, mut p) = read_name(buf, pos)?;
    let rtype = be16(buf, p)?;
    let rdlen = be16(buf, p + 8)? as usize;
    p += 10;
    let rd = buf.get(p..p + rdlen).ok_or(DnsError("truncated rdata"))?;
    let data = match rtype {
        T_A if rdlen == 4 => RData::A(Ipv4Addr::new(rd[0], rd[1], rd[2], rd[3])),
        T_AAAA if rdlen == 16 => {
            let mut o = [0u8; 16];
            o.copy_from_slice(rd);
            RData::Aaaa(Ipv6Addr::from(o))
        }
        T_PTR => RData::Ptr(read_name(buf, p)?.0),
        T_SRV if rdlen >= 7 => RData::Srv { port: be16(buf, p + 4)?, target: read_name(buf, p + 6)?.0 },
        T_TXT => {
            let mut strings = Vec::new();
            let mut i = 0;
            while i < rd.len() && strings.len() < 32 {
                let l = rd[i] as usize;
                i += 1;
                let Some(s) = rd.get(i..i + l) else { break };
                strings.push(String::from_utf8_lossy(s).into_owned());
                i += l;
            }
            RData::Txt(strings)
        }
        _ => RData::Other,
    };
    Ok((Record { name, rtype, data }, p + rdlen))
}

/// Decode a DNS message.
pub fn parse(buf: &[u8]) -> Result<Message, DnsError> {
    if buf.len() < 12 {
        return Err(DnsError("short header"));
    }
    let id = be16(buf, 0)?;
    let flags = be16(buf, 2)?;
    let qd = be16(buf, 4)? as usize;
    let rr = be16(buf, 6)? as usize + be16(buf, 8)? as usize + be16(buf, 10)? as usize;
    if qd > 64 || rr > MAX_RECORDS {
        return Err(DnsError("too many entries"));
    }
    let mut pos = 12;
    let mut msg = Message { id, flags, ..Message::default() };
    for _ in 0..qd {
        let (name, p) = read_name(buf, pos)?;
        let qtype = be16(buf, p)?;
        pos = p + 4;
        if pos > buf.len() {
            return Err(DnsError("truncated question"));
        }
        msg.questions.push((name, qtype));
    }
    for _ in 0..rr {
        if pos >= buf.len() {
            break; // tolerate under-counted bodies; keep what we have
        }
        match read_record(buf, pos) {
            Ok((rec, next)) => {
                msg.records.push(rec);
                pos = next;
            }
            Err(e) if msg.records.is_empty() => return Err(e),
            Err(_) => break,
        }
    }
    Ok(msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a response with an A record for tests.
    fn response_with(records: &[(&str, u16, Vec<u8>)]) -> Vec<u8> {
        let mut out = vec![0, 0, 0x84, 0, 0, 0];
        out.extend_from_slice(&(records.len() as u16).to_be_bytes());
        out.extend_from_slice(&[0, 0, 0, 0]);
        for (name, t, rdata) in records {
            encode_name(&mut out, name);
            out.extend_from_slice(&t.to_be_bytes());
            out.extend_from_slice(&[0x00, 0x01, 0, 0, 0, 120]);
            out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            out.extend_from_slice(rdata);
        }
        out
    }

    #[test]
    fn query_roundtrip() {
        let q = build_query(&[("_services._dns-sd._udp.local", T_PTR)], true);
        let m = parse(&q).unwrap();
        assert_eq!(m.questions, vec![("_services._dns-sd._udp.local".to_string(), T_PTR)]);
        assert!(!m.is_response());
        // QU bit set.
        assert_eq!(&q[q.len() - 2..], &[0x80, 0x01]);
    }

    #[test]
    fn parses_a_aaaa_ptr_srv_txt() {
        let mut ptr = Vec::new();
        encode_name(&mut ptr, "My TV._googlecast._tcp.local");
        let mut srv = vec![0, 0, 0, 0, 0x1f, 0x49];
        encode_name(&mut srv, "tv.local");
        let txt = vec![9, b'm', b'd', b'=', b'C', b'h', b'r', b'o', b'm', b'e'];
        let aaaa = "fe80::1".parse::<Ipv6Addr>().unwrap().octets().to_vec();
        let pkt = response_with(&[
            ("tv.local", T_A, vec![192, 168, 1, 9]),
            ("tv.local", T_AAAA, aaaa),
            ("_googlecast._tcp.local", T_PTR, ptr),
            ("My TV._googlecast._tcp.local", T_SRV, srv),
            ("My TV._googlecast._tcp.local", T_TXT, txt),
        ]);
        let m = parse(&pkt).unwrap();
        assert!(m.is_response());
        assert_eq!(m.records.len(), 5);
        assert_eq!(m.records[0].data, RData::A(Ipv4Addr::new(192, 168, 1, 9)));
        assert!(matches!(m.records[1].data, RData::Aaaa(_)));
        assert_eq!(m.records[2].data, RData::Ptr("My TV._googlecast._tcp.local".into()));
        assert_eq!(m.records[3].data, RData::Srv { port: 8009, target: "tv.local".into() });
        assert_eq!(m.records[4].data, RData::Txt(vec!["md=Chrome".into()]));
    }

    #[test]
    fn handles_compression_pointers() {
        // header + question "a.local" A, answer with pointer to offset 12.
        let mut p = vec![0, 0, 0x84, 0, 0, 1, 0, 1, 0, 0, 0, 0];
        encode_name(&mut p, "a.local");
        p.extend_from_slice(&[0, 1, 0, 1]);
        p.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 10, 0, 4, 10, 0, 0, 7]);
        let m = parse(&p).unwrap();
        assert_eq!(m.records[0].name, "a.local");
        assert_eq!(m.records[0].data, RData::A(Ipv4Addr::new(10, 0, 0, 7)));
    }

    #[test]
    fn pointer_loop_is_rejected() {
        let mut p = vec![0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0];
        p.extend_from_slice(&[0xC0, 12]); // points at itself
        p.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 10, 0, 0]);
        assert!(parse(&p).is_err());
    }

    #[test]
    fn rejects_truncated_and_huge_counts() {
        assert!(parse(&[]).is_err());
        assert!(parse(&[0; 11]).is_err());
        let mut p = vec![0u8; 12];
        p[6] = 0xff;
        p[7] = 0xff;
        assert!(parse(&p).is_err());
        let ok = response_with(&[("x.local", T_A, vec![1, 2, 3, 4])]);
        for cut in 0..ok.len() {
            let _ = parse(&ok[..cut]); // must never panic
        }
    }

    #[test]
    fn random_bytes_never_panic() {
        // xorshift fuzzing: the decoder must return Ok or Err for any input.
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for _ in 0..20_000 {
            let len = (next() % 300) as usize;
            let mut buf: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            if len > 12 && next() % 2 == 0 {
                buf[4] = 0;
                buf[5] = (next() % 3) as u8;
                buf[6] = 0;
                buf[7] = (next() % 6) as u8;
            }
            let _ = parse(&buf);
        }
    }

    #[test]
    fn oversized_name_rejected() {
        let mut p = vec![0, 0, 0x84, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        for _ in 0..10 {
            p.push(60);
            p.extend(std::iter::repeat_n(b'a', 60));
        }
        p.push(0);
        p.extend_from_slice(&[0, 1, 0, 1]);
        assert!(parse(&p).is_err());
    }
}
