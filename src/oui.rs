//! MAC address → vendor lookup using an embedded copy of the IEEE registry.
//!
//! The table is `data/oui.tsv` (`AABBCC<TAB>Vendor`, sorted). Refresh it with
//! `scripts/update-oui.sh`.

use std::sync::OnceLock;

static RAW: &str = include_str!("../data/oui.tsv");

struct Table {
    /// 24-bit (MA-L) assignments, sorted by prefix.
    l: Vec<(u32, &'static str)>,
    /// 28-bit (MA-M) assignments, sorted by prefix.
    m: Vec<(u32, &'static str)>,
}

fn table() -> &'static Table {
    static T: OnceLock<Table> = OnceLock::new();
    T.get_or_init(|| {
        let mut l = Vec::with_capacity(32_768);
        let mut m = Vec::with_capacity(4_096);
        for line in RAW.lines() {
            let Some((k, v)) = line.split_once('\t') else { continue };
            let Ok(n) = u32::from_str_radix(k, 16) else { continue };
            match k.len() {
                6 => l.push((n, v)),
                7 => m.push((n, v)),
                _ => {}
            }
        }
        l.sort_unstable_by_key(|e| e.0);
        m.sort_unstable_by_key(|e| e.0);
        Table { l, m }
    })
}

/// True when the locally-administered bit is set (random/private MACs used by phones).
pub fn is_locally_administered(mac: &[u8; 6]) -> bool {
    mac[0] & 0x02 != 0
}

/// Look up the vendor for a MAC address.
pub fn vendor(mac: &[u8; 6]) -> Option<String> {
    if is_locally_administered(mac) {
        return Some("Private/randomized address".to_string());
    }
    let t = table();
    // MA-M: first 28 bits.
    let m28 = ((mac[0] as u32) << 20) | ((mac[1] as u32) << 12) | ((mac[2] as u32) << 4) | ((mac[3] as u32) >> 4);
    if let Ok(i) = t.m.binary_search_by_key(&m28, |e| e.0) {
        return Some(t.m[i].1.to_string());
    }
    let l24 = ((mac[0] as u32) << 16) | ((mac[1] as u32) << 8) | mac[2] as u32;
    t.l.binary_search_by_key(&l24, |e| e.0).ok().map(|i| t.l[i].1.to_string())
}

/// Number of entries loaded (for diagnostics).
pub fn entries() -> usize {
    let t = table();
    t.l.len() + t.m.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::parse_mac;

    #[test]
    fn known_vendors() {
        let e = parse_mac("08:3a:8d:01:02:03").unwrap();
        assert_eq!(vendor(&e).as_deref(), Some("Espressif"));
        let h = parse_mac("04:03:12:aa:bb:cc").unwrap();
        assert!(vendor(&h).unwrap().contains("Hikvision"));
    }

    #[test]
    fn randomized() {
        let m = parse_mac("02:11:22:33:44:55").unwrap();
        assert!(is_locally_administered(&m));
        assert_eq!(vendor(&m).as_deref(), Some("Private/randomized address"));
    }

    #[test]
    fn unassigned_prefix_is_none() {
        // Find a prefix absent from the table so the test does not depend on registry contents.
        let t = table();
        let free = (0u32..0x00FF_FFFF).step_by(2).find(|n| t.l.binary_search_by_key(n, |e| e.0).is_err()).unwrap() & 0x00FF_FFFC;
        let mac = [(free >> 16) as u8 & 0xFC, (free >> 8) as u8, free as u8, 0, 0, 0];
        if t.l.binary_search_by_key(&(((mac[0] as u32) << 16) | ((mac[1] as u32) << 8) | mac[2] as u32), |e| e.0).is_err() {
            assert!(vendor(&mac).is_none());
        }
    }

    #[test]
    fn table_is_big_and_sorted() {
        assert!(entries() > 20_000);
        let t = table();
        assert!(t.l.windows(2).all(|w| w[0].0 < w[1].0));
    }
}
