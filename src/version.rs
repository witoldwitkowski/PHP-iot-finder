//! Tolerant version parsing and comparison for banner strings such as
//! `8.2.30`, `7.4.33-1+deb11u1` or `8.1.2-1ubuntu2.14`.

use serde::{Deserialize, Serialize};
use std::cmp::Ordering;

/// A parsed `major.minor[.patch]` version plus whatever text followed it.
#[derive(Clone, Debug, Serialize, Deserialize, Eq)]
pub struct Version {
    /// Major component.
    pub major: u32,
    /// Minor component.
    pub minor: u32,
    /// Patch component (0 when absent).
    pub patch: u32,
    /// Whether a patch component was present in the source text.
    pub has_patch: bool,
    /// Trailing text after the numeric part, e.g. `-1ubuntu2.14` or `RC1`.
    pub suffix: String,
}

impl PartialEq for Version {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Version {
    /// Parse a version from the start of `s`. Leading non-digits are skipped
    /// only when they are a short alphabetic prefix such as `PHP/` or `v`.
    pub fn parse(s: &str) -> Option<Version> {
        let s = s.trim();
        let start = s.find(|c: char| c.is_ascii_digit())?;
        if start > 8 {
            return None;
        }
        let rest = &s[start..];
        let mut nums = [0u32; 3];
        let mut count = 0;
        let mut idx = 0;
        let bytes = rest.as_bytes();
        while count < 3 {
            let begin = idx;
            while idx < bytes.len() && bytes[idx].is_ascii_digit() {
                idx += 1;
            }
            if idx == begin || idx - begin > 6 {
                if count == 0 {
                    return None;
                }
                break;
            }
            nums[count] = rest[begin..idx].parse().ok()?;
            count += 1;
            if idx < bytes.len() && bytes[idx] == b'.' && idx + 1 < bytes.len() && bytes[idx + 1].is_ascii_digit() {
                idx += 1;
            } else {
                break;
            }
        }
        if count < 2 {
            return None;
        }
        let suffix: String = rest[idx..]
            .chars()
            .take_while(|c| !c.is_whitespace() && !c.is_control() && !matches!(c, ')' | ';' | ',' | '"' | '<' | '('))
            .take(64)
            .collect();
        Some(Version { major: nums[0], minor: nums[1], patch: nums[2], has_patch: count >= 3, suffix })
    }

    /// `major.minor`, e.g. `8.2`.
    pub fn branch(&self) -> String {
        format!("{}.{}", self.major, self.minor)
    }

    /// True for `8.5.0RC1`, `8.4.0alpha2`, `8.3.0-dev` style builds.
    pub fn is_prerelease(&self) -> bool {
        let s = self.suffix.trim_start_matches(['-', '~', '_', '.']).to_ascii_lowercase();
        ["alpha", "beta", "rc", "dev"].iter().any(|p| s.starts_with(p))
    }

    /// True when the suffix looks like a distribution/vendor package revision
    /// (`-1ubuntu2`, `+deb12u1`, `.el9`, …). Such builds commonly carry
    /// security fixes without bumping the upstream version.
    pub fn looks_vendor_packaged(&self) -> bool {
        let s = self.suffix.to_ascii_lowercase();
        if s.is_empty() {
            return false;
        }
        ["ubuntu", "deb", "debian", "el7", "el8", "el9", "el10", "fc", "amzn", "alpine", "suse", "sles", "~", "+"]
            .iter()
            .any(|m| s.contains(m))
            || (s.starts_with('-') && s[1..].chars().next().is_some_and(|c| c.is_ascii_digit()))
    }

    /// Compare against `major.minor.patch` ignoring suffixes.
    pub fn cmp_triplet(&self, other: &Version) -> Ordering {
        (self.major, self.minor, self.patch).cmp(&(other.major, other.minor, other.patch))
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        self.cmp_triplet(other).then_with(|| match (self.is_prerelease(), other.is_prerelease()) {
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            _ => Ordering::Equal,
        })
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.has_patch {
            write!(f, "{}.{}.{}{}", self.major, self.minor, self.patch, self.suffix)
        } else {
            write!(f, "{}.{}{}", self.major, self.minor, self.suffix)
        }
    }
}

/// Compare two `major.minor` branch strings numerically.
pub fn cmp_branch(a: &str, b: &str) -> Ordering {
    match (Version::parse(a), Version::parse(b)) {
        (Some(x), Some(y)) => (x.major, x.minor).cmp(&(y.major, y.minor)),
        _ => a.cmp(b),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Version {
        Version::parse(s).unwrap_or_else(|| panic!("parse {s}"))
    }

    #[test]
    fn parses_common_banners() {
        assert_eq!(v("8.2.30").to_string(), "8.2.30");
        let d = v("7.4.33-1+deb11u1");
        assert_eq!((d.major, d.minor, d.patch), (7, 4, 33));
        assert!(d.looks_vendor_packaged());
        let u = v("PHP/8.1.2-1ubuntu2.14");
        assert_eq!(u.branch(), "8.1");
        assert!(u.looks_vendor_packaged());
        assert!(!v("8.3.36").looks_vendor_packaged());
        assert!(v("8.2").patch == 0 && !v("8.2").has_patch);
    }

    #[test]
    fn rejects_garbage() {
        assert!(Version::parse("").is_none());
        assert!(Version::parse("abc").is_none());
        assert!(Version::parse("12").is_none());
        assert!(Version::parse("a very long prefix 1.2.3").is_none());
        assert!(Version::parse("99999999.1.1").is_none());
        // Trailing prose is not part of the suffix.
        assert_eq!(v("8.2.30 System Linux").suffix, "");
        assert_eq!(v("8.2.30-1ubuntu1 (cli)").suffix, "-1ubuntu1");
        // Control characters never become part of a version.
        assert_eq!(v("7.4.33-1\u{0}evil\u{1b}[2J").suffix, "-1");
    }

    #[test]
    fn ordering() {
        assert!(v("8.2.34") < v("8.2.35"));
        assert!(v("8.2.9") < v("8.2.10"));
        assert!(v("8.10.0") > v("8.9.9"));
        assert!(v("8.2.35RC1") < v("8.2.35"));
        assert_eq!(v("8.2.35-1ubuntu1"), v("8.2.35"));
    }

    #[test]
    fn branch_cmp() {
        assert_eq!(cmp_branch("8.10", "8.9"), Ordering::Greater);
        assert_eq!(cmp_branch("7.4", "8.0"), Ordering::Less);
    }

    #[test]
    fn prerelease() {
        assert!(v("8.5.0RC1").is_prerelease());
        assert!(v("8.4.0-dev").is_prerelease());
        assert!(!v("8.4.1").is_prerelease());
    }
}
