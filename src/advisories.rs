//! The advisory database: which versions of which products are affected.
//!
//! The built-in database (`data/advisories.toml`) is compiled in. A user file is
//! merged on top so new knowledge can be added without recompiling.

use crate::model::Severity;
use crate::util::Date;
use crate::version::{Version, cmp_branch};
use serde::Deserialize;
use std::path::{Path, PathBuf};

static EMBEDDED: &str = include_str!("../data/advisories.toml");

/// A support window for a PHP branch.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct PhpBranch {
    /// `major.minor`.
    pub branch: String,
    /// End of active support (bug fixes), if tracked.
    #[serde(default)]
    pub active_until: Option<String>,
    /// End of security support.
    pub security_until: String,
}

impl PhpBranch {
    /// Parsed end-of-security-support date.
    pub fn security_end(&self) -> Option<Date> {
        Date::parse(&self.security_until)
    }
    /// Parsed end-of-active-support date.
    pub fn active_end(&self) -> Option<Date> {
        self.active_until.as_deref().and_then(Date::parse)
    }
}

/// One affected-version rule.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct Affected {
    /// Restrict to a `major.minor` branch.
    #[serde(default)]
    pub branch: Option<String>,
    /// Versions at or above this are in range (default: all).
    #[serde(default)]
    pub from: Option<String>,
    /// First fixed version; versions below it are affected. Absent = never fixed.
    #[serde(default)]
    pub fixed: Option<String>,
}

/// Branches that have no official fix.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct Legacy {
    /// Branches strictly older than this have no official fixed release.
    pub below: String,
    /// Branches strictly older than this are not confirmed as affected at all.
    #[serde(default)]
    pub unconfirmed_below: Option<String>,
    /// Explanation shown to the user.
    #[serde(default)]
    pub note: String,
}

/// One advisory.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct Advisory {
    /// Stable id (used by `--only`, the allowlist and reports).
    pub id: String,
    /// Product name as it appears (lowercase) in banners, e.g. `php`.
    pub product: String,
    /// Name of a dedicated checker, or absent to use the generic data-driven one.
    #[serde(default)]
    pub checker: Option<String>,
    /// Headline.
    pub title: String,
    /// Severity if exploited.
    pub severity: Severity,
    /// CVE ids.
    #[serde(default)]
    pub cves: Vec<String>,
    /// Publication date.
    #[serde(default)]
    pub published: String,
    /// What it is.
    #[serde(default)]
    pub summary: String,
    /// What to do.
    #[serde(default)]
    pub remediation: String,
    /// Links.
    #[serde(default)]
    pub references: Vec<String>,
    /// Affected-version rules.
    #[serde(default)]
    pub affected: Vec<Affected>,
    /// Also match banners that name the product without a version (for products where every
    /// version is affected, such as discontinued software).
    #[serde(default)]
    pub any_version: bool,
    /// Handling of branches with no official fix.
    #[serde(default)]
    pub legacy: Option<Legacy>,
    /// True only when the version data was checked against the vendor's own advisory.
    /// Unverified advisories still work, but findings say so.
    #[serde(default)]
    pub verified: bool,
    /// Provenance and open questions: sources used, date, anything that conflicted.
    /// Required when `verified` is false.
    #[serde(default)]
    pub notes: Vec<String>,
}

/// Result of checking a version against an advisory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// In a vulnerable range; `fixed` is the first fixed version, if any.
    Affected {
        /// First fixed version on this branch.
        fixed: Option<String>,
    },
    /// At or above the fixed version.
    Fixed,
    /// On a branch with no official fix.
    Legacy {
        /// Explanation.
        note: String,
        /// True when upstream has not confirmed the branch as affected.
        unconfirmed: bool,
    },
    /// The advisory says nothing about this branch.
    NotCovered,
}

impl Advisory {
    /// Decide whether `v` is affected.
    pub fn verdict(&self, v: &Version) -> Verdict {
        let branch = v.branch();
        let mut branch_seen = false;
        for rule in &self.affected {
            if let Some(b) = &rule.branch {
                if *b != branch {
                    continue;
                }
                branch_seen = true;
            }
            if let Some(from) = rule.from.as_deref().and_then(Version::parse)
                && v.cmp_triplet(&from).is_lt()
            {
                continue;
            }
            match rule.fixed.as_deref().and_then(Version::parse) {
                Some(fixed) if *v >= fixed => continue,
                Some(fixed) => return Verdict::Affected { fixed: Some(fixed.to_string()) },
                None => return Verdict::Affected { fixed: None },
            }
        }
        if branch_seen {
            return Verdict::Fixed;
        }
        if let Some(l) = &self.legacy
            && cmp_branch(&branch, &l.below).is_lt()
        {
            let unconfirmed = l.unconfirmed_below.as_deref().is_some_and(|u| cmp_branch(&branch, u).is_lt());
            return Verdict::Legacy { note: l.note.clone(), unconfirmed };
        }
        Verdict::NotCovered
    }
}

/// The complete database.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct AdvisoryDb {
    /// Schema version.
    #[serde(default)]
    pub schema: u32,
    /// Last data update.
    #[serde(default)]
    pub updated: String,
    /// PHP support windows.
    #[serde(default)]
    pub php_branch: Vec<PhpBranch>,
    /// Advisories.
    #[serde(default)]
    pub advisory: Vec<Advisory>,
}

/// Where the optional user database lives.
pub fn user_db_path() -> Option<PathBuf> {
    crate::paths::config_dir().map(|d| d.join("advisories.toml"))
}

impl AdvisoryDb {
    /// Parse a TOML document.
    pub fn parse(text: &str) -> Result<AdvisoryDb, String> {
        toml::from_str(text).map_err(|e| e.to_string())
    }

    /// The compiled-in database.
    pub fn embedded() -> AdvisoryDb {
        AdvisoryDb::parse(EMBEDDED).expect("built-in advisories.toml is valid (checked by tests)")
    }

    /// Merge `other` on top: same-id advisories and same-branch windows are replaced.
    pub fn merge(&mut self, other: AdvisoryDb) {
        for a in other.advisory {
            if let Some(slot) = self.advisory.iter_mut().find(|x| x.id == a.id) {
                *slot = a;
            } else {
                self.advisory.push(a);
            }
        }
        for b in other.php_branch {
            if let Some(slot) = self.php_branch.iter_mut().find(|x| x.branch == b.branch) {
                *slot = b;
            } else {
                self.php_branch.push(b);
            }
        }
        if !other.updated.is_empty() {
            self.updated = other.updated;
        }
    }

    /// Embedded database plus an optional overlay file (explicit path, else the user config file).
    /// Returns warnings for an unreadable/invalid overlay instead of failing the scan.
    pub fn load(explicit: Option<&Path>) -> (AdvisoryDb, Vec<String>) {
        let mut db = AdvisoryDb::embedded();
        let mut warnings = Vec::new();
        let path = explicit.map(Path::to_path_buf).or_else(user_db_path);
        if let Some(p) = path {
            let required = explicit.is_some();
            match std::fs::read_to_string(&p) {
                Ok(text) => match AdvisoryDb::parse(&text) {
                    Ok(over) => {
                        let problems = over.validate();
                        if problems.is_empty() {
                            db.merge(over);
                        } else {
                            warnings.push(format!("ignoring {}: {}", p.display(), problems.join("; ")));
                        }
                    }
                    Err(e) => warnings.push(format!("ignoring {}: {e}", p.display())),
                },
                Err(e) if required => warnings.push(format!("cannot read {}: {e}", p.display())),
                Err(_) => {}
            }
        }
        (db, warnings)
    }

    /// Look up an advisory by id.
    pub fn get(&self, id: &str) -> Option<&Advisory> {
        self.advisory.iter().find(|a| a.id == id)
    }

    /// Support window for a PHP branch.
    pub fn php_branch(&self, branch: &str) -> Option<&PhpBranch> {
        self.php_branch.iter().find(|b| b.branch == branch)
    }

    /// Check the database for mistakes. Empty means valid.
    pub fn validate(&self) -> Vec<String> {
        let mut p = Vec::new();
        let mut ids = std::collections::HashSet::new();
        for a in &self.advisory {
            if a.id.is_empty() || !a.id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
                p.push(format!("advisory id '{}' must be alphanumeric/-/_", a.id));
            }
            if !ids.insert(&a.id) {
                p.push(format!("duplicate advisory id '{}'", a.id));
            }
            if a.product.is_empty() || a.product != a.product.to_ascii_lowercase() {
                p.push(format!("{}: product must be non-empty lowercase", a.id));
            }
            if !a.published.is_empty() && Date::parse(&a.published).is_none() {
                p.push(format!("{}: bad published date '{}'", a.id, a.published));
            }
            for r in &a.affected {
                for (label, v) in [("from", &r.from), ("fixed", &r.fixed)] {
                    if let Some(s) = v
                        && Version::parse(s).is_none()
                    {
                        p.push(format!("{}: unparseable {label} version '{s}'", a.id));
                    }
                }
                if let (Some(b), Some(f)) = (&r.branch, r.fixed.as_deref().and_then(Version::parse))
                    && f.branch() != *b
                {
                    p.push(format!("{}: fixed version {} is not on branch {b}", a.id, f));
                }
            }
            if let Some(l) = &a.legacy
                && Version::parse(&l.below).is_none()
            {
                p.push(format!("{}: bad legacy.below '{}'", a.id, l.below));
            }
            if a.any_version && !a.affected.iter().any(|r| r.fixed.is_none() && r.branch.is_none()) {
                p.push(format!(
                    "{}: `any_version = true` only makes sense when every version is affected (add `from = \"0.0\"` with no `fixed`)",
                    a.id
                ));
            }
            if a.affected.is_empty() && a.legacy.is_none() {
                p.push(format!("{}: has neither `affected` rules nor `legacy`", a.id));
            }
            if a.title.is_empty() {
                p.push(format!("{}: missing title", a.id));
            }
            if !a.verified && a.notes.is_empty() {
                p.push(format!("{}: `verified = false` needs `notes` saying where the data came from and what is unconfirmed", a.id));
            }
            for c in &a.cves {
                if !(c.starts_with("CVE-") && c.len() >= 9) {
                    p.push(format!("{}: malformed CVE id '{c}'", a.id));
                }
            }
        }
        for b in &self.php_branch {
            if Date::parse(&b.security_until).is_none() {
                p.push(format!("php_branch {}: bad security_until '{}'", b.branch, b.security_until));
            }
            if let Some(d) = &b.active_until
                && Date::parse(d).is_none()
            {
                p.push(format!("php_branch {}: bad active_until '{d}'", b.branch));
            }
        }
        p
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Version {
        Version::parse(s).unwrap()
    }

    #[test]
    fn embedded_is_valid() {
        let db = AdvisoryDb::embedded();
        assert!(db.validate().is_empty(), "{:?}", db.validate());
        assert!(db.get("php2shell").is_some());
        assert!(db.php_branch("8.2").is_some());
    }

    #[test]
    fn php2shell_verdicts() {
        let db = AdvisoryDb::embedded();
        let a = db.get("php2shell").unwrap();
        // Vulnerable up to the fixed release on each supported branch.
        assert_eq!(a.verdict(&v("8.5.11")), Verdict::Affected { fixed: Some("8.5.12".into()) });
        assert_eq!(a.verdict(&v("8.4.26")), Verdict::Affected { fixed: Some("8.4.27".into()) });
        assert_eq!(a.verdict(&v("8.3.35")), Verdict::Affected { fixed: Some("8.3.36".into()) });
        assert_eq!(a.verdict(&v("8.2.34")), Verdict::Affected { fixed: Some("8.2.35".into()) });
        assert_eq!(a.verdict(&v("8.2.0")), Verdict::Affected { fixed: Some("8.2.35".into()) });
        // Fixed releases and later.
        for ok in ["8.5.12", "8.5.13", "8.4.27", "8.3.36", "8.2.35", "8.2.40"] {
            assert_eq!(a.verdict(&v(ok)), Verdict::Fixed, "{ok}");
        }
        // Legacy branches with no official fix.
        for old in ["8.1.33", "8.0.30", "7.4.33"] {
            assert!(matches!(a.verdict(&v(old)), Verdict::Legacy { unconfirmed: false, .. }), "{old}");
        }
        for ancient in ["7.3.33", "5.6.40", "7.0.0"] {
            assert!(matches!(a.verdict(&v(ancient)), Verdict::Legacy { unconfirmed: true, .. }), "{ancient}");
        }
        // A branch newer than anything listed: not covered (assumed fixed).
        assert_eq!(a.verdict(&v("8.6.0")), Verdict::NotCovered);
        assert_eq!(a.verdict(&v("9.0.0")), Verdict::NotCovered);
    }

    #[test]
    fn open_ended_ranges() {
        let a = AdvisoryDb::parse(
            r#"
[[advisory]]
id = "x"
product = "boa"
title = "t"
severity = "high"
[[advisory.affected]]
from = "0.0"
"#,
        )
        .unwrap()
        .advisory
        .remove(0);
        assert_eq!(a.verdict(&v("0.94.14")), Verdict::Affected { fixed: None });
        let b = AdvisoryDb::parse(
            r#"
[[advisory]]
id = "y"
product = "p"
title = "t"
severity = "low"
[[advisory.affected]]
from = "1.2.0"
fixed = "1.2.9"
"#,
        )
        .unwrap()
        .advisory
        .remove(0);
        assert_eq!(b.verdict(&v("1.1.9")), Verdict::NotCovered);
        assert_eq!(b.verdict(&v("1.2.3")), Verdict::Affected { fixed: Some("1.2.9".into()) });
        assert_eq!(b.verdict(&v("1.2.9")), Verdict::NotCovered);
    }

    #[test]
    fn merge_replaces_by_id() {
        let mut base = AdvisoryDb::embedded();
        let n = base.advisory.len();
        let over = AdvisoryDb::parse(
            r#"
[[advisory]]
id = "php2shell"
product = "php"
title = "overridden"
severity = "low"
[[advisory.affected]]
branch = "8.2"
fixed = "8.2.99"
[[advisory]]
id = "brand-new"
product = "foo"
title = "new"
severity = "medium"
[[advisory.affected]]
from = "1.0"
"#,
        )
        .unwrap();
        base.merge(over);
        assert_eq!(base.advisory.len(), n + 1);
        assert_eq!(base.get("php2shell").unwrap().title, "overridden");
    }

    #[test]
    fn validation_catches_mistakes() {
        let db = AdvisoryDb::parse(
            r#"
[[advisory]]
id = "bad id!"
product = "PHP"
title = ""
severity = "high"
published = "yesterday"
cves = ["nope"]
[[advisory.affected]]
branch = "8.2"
fixed = "8.3.1"
[[php_branch]]
branch = "9.9"
security_until = "later"
"#,
        )
        .unwrap();
        let p = db.validate();
        assert!(p.len() >= 6, "{p:?}");
    }

    #[test]
    fn bad_overlay_is_ignored_with_warning() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("a.toml");
        std::fs::write(&f, "this is = not [valid").unwrap();
        let (db, w) = AdvisoryDb::load(Some(&f));
        assert_eq!(w.len(), 1);
        assert!(db.get("php2shell").is_some());
        let (_, w) = AdvisoryDb::load(Some(&dir.path().join("missing.toml")));
        assert_eq!(w.len(), 1);
    }
}
