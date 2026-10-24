//! Saved scans, so each run can be compared with the last.

use crate::model::ScanResult;
use crate::util::{file_timestamp, unix_now};
use serde::Serialize;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Scans kept on disk.
pub const KEEP: usize = 60;

/// One saved scan.
#[derive(Clone, Debug, Serialize)]
pub struct Entry {
    /// File name (`scan-20261024T031500Z.json`).
    pub name: String,
    /// Start time.
    pub started: String,
    /// Devices in the scan.
    pub devices: usize,
    /// Active findings in the scan.
    pub findings: usize,
}

/// Is `name` a file name this module created? Guards the GUI against path traversal.
pub fn valid_name(name: &str) -> bool {
    name.len() < 64
        && name.starts_with("scan-")
        && name.ends_with(".json")
        && name[5..name.len() - 5].chars().all(|c| c.is_ascii_digit() || c == 'T' || c == 'Z' || c == '-')
}

/// Create the directory (mode 0700) if needed.
fn ensure_dir(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)
}

/// Save a result; returns the file name. Written atomically with mode 0600.
pub fn save(dir: &Path, result: &ScanResult) -> std::io::Result<String> {
    use std::os::unix::fs::OpenOptionsExt;
    ensure_dir(dir)?;
    let mut name = format!("scan-{}.json", file_timestamp(unix_now()));
    let mut n = 1;
    while dir.join(&name).exists() {
        name = format!("scan-{}-{n}.json", file_timestamp(unix_now()));
        n += 1;
    }
    let tmp = dir.join(format!(".{name}.tmp"));
    {
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)?;
        f.write_all(&serde_json::to_vec(result).map_err(std::io::Error::other)?)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, dir.join(&name))?;
    prune(dir);
    Ok(name)
}

fn names(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .map(|rd| rd.filter_map(|e| e.ok()).filter_map(|e| e.file_name().into_string().ok()).filter(|n| valid_name(n)).collect())
        .unwrap_or_default();
    v.sort();
    v
}

fn prune(dir: &Path) {
    let all = names(dir);
    if all.len() > KEEP {
        for old in &all[..all.len() - KEEP] {
            let _ = std::fs::remove_file(dir.join(old));
        }
    }
}

/// Load a saved scan by file name.
pub fn load(dir: &Path, name: &str) -> Result<ScanResult, String> {
    if !valid_name(name) {
        return Err("invalid scan name".into());
    }
    let text = std::fs::read(dir.join(name)).map_err(|e| e.to_string())?;
    serde_json::from_slice(&text).map_err(|e| format!("{name}: {e}"))
}

/// Load a scan from any path (for `--baseline` and `diff`).
pub fn load_path(path: &Path) -> Result<ScanResult, String> {
    let meta = std::fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if meta.len() > 64 * 1024 * 1024 {
        return Err(format!("{}: file is too large to be a scan", path.display()));
    }
    let text = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_json::from_slice(&text).map_err(|e| format!("{}: not a valid iotscan result: {e}", path.display()))
}

/// The most recent saved scan.
pub fn latest(dir: &Path) -> Option<(String, ScanResult)> {
    names(dir).into_iter().rev().find_map(|n| load(dir, &n).ok().map(|r| (n, r)))
}

/// List saved scans, newest first.
pub fn list(dir: &Path) -> Vec<Entry> {
    names(dir)
        .into_iter()
        .rev()
        .filter_map(|n| {
            let r = load(dir, &n).ok()?;
            Some(Entry {
                started: r.started.clone(),
                devices: r.devices.len(),
                findings: r.devices.iter().map(|d| d.active_findings().count()).sum(),
                name: n,
            })
        })
        .collect()
}

/// Default history directory.
pub fn default_dir() -> Option<PathBuf> {
    crate::paths::history_dir()
}

/// The `n` most recent saved scans, newest first.
pub fn recent(dir: &Path, n: usize) -> Vec<(String, ScanResult)> {
    names(dir).into_iter().rev().filter_map(|name| load(dir, &name).ok().map(|r| (name, r))).take(n).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{SCHEMA_VERSION, ScanSummary, Stats};

    fn result() -> ScanResult {
        ScanResult {
            schema_version: SCHEMA_VERSION,
            tool_version: "t".into(),
            started: "2026-10-24T00:00:00Z".into(),
            finished: "2026-10-24T00:00:01Z".into(),
            summary: ScanSummary::default(),
            devices: vec![],
            warnings: vec![],
            stats: Stats::default(),
        }
    }

    #[test]
    fn save_load_list_latest() {
        let dir = tempfile::tempdir().unwrap();
        let n1 = save(dir.path(), &result()).unwrap();
        let n2 = save(dir.path(), &result()).unwrap();
        assert_ne!(n1, n2, "same-second saves must not collide");
        assert!(valid_name(&n1));
        assert_eq!(list(dir.path()).len(), 2);
        assert_eq!(latest(dir.path()).unwrap().0, n2.clone().max(n1.clone()));
        assert_eq!(load(dir.path(), &n1).unwrap().tool_version, "t");
    }

    #[test]
    fn files_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("h");
        let n = save(&sub, &result()).unwrap();
        assert_eq!(std::fs::metadata(sub.join(&n)).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::metadata(&sub).unwrap().permissions().mode() & 0o777, 0o700);
    }

    #[test]
    fn rejects_path_traversal() {
        let dir = tempfile::tempdir().unwrap();
        for bad in ["../etc/passwd", "scan-../../x.json", "/etc/passwd", "scan-1.json/../x", "scan-.json.bak", "x.json"] {
            assert!(!valid_name(bad), "{bad}");
            assert!(load(dir.path(), bad).is_err());
        }
        assert!(valid_name("scan-20261024T031500Z.json"));
        assert!(valid_name("scan-20261024T031500Z-2.json"));
    }

    #[test]
    fn prunes_old_scans() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..(KEEP + 5) {
            std::fs::write(dir.path().join(format!("scan-20200101T0000{:02}Z-{i}.json", i % 60)), serde_json::to_vec(&result()).unwrap())
                .unwrap();
        }
        prune(dir.path());
        assert_eq!(names(dir.path()).len(), KEEP);
    }

    #[test]
    fn corrupt_files_are_skipped() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("scan-20200101T000000Z.json"), b"{ not json").unwrap();
        assert!(latest(dir.path()).is_none());
        assert!(list(dir.path()).is_empty());
    }

    #[test]
    fn load_path_checks() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("x.json");
        std::fs::write(&f, b"[]").unwrap();
        assert!(load_path(&f).is_err());
        assert!(load_path(&dir.path().join("missing.json")).is_err());
    }
}
