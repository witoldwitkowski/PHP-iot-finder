//! XDG-style config and data directories.

use std::path::PathBuf;
use std::sync::OnceLock;

static HOME_OVERRIDE: OnceLock<PathBuf> = OnceLock::new();

/// Use this home directory instead of `$HOME` (set after dropping root).
pub fn set_home_override(p: PathBuf) {
    let _ = HOME_OVERRIDE.set(p);
}

fn home() -> Option<PathBuf> {
    if let Some(h) = HOME_OVERRIDE.get() {
        return Some(h.clone());
    }
    std::env::var_os("HOME").filter(|h| !h.is_empty()).map(PathBuf::from)
}

fn xdg(var: &str, fallback: &str) -> Option<PathBuf> {
    if HOME_OVERRIDE.get().is_some() {
        return home().map(|h| h.join(fallback));
    }
    match std::env::var_os(var).filter(|v| !v.is_empty()).map(PathBuf::from) {
        Some(p) if p.is_absolute() => Some(p),
        _ => home().map(|h| h.join(fallback)),
    }
}

/// `$XDG_CONFIG_HOME/iotscan` (default `~/.config/iotscan`).
pub fn config_dir() -> Option<PathBuf> {
    xdg("XDG_CONFIG_HOME", ".config").map(|p| p.join("iotscan"))
}

/// `$XDG_DATA_HOME/iotscan` (default `~/.local/share/iotscan`).
pub fn data_dir() -> Option<PathBuf> {
    xdg("XDG_DATA_HOME", ".local/share").map(|p| p.join("iotscan"))
}

/// Scan history directory.
pub fn history_dir() -> Option<PathBuf> {
    data_dir().map(|p| p.join("history"))
}
