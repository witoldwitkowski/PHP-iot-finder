//! Thread-safe scan progress shared between the engine, the CLI and the GUI.

use crate::model::Device;
use serde::Serialize;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Maximum retained log lines.
const MAX_LOG: usize = 400;

/// Live progress of a running scan.
pub struct Progress {
    phase: Mutex<String>,
    done: AtomicUsize,
    total: AtomicUsize,
    log: Mutex<Vec<String>>,
    live: Mutex<Vec<Device>>,
    cancel: Arc<AtomicBool>,
    echo: bool,
    started: Instant,
}

/// A point-in-time copy for the GUI/API.
#[derive(Clone, Debug, Serialize)]
pub struct Snapshot {
    /// Current phase name.
    pub phase: String,
    /// Units done in this phase.
    pub done: usize,
    /// Units expected in this phase (0 = unknown).
    pub total: usize,
    /// Most recent log lines.
    pub log: Vec<String>,
    /// Devices found so far.
    pub devices_found: usize,
    /// Seconds since the scan started.
    pub elapsed_secs: f64,
    /// Whether cancellation was requested.
    pub cancelling: bool,
}

impl Progress {
    /// Create. When `echo` is true, phases and log lines are printed to stderr.
    pub fn new(echo: bool) -> Arc<Progress> {
        Arc::new(Progress {
            phase: Mutex::new(String::from("Starting")),
            done: AtomicUsize::new(0),
            total: AtomicUsize::new(0),
            log: Mutex::new(Vec::new()),
            live: Mutex::new(Vec::new()),
            cancel: Arc::new(AtomicBool::new(false)),
            echo,
            started: Instant::now(),
        })
    }

    /// The shared cancellation flag.
    pub fn cancel_flag(&self) -> Arc<AtomicBool> {
        self.cancel.clone()
    }

    /// Request cancellation.
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }

    /// Whether cancellation was requested.
    pub fn is_cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }

    /// Begin a phase with an expected number of work units (0 = unknown).
    pub fn phase(&self, name: &str, total: usize) {
        *self.phase.lock().unwrap_or_else(|e| e.into_inner()) = name.to_string();
        self.done.store(0, Ordering::Relaxed);
        self.total.store(total, Ordering::Relaxed);
        self.log(format!("{name}…"));
    }

    /// Record one finished work unit.
    pub fn tick(&self) {
        self.done.fetch_add(1, Ordering::Relaxed);
    }

    /// Append a log line.
    pub fn log(&self, line: impl Into<String>) {
        let line = line.into();
        if self.echo {
            eprintln!("  {line}");
        }
        let mut l = self.log.lock().unwrap_or_else(|e| e.into_inner());
        l.push(line);
        if l.len() > MAX_LOG {
            let drop = l.len() - MAX_LOG;
            l.drain(..drop);
        }
    }

    /// Publish the devices found so far (for live GUI updates).
    pub fn set_live(&self, devices: Vec<Device>) {
        *self.live.lock().unwrap_or_else(|e| e.into_inner()) = devices;
    }

    /// The devices found so far.
    pub fn live(&self) -> Vec<Device> {
        self.live.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Copy the current state.
    pub fn snapshot(&self) -> Snapshot {
        let log = self.log.lock().unwrap_or_else(|e| e.into_inner());
        Snapshot {
            phase: self.phase.lock().unwrap_or_else(|e| e.into_inner()).clone(),
            done: self.done.load(Ordering::Relaxed),
            total: self.total.load(Ordering::Relaxed),
            log: log.iter().rev().take(12).rev().cloned().collect(),
            devices_found: self.live.lock().unwrap_or_else(|e| e.into_inner()).len(),
            elapsed_secs: self.started.elapsed().as_secs_f64(),
            cancelling: self.is_cancelled(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracks_phases_and_log() {
        let p = Progress::new(false);
        p.phase("Sweeping", 10);
        p.tick();
        p.tick();
        p.log("hello");
        let s = p.snapshot();
        assert_eq!((s.phase.as_str(), s.done, s.total), ("Sweeping", 2, 10));
        assert!(s.log.contains(&"hello".to_string()));
        p.phase("Next", 0);
        assert_eq!(p.snapshot().done, 0);
    }

    #[test]
    fn log_is_bounded() {
        let p = Progress::new(false);
        for i in 0..2000 {
            p.log(format!("line {i}"));
        }
        assert!(p.log.lock().unwrap().len() <= MAX_LOG);
        assert_eq!(p.snapshot().log.last().unwrap(), "line 1999");
    }

    #[test]
    fn cancel_flag_is_shared() {
        let p = Progress::new(false);
        let f = p.cancel_flag();
        assert!(!p.is_cancelled());
        p.cancel();
        assert!(f.load(Ordering::Relaxed));
        assert!(p.snapshot().cancelling);
    }
}
