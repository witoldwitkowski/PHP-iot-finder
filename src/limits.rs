//! Politeness controls: concurrency caps, a global rate limit and cancellation.
//!
//! Cheap IoT devices fall over easily, so every network operation the engine
//! performs first takes a [`Permit`] from a [`NetCtx`]. A permit enforces:
//!
//! * a global cap on in-flight operations,
//! * a per-host cap (default 2) so one device is never hammered,
//! * a global operations-per-second budget,
//! * cooperative cancellation.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;

/// Tunable limits for a scan.
#[derive(Clone, Debug)]
pub struct Limits {
    /// Maximum operations in flight across all hosts.
    pub global_concurrency: usize,
    /// Maximum operations in flight against a single host.
    pub per_host: usize,
    /// Maximum operations started per second (0 = unlimited).
    pub rate_per_sec: u32,
    /// TCP connect timeout.
    pub connect_timeout: Duration,
    /// Overall deadline for one request/response exchange.
    pub io_timeout: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            global_concurrency: 256,
            per_host: 2,
            rate_per_sec: 400,
            connect_timeout: Duration::from_millis(1200),
            io_timeout: Duration::from_secs(6),
        }
    }
}

impl Limits {
    /// Gentle-but-quicker preset for sturdy networks (`--fast`).
    pub fn fast() -> Limits {
        Limits {
            global_concurrency: 512,
            per_host: 8,
            rate_per_sec: 0,
            connect_timeout: Duration::from_millis(500),
            io_timeout: Duration::from_secs(4),
        }
    }
}

struct RateLimiter {
    interval: Duration,
    next: Mutex<Instant>,
}

impl RateLimiter {
    fn new(per_sec: u32) -> Option<RateLimiter> {
        if per_sec == 0 {
            return None;
        }
        Some(RateLimiter { interval: Duration::from_secs_f64(1.0 / per_sec as f64), next: Mutex::new(Instant::now()) })
    }

    async fn acquire(&self) {
        let slot = {
            let mut next = self.next.lock().unwrap_or_else(|e| e.into_inner());
            let now = Instant::now();
            let slot = (*next).max(now);
            *next = slot + self.interval;
            slot
        };
        tokio::time::sleep_until(slot).await;
    }
}

/// Shared network context handed to every scan task.
pub struct NetCtx {
    /// The limits in force.
    pub limits: Limits,
    global: Arc<Semaphore>,
    hosts: Mutex<HashMap<IpAddr, Arc<Semaphore>>>,
    rate: Option<RateLimiter>,
    cancel: Arc<AtomicBool>,
}

/// Held while one network operation is in flight; releases on drop.
pub struct Permit {
    _global: OwnedSemaphorePermit,
    _host: OwnedSemaphorePermit,
}

impl NetCtx {
    /// Build a context from limits and a cancellation flag.
    pub fn new(limits: Limits, cancel: Arc<AtomicBool>) -> NetCtx {
        NetCtx {
            global: Arc::new(Semaphore::new(limits.global_concurrency.max(1))),
            hosts: Mutex::new(HashMap::new()),
            rate: RateLimiter::new(limits.rate_per_sec),
            limits,
            cancel,
        }
    }

    /// True once the scan was cancelled.
    pub fn is_cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }

    /// Wait for permission to start one operation against `ip`.
    /// Returns `None` if the scan was cancelled.
    pub async fn permit(&self, ip: IpAddr) -> Option<Permit> {
        if self.is_cancelled() {
            return None;
        }
        let host_sem = {
            let mut map = self.hosts.lock().unwrap_or_else(|e| e.into_inner());
            map.entry(ip).or_insert_with(|| Arc::new(Semaphore::new(self.limits.per_host.max(1)))).clone()
        };
        // Take the per-host permit first so a busy host does not hold global slots idle.
        let host = host_sem.acquire_owned().await.ok()?;
        let global = self.global.clone().acquire_owned().await.ok()?;
        if let Some(r) = &self.rate {
            r.acquire().await;
        }
        if self.is_cancelled() {
            return None;
        }
        Some(Permit { _global: global, _host: host })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    fn ctx(limits: Limits) -> Arc<NetCtx> {
        Arc::new(NetCtx::new(limits, Arc::new(AtomicBool::new(false))))
    }

    #[tokio::test]
    async fn per_host_cap_is_enforced() {
        let c = ctx(Limits { per_host: 2, rate_per_sec: 0, global_concurrency: 100, ..Limits::default() });
        let current = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let mut tasks = vec![];
        for _ in 0..12 {
            let (c, current, peak) = (c.clone(), current.clone(), peak.clone());
            tasks.push(tokio::spawn(async move {
                let _p = c.permit(ip).await.unwrap();
                let n = current.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(n, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(15)).await;
                current.fetch_sub(1, Ordering::SeqCst);
            }));
        }
        for t in tasks {
            t.await.unwrap();
        }
        assert!(peak.load(Ordering::SeqCst) <= 2, "peak {}", peak.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn global_cap_is_enforced_across_hosts() {
        let c = ctx(Limits { per_host: 4, rate_per_sec: 0, global_concurrency: 3, ..Limits::default() });
        let current = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let mut tasks = vec![];
        for i in 0..20u8 {
            let (c, current, peak) = (c.clone(), current.clone(), peak.clone());
            let ip: IpAddr = format!("10.0.0.{}", i + 1).parse().unwrap();
            tasks.push(tokio::spawn(async move {
                let _p = c.permit(ip).await.unwrap();
                let n = current.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(n, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(10)).await;
                current.fetch_sub(1, Ordering::SeqCst);
            }));
        }
        for t in tasks {
            t.await.unwrap();
        }
        assert!(peak.load(Ordering::SeqCst) <= 3);
    }

    #[tokio::test]
    async fn rate_limit_spaces_operations() {
        let c = ctx(Limits { rate_per_sec: 100, per_host: 50, global_concurrency: 50, ..Limits::default() });
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let start = std::time::Instant::now();
        for _ in 0..11 {
            let _p = c.permit(ip).await.unwrap();
        }
        // 11 operations at 100/s need at least ~100ms.
        assert!(start.elapsed() >= Duration::from_millis(90), "{:?}", start.elapsed());
    }

    #[tokio::test]
    async fn cancellation_stops_permits() {
        let cancel = Arc::new(AtomicBool::new(false));
        let c = NetCtx::new(Limits::default(), cancel.clone());
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(c.permit(ip).await.is_some());
        cancel.store(true, Ordering::Relaxed);
        assert!(c.permit(ip).await.is_none());
    }
}
