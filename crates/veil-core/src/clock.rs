//! The engine's wall clock, which an embedder can replace.
//!
//! Every timestamp the engine records (snapshots, operations, key-ring
//! changes, embargo releases, vault backups, lock leases) comes from
//! [`now_millis`]. By default that is the system clock. A program can
//! install its own with [`set_clock`]: a browser embedding passes
//! `Date.now()`, a test a fixed or simulated time, and later a trusted
//! time source (see docs/HUB.md §8.2).
//!
//! On `wasm32-unknown-unknown` there is no system clock
//! (`SystemTime::now()` panics there), so until a clock is installed the
//! time stands still at 0 (the Unix epoch). That is fail-safe rather than
//! convenient: nothing that waits for time to pass (embargo deadlines, gc
//! grace periods, lock leases, vault backup expiry) ever happens early.
//! Embedders should install a clock before they record anything.

use std::{
    sync::{Arc, RwLock},
    time::Duration,
};

/// A source of wall-clock time.
pub trait Clock: Send + Sync {
    /// Milliseconds since the Unix epoch.
    fn now_millis(&self) -> i64;
}

impl<F: Fn() -> i64 + Send + Sync> Clock for F {
    fn now_millis(&self) -> i64 {
        self()
    }
}

/// The system clock. Only available where the platform has one.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_millis(&self) -> i64 {
        system_millis().unwrap_or(0)
    }
}

/// Milliseconds since the Unix epoch by the system clock, or `None` where
/// there is none.
fn system_millis() -> Option<i64> {
    if cfg!(all(target_family = "wasm", target_os = "unknown")) {
        return None;
    }
    Some(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0),
    )
}

static INSTALLED: RwLock<Option<Arc<dyn Clock>>> = RwLock::new(None);

/// Install `clock` as the engine's clock for the whole process (replacing
/// any earlier one).
pub fn set_clock(clock: Arc<dyn Clock>) {
    *INSTALLED.write().unwrap_or_else(|e| e.into_inner()) = Some(clock);
}

/// Go back to the default clock (the system clock, where there is one).
pub fn reset_clock() {
    *INSTALLED.write().unwrap_or_else(|e| e.into_inner()) = None;
}

/// Is a clock installed with [`set_clock`]?
pub fn clock_installed() -> bool {
    INSTALLED.read().unwrap_or_else(|e| e.into_inner()).is_some()
}

/// Current wall-clock time in milliseconds since the Unix epoch, by the
/// installed clock, else the system clock, else 0 (see the module
/// documentation).
pub fn now_millis() -> i64 {
    if let Some(c) = INSTALLED.read().unwrap_or_else(|e| e.into_inner()).as_ref() {
        return c.now_millis();
    }
    system_millis().unwrap_or(0)
}

/// Monotonic time since an arbitrary origin, for timeouts and caches on
/// this machine: `std::time::Instant` with the `os` feature. Without it
/// (`Instant::now()` panics on `wasm32-unknown-unknown`), the wall clock
/// is used instead, made non-decreasing.
pub fn monotonic() -> Duration {
    #[cfg(feature = "os")]
    {
        static ORIGIN: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
        ORIGIN.get_or_init(std::time::Instant::now).elapsed()
    }
    #[cfg(not(feature = "os"))]
    {
        use std::sync::atomic::{AtomicI64, Ordering};
        static LAST: AtomicI64 = AtomicI64::new(0);
        let now = now_millis().max(0);
        let seen = LAST.fetch_max(now, Ordering::Relaxed).max(now);
        Duration::from_millis(seen as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closures_are_clocks() {
        let c = || 42i64;
        assert_eq!(Clock::now_millis(&c), 42);
    }

    #[test]
    fn system_clock_is_after_2020() {
        assert!(SystemClock.now_millis() > 1_577_836_800_000);
    }

    #[test]
    fn monotonic_never_goes_back() {
        let a = monotonic();
        let b = monotonic();
        assert!(b >= a);
    }
}
