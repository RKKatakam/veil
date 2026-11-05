//! Durability: the repository lock, crash injection and the durability barrier.
//!
//! One test binary for several suites, to save linking time and disk: each
//! module was its own binary before (`tests/<module>.rs`, or a directory
//! with a `main.rs`), and is unchanged apart from where its shared support
//! module comes from. No test changes process-wide state (environment,
//! umask, current directory, signal handlers), so the suites can share a
//! process; `cargo nextest` runs every test in its own process anyway.

#[path = "../adversarial_support/mod.rs"]
mod adversarial_support;

mod adversarial2_durability;
mod adversarial5_durability;
mod adversarial6_lock;
mod adversarial_lock;
mod crash;
mod durability;
mod lock;
mod metadata_lock;
