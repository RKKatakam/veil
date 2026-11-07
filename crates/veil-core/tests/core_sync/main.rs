//! Repository-to-repository sync (the engine's in-process transfer),
//! repository locks across hosts, and storage efficiency.
//!
//! One test binary for several suites, to save linking time and disk: each
//! module was its own binary before (`tests/<module>.rs`, or a directory
//! with a `main.rs`), and is unchanged apart from where its shared support
//! module comes from. No test changes process-wide state (environment,
//! umask, current directory, signal handlers), so the suites can share a
//! process; `cargo nextest` runs every test in its own process anyway.

#[path = "../adversarial_support/mod.rs"]
mod adversarial_support;

mod leak_helper;
mod push_releases;
mod remote_init_race;
mod remote_lock;
mod storage;
mod sync_repair;
mod thin;
