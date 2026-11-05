//! Remotes: incremental push and pull, push plans, remote locks, SFTP and
//! storage efficiency.
//!
//! One test binary for several suites, to save linking time and disk: each
//! module was its own binary before (`tests/<module>.rs`, or a directory
//! with a `main.rs`), and is unchanged apart from where its shared support
//! module comes from. No test changes process-wide state (environment,
//! umask, current directory, signal handlers), so the suites can share a
//! process; `cargo nextest` runs every test in its own process anyway.

#[path = "../adversarial_support/mod.rs"]
mod adversarial_support;
#[path = "../sftp_support/mod.rs"]
mod sftp_support;

mod adversarial3_sftp;
mod leak_helper;
mod push_plan;
mod remote_init_race;
mod remote_lock;
mod sftp_backend;
mod sftp_sync;
mod storage;
mod sync_incremental;
