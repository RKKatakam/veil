//! Benchmarks (all `#[ignore]`d; run with `--ignored --nocapture`, best with
//! `--release`).
//!
//! One test binary for several suites, to save linking time and disk: each
//! module was its own binary before (`tests/<module>.rs`, or a directory
//! with a `main.rs`), and is unchanged apart from where its shared support
//! module comes from. No test changes process-wide state (environment,
//! umask, current directory, signal handlers), so the suites can share a
//! process; `cargo nextest` runs every test in its own process anyway.

#[path = "../sftp_support/mod.rs"]
mod sftp_support;

mod sftp_bench;
mod storage_bench;
mod tree_bench;
