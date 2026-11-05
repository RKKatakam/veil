//! Everyday commands through the real `vl` binary: init, status, `--json`,
//! fsck, gc, upgrade, messages and exit codes.
//!
//! One test binary for several suites, to save linking time and disk: each
//! module was its own binary before (`tests/<module>.rs`, or a directory
//! with a `main.rs`), and is unchanged apart from where its shared support
//! module comes from. No test changes process-wide state (environment,
//! umask, current directory, signal handlers), so the suites can share a
//! process; `cargo nextest` runs every test in its own process anyway.

#[path = "../adversarial_support/mod.rs"]
mod adversarial_support;

mod cli;
mod cli_polish;
mod doctor_lock_cli;
mod fsck;
mod gc;
mod json_cli;
mod materialise_cli;
mod round4_messages_cli;
mod tiers_cli;
mod upgrade_cli;
mod version;
mod working_copy_cli;
