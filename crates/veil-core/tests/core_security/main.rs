//! Confidentiality and keys: visibility, embargoes, audiences, access, the team
//! vault, hostile objects and remotes, the secret scanner.
//!
//! One test binary for several suites, to save linking time and disk: each
//! module was its own binary before (`tests/<module>.rs`, or a directory
//! with a `main.rs`), and is unchanged apart from where its shared support
//! module comes from. No test changes process-wide state (environment,
//! umask, current directory, signal handlers), so the suites can share a
//! process; `cargo nextest` runs every test in its own process anyway.
//!
//! `adversarial7_core::pack` installs a counting global allocator, so every
//! suite here allocates through it. It only keeps per-thread counters, which
//! no other test reads.

#[path = "../adversarial_support/mod.rs"]
mod adversarial_support;

mod access;
mod adversarial2_embargo;
mod adversarial2_scanner;
mod adversarial2_visibility;
mod adversarial4_crypto;
mod adversarial5_scanner;
mod adversarial5_visibility;
mod adversarial6_visibility;
mod adversarial7_core;
mod adversarial8_core;
mod adversarial_confidentiality;
mod adversarial_remote;
mod audiences;
mod hostile_objects;
mod hostile_policy_dir;
mod injected_binary;
mod ring_shares;
mod round4_keys;
mod scanner;
mod scanner_upgrade;
mod team_vault;
mod visibility;
