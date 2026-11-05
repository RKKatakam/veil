//! Policy, scopes, embargoes, identities and the team vault through the real
//! `vl` binary.
//!
//! One test binary for several suites, to save linking time and disk: each
//! module was its own binary before (`tests/<module>.rs`, or a directory
//! with a `main.rs`), and is unchanged apart from where its shared support
//! module comes from. No test changes process-wide state (environment,
//! umask, current directory, signal handlers), so the suites can share a
//! process; `cargo nextest` runs every test in its own process anyway.

#[path = "../adversarial_support/mod.rs"]
mod adversarial_support;

mod access_cli;
mod artefacts_cli;
mod cloaked_work_cli;
mod embargo_copy_cli;
mod embargo_release_cli;
mod hostile_cli;
mod identity_cli;
mod policy_cli;
mod policy_round4_cli;
mod policy_routes_cli;
mod team_vault_cli;
