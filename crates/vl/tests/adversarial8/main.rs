//! Round-8 adversarial tests (Opus) through the real `vl` binary, against
//! persistent and sparse `vl ws exec` sandboxes, the FUSE mount (`vl ws
//! mount`) and the synced team vault (`vl secret --scope`, `vl run`).
//!
//! Every `#[ignore = "BUG-NNN: …"]` test asserts the secure (or correct)
//! behaviour and currently fails; see `docs/BUGS.md` ("Round 8 findings").
//! The tests without `ignore` are controls.

#[path = "../adversarial_support/mod.rs"]
mod adversarial_support;

mod common;
pub use common::*;

mod mount;
mod sandbox;
mod vault;
