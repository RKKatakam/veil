//! Round-9 adversarial tests (Opus) of the Git-parity round: format 5
//! (atags, symlinks), `.veilhooks`, the history tools, symlinks,
//! attributes, duplicate and rename-aware merges, embargo confinement.
//!
//! Every `#[ignore = "BUG-NNN: …"]` test asserts the secure (or correct)
//! behaviour and fails today; see `docs/BUGS.md` ("Round 9 findings").
//! The tests without `ignore` are controls.

use crate::adversarial_support;

mod common;
pub use common::*;

mod attributes;
mod symlinks;
mod hooks;
mod tags;
