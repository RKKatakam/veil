//! Conformance tests: history, diff, merge and rewriting.
//!
//! Scenarios translated from Git's test suite (t4xxx diff and log, t6xxx
//! revision walking and merging, t34xx rebase) and from Jujutsu's CLI and
//! library tests (rebase, squash, abandon, diff, log, evolog, revsets,
//! conflicts, rewrite). Each test names its source in a one-line comment.
//! The coverage map is `docs/conformance/history.md`.
//!
//! Tests marked `#[ignore = "BUG-NNN: …"]` assert the correct behaviour and
//! currently fail; see `docs/BUGS.md` ("Conformance findings: history, diff,
//! merge and rewriting").

mod support;

mod diff;
mod log;
mod merge;
mod revisions;
mod rewrite;
mod veil_angles;
