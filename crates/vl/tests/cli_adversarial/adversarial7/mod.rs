//! Round-7 adversarial tests (Opus) through the real `vl` binary, against
//! the local-tooling features: `vl serve --local`.
//!
//! Every `#[ignore = "BUG-NNN: …"]` test asserts the secure (or correct)
//! behaviour and currently fails; see `docs/BUGS.md` ("Round 7 findings").
//! The tests without `ignore` are controls: the same flow through a route
//! that works, so a failure of the ignored test is the bug and not the
//! setup.

use crate::adversarial_support;

mod serve;

pub const U: &str = "alice";
