//! Round-7 adversarial tests (Opus) of the engine: first-class conflicts
//! (format 4) and the secret scanner (v6).
//!
//! Every `#[ignore = "BUG-NNN: …"]` test asserts the correct behaviour and
//! currently fails; see `docs/BUGS.md` ("Round 7 findings").

#[path = "../adversarial_support/mod.rs"]
mod adversarial_support;

mod conflicts;
mod scanner;
