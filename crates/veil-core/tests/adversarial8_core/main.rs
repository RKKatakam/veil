//! Round-8 adversarial tests (Opus) against `veil-core`: the synced team
//! vault. Every `#[ignore = "BUG-NNN: …"]` test asserts the correct
//! behaviour and currently fails; see `docs/BUGS.md` ("Round 8 findings").

#[path = "../adversarial_support/mod.rs"]
mod adversarial_support;

mod vault;
