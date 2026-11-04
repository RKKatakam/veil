//! Round-7 adversarial tests (Opus) of the engine: first-class conflicts
//! (format 4), the secret scanner (v6), and decompression bombs in packs
//! (BUG-490, from the round-7 fix wave; `pack` installs a counting global
//! allocator for this binary).
//!
//! Every `#[ignore = "BUG-NNN: …"]` test asserts the correct behaviour and
//! currently fails; see `docs/BUGS.md` ("Round 7 findings").

#[path = "../adversarial_support/mod.rs"]
mod adversarial_support;

mod conflicts;
mod pack;
mod scanner;
