//! Round-7 adversarial tests (Opus) of the engine: first-class conflicts
//! (format 4), the secret scanner (v6), and decompression bombs in packs
//! (BUG-490, from the round-7 fix wave; `pack` installs a counting global
//! allocator for the whole `core_security` binary: it counts per thread, so
//! the other suites there do not disturb its measurements).
//!
//! Every `#[ignore = "BUG-NNN: …"]` test asserts the correct behaviour and
//! currently fails; see `docs/BUGS.md` ("Round 7 findings").

use crate::adversarial_support;

mod conflicts;
mod pack;
mod scanner;
