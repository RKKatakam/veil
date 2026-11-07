//! The Veil server's permission model and wire protocol, as pure functions
//! (no I/O, so they build for WASM and the server and `vl` share them).
//!
//! * [`access`]: the access lines of `.veilpolicy` (`billing/  finance`,
//!   `src/  public`), the last matching line deciding, and a viewer's
//!   read and write decisions ([`access::View`]).
//! * [`project`]: the per-viewer projection of trees (entries a viewer may
//!   not read are left out, names included), and the graft that turns a
//!   pushed tree back into the full tree (`docs/HUB.md` §4.6, §5.4).
//! * [`wire`]: the JSON messages and the object frames of the protocol
//!   (`docs/HUB.md` §4).
//! * [`encoding`]: objects compressed (zstd) for storage and transport,
//!   ids unchanged (`docs/HUB.md` §13.13).
//!
//! The server is the authority (`docs/VISIBILITY.md`): it decides from its
//! own records and the accepted policy, never from labels in a snapshot.

pub mod access;
pub mod encoding;
pub mod project;
pub mod wire;
