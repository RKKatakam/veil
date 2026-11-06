//! # veil-core
//!
//! The storage engine behind Veil (`vl`). The crate is layered bottom-up:
//!
//! | Layer | Modules | Responsibility |
//! |-------|---------|----------------|
//! | VFS | [`vfs`], [`vpath`] | `StorageBackend` trait + disk / memory / overlay backends |
//! | Crypto | [`crypto`], [`identity`], [`keychain`] | XChaCha20-Poly1305 envelopes, X25519 identity rings, scope keys |
//! | CAS | [`id`], [`object`], [`store`], [`pack`], [`gc`] | BLAKE3 content-addressed objects, sealed (encrypted) nodes, packfiles, garbage collection |
//! | Policy | [`policy`], [`secrets`] | per-path visibility tiers, engine-level secret detection |
//! | Trees | [`tree`], [`builder`], [`checkout`], [`merge`], [`conflict`], [`statcache`] | tree views, snapshotting, materialisation, 3-way merge, first-class conflicts, stat cache |
//! | Graph | [`oplog`], [`repo`], [`transaction`], [`revset`] | snapshot DAG, change ids, operation log, undo |
//! | Features | [`workspace`], [`sandbox`], [`commands`], [`embargo`], [`remote`], [`vault`], [`team_vault`], [`upgrade`] | workspaces, `ws exec` sandboxes, cloaking, embargoes, sync, local and team secret vaults, format migrations |
//!
//! Nothing in the engine touches `std::fs` directly except the [`vfs`] layer
//! (`vfs::DiskBackend`, and the host primitives of `vfs::SandboxFs`) and
//! `sandbox`'s directory housekeeping, all of them only with the `os`
//! feature:
//! every repository, working copy and remote is just a `StorageBackend`, so the
//! whole engine runs unchanged in memory, over overlays, or inside a sandbox.
//!
//! ## Features
//!
//! | Feature | Default | What it adds |
//! |---------|---------|--------------|
//! | `os` | yes | `DiskBackend`, `SftpBackend`, process checks and a heartbeat thread in the [`lock`], worker threads, the system clock |
//! | `zstd` | yes | the zstd C library: compressed and delta pack entries |
//! | `ruzstd` | no | a pure-Rust zstd decoder that reads every pack without the C library |
//! | `wasm` | no | `ruzstd` plus WebCrypto randomness: with `--no-default-features`, the engine for `wasm32-unknown-unknown` |
//!
//! Without `os` the engine runs over [`MemoryBackend`], [`OverlayBackend`]
//! or any `StorageBackend` the embedder provides, on the clock it installs
//! ([`clock::set_clock`]). See `examples/wasm_smoke.rs`.
//!
//! ```
//! # fn main() -> veil_core::Result<()> {
//! use std::sync::Arc;
//! use veil_core::{Identity, MemoryBackend, Repo};
//!
//! let backend = Arc::new(MemoryBackend::new());
//! let mut repo = Repo::init(backend, Some(Identity::generate("agent")), "agent")?;
//! let base = repo.root_id();
//!
//! let ws = repo.ephemeral_workspace(base)?; // O(1): overlay over a tree view
//! ws.write("src/lib.rs", "pub fn hello() {}")?;
//! let (snapshot, _report) = repo.commit_ephemeral(&ws, "agent: add hello")?;
//! drop(ws); // the workspace vanishes; the snapshot remains
//! assert_eq!(repo.snapshot(&snapshot)?.parents, vec![base]);
//! # Ok(()) }
//! ```

pub mod attributes;
pub mod bisect;
pub mod blame;
pub mod builder;
pub mod cache;
pub mod checkout;
pub mod clock;
pub mod commands;
pub mod confinement;
pub mod conflict;
pub mod crypto;
pub mod duplicate;
pub mod embargo;
pub mod error;
pub mod fsck;
pub mod gc;
pub mod graph_index;
pub mod hub;
pub mod hunks;
pub mod grep;
pub mod id;
pub mod identity;
pub mod keychain;
pub mod lock;
pub mod maintenance;
pub mod merge;
pub mod object;
pub mod oplog;
pub mod pack;
pub mod policy;
#[cfg(feature = "os")]
mod prefetch;
pub mod push_plan;
pub mod remote;
pub mod rename;
pub mod repo;
pub mod revset;
#[cfg(feature = "os")]
pub mod sandbox;
pub mod search;
pub mod secrets;
pub mod selection;
pub mod statcache;
pub mod store;
pub mod tag_object;
pub mod team_vault;
pub mod transaction;
pub mod textmerge;
pub mod tree;
pub mod upgrade;
pub mod vault;
pub mod vfs;
pub mod vpath;
pub mod wc_policy;
pub mod working_copy;
pub mod workspace;

pub use error::{Result, VeilError};
pub use id::{ChangeId, ObjectId};
pub use identity::Identity;
pub use object::{Conflict, ConflictTerm, EntryKind, Snapshot, Tree, TreeEntry, Visibility};
pub use repo::Repo;
pub use vfs::{MemoryBackend, OverlayBackend, SshUrl, StorageBackend};
#[cfg(feature = "os")]
pub use vfs::{DiskBackend, SftpBackend};
pub use vpath::VPath;

#[cfg(not(any(feature = "zstd", feature = "ruzstd")))]
compile_error!(
    "veil-core needs a zstd decoder to read packs: enable the `zstd` feature (the default) \
     or `ruzstd` (part of `wasm`)"
);

/// Current wall-clock time in milliseconds since the Unix epoch, by the
/// engine's clock (see [`clock`]: the system clock unless the embedder
/// installed another).
pub fn now_millis() -> i64 {
    clock::now_millis()
}
