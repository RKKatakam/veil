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
//! | Features | [`workspace`], [`commands`], [`embargo`], [`remote`], [`vault`], [`upgrade`] | workspaces, cloaking, embargoes, sync, secrets vault, format migrations |
//!
//! Nothing in the engine touches `std::fs` directly except `vfs::DiskBackend`:
//! every repository, working copy and remote is just a `StorageBackend`, so the
//! whole engine runs unchanged in memory, over overlays, or inside a sandbox.
//!
//! ## Features
//!
//! | Feature | Default | What it adds |
//! |---------|---------|--------------|
//! | `os` | yes | `DiskBackend`, `SftpBackend`, process checks and a heartbeat thread in the [`lock`], worker threads, the system clock |
//! | `zstd` | yes | the zstd C library: compressed and delta pack entries |
//! | `git` | yes | two-way Git interop (`git`, needs `os`) |
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

pub mod builder;
pub mod cache;
pub mod checkout;
pub mod clock;
pub mod commands;
pub mod conflict;
pub mod crypto;
pub mod embargo;
pub mod error;
pub mod fsck;
pub mod gc;
pub mod hunks;
#[cfg(feature = "git")]
pub mod git;
pub mod id;
pub mod identity;
pub mod keychain;
pub mod lock;
pub mod merge;
pub mod object;
pub mod oplog;
pub mod pack;
pub mod policy;
pub mod push_plan;
pub mod remote;
pub mod repo;
pub mod revset;
pub mod secrets;
pub mod selection;
pub mod statcache;
pub mod store;
pub mod transaction;
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
