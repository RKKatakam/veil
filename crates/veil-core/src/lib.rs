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
//! | Trees | [`tree`], [`builder`], [`checkout`], [`merge`], [`statcache`] | tree views, snapshotting, materialisation, 3-way merge, stat cache |
//! | Graph | [`oplog`], [`repo`], [`transaction`], [`revset`] | snapshot DAG, change ids, operation log, undo |
//! | Features | [`workspace`], [`sandbox`], [`commands`], [`embargo`], [`remote`], [`vault`], [`upgrade`] | workspaces, `ws exec` sandboxes, cloaking, embargoes, sync, secrets vault, format migrations |
//!
//! Nothing in the engine touches `std::fs` directly except the [`vfs`] layer
//! ([`vfs::DiskBackend`], and the host primitives of [`vfs::SandboxFs`]) and
//! [`sandbox`]'s directory housekeeping:
//! every repository, working copy and remote is just a `StorageBackend`, so the
//! whole engine runs unchanged in memory, over overlays, or inside a sandbox.
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
pub mod commands;
pub mod crypto;
pub mod embargo;
pub mod error;
pub mod fsck;
pub mod gc;
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
pub mod remote;
pub mod repo;
pub mod revset;
pub mod sandbox;
pub mod secrets;
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
pub use object::{EntryKind, Snapshot, Tree, TreeEntry, Visibility};
pub use repo::Repo;
pub use vfs::{DiskBackend, MemoryBackend, OverlayBackend, SftpBackend, SshUrl, StorageBackend};
pub use vpath::VPath;

/// Current wall-clock time in milliseconds since the Unix epoch.
pub fn now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
