//! The library examples in docs/guide/workspaces-and-agents.md, compiled
//! and run. Keep the two in step: the guide quotes the bodies of these
//! functions.

use std::sync::Arc;

use veil_core::{Identity, MemoryBackend, Repo, StorageBackend, VPath};

#[test]
fn in_memory_agent_workspace() -> veil_core::Result<()> {
    // --- guide: in-memory ---
    let backend = Arc::new(MemoryBackend::new());
    let mut repo = Repo::init(backend, Some(Identity::generate("agent")), "agent")?;
    let base = repo.root_id();

    let ws = repo.ephemeral_workspace(base)?; // O(1): an overlay over a tree view
    ws.write("src/lib.rs", "pub fn hello() {}")?;
    let (snapshot, report) = repo.commit_ephemeral(&ws, "agent: add hello")?;
    drop(ws); // the overlay vanishes; the snapshot stays
    assert!(report.quarantined.is_empty());

    // Read the result back without a checkout.
    let view = repo.tree_view(&snapshot)?;
    assert_eq!(view.read(&VPath::new("src/lib.rs")?)?, b"pub fn hello() {}");
    // --- end ---

    // Secrets are refused there too: the builder is the same.
    let ws = repo.ephemeral_workspace(snapshot)?;
    ws.write("config.js", "key = \"AKIAIOSFODNN7EXAMPLE\"")?;
    ws.write(".env", "TOKEN=abc")?;
    let (s2, report) = repo.commit_ephemeral(&ws, "agent: config")?;
    assert_eq!(report.quarantined.len(), 1, "{report:?}");
    let view = repo.tree_view(&s2)?;
    assert!(!view.exists(&VPath::new("config.js")?)?);
    assert!(!view.exists(&VPath::new(".env")?)?);
    Ok(())
}

#[test]
fn agent_workspace_in_an_on_disk_repository() -> veil_core::Result<()> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path();
    Repo::init(Arc::new(veil_core::DiskBackend::new(path)), Some(Identity::generate("alice")), "alice")?;
    let identity = Identity::generate("agent");

    // --- guide: on-disk ---
    let mut repo = Repo::open(Arc::new(veil_core::DiskBackend::new(path)), Some(identity), "agent")?;
    let base = repo.root_id(); // or any revision: veil_core::revset::resolve(&repo, "main", "default")?
    let ws = repo.ephemeral_workspace(base)?;
    ws.write("NOTES.md", "written by an agent\n")?;
    let (snapshot, _) = repo.commit_ephemeral(&ws, "agent: notes")?;
    repo.set_tag("agent-result", snapshot, false)?;
    // --- end ---

    assert_eq!(veil_core::revset::resolve(&repo, "agent-result", "default")?, snapshot);
    Ok(())
}
