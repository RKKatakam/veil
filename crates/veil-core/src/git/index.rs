//! The `.git/index` of colocated mode, with skip-worktree bits.
//!
//! Colocated Git mode (feature 9; `docs/design/git-parity/9-colocated-git.md`)
//! writes the index Git uses as its staging area: the public projection of
//! `HEAD`'s commit, with **skip-worktree** set on every path whose
//! working-copy content may differ from what Git shows (and on every path
//! in frozen mode). Git then never reads those files from the disk:
//! `git status` and `git diff` show nothing, and `git add -A`,
//! `git commit -a` and `git stash` leave them alone.
//!
//! Encoding and decoding are `gix-index`'s (index versions 2 to 4, split
//! indexes, sparse directory entries): nothing here parses the format by
//! hand. What this module adds is the locking rule of the design:
//!
//! * the new index is written to `index.lock`, created **exclusively**
//!   (`O_CREAT | O_EXCL`), and renamed over `index`;
//! * if `index.lock` already exists, Git (or another tool) is using the
//!   index: nothing is written and [`write`] says so. Veil never waits for
//!   it and never removes it;
//! * the stat data of an entry whose content is unchanged is carried over
//!   from the old index, so `git status` does not rehash the whole tree.

use std::{
    collections::HashMap,
    io::Write,
    path::{Path, PathBuf},
};

use gix::index as gi;

use super::{gerr, map::GitOid};
use crate::error::{Result, VeilError};

/// One entry of the index as Veil reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexEntry {
    /// Repository-relative, `/`-separated, as Git stores it (bytes: Git
    /// paths need not be UTF-8).
    pub path: Vec<u8>,
    /// The tree entry mode bits (`0o100644`, `0o100755`, `0o120000`,
    /// `0o160000`; `0o040000` for a sparse directory entry).
    pub mode: u32,
    pub oid: GitOid,
    /// Merge stage (0 = normal; 1–3 during a conflicted merge).
    pub stage: u8,
    pub skip_worktree: bool,
    /// `git add --intent-to-add`.
    pub intent_to_add: bool,
}

/// One entry for [`write`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewEntry {
    pub path: Vec<u8>,
    pub mode: u32,
    pub oid: GitOid,
    pub skip_worktree: bool,
}

fn io(path: &Path) -> impl FnOnce(std::io::Error) -> VeilError + '_ {
    move |source| VeilError::Io {
        path: path.display().to_string(),
        source,
    }
}

/// The index file Git uses for `git_dir`. `$GIT_INDEX_FILE` is honoured
/// only when the caller asks for it ([`read_staged`]).
pub fn index_path(git_dir: &Path) -> PathBuf {
    git_dir.join("index")
}

/// Is the index locked (`index.lock` exists): is Git, or another tool,
/// writing it right now?
pub fn is_locked(git_dir: &Path) -> bool {
    std::fs::symlink_metadata(git_dir.join("index.lock")).is_ok()
}

/// Decode the index at `path`. `Ok(None)`: there is none (a fresh
/// repository, or after `rm .git/index`).
pub fn read(path: &Path) -> Result<Option<Vec<IndexEntry>>> {
    let Some(state) = read_state(path)? else { return Ok(None) };
    let backing = state.path_backing();
    let out = state
        .entries()
        .iter()
        .map(|e| IndexEntry {
            path: e.path_in(backing).to_vec(),
            mode: e.mode.bits(),
            oid: e.id,
            stage: e.stage_raw() as u8,
            skip_worktree: e.flags.contains(gi::entry::Flags::SKIP_WORKTREE),
            intent_to_add: e.flags.contains(gi::entry::Flags::INTENT_TO_ADD),
        })
        .collect();
    Ok(Some(out))
}

fn read_state(path: &Path) -> Result<Option<gi::State>> {
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(io(path)(e)),
        // A symlinked index is not Git's: never followed.
        Ok(m) if !m.file_type().is_file() => {
            return Err(VeilError::repo(format!("{} is not a regular file", path.display())))
        }
        Ok(_) => {}
    }
    let options = gi::decode::Options {
        // An index is the user's own file, but a corrupt one must not make
        // Veil allocate without bound.
        alloc_limit_bytes: Some(1 << 30),
        ..Default::default()
    };
    let file = gi::File::at(path, gix::hash::Kind::Sha1, false, options).map_err(gerr)?;
    Ok(Some(file.into()))
}

/// Write `entries` as the index of `git_dir` (see the module docs).
/// `Ok(false)`: `index.lock` exists, nothing was written.
pub fn write(git_dir: &Path, entries: &[NewEntry]) -> Result<bool> {
    let lock = git_dir.join("index.lock");
    let index = index_path(git_dir);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o644).custom_flags(libc::O_NOFOLLOW);
    }
    let file = match opts.open(&lock) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => return Ok(false),
        Err(e) => return Err(io(&lock)(e)),
    };
    // From here the lock is ours: removed again on any failure.
    let written = (|| -> Result<()> {
        // Stat data of unchanged entries, so Git need not rehash them.
        let old: HashMap<(Vec<u8>, u32, GitOid), gi::entry::Stat> = match read_state(&index) {
            Ok(Some(st)) => {
                let backing = st.path_backing();
                st.entries()
                    .iter()
                    .filter(|e| e.stage_raw() == 0)
                    .map(|e| ((e.path_in(backing).to_vec(), e.mode.bits(), e.id), e.stat))
                    .collect()
            }
            _ => HashMap::new(),
        };
        let mut state = gi::State::new(gix::hash::Kind::Sha1);
        for e in entries {
            let mode = gi::entry::Mode::from_bits(e.mode)
                .ok_or_else(|| VeilError::repo(format!("git index: unsupported mode {:o}", e.mode)))?;
            let mut flags = gi::entry::Flags::empty();
            if e.skip_worktree {
                flags |= gi::entry::Flags::SKIP_WORKTREE | gi::entry::Flags::EXTENDED;
            }
            let stat = old.get(&(e.path.clone(), e.mode, e.oid)).copied().unwrap_or_default();
            state.dangerously_push_entry(stat, e.oid, flags, mode, e.path.as_slice().into());
        }
        state.sort_entries();
        let mut buf = Vec::with_capacity(64 + entries.len() * 96);
        let mut hasher = gix::hash::io::Write::new(&mut buf, gix::hash::Kind::Sha1);
        state
            .write_to(
                &mut hasher,
                gi::write::Options {
                    extensions: gi::write::Extensions::None,
                    skip_hash: false,
                },
            )
            .map_err(gerr)?;
        let digest = hasher.hash.try_finalize().map_err(gerr)?;
        buf.extend_from_slice(digest.as_slice());
        let mut f = file;
        f.write_all(&buf).map_err(io(&lock))?;
        f.sync_all().map_err(io(&lock))?;
        drop(f);
        std::fs::rename(&lock, &index).map_err(io(&index))?;
        Ok(())
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&lock);
    }
    written.map(|()| true)
}

/// The entries Git would commit now: the index `$GIT_INDEX_FILE` names
/// (Git sets it for hooks while `git commit -a` or `git commit <paths>`
/// builds a temporary one) when it lies inside `git_dir`, else the index.
pub fn read_staged(git_dir: &Path) -> Result<Option<Vec<IndexEntry>>> {
    let path = match std::env::var_os("GIT_INDEX_FILE") {
        Some(p) => {
            let p = PathBuf::from(p);
            let p = if p.is_absolute() {
                p
            } else {
                // Git gives it relative to the work tree it runs in.
                std::env::current_dir().map_err(|e| io(&p)(e))?.join(p)
            };
            let inside = match (p.parent().and_then(|d| d.canonicalize().ok()), git_dir.canonicalize().ok()) {
                (Some(d), Some(g)) => d.starts_with(&g),
                _ => false,
            };
            if !inside {
                return Err(VeilError::repo(format!(
                    "GIT_INDEX_FILE ({}) is outside the colocated Git directory; refusing to judge it",
                    p.display()
                )));
            }
            p
        }
        None => index_path(git_dir),
    };
    read(&path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn oid(n: u8) -> GitOid {
        GitOid::from_bytes_or_panic(&[n; 20])
    }

    #[test]
    fn round_trip_keeps_skip_worktree_and_sorts() {
        let dir = tempfile::tempdir().unwrap();
        let entries = vec![
            NewEntry { path: b"b/x".to_vec(), mode: 0o100644, oid: oid(1), skip_worktree: true },
            NewEntry { path: b"a".to_vec(), mode: 0o100755, oid: oid(2), skip_worktree: false },
            NewEntry { path: b"b-c".to_vec(), mode: 0o120000, oid: oid(3), skip_worktree: false },
        ];
        assert!(write(dir.path(), &entries).unwrap());
        let back = read(&index_path(dir.path())).unwrap().unwrap();
        let paths: Vec<&[u8]> = back.iter().map(|e| e.path.as_slice()).collect();
        // Git's order: byte order of the full path.
        assert_eq!(paths, vec![&b"a"[..], b"b-c", b"b/x"]);
        assert!(back[2].skip_worktree && !back[0].skip_worktree);
        assert_eq!(back[0].mode, 0o100755);
        assert!(!dir.path().join("index.lock").exists());
    }

    #[test]
    fn an_existing_lock_is_never_waited_for_nor_removed() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("index.lock"), b"git's").unwrap();
        let e = vec![NewEntry { path: b"a".to_vec(), mode: 0o100644, oid: oid(1), skip_worktree: true }];
        assert!(!write(dir.path(), &e).unwrap());
        assert_eq!(std::fs::read(dir.path().join("index.lock")).unwrap(), b"git's");
        assert!(!dir.path().join("index").exists());
        assert!(is_locked(dir.path()));
    }

    #[test]
    fn missing_index_reads_as_none_and_garbage_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read(&index_path(dir.path())).unwrap().is_none());
        std::fs::write(index_path(dir.path()), b"DIRC garbage").unwrap();
        assert!(read(&index_path(dir.path())).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_index_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink("/etc/passwd", index_path(dir.path())).unwrap();
        assert!(read(&index_path(dir.path())).is_err());
    }
}
