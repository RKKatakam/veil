//! Helpers shared by the round-9 modules.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

use veil_core::{cache::LruCache, pack, StorageBackend, VPath};

use crate::adversarial_support::{text, Env};

pub const U: &str = "alice";

/// The change id of `rev` (`vl log --json`).
pub fn change_id(env: &Env, user: &str, proj: &Path, rev: &str) -> String {
    let out = env.stdout(user, proj, &["log", "--json", "-r", rev]);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    v["entries"][0]["change_id"].as_str().unwrap().to_string()
}

/// Fails, returning stdout + stderr.
pub fn fails(env: &Env, user: &str, cwd: &Path, args: &[&str]) -> String {
    let out = env.vl(user, cwd, args);
    assert!(!out.status.success(), "vl {args:?} succeeded:\n{}", text(&out));
    text(&out)
}

/// A directory for marker files, outside every project.
pub fn markers(env: &Env) -> PathBuf {
    env.dir("markers")
}

/// Every place `needle` occurs in the repository at `dir`: raw file bytes
/// and the decoded bytes of every packed object (packs are compressed).
pub fn repo_contains(dir: &Path, needle: &[u8]) -> Vec<String> {
    if !dir.exists() {
        return vec![];
    }
    let backend = veil_core::DiskBackend::new(dir);
    let has = |data: &[u8]| data.windows(needle.len()).any(|w| w == needle);
    let mut hits: Vec<String> = veil_core::vfs::walk_files(&backend, &VPath::root(), &|_| false)
        .unwrap()
        .into_iter()
        .filter(|f| has(&backend.read(f).unwrap()))
        .map(|f| f.to_string())
        .collect();
    let pdir = VPath::new(".veil/objects/pack").unwrap();
    if let Ok(entries) = backend.list_dir(&pdir) {
        let bases = LruCache::new(64 << 20);
        for e in entries {
            let Some(name) = pack::name_from_index_file(&e.name) else { continue };
            let p = pack::Pack::open(&backend, &pdir, name).unwrap();
            for id in p.index().ids() {
                let raw = p.get(&backend, id, &bases).unwrap().expect("indexed");
                if has(&raw) {
                    hits.push(format!("{}#{}", e.name, id.short()));
                }
            }
        }
    }
    hits
}

/// `vl ws write WS PATH` with `content` on stdin.
pub fn ws_write(env: &Env, proj: &Path, ws: &str, path: &str, content: &str) {
    use std::io::Write;
    let mut c = env.cmd(U, proj, &["ws", "write", ws, path]);
    c.stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
    let mut child = c.spawn().unwrap();
    child.stdin.take().unwrap().write_all(content.as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "ws write: {}", String::from_utf8_lossy(&out.stderr));
}
