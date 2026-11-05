//! Helpers shared by the round-8 modules.

#![allow(dead_code)]

use std::{
    io::Write,
    path::{Path, PathBuf},
    process::{Output, Stdio},
};

use super::adversarial_support::{text, Env};

pub const U: &str = "alice";

/// Write `content` to `path` in workspace `ws` (`vl ws write`, from stdin).
pub fn ws_write(env: &Env, proj: &Path, ws: &str, path: &str, content: &str) {
    let mut c = env.cmd(U, proj, &["ws", "write", ws, path]);
    c.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = c.spawn().unwrap();
    child.stdin.take().unwrap().write_all(content.as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "ws write: {}", String::from_utf8_lossy(&out.stderr));
}

/// Run `vl` as `user` with `stdin` fed in.
pub fn vl_stdin(env: &Env, user: &str, cwd: &Path, args: &[&str], stdin: &[u8]) -> Output {
    let mut c = env.cmd(user, cwd, args);
    c.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = c.spawn().unwrap();
    child.stdin.take().unwrap().write_all(stdin).unwrap();
    child.wait_with_output().unwrap()
}

/// Fails, returning stdout + stderr.
pub fn fails(env: &Env, user: &str, cwd: &Path, args: &[&str]) -> String {
    let out = env.vl(user, cwd, args);
    assert!(!out.status.success(), "vl {args:?} succeeded:\n{}", text(&out));
    text(&out)
}

/// `user`'s public key (`vl identity show`).
pub fn public_key(env: &Env, user: &str) -> String {
    let out = env.ok(user, &env.root, &["identity", "show"]);
    out.lines()
        .find(|l| l.starts_with("public key"))
        .unwrap()
        .split_whitespace()
        .last()
        .unwrap()
        .to_string()
}

/// The content of `path` in revision `rev` (`vl cat`), if it exists.
pub fn cat(env: &Env, user: &str, proj: &Path, rev: &str, path: &str) -> Option<String> {
    let out = env.vl(user, proj, &["cat", "-r", rev, path]);
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Every file under `dir` recursively (relative paths), symlinks not followed.
pub fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            match std::fs::symlink_metadata(&p) {
                Ok(m) if m.is_dir() => stack.push(p.clone()),
                _ => {}
            }
            out.push(p.strip_prefix(dir).unwrap().to_path_buf());
        }
    }
    out.sort();
    out
}

/// Does any file under `dir` (recursively, any depth, `.veil` included)
/// contain `needle`?
pub fn tree_contains(dir: &Path, needle: &[u8]) -> Vec<PathBuf> {
    walk(dir)
        .into_iter()
        .filter(|p| {
            let full = dir.join(p);
            std::fs::symlink_metadata(&full).is_ok_and(|m| m.is_file())
                && std::fs::read(&full).is_ok_and(|d| d.windows(needle.len()).any(|w| w == needle))
        })
        .collect()
}
