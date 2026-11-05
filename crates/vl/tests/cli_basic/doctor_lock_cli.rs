//! `vl doctor`'s lock checks: leftover takeover guards and sub-guards.

use crate::adversarial_support;

use std::sync::Arc;

use adversarial_support::*;
use veil_core::{
    lock::{RepoLock, STEAL_PATH},
    MemoryBackend, StorageBackend,
};

/// A guard file as a `vl` on this machine that has since exited would have
/// left it.
#[cfg(unix)]
fn dead_guard() -> String {
    let mem: Arc<dyn StorageBackend> = Arc::new(MemoryBackend::new());
    let me = {
        let _l = RepoLock::acquire(mem.clone()).unwrap();
        RepoLock::holder(&*mem).unwrap().unwrap()
    };
    let mut child = std::process::Command::new("true").spawn().unwrap();
    let pid = child.id();
    child.wait().unwrap();
    let mut v = serde_json::to_value(me).unwrap();
    v["pid"] = pid.into();
    v["token"] = "0123456789abcdef0123456789abcdef".into();
    v["lease_ms"] = 5000.into();
    v.to_string()
}

/// A crash mid-takeover can leave `.veil/lock.steal.<hash>` behind, which
/// no later takeover contends for. `vl fsck` reports it, `vl doctor`
/// removes it (it is provably stale) and says so; the next run is clean.
#[cfg(unix)]
#[test]
fn doctor_removes_stale_takeover_guards() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("a.txt", "a\n")]);
    let sub = proj.join(format!("{STEAL_PATH}.0123456789abcdef"));
    std::fs::write(&sub, dead_guard()).unwrap();
    std::fs::write(proj.join(STEAL_PATH), dead_guard()).unwrap();

    let fsck = text(&env.vl("alice", &proj, &["fsck", "--verbose"]));
    assert!(fsck.contains(".veil/lock.steal.0123456789abcdef present") && fsck.contains("stale"), "{fsck}");

    let out = text(&env.vl("alice", &proj, &["doctor"]));
    assert!(out.contains("removed 2 stale lock takeover guard(s)"), "{out}");
    assert!(!sub.exists() && !proj.join(STEAL_PATH).exists(), "{out}");
    assert!(!proj.join(".veil/lock").exists(), "{out}");
    let again = text(&env.vl("alice", &proj, &["doctor"]));
    assert!(!again.contains("lock.steal"), "{again}");
}

/// `vl doctor --remotes` lists the push uploads a remote holds unpublished
/// for more than a day, with their size; fresh ones are not listed.
#[test]
fn doctor_lists_old_push_staging_on_a_remote() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("a.txt", "a\n")]);
    let hub = env.dir("hub");
    env.ok("alice", &proj, &["remote", "add", "origin", hub.to_str().unwrap()]);
    env.ok("alice", &proj, &["push"]);
    let day = 24 * 3600 * 1000;
    let now = veil_core::now_millis();
    for (name, age) in [("old", 3 * day), ("new", 60_000)] {
        let dir = hub.join(format!(".veil/objects/incoming/push-{name}0000000000000000000000000000a"));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("touched"), (now - age).to_string()).unwrap();
        std::fs::write(dir.join("pack-x.pack"), vec![7u8; 4096]).unwrap();
    }
    let out = text(&env.vl("alice", &proj, &["doctor", "--remotes"]));
    assert!(out.contains("1 unpublished push upload(s)") && out.contains("push-old") && out.contains("3 days old"), "{out}");
    assert!(!out.contains("push-new"), "{out}");
}
