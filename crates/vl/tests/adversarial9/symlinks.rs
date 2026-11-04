//! Symlinks (design 6) in `vl ws exec` sandboxes.

use crate::{
    adversarial_support::{text, write, Env},
    U,
};

const SECRET: &str = "SESSION_SALT=isolated-7781";

/// BUG-708: threat 7's invariant is that a sandbox never materialises a
/// relative link that resolves outside it, so a command in `ws exec`
/// (without `--with-isolated`) cannot reach the project's isolated `.env`
/// through a tree's links. `SandboxFs::guard_link` checks each link
/// *lexically* (`vfs::link_escapes`), as if every component before a
/// `..` were a directory. A chain defeats it: `s1/s2/s3/s4/u -> ../../../..`
/// (the sandbox root: inside) and `s1/s2/s3/s4/x -> u/../../../../../.env`
/// (lexically `s1/s2/s3/s4/u` up five: the root's `.env`, inside), but the
/// kernel resolves `u` first, then climbs five levels above the sandbox
/// root: `.veil/local/sandboxes/agent/files/../../../../../.env` is the
/// project's `.env`. Both links come from a teammate's tree.
#[test]
#[ignore = "BUG-708: a chain of two lexically-inside links escapes the ws exec sandbox to the isolated .env"]
fn a_chain_of_links_never_reaches_the_projects_isolated_files() {
    let env = Env::new();
    let proj = env.dir("proj");
    env.ok(U, &proj, &["init"]);
    write(&proj, ".env", &format!("{SECRET}\n"));
    write(&proj, "a.txt", "a\n");
    std::fs::create_dir_all(proj.join("s1/s2/s3/s4")).unwrap();
    std::os::unix::fs::symlink("../../../..", proj.join("s1/s2/s3/s4/u")).unwrap();
    std::os::unix::fs::symlink("u/../../../../../.env", proj.join("s1/s2/s3/s4/x")).unwrap();
    env.ok(U, &proj, &["commit", "-m", "links"]);
    let ls = env.stdout(U, &proj, &["ls", "-r", "@-"]);
    assert!(ls.contains("isolated") && ls.contains("s1/s2/s3/s4/x ->"), "{ls}");
    env.ok(U, &proj, &["ws", "new", "agent", "-r", "@-"]);
    let out = env.vl(U, &proj, &["ws", "exec", "agent", "--", "cat", "s1/s2/s3/s4/x"]);
    assert!(!text(&out).contains(SECRET), "the sandboxed command read the isolated .env through the links:\n{}", text(&out));
}

/// Control: a single link that climbs out lexically is blocked.
#[test]
fn control_a_single_escaping_link_is_blocked() {
    let env = Env::new();
    let proj = env.dir("proj");
    env.ok(U, &proj, &["init"]);
    write(&proj, ".env", &format!("{SECRET}\n"));
    std::os::unix::fs::symlink("../../../../../.env", proj.join("x")).unwrap();
    env.ok(U, &proj, &["commit", "-m", "link"]);
    env.ok(U, &proj, &["ws", "new", "agent", "-r", "@-"]);
    let out = env.vl(U, &proj, &["ws", "exec", "agent", "--", "cat", "x"]);
    assert!(!text(&out).contains(SECRET), "{}", text(&out));
}

/// BUG-709: absolute targets are materialised unless they lie, lexically,
/// inside the project or `$VEIL_HOME` (`SandboxFs::guard_link`). A magic
/// link of `/proc` names the sandbox itself: `/proc/self/cwd` is the
/// reading command's working directory (the sandbox root under `ws
/// exec`), so `x -> /proc/self/cwd/../../../../../.env` is lexically
/// `/.env` (allowed) and, for the kernel, the project's isolated `.env`.
/// `/proc/self/root/<project path>` and `/proc/<pid>/cwd` work the same
/// way. One link from a teammate's tree is enough.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "BUG-709: an absolute link through /proc/self/cwd escapes the ws exec sandbox to the isolated .env"]
fn a_proc_self_link_never_reaches_the_projects_isolated_files() {
    let env = Env::new();
    let proj = env.dir("proj");
    env.ok(U, &proj, &["init"]);
    write(&proj, ".env", &format!("{SECRET}\n"));
    std::os::unix::fs::symlink("/proc/self/cwd/../../../../../.env", proj.join("x")).unwrap();
    env.ok(U, &proj, &["commit", "-m", "link"]);
    env.ok(U, &proj, &["ws", "new", "agent", "-r", "@-"]);
    let out = env.vl(U, &proj, &["ws", "exec", "agent", "--", "cat", "x"]);
    assert!(!text(&out).contains(SECRET), "the sandboxed command read the isolated .env through /proc/self/cwd:\n{}", text(&out));
}
