//! Symlinks (design 6) in `vl ws exec` sandboxes.

use super::{
    adversarial_support::{text, write, Env},
    U,
};

const SECRET: &str = "SESSION_SALT=isolated-7781";

/// BUG-708: threat 7's invariant is that a sandbox never materialises a
/// relative link that resolves outside it, so a command in `ws exec`
/// (without `--with-isolated`) cannot reach the project's isolated `.netrc`
/// through a tree's links. `SandboxFs::guard_link` checks each link
/// *lexically* (`vfs::link_escapes`), as if every component before a
/// `..` were a directory. A chain defeats it: `s1/s2/s3/s4/u -> ../../../..`
/// (the sandbox root: inside) and `s1/s2/s3/s4/x -> u/../../../../../.netrc`
/// (lexically `s1/s2/s3/s4/u` up five: the root's `.netrc`, inside), but the
/// kernel resolves `u` first, then climbs five levels above the sandbox
/// root: `.veil/local/sandboxes/agent/files/../../../../../.netrc` is the
/// project's `.netrc`. Both links come from a teammate's tree.
#[test]
fn a_chain_of_links_never_reaches_the_projects_isolated_files() {
    let env = Env::new();
    let proj = env.dir("proj");
    env.ok(U, &proj, &["init"]);
    write(&proj, ".netrc", &format!("{SECRET}\n"));
    write(&proj, "a.txt", "a\n");
    std::fs::create_dir_all(proj.join("s1/s2/s3/s4")).unwrap();
    std::os::unix::fs::symlink("../../../..", proj.join("s1/s2/s3/s4/u")).unwrap();
    std::os::unix::fs::symlink("u/../../../../../.netrc", proj.join("s1/s2/s3/s4/x")).unwrap();
    // `.netrc` is isolated (`commit` says so of the link that names it), and
    // both links are recorded.
    let commit = env.ok(U, &proj, &["commit", "-m", "links"]);
    assert!(commit.contains("isolates"), "{commit}");
    let ls = env.stdout(U, &proj, &["ls", "-r", "@-"]);
    assert!(ls.contains("s1/s2/s3/s4/u ->") && ls.contains("s1/s2/s3/s4/x ->"), "{ls}");
    env.ok(U, &proj, &["ws", "new", "agent", "-r", "@-"]);
    let out = env.vl(U, &proj, &["ws", "exec", "agent", "--", "cat", "s1/s2/s3/s4/x"]);
    assert!(!text(&out).contains(SECRET), "the sandboxed command read the isolated .netrc through the links:\n{}", text(&out));
}

/// Control: a single link that climbs out lexically is blocked.
#[test]
fn control_a_single_escaping_link_is_blocked() {
    let env = Env::new();
    let proj = env.dir("proj");
    env.ok(U, &proj, &["init"]);
    write(&proj, ".netrc", &format!("{SECRET}\n"));
    std::os::unix::fs::symlink("../../../../../.netrc", proj.join("x")).unwrap();
    env.ok(U, &proj, &["commit", "-m", "link"]);
    env.ok(U, &proj, &["ws", "new", "agent", "-r", "@-"]);
    let out = env.vl(U, &proj, &["ws", "exec", "agent", "--", "cat", "x"]);
    assert!(!text(&out).contains(SECRET), "{}", text(&out));
}

/// BUG-709: absolute targets are materialised unless they lie, lexically,
/// inside the project or `$VEIL_HOME` (`SandboxFs::guard_link`). A magic
/// link of `/proc` names the sandbox itself: `/proc/self/cwd` is the
/// reading command's working directory (the sandbox root under `ws
/// exec`), so `x -> /proc/self/cwd/../../../../../.netrc` is lexically
/// `/.netrc` (allowed) and, for the kernel, the project's isolated `.netrc`.
/// `/proc/self/root/<project path>` and `/proc/<pid>/cwd` work the same
/// way. One link from a teammate's tree is enough.
#[cfg(target_os = "linux")]
#[test]
fn a_proc_self_link_never_reaches_the_projects_isolated_files() {
    let env = Env::new();
    let proj = env.dir("proj");
    env.ok(U, &proj, &["init"]);
    write(&proj, ".netrc", &format!("{SECRET}\n"));
    std::os::unix::fs::symlink("/proc/self/cwd/../../../../../.netrc", proj.join("x")).unwrap();
    env.ok(U, &proj, &["commit", "-m", "link"]);
    env.ok(U, &proj, &["ws", "new", "agent", "-r", "@-"]);
    let out = env.vl(U, &proj, &["ws", "exec", "agent", "--", "cat", "x"]);
    assert!(!text(&out).contains(SECRET), "the sandboxed command read the isolated .netrc through /proc/self/cwd:\n{}", text(&out));
}

/// BUG-708 and BUG-709 in `--only` (sparse) and `--ephemeral` sandboxes:
/// the rule does not depend on where the sandbox lives or what it holds,
/// so chains of every depth and `/proc` links are refused in all of them.
#[cfg(target_os = "linux")]
#[test]
fn sparse_and_ephemeral_sandboxes_never_reach_the_projects_isolated_files() {
    let env = Env::new();
    let proj = env.dir("proj");
    env.ok(U, &proj, &["init"]);
    write(&proj, ".netrc", &format!("{SECRET}\n"));
    let mut names = Vec::new();
    // A chain at every depth from 1 to 7, climbing 1 to 12 levels.
    for depth in 1..=7 {
        let dir = (1..=depth).map(|i| format!("s{i}")).collect::<Vec<_>>().join("/");
        std::fs::create_dir_all(proj.join(&dir)).unwrap();
        std::os::unix::fs::symlink(vec![".."; depth].join("/"), proj.join(&dir).join("u")).unwrap();
        for up in 1..=12 {
            let name = format!("{dir}/x{up}");
            std::os::unix::fs::symlink(format!("u/{}/.netrc", vec![".."; up].join("/")), proj.join(&name)).unwrap();
            names.push(name);
        }
    }
    std::os::unix::fs::symlink("/proc/self/cwd/../../../../../.netrc", proj.join("s1/p")).unwrap();
    std::os::unix::fs::symlink("/proc/self/cwd/../../../.netrc", proj.join("s1/q")).unwrap();
    names.extend(["s1/p".to_string(), "s1/q".to_string()]);
    env.ok(U, &proj, &["commit", "-m", "links"]);
    env.ok(U, &proj, &["ws", "new", "agent", "-r", "@-"]);
    let mut cat = vec!["cat"];
    cat.extend(names.iter().map(String::as_str));
    for how in [&["--only", "s1"][..], &["--ephemeral"], &["--ephemeral", "--only", "s1"]] {
        let mut args = vec!["ws", "exec", "agent"];
        args.extend(how);
        args.push("--");
        args.extend(&cat);
        let out = env.vl(U, &proj, &args);
        assert!(!text(&out).contains(SECRET), "{how:?}: the sandboxed command read the isolated .netrc:\n{}", text(&out));
        // The command ran, and found none of the refused links.
        assert!(text(&out).contains("cat: s1/s2/s3/s4/x5: No such file"), "{how:?}:\n{}", text(&out));
    }
}
