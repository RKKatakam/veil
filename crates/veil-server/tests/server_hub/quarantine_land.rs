//! BUG-2140 and BUG-2170 against the server: a quarantine is not a plain
//! success at `vl push` or `vl land` either. Each sends the change left
//! without the file (the work is done all the same) and exits 3 while the
//! working copy holds it; once it is isolated, they exit 0.

use crate::support::*;

const LEAKY: &str = "const key = 'AKIAIOSFODNN7EXAMPLE';\n";

/// The files of `branch` on the server, as a fresh clone of the admin's
/// lists them.
fn server_files(p: &Project, url: &str, clone: &str, branch: &str) -> String {
    let dir = p.admin.dir(clone);
    p.admin.clone_trusting(url, &dir, &p.fp);
    p.admin.ok(&dir, &["files", "-r", branch])
}

/// The output of a command that did its work beside a quarantined file:
/// exit status 3 exactly, the file named.
fn quarantined(p: &Project, args: &[&str], done: &str) -> String {
    let o = p.admin.run(&p.dir, args);
    let all = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
    assert_eq!(o.status.code(), Some(3), "vl {args:?}: expected exit 3:\n{all}");
    assert!(
        all.contains(&format!("error: {done}, but without 1 quarantined file (it looks like a secret):\n  src/cfg.js (aws-access-key-id at line 1; never recorded)\n")),
        "{all}"
    );
    all
}

#[test]
fn bug_2170_land_and_push_beside_a_quarantined_file_exit_3_and_send_the_rest() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let url = hub.url(&p.name);
    // `vl push` to the server.
    write_files(&p.dir, &[("src/pushed.txt", "pushed\n"), ("src/cfg.js", LEAKY)]);
    quarantined(&p, &["commit", "-m", "pushed without the key"], "committed");
    p.admin.ok(&p.dir, &["tag", "set", "main", "-r", "@-", "--force"]);
    quarantined(&p, &["push"], "pushed");
    let files = server_files(&p, &url, "c1", "main");
    assert!(files.contains("src/pushed.txt"), "{files}");
    assert!(!files.contains("cfg.js"), "{files}");

    // `vl land`, the same.
    write_files(&p.dir, &[("src/landed.txt", "landed\n")]);
    quarantined(&p, &["commit", "-m", "lands without the key"], "committed");
    let out = quarantined(&p, &["land"], "sent to land");
    assert!(out.contains("landed main"), "{out}");
    let files = server_files(&p, &url, "c2", "main");
    assert!(files.contains("src/landed.txt"), "{files}");
    assert!(!files.contains("cfg.js"), "{files}");

    // Kept on this machine on purpose: both exit 0.
    p.admin.ok(&p.dir, &["isolate", "src/cfg.js"]);
    write_files(&p.dir, &[("src/after.txt", "after\n")]);
    let out = p.admin.ok(&p.dir, &["commit", "-m", "after isolate"]);
    assert!(!out.contains("quarantined file"), "{out}");
    let out = p.admin.ok(&p.dir, &["land"]);
    assert!(out.contains("landed main") && !out.contains("quarantined file"), "{out}");
    let out = p.admin.ok(&p.dir, &["push"]);
    assert!(!out.contains("quarantined file"), "{out}");
}
