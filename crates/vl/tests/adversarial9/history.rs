//! History tools (designs 1 and 3): what `--public` promises.

use crate::{
    adversarial_support::{text, Env},
    ws_write, U,
};

const CLOAKED_DESC: &str = "CLOAKED-DESC-5521";
const EMBARGO_DESC: &str = "EMBARGO-DESC-7730";

/// BUG-704: `vl blame --public` "annotates as a public mirror sees the
/// history" (design 1: for screenshots and issues), and its lines are
/// right, but the `--json` document's `rev` (and `changes`) carry the
/// descriptions as *this reader* reads them: the sealed description of a
/// cloaked change, and that of an unreleased embargoed merge, in plain
/// text. A mirror shows `(description withheld)` / `[cloaked:embargo/…]`.
#[test]
#[ignore = "BUG-704: vl blame --public --json prints sealed descriptions (cloaked change, embargoed merge)"]
fn blame_public_never_prints_a_sealed_description() {
    let env = Env::new();
    let proj = env.project(U, "proj", &[("README.md", "hello\nworld\n"), ("vuln.c", "int a;\nint b;\n")]);
    env.ok(U, &proj, &["ws", "new", "plan", "-r", "main", "--cloak", "team"]);
    ws_write(&env, &proj, "plan", "README.md", "hello\ncloaked line\nworld\n");
    env.ok(U, &proj, &["describe", "-r", "plan@", "-m", CLOAKED_DESC]);
    env.ok(U, &proj, &["ws", "new", "fix", "-r", "main"]);
    ws_write(&env, &proj, "fix", "vuln.c", "int a;\nint fixed;\n");
    env.ok(U, &proj, &["describe", "-r", "fix@", "-m", "fix"]);
    env.ok(U, &proj, &["merge", "fix@", "--into", "main", "--embargo", "-m", EMBARGO_DESC]);

    // What the public mirror shows of the two descriptions.
    let mirror = env.root.join("mirror");
    env.ok(U, &proj, &["remote", "add", "mirror", mirror.to_str().unwrap(), "--public"]);
    env.ok(U, &proj, &["push", "mirror"]);
    env.ok("carol", &env.root, &["clone", "mirror", "carol"]);
    let carol_log = env.stdout("carol", &env.root.join("carol"), &["log"]);
    assert!(!carol_log.contains(EMBARGO_DESC), "control: the mirror withholds the embargoed merge's description");

    let mut out = String::new();
    for (path, rev) in [("README.md", "plan@"), ("vuln.c", "main")] {
        for extra in [&["--json"][..], &[]] {
            let mut args = vec!["blame", path, "-r", rev, "--public"];
            args.extend_from_slice(extra);
            out.push_str(&text(&env.vl(U, &proj, &args)));
        }
    }
    for d in [CLOAKED_DESC, EMBARGO_DESC] {
        assert!(!out.contains(d), "`vl blame --public` printed the sealed description {d}:\n{out}");
    }
}
