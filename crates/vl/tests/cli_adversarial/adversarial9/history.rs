//! History tools (designs 1 and 3): what `--public` promises.

use super::{
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

/// BUG-704, the shape of the fix: `blame --public --json` hides a sealed
/// description as `not_public` (naming its scope, as the mirror's `[cloaked:…]`
/// does), still shows public descriptions, and without `--public` the
/// member reads their own descriptions as before.
#[test]
fn blame_public_hides_sealed_descriptions_and_keeps_public_ones() {
    let env = Env::new();
    let proj = env.project(U, "proj", &[("README.md", "hello\nworld\n")]);
    env.ok(U, &proj, &["ws", "new", "plan", "-r", "main", "--cloak", "team"]);
    ws_write(&env, &proj, "plan", "README.md", "hello\ncloaked line\nworld\n");
    env.ok(U, &proj, &["describe", "-r", "plan@", "-m", CLOAKED_DESC]);
    let doc = |public: bool| -> serde_json::Value {
        let mut args = vec!["blame", "README.md", "-r", "plan@", "--json"];
        if public {
            args.push("--public");
        }
        serde_json::from_str(&env.stdout(U, &proj, &args)).unwrap()
    };
    let public = doc(true);
    assert_eq!(public["rev"]["description"], serde_json::Value::Null, "{public}");
    assert_eq!(public["rev"]["description_hidden"]["reason"], "not_public", "{public}");
    assert_eq!(public["rev"]["description_hidden"]["scope"], "team", "{public}");
    let descriptions: Vec<&str> = public["changes"].as_array().unwrap().iter().filter_map(|c| c["description"].as_str()).collect();
    assert!(descriptions.iter().any(|d| d.contains("initial")), "{public}");
    let own = doc(false);
    assert_eq!(own["rev"]["description"].as_str().map(str::trim), Some(CLOAKED_DESC), "{own}");
}
