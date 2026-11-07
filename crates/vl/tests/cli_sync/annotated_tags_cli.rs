//! Annotated and signed tags through the real `vl` binary (`vl tag set
//! -a`, `vl tag verify`).

use std::{
    path::{Path, PathBuf},
    process::{Command, Output},
};

struct Env {
    _tmp: tempfile::TempDir,
    root: PathBuf,
}

impl Env {
    fn new() -> Env {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        Env { _tmp: tmp, root }
    }

    fn vl(&self, cwd: &Path, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_vl"))
            .env("VEIL_TEST_PATH_REMOTES", "1")
            .args(args)
            .current_dir(cwd)
            .env("VEIL_HOME", self.root.join("home-alice"))
            .env("VEIL_USER", "alice")
            .env("NO_COLOR", "1")
            .output()
            .unwrap()
    }

    fn ok(&self, cwd: &Path, args: &[&str]) -> String {
        let out = self.vl(cwd, args);
        let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        assert!(out.status.success(), "vl {args:?} failed:\n{text}");
        text
    }

    /// `vl args` fails (exit 1); returns stdout + stderr.
    fn fails(&self, cwd: &Path, args: &[&str]) -> String {
        let out = self.vl(cwd, args);
        let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        assert_eq!(out.status.code(), Some(1), "vl {args:?}:\n{text}");
        assert!(!text.contains("panicked"), "{text}");
        text
    }

    fn json(&self, cwd: &Path, args: &[&str]) -> serde_json::Value {
        let out = self.vl(cwd, args);
        assert!(out.status.success(), "vl {args:?}: {}", String::from_utf8_lossy(&out.stderr));
        serde_json::from_slice(&out.stdout).unwrap()
    }

    /// A Veil project with one commit, tagged `main`.
    fn project(&self, name: &str) -> PathBuf {
        let dir = self.root.join(name);
        std::fs::create_dir_all(&dir).unwrap();
        self.ok(&dir, &["init"]);
        std::fs::write(dir.join("README.md"), "hello\n").unwrap();
        self.ok(&dir, &["commit", "-m", "first"]);
        self.ok(&dir, &["tag", "set", "main", "-r", "@-"]);
        dir
    }
}

fn no_escapes(text: &str) {
    assert!(!text.contains('\u{1b}') && !text.contains('\u{7}'), "raw control characters printed: {text:?}");
}

// ---- annotated tags --------------------------------------------------------------

#[test]
fn annotated_tags_are_signed_verified_and_immutable() {
    let env = Env::new();
    let dir = env.project("p");
    let out = env.ok(&dir, &["tag", "set", "v1.0", "-r", "@-", "-a", "-m", "Release 1.0\n\u{1b}]8;;http://evil\u{7}click"]);
    assert!(out.contains("Release tag v1.0") && out.contains("(signed)"), "{out}");
    let out = env.ok(&dir, &["tag", "verify", "v1.0"]);
    assert!(out.contains("good signature by alice"), "{out}");
    assert!(out.contains("Release 1.0"), "{out}");
    no_escapes(&out);
    // Immutable: moving it is refused, nothing changes; --force replaces it
    // and keeps the message.
    std::fs::write(dir.join("README.md"), "two\n").unwrap();
    env.ok(&dir, &["commit", "-m", "two"]);
    let before = env.json(&dir, &["tag", "list", "--json"]);
    let err = env.fails(&dir, &["tag", "set", "v1.0", "-r", "@-"]);
    assert!(err.contains("immutable") && err.contains("--force"), "{err}");
    assert_eq!(env.json(&dir, &["tag", "list", "--json"]), before);
    let out = env.ok(&dir, &["tag", "set", "v1.0", "-r", "@-", "--force"]);
    assert!(out.contains("replaced release tag"), "{out}");
    let out = env.ok(&dir, &["tag", "verify", "v1.0"]);
    assert!(out.contains("Release 1.0"), "{out}");
    // The commit did not move the release tag; `main` moved.
    let list = env.json(&dir, &["tag", "list", "--json"]);
    let tags = list["tags"].as_array().unwrap();
    let v1 = tags.iter().find(|t| t["name"] == "v1.0").unwrap();
    assert_eq!(v1["kind"], "release");
    assert_eq!(v1["annotation"]["verified"], true);
    assert_eq!(v1["annotation"]["kind"], "annotated");
    assert!(v1["annotation"]["message"].as_str().unwrap().contains('\u{1b}'), "JSON keeps the data, escaped");
    let main = tags.iter().find(|t| t["name"] == "main").unwrap();
    assert_eq!(main["kind"].as_str(), Some("branch"));
    no_escapes(&env.ok(&dir, &["tag", "list"]));
    // A plain tag has nothing to verify; annotating it needs --force.
    let err = env.fails(&dir, &["tag", "verify", "main"]);
    assert!(err.contains("plain tag"), "{err}");
    let err = env.fails(&dir, &["tag", "set", "main", "-a", "-m", "x"]);
    assert!(err.contains("--force"), "{err}");
    // The commit printed that release tags stay.
    std::fs::write(dir.join("README.md"), "three\n").unwrap();
    env.ok(&dir, &["tag", "set", "v1.1", "-a", "-m", "on @-", "-r", "@-"]);
    let out = env.ok(&dir, &["commit", "-m", "three"]);
    assert!(out.contains("annotated release tags are immutable"), "{out}");
}
