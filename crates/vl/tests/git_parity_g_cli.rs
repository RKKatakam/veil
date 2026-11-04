//! Git-parity stream G through the real `vl` binary: annotated and signed
//! tags (`vl tag set -a`, `vl tag verify`), Git tags in the bridge (`vl git
//! push --force-tags/--delete-tag`, `vl git fetch --no-tags/--prune-tags`)
//! and submodules (`vl submodule status|update|set|add`), with plain `git`
//! playing GitHub. Offline: every remote is a local repository.

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

    fn bare(&self, name: &str) -> PathBuf {
        let bare = self.root.join(name);
        git(&self.root, &["init", "-q", "--bare", bare.to_str().unwrap()]);
        bare
    }
}

fn git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .current_dir(dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", "Gita Hub")
        .env("GIT_AUTHOR_EMAIL", "gita@example.com")
        .env("GIT_COMMITTER_NAME", "Gita Hub")
        .env("GIT_COMMITTER_EMAIL", "gita@example.com")
        .args(["-c", "init.defaultBranch=main", "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false"])
        .args(["-c", "protocol.file.allow=always", "-c", "advice.detachedHead=false"])
        .args(args)
        .output()
        .unwrap();
    assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).trim().to_string()
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
    assert_eq!(v1["git_ref"], "refs/tags/v1.0");
    assert_eq!(v1["annotation"]["verified"], true);
    assert_eq!(v1["annotation"]["kind"], "annotated");
    assert!(v1["annotation"]["message"].as_str().unwrap().contains('\u{1b}'), "JSON keeps the data, escaped");
    let main = tags.iter().find(|t| t["name"] == "main").unwrap();
    assert_eq!((main["kind"].as_str(), main["git_ref"].as_str()), (Some("branch"), Some("refs/heads/main")));
    no_escapes(&env.ok(&dir, &["tag", "list"]));
    // A plain tag has nothing to verify; annotating it needs --force.
    let err = env.fails(&dir, &["tag", "verify", "main"]);
    assert!(err.contains("plain tag"), "{err}");
    let err = env.fails(&dir, &["tag", "set", "main", "-a", "-m", "x"]);
    assert!(err.contains("--force"), "{err}");
    // A cloaked annotated tag: its message is sealed.
    env.ok(&dir, &["tag", "set", "v-team", "-r", "@-", "-a", "-m", "TEAM-ONLY-NOTES", "--cloak"]);
    let out = env.ok(&dir, &["tag", "verify", "v-team"]);
    assert!(out.contains("TEAM-ONLY-NOTES"), "a member reads it: {out}");
    // The commit printed that release tags stay.
    std::fs::write(dir.join("README.md"), "three\n").unwrap();
    env.ok(&dir, &["tag", "set", "v1.1", "-a", "-m", "on @-", "-r", "@-"]);
    let out = env.ok(&dir, &["commit", "-m", "three"]);
    assert!(out.contains("annotated release tags are immutable"), "{out}");
}

// ---- Git tags in the bridge ------------------------------------------------------

#[test]
fn git_tag_flags_and_supply_chain_warnings() {
    let env = Env::new();
    let dir = env.project("p");
    let bare = env.bare("github.git");
    env.ok(&dir, &["git", "remote", "add", "origin", bare.to_str().unwrap()]);
    env.ok(&dir, &["tag", "set", "v1.0", "-r", "@-", "-a", "-m", "Release 1.0"]);
    env.ok(&dir, &["tag", "set", "v-team", "-r", "@-", "-a", "-m", "CLOAKED-TAG-MSG", "--cloak"]);
    let out = env.ok(&dir, &["git", "push"]);
    assert!(out.contains("pushed tag v1.0") && out.contains("(new tag)"), "{out}");
    assert!(out.contains("skipped v-team"), "{out}");
    assert_eq!(git(&bare, &["tag", "-l"]), "v1.0");
    assert_eq!(git(&bare, &["cat-file", "-t", "v1.0"]), "tag");

    // Someone moves the tag on GitHub: the fetch says so; the local tag stays.
    let work = env.root.join("work");
    git(&env.root, &["clone", "-q", bare.to_str().unwrap(), work.to_str().unwrap()]);
    std::fs::write(work.join("evil.txt"), "x\n").unwrap();
    git(&work, &["add", "-A"]);
    git(&work, &["commit", "-q", "-m", "evil"]);
    git(&work, &["tag", "-f", "-a", "v1.0", "-m", "Release 1.0"]);
    git(&work, &["push", "-q", "-f", "origin", "main", "refs/tags/v1.0"]);
    let before = env.json(&dir, &["tag", "list", "--json"])["tags"].clone();
    let out = env.ok(&dir, &["git", "pull"]);
    assert!(out.contains("moved Git tag v1.0"), "{out}");
    assert!(out.contains("release tag v1.0 stays"), "{out}");
    let after = env.json(&dir, &["tag", "list", "--json"]);
    let v1 = |v: &serde_json::Value| v.as_array().unwrap().iter().find(|t| t["name"] == "v1.0").cloned().unwrap();
    assert_eq!(v1(&before)["target"], v1(&after["tags"])["target"]);
    let remote = after["remote_release_tags"].as_array().unwrap();
    assert!(remote.iter().any(|t| t["name"] == "origin/v1.0"), "{remote:?}");
    // Our push is refused (tags are never forced) …
    let out = env.vl(&dir, &["git", "push"]);
    let text = String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{text}");
    assert!(text.contains("rejected") && text.contains("another target"), "{text}");
    // … until --force-tags, leased on what was fetched.
    let ours = env.ok(&dir, &["git", "export"]);
    let ours_tag = ours.lines().find(|l| l.starts_with("tag v1.0")).unwrap().split_whitespace().last().unwrap().to_string();
    env.ok(&dir, &["git", "push", "--force-tags"]);
    assert_eq!(git(&bare, &["rev-parse", "refs/tags/v1.0"]), ours_tag);
    // --delete-tag: refused while the tag exists here.
    let err = env.fails(&dir, &["git", "push", "--delete-tag", "v1.0"]);
    assert!(err.contains("vl tag delete"), "{err}");
    env.ok(&dir, &["tag", "delete", "v1.0"]);
    let out = env.ok(&dir, &["git", "push", "--delete-tag", "v1.0"]);
    assert!(out.contains("deleted") && out.contains("tag v1.0"), "{out}");
    assert!(git(&bare, &["tag", "-l"]).is_empty());
    // --no-tags and --prune-tags.
    git(&work, &["tag", "v2.0"]);
    git(&work, &["push", "-q", "origin", "v2.0"]);
    let out = env.ok(&dir, &["git", "fetch", "--no-tags"]);
    assert!(!out.contains("v2.0"), "{out}");
    env.ok(&dir, &["git", "fetch"]);
    git(&work, &["push", "-q", "origin", ":refs/tags/v2.0"]);
    let out = env.ok(&dir, &["git", "fetch"]);
    assert!(out.contains("v2.0 was deleted"), "{out}");
    let out = env.ok(&dir, &["git", "fetch", "--prune-tags"]);
    assert!(out.contains("forgot Git tag origin/v2.0"), "{out}");
    let list = env.json(&dir, &["tag", "list", "--json"]);
    assert!(!list["remote_release_tags"].as_array().unwrap().iter().any(|t| t["name"] == "origin/v2.0"));
    // Nothing cloaked ever reached the remote.
    let all = Command::new("git").args(["cat-file", "--batch-all-objects", "--batch"]).current_dir(&bare).output().unwrap();
    assert!(!String::from_utf8_lossy(&all.stdout).contains("CLOAKED-TAG-MSG"));
}

#[test]
fn a_git_signature_is_never_verified() {
    let env = Env::new();
    let up = env.root.join("up");
    git(&env.root, &["init", "-q", up.to_str().unwrap()]);
    std::fs::write(up.join("a.txt"), "1\n").unwrap();
    git(&up, &["add", "-A"]);
    git(&up, &["commit", "-q", "-m", "one"]);
    let head = git(&up, &["rev-parse", "HEAD"]);
    let raw = format!(
        "object {head}\ntype commit\ntag v1.0\ntagger Mallory <m@x> 1700000000 +0000\n\nsigned\n-----BEGIN PGP SIGNATURE-----\n\njunk\n-----END PGP SIGNATURE-----\n"
    );
    let path = env.root.join("tag.txt");
    std::fs::write(&path, raw).unwrap();
    let oid = git(&up, &["hash-object", "-t", "tag", "-w", path.to_str().unwrap()]);
    git(&up, &["update-ref", "refs/tags/v1.0", &oid]);
    let dir = env.root.join("v");
    std::fs::create_dir_all(&dir).unwrap();
    env.ok(&dir, &["init"]);
    env.ok(&dir, &["git", "import", up.to_str().unwrap()]);
    let err = env.fails(&dir, &["tag", "verify", "v1.0"]);
    assert!(err.contains("Git signature, not verified by Veil"), "{err}");
    let list = env.json(&dir, &["tag", "list", "--json"]);
    let v1 = list["tags"].as_array().unwrap().iter().find(|t| t["name"] == "v1.0").unwrap().clone();
    assert_eq!(v1["annotation"]["verified"], false);
}

// ---- submodules ------------------------------------------------------------------

/// A Git superproject with a submodule `vendor/lib` (URL `../lib`).
fn superproject(env: &Env) -> (PathBuf, PathBuf, String) {
    let lib = env.root.join("lib");
    git(&env.root, &["init", "-q", lib.to_str().unwrap()]);
    std::fs::write(lib.join("l.txt"), "lib\n").unwrap();
    git(&lib, &["add", "-A"]);
    git(&lib, &["commit", "-q", "-m", "lib"]);
    let pin = git(&lib, &["rev-parse", "HEAD"]);
    let up = env.root.join("up");
    git(&env.root, &["init", "-q", up.to_str().unwrap()]);
    std::fs::write(up.join("a.txt"), "app\n").unwrap();
    std::fs::write(up.join(".gitmodules"), "[submodule \"lib\"]\n\tpath = vendor/lib\n\turl = ../lib\n").unwrap();
    git(&up, &["add", "-A"]);
    git(&up, &["update-index", "--add", "--cacheinfo", &format!("160000,{pin},vendor/lib")]);
    git(&up, &["commit", "-q", "-m", "app"]);
    let bare = env.root.join("up.git");
    git(&env.root, &["clone", "-q", "--bare", up.to_str().unwrap(), bare.to_str().unwrap()]);
    (lib, bare, pin)
}

#[test]
fn submodules_update_explicitly_and_are_never_recorded_below() {
    let env = Env::new();
    let (lib, bare, pin) = superproject(&env);
    let dir = env.root.join("v");
    std::fs::create_dir_all(&dir).unwrap();
    env.ok(&dir, &["init"]);
    env.ok(&dir, &["git", "import", bare.to_str().unwrap()]);
    let out = env.ok(&dir, &["submodule", "status"]);
    assert!(out.contains("vendor/lib") && out.contains(&pin[..12]) && out.contains("not checked out"), "{out}");
    // A pull never fetches a submodule.
    env.ok(&dir, &["git", "pull"]);
    assert!(!dir.join("vendor/lib/l.txt").exists());
    // A local URL needs --allow-local.
    let out = env.fails(&dir, &["submodule", "update"]);
    assert!(out.contains("--allow-local") && out.contains("vendor/lib"), "{out}");
    let out = env.ok(&dir, &["submodule", "update", "--allow-local"]);
    assert!(out.contains("cloned vendor/lib"), "{out}");
    assert_eq!(std::fs::read_to_string(dir.join("vendor/lib/l.txt")).unwrap(), "lib\n");
    assert!(!dir.join(".git").exists(), "never .git/modules");
    assert!(dir.join(".veil/local/submodules").is_dir());
    let out = env.ok(&dir, &["submodule", "status"]);
    assert!(out.contains("up to date"), "{out}");
    // Files in the submodule (even one the policy would cloak) are never
    // recorded: its own repository decides where they go.
    std::fs::write(dir.join(".veilpolicy"), "vendor/lib/secret.txt cloak\n").unwrap();
    std::fs::write(dir.join("vendor/lib/secret.txt"), "SUBMODULE-SECRET\n").unwrap();
    let out = env.ok(&dir, &["status"]);
    assert!(!out.contains("vendor/lib/"), "{out}");
    let ls = env.ok(&dir, &["ls"]);
    assert!(ls.contains("vendor/lib") && !ls.contains("l.txt") && !ls.contains("secret.txt"), "{ls}");
    // Move the pin explicitly and push it to Git.
    std::fs::write(lib.join("l.txt"), "lib 2\n").unwrap();
    git(&lib, &["commit", "-q", "-am", "lib 2"]);
    let pin2 = git(&lib, &["rev-parse", "HEAD"]);
    let err = env.fails(&dir, &["submodule", "set", "vendor/lib", "abc"]);
    assert!(err.contains("full Git commit id"), "{err}");
    let out = env.ok(&dir, &["submodule", "set", "vendor/lib", &pin2]);
    assert!(out.contains(&format!("Pinned vendor/lib to {}", &pin2[..12])), "{out}");
    env.ok(&dir, &["submodule", "update", "--allow-local"]);
    assert_eq!(std::fs::read_to_string(dir.join("vendor/lib/l.txt")).unwrap(), "lib 2\n");
    env.ok(&dir, &["commit", "-m", "bump lib"]);
    env.ok(&dir, &["tag", "set", "main", "-r", "@-"]);
    env.ok(&dir, &["git", "push"]);
    let tree = git(&bare, &["ls-tree", "-r", "main"]);
    assert!(tree.contains(&format!("160000 commit {pin2}\tvendor/lib")), "{tree}");
    assert!(!tree.contains("secret.txt") && !tree.contains("l.txt"), "{tree}");
    let all = Command::new("git").args(["cat-file", "--batch-all-objects", "--batch"]).current_dir(&bare).output().unwrap();
    assert!(!String::from_utf8_lossy(&all.stdout).contains("SUBMODULE-SECRET"));
}

/// Threats 5b.10 and 5b.11: hostile `.gitmodules` URLs and names never run
/// anything, never write outside `.veil/local/submodules`, and each
/// failure names its submodule.
#[test]
fn hostile_gitmodules_never_execute_anything() {
    let env = Env::new();
    let mark = env.root.join("PWNED");
    let m = mark.to_str().unwrap();
    let victim = env.root.join("private-repo");
    git(&env.root, &["init", "-q", victim.to_str().unwrap()]);
    std::fs::write(victim.join("p.txt"), "private\n").unwrap();
    git(&victim, &["add", "-A"]);
    git(&victim, &["commit", "-q", "-m", "private"]);
    let up = env.root.join("up");
    git(&env.root, &["init", "-q", up.to_str().unwrap()]);
    let gitmodules = format!(
        "[submodule \"a\"]\n\tpath = a\n\turl = --upload-pack=touch {m}\n\
         [submodule \"b\"]\n\tpath = b\n\turl = ext::sh -c touch% {m}\n\
         [submodule \"c\"]\n\tpath = c\n\turl = file://{}\n\
         [submodule \"../../../.veil/hooks\"]\n\tpath = d\n\turl = https://example.invalid/x.git\n\
         [submodule \"e\"]\n\tpath = e\n\turl = {}\n\tupdate = !touch {m}\n\
         [submodule \"f\"]\n\tpath = f\n\turl = ssh://-oProxyCommand=touch%20{m}/x\n\
         [submodule \"g\"]\n\tpath = g\n\turl = fd::7\n",
        victim.display(),
        victim.display()
    );
    std::fs::write(up.join(".gitmodules"), gitmodules).unwrap();
    git(&up, &["add", "-A"]);
    let pin = git(&victim, &["rev-parse", "HEAD"]);
    for path in ["a", "b", "c", "d", "e", "f", "g"] {
        git(&up, &["update-index", "--add", "--cacheinfo", &format!("160000,{pin},{path}")]);
    }
    git(&up, &["commit", "-q", "-m", "hostile"]);
    let dir = env.root.join("v");
    std::fs::create_dir_all(&dir).unwrap();
    env.ok(&dir, &["init"]);
    env.ok(&dir, &["git", "import", up.to_str().unwrap()]);
    let out = env.fails(&dir, &["submodule", "update"]);
    for path in ["a", "b", "c", "d", "e", "f", "g"] {
        assert!(out.contains(&format!("failed {path}:")), "{path} not refused: {out}");
    }
    assert!(out.contains("option"), "{out}");
    assert!(out.contains("remote helpers"), "{out}");
    assert!(out.contains("'..'"), "{out}");
    assert!(!mark.exists(), "a .gitmodules URL ran a command");
    assert!(!dir.join(".veil/hooks").exists());
    assert!(!dir.join("c/p.txt").exists(), "a file:// URL was cloned without --allow-local");
    // With --allow-local the local one clones, and `update = !cmd` is
    // never run; the hostile ones stay refused.
    let out = env.vl(&dir, &["submodule", "update", "--allow-local"]);
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(text.contains("cloned c") && text.contains("cloned e"), "{text}");
    for path in ["a", "b", "d", "f", "g"] {
        assert!(text.contains(&format!("failed {path}:")), "{path}: {text}");
    }
    assert!(!mark.exists(), "update = !command ran");
    assert!(!dir.join(".veil/hooks").exists());
    // Every clone's Git directory is under .veil/local/submodules.
    let modules: Vec<_> = std::fs::read_dir(dir.join(".veil/local/submodules")).unwrap().collect();
    assert_eq!(modules.len(), 2);
}

/// A symlink planted at a submodule's parent never sends the clone
/// outside the working copy.
#[test]
fn a_symlinked_submodule_path_is_refused() {
    let env = Env::new();
    let (_lib, bare, _pin) = superproject(&env);
    let dir = env.root.join("v");
    std::fs::create_dir_all(&dir).unwrap();
    env.ok(&dir, &["init"]);
    env.ok(&dir, &["git", "import", bare.to_str().unwrap()]);
    let outside = env.root.join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    let _ = std::fs::remove_dir_all(dir.join("vendor"));
    std::os::unix::fs::symlink(&outside, dir.join("vendor")).unwrap();
    let out = env.fails(&dir, &["submodule", "update", "--allow-local"]);
    assert!(out.contains("symlink"), "{out}");
    assert!(std::fs::read_dir(&outside).unwrap().next().is_none(), "the clone went through the link");
}

#[test]
fn submodule_add_records_a_pin_and_gitmodules() {
    let env = Env::new();
    let (lib, _bare, pin) = superproject(&env);
    let dir = env.project("p");
    let err = env.fails(&dir, &["submodule", "add", lib.to_str().unwrap(), "vendor/lib"]);
    assert!(err.contains("--allow-local"), "{err}");
    let out = env.ok(&dir, &["submodule", "add", lib.to_str().unwrap(), "vendor/lib", "--allow-local"]);
    assert!(out.contains("Added submodule vendor/lib"), "{out}");
    let gm = std::fs::read_to_string(dir.join(".gitmodules")).unwrap();
    assert!(gm.contains("path = \"vendor/lib\"") || gm.contains("path = vendor/lib"), "{gm}");
    let out = env.ok(&dir, &["submodule", "status"]);
    assert!(out.contains(&pin[..12]) && out.contains("up to date"), "{out}");
    let err = env.fails(&dir, &["submodule", "add", lib.to_str().unwrap(), "vendor/lib", "--allow-local"]);
    assert!(err.contains("already") || err.contains("not empty"), "{err}");
    for bad in [".git/hooks", "../escape", ".veil/x"] {
        let err = env.fails(&dir, &["submodule", "add", lib.to_str().unwrap(), bad, "--allow-local"]);
        assert!(!err.contains("Added"), "{bad}: {err}");
    }
}

/// BUG-640: `vl git export` in a repository that never talked to Git
/// creates the bridge (`.veil/git/`) instead of failing.
#[test]
fn bug_640_git_export_in_a_fresh_repository() {
    let env = Env::new();
    let dir = env.project("p");
    assert!(!dir.join(".veil/git").exists());
    let out = env.ok(&dir, &["git", "export"]);
    assert!(out.contains("main"), "{out}");
    assert!(dir.join(".veil/git/repo.git").is_dir());
    env.ok(&dir, &["git", "export"]);
}
