//! `.veilhooks` trust (design 5a, threats 1–3): a trusted suggested hook
//! must run only the bytes this device pinned. Every repository file the
//! command reads has to be in the trust record; here three kinds of
//! argument are not, so a teammate's later change runs on the victim's
//! device at the next commit without any new `vl hooks trust`.
//!
//! The "teammate's change" is made in place (it would arrive with `vl
//! pull`; the trust check only looks at the files on disk).

use std::path::Path;

use crate::{
    adversarial_support::{write, Env},
    markers, U,
};

/// A project whose `.veilhooks` is `veilhooks`, with `files` written, the
/// whole committed and then trusted (`vl hooks trust --yes`).
fn trusted_project(env: &Env, veilhooks: &str, files: &[(&str, &str)]) -> std::path::PathBuf {
    let proj = env.dir("proj");
    env.ok(U, &proj, &["init"]);
    write(&proj, ".veilhooks", veilhooks);
    for (p, c) in files {
        write(&proj, p, c);
    }
    env.ok(U, &proj, &["commit", "--no-verify", "-m", "hooks"]);
    env.ok(U, &proj, &["hooks", "trust", "--yes", "--i-understand-indirect"]);
    proj
}

/// Commit an edit (running pre-commit hooks), whatever they do.
fn commit_edit(env: &Env, proj: &Path, n: u32) {
    write(proj, "work.txt", &format!("{n}\n"));
    let _ = env.vl(U, proj, &["commit", "-m", &format!("work {n}")]);
}

/// Control: the trusted hook runs as trusted, and a change to the script
/// a plain repository path names untrusts it.
#[test]
fn control_a_changed_script_named_by_its_path_does_not_run() {
    let env = Env::new();
    let m = markers(&env);
    let proj = trusted_project(
        &env,
        "[pre-commit]\nrun = [\"sh\", \"s/lint.sh\"]\n",
        &[("s/lint.sh", &format!("touch {}/trusted\n", m.display()))],
    );
    commit_edit(&env, &proj, 1);
    assert!(m.join("trusted").exists(), "the trusted hook did not run");
    write(&proj, "s/lint.sh", &format!("touch {}/PWNED\n", m.display()));
    commit_edit(&env, &proj, 2);
    assert!(!m.join("PWNED").exists());
}

/// BUG-700: a `.veilhooks` argument naming a **directory** is pinned as
/// the word `directory`: its content is never hashed. `python3 tools`
/// runs `tools/__main__.py` (as `node tools` runs `tools/index.js`), so a
/// teammate who later changes `tools/__main__.py` runs code on every
/// device that trusted the hook once. `vl hooks trust` prints `tools
/// directory` as a pinned file, which reads as if it were pinned.
#[test]
fn a_changed_file_inside_a_trusted_directory_argument_does_not_run() {
    let env = Env::new();
    let m = markers(&env);
    let script = |name: &str| format!("open({:?}, 'w').write('x')\n", m.join(name).display().to_string());
    let proj = trusted_project(
        &env,
        "[pre-commit]\nrun = [\"python3\", \"tools\"]\n",
        &[("tools/__main__.py", &script("trusted"))],
    );
    commit_edit(&env, &proj, 1);
    assert!(m.join("trusted").exists(), "the trusted hook did not run (is python3 installed?)");
    // The teammate's change.
    write(&proj, "tools/__main__.py", &script("PWNED"));
    commit_edit(&env, &proj, 2);
    assert!(
        !m.join("PWNED").exists(),
        "tools/__main__.py changed after `vl hooks trust` and the new code ran without a new trust"
    );
}

/// BUG-701: an argument that names a repository file through a
/// non-canonical spelling (`./s/lint.sh`, `s//lint.sh`, `s/./lint.sh`)
/// is classified as a literal (`hooks::classify`: `repo_path` refuses `.`
/// and empty components) and is neither pinned nor replaced by its trusted
/// copy: `sh` reads whatever the file holds at commit time.
#[test]
fn a_changed_script_named_with_a_dot_slash_does_not_run() {
    let env = Env::new();
    let m = markers(&env);
    let proj = trusted_project(
        &env,
        "[pre-commit]\nrun = [\"sh\", \"./s/lint.sh\"]\n",
        &[("s/lint.sh", &format!("touch {}/trusted\n", m.display()))],
    );
    commit_edit(&env, &proj, 1);
    assert!(m.join("trusted").exists(), "the trusted hook did not run");
    write(&proj, "s/lint.sh", &format!("touch {}/PWNED\n", m.display()));
    commit_edit(&env, &proj, 2);
    assert!(!m.join("PWNED").exists(), "./s/lint.sh changed after `vl hooks trust` and ran without a new trust");
}

/// BUG-702: build-tool indirection (threat 3) is recognised only when the
/// build tool is the program itself, or behind `env`. Behind any other
/// launcher (`nice make`, `timeout 60 make`, `nohup make`, `xargs make`,
/// `sh -c "make lint"`) it is not: `vl hooks trust` does not ask for
/// `--i-understand-indirect` and does not pin the `Makefile`, so a
/// teammate's later `Makefile` change runs.
#[test]
fn a_build_tool_behind_a_launcher_still_pins_its_files() {
    let env = Env::new();
    let m = markers(&env);
    let proj = env.dir("proj");
    env.ok(U, &proj, &["init"]);
    write(&proj, ".veilhooks", "[pre-commit]\nrun = [\"nice\", \"make\", \"-s\"]\n");
    write(&proj, "Makefile", &format!("all:\n\ttouch {}/trusted\n", m.display()));
    env.ok(U, &proj, &["commit", "--no-verify", "-m", "hooks"]);
    // Without --i-understand-indirect, as a user who was never told.
    let trust = env.vl(U, &proj, &["hooks", "trust", "--yes"]);
    if trust.status.success() {
        commit_edit(&env, &proj, 1);
        assert!(m.join("trusted").exists(), "the trusted hook did not run (is make installed?)");
        write(&proj, "Makefile", &format!("all:\n\ttouch {}/PWNED\n", m.display()));
        commit_edit(&env, &proj, 2);
        assert!(!m.join("PWNED").exists(), "the Makefile changed after `vl hooks trust` and its new recipe ran");
    }
}
