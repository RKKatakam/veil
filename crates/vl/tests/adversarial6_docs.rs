//! Round-6 (Fable): claims in the user guide checked against the code.
//!
//! Every `#[ignore = "BUG-NNN: …"]` test asserts the documented behaviour
//! and currently fails; see `docs/BUGS.md` ("Round 6 findings (Fable)").

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(rel: &str) -> String {
    std::fs::read_to_string(repo_root().join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

/// The README says `vl doctor --remotes` connects to SSH remotes and
/// compares their clock (and `doctor.rs` has `check_ssh_remote`, added by
/// the SFTP hardening wave). The maintenance guide still tells users that
/// "SSH remotes are not contacted by `doctor` in 1.0", so an admin
/// debugging a remote lock or clock-skew problem is sent to `vl pull`
/// instead of the check that exists for exactly that.
#[test]
fn the_guide_does_not_say_doctor_skips_ssh_remotes() {
    let doctor = read("crates/vl/src/doctor.rs");
    assert!(doctor.contains("fn check_ssh_remote"), "doctor no longer checks SSH remotes; update this test");
    let guide = read("docs/guide/maintenance.md");
    assert!(
        !guide.contains("SSH remotes are not contacted"),
        "docs/guide/maintenance.md still says SSH remotes are not contacted by `vl doctor`"
    );
}

/// Control: the README documents the SSH clock check that the code has.
#[test]
fn the_readme_documents_the_ssh_clock_check() {
    let readme = read("README.md");
    assert!(readme.contains("for SSH remotes, also that the server's clock"));
}
