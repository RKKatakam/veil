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

/// Control: the README documents the SSH clock check that the code has.
#[test]
fn the_readme_documents_the_ssh_clock_check() {
    let readme = read("README.md");
    assert!(readme.contains("for SSH remotes, also that the server's clock"));
}
