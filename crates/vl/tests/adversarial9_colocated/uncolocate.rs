//! BUG-744: `vl git uncolocate` drops every guard and warns about none of
//! the untracked protected files it exposes.

use crate::*;

#[test]
fn bug744_uncolocate_keeps_protected_files_out_of_git_add() {
    need_git!();
    let env = Env::new();
    let dir = env.project("p");
    env.write(&dir, ".env", "ISOLATED-MARKER-3\n");
    env.ok(&dir, &["status"]);
    env.ok(&dir, &["git", "uncolocate"]);
    let _ = env.git(&dir, &["add", "-A"]);
    let staged = env.git_ok(&dir, &["ls-files"]);
    for p in [".env", "secrets/db.yml", ".veil/"] {
        assert!(!staged.contains(p), "git add -A after uncolocate staged {p}:\n{staged}");
    }
}
