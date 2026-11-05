//! BUG-755: what Git does to a file on checkout (here the `ident`
//! attribute expanding `$Id$`) is recorded by Veil as the member's edit.
//! Fixed: `info/attributes` (which outranks every `.gitattributes`) turns
//! `ident` off in the colocated work tree.

use crate::*;

#[test]
fn bug755_a_git_checkout_transform_is_not_recorded_as_an_edit() {
    need_git!();
    let env = Env::new();
    let dir = env.project("p");
    let (_remote, other) = upstream(&env, &dir, "p");
    env.ok(&dir, &["status"]);
    contributor_pushes(&env, &other, &[(".gitattributes", "*.txt ident\n"), ("v.txt", "version $Id$\n")]);
    env.git_ok(&dir, &["pull", "-q", "--ff-only"]);
    let st = env.ok(&dir, &["status"]);
    assert!(!st.contains("v.txt"), "Veil recorded Git's expansion as an edit:\n{st}");
}
