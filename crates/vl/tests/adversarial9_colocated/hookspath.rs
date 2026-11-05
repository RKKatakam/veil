//! BUG-753: a `core.hooksPath` set after colocation (a hook manager's
//! setup) turns both guards off, and only `vl git colocate --status` says
//! so.

use crate::*;

#[test]
fn bug753_ordinary_commands_warn_when_the_guards_are_inactive() {
    need_git!();
    let env = Env::new();
    let dir = env.project("p");
    std::fs::create_dir_all(dir.join(".hooks")).unwrap();
    env.git_ok(&dir, &["config", "core.hooksPath", ".hooks"]);
    let st = env.ok(&dir, &["status"]);
    assert!(st.contains("hooksPath"), "vl status says nothing about the inactive guards:\n{st}");
}
