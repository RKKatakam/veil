//! `vl --version` / `vl -V` report what a release must get right: the
//! package version and the repository format this binary reads and writes
//! (see docs/RELEASING.md).

use std::process::Command;

use veil_core::repo::REPO_FORMAT_VERSION;

fn vl(args: &[&str]) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_vl")).args(args).output().unwrap();
    assert!(out.status.success(), "vl {args:?} failed");
    String::from_utf8(out.stdout).unwrap()
}

#[test]
fn long_version_names_the_package_version_and_repository_format() {
    let out = vl(&["--version"]);
    let mut lines = out.lines();
    assert_eq!(lines.next(), Some(concat!("vl ", env!("CARGO_PKG_VERSION"))), "{out}");
    assert!(lines.next().is_some_and(|l| l.starts_with("commit: ")), "{out}");
    assert_eq!(lines.next(), Some(format!("repository format: {REPO_FORMAT_VERSION}").as_str()), "{out}");
    assert!(lines.next().is_some_and(|l| l.starts_with("target: ")), "{out}");
}

#[test]
fn short_version_names_the_repository_format() {
    let out = vl(&["-V"]);
    assert!(out.starts_with(concat!("vl ", env!("CARGO_PKG_VERSION"), " (commit ")), "{out}");
    assert!(out.trim_end().ends_with(&format!(", repository format {REPO_FORMAT_VERSION})")), "{out}");
}
