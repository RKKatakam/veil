//! Feature 7 (`.gitattributes`, line endings) against the system `git`:
//! differential tests on generated trees.
//!
//! * `git check-attr -a` versus [`Attrs::assigned`], with patterns and
//!   precedence across nested files, macros and the local file;
//! * `git add` (blob bytes) versus Veil's recorded bytes, and `git
//!   checkout` (working-tree bytes) versus Veil's checkout, with
//!   `core.autocrlf=false`, for every attribute combination (threat 9).
//!   Where Veil refuses a lossy conversion (mixed line endings, a lone CR),
//!   which Git performs with a warning, Veil records the bytes unchanged.
//!
//! Skipped when `git` is not installed.

mod adversarial_support;

use std::{
    io::Write,
    path::Path,
    process::{Command, Stdio},
    sync::Arc,
};

use adversarial_support::*;
use veil_core::{
    attributes::{to_odb, to_worktree, Attrs, BackendSource, State, ToOdb},
    vfs::DiskBackend,
    StorageBackend, VPath,
};

fn have_git() -> bool {
    Command::new("git").arg("--version").output().is_ok_and(|o| o.status.success())
}

fn git(dir: &Path, args: &[&str], stdin: Option<&[u8]>) -> Vec<u8> {
    let home = dir.join(".home");
    std::fs::create_dir_all(&home).unwrap();
    let mut c = Command::new("git");
    c.current_dir(dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &home)
        .env("GIT_AUTHOR_NAME", "Gita Hub")
        .env("GIT_AUTHOR_EMAIL", "gita@example.com")
        .env("GIT_COMMITTER_NAME", "Gita Hub")
        .env("GIT_COMMITTER_EMAIL", "gita@example.com")
        .args([
            "-c",
            "core.autocrlf=false",
            "-c",
            "core.eol=lf",
            "-c",
            "core.safecrlf=false",
            "-c",
            "core.ignorecase=false",
            "-c",
            "init.defaultBranch=main",
        ])
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = c.spawn().unwrap();
    {
        let mut si = child.stdin.take().unwrap();
        if let Some(d) = stdin {
            si.write_all(d).unwrap();
        }
    }
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    out.stdout
}

/// A small deterministic generator (xorshift).
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn pick<'a, T>(&mut self, v: &'a [T]) -> &'a T {
        &v[self.below(v.len())]
    }
}

const PATTERNS: &[&str] = &[
    "*",
    "*.txt",
    "*.c",
    "a*",
    "?.md",
    "[ab]*",
    "[!a]*.txt",
    "[^b]*",
    "sub/*",
    "/top.txt",
    "top.txt",
    "sub/**",
    "**/deep.txt",
    "sub/**/x.c",
    "a**/b.txt",
    "*/x.c",
    "\"quoted name.txt\"",
    "\"q\\164.md\"",
    "dir/",
    "!neg",
    "\\!bang",
    "**",
    "x[[:digit:]].txt",
    "*.[ch]",
    "sub/*.txt",
    "deep/*",
    "/deep/*",
    "*.TXT",
    "a/b.txt",
    "x.c/",
    "[a-c]?.c",
    "**/*.md",
    "s*b/a.txt",
];

const ATTRS: &[&str] = &[
    "text",
    "-text",
    "!text",
    "text=auto",
    "text=input",
    "eol=lf",
    "eol=crlf",
    "eol=bogus",
    "binary",
    "-binary",
    "-diff",
    "diff=foo",
    "merge=union",
    "-merge",
    "merge=text",
    "crlf",
    "-crlf",
    "crlf=input",
    "mymacro",
    "-mymacro",
    "foo=bar",
    "filter=lfs",
    "linguist-generated",
    "!eol",
];

const PATHS: &[&str] = &[
    "top.txt",
    "a.txt",
    "b.c",
    "x1.txt",
    "x.c",
    "quoted name.txt",
    "qt.md",
    "a.md",
    "A.TXT",
    "sub/a.txt",
    "sub/x.c",
    "sub/top.txt",
    "sub/deep/x.c",
    "sub/deep/deep.txt",
    "sub/deep/more/x.c",
    "dir/f",
    "other/deep.txt",
    "deep/a.c",
    "a/b.txt",
    "ab/c/b.txt",
    "ax/y/b.txt",
    "!bang",
    "!neg",
    "neg",
    "bb.c",
    "c1.c",
    "sub/sub/a.txt",
    "x.c/y",
];

fn gen_file(rng: &mut Rng, macros: bool) -> String {
    let mut s = String::new();
    if macros && rng.below(2) == 0 {
        let m = ["text eol=crlf", "-text", "binary", "text -diff", "mymacro2"];
        s.push_str(&format!("[attr]mymacro {}\n", rng.pick(&m)));
        if rng.below(3) == 0 {
            s.push_str("[attr]mymacro2 eol=lf\n");
        }
    }
    for _ in 0..rng.below(7) {
        if rng.below(10) == 0 {
            s.push_str("# a comment\n");
        }
        let pat = rng.pick(PATTERNS);
        let mut line = String::from(*pat);
        for _ in 0..1 + rng.below(3) {
            line.push(if rng.below(4) == 0 { '\t' } else { ' ' });
            line.push_str(rng.pick(ATTRS));
        }
        if rng.below(12) == 0 {
            line.push_str(" inv@lid");
        }
        if rng.below(8) == 0 {
            line.push('\r');
        }
        s.push_str(&line);
        s.push('\n');
    }
    s
}

fn git_check_attr(dir: &Path, paths: &[&str]) -> Vec<Vec<(String, String)>> {
    let mut input = Vec::new();
    for p in paths {
        input.extend_from_slice(p.as_bytes());
        input.push(0);
    }
    let out = git(dir, &["check-attr", "-a", "-z", "--stdin"], Some(&input));
    let parts: Vec<&[u8]> = out.split(|&c| c == 0).collect();
    let mut res: Vec<Vec<(String, String)>> = vec![Vec::new(); paths.len()];
    let mut i = 0;
    while i + 2 < parts.len() {
        let path = String::from_utf8_lossy(parts[i]).into_owned();
        let k = paths.iter().position(|p| **p == path).expect("a path we asked about");
        res[k].push((String::from_utf8_lossy(parts[i + 1]).into_owned(), String::from_utf8_lossy(parts[i + 2]).into_owned()));
        i += 3;
    }
    for r in &mut res {
        r.sort();
    }
    res
}

fn veil_check_attr(attrs: &Attrs, paths: &[&str]) -> Vec<Vec<(String, String)>> {
    paths
        .iter()
        .map(|p| {
            let mut v: Vec<(String, String)> = attrs
                .assigned(&VPath::new(p).unwrap())
                .into_iter()
                .filter(|(_, s)| *s != State::Unspecified)
                .map(|(n, s)| (n.to_string(), s.display().to_string()))
                .collect();
            v.sort();
            v
        })
        .collect()
}

#[test]
fn check_attr_agrees_with_git_on_generated_trees() {
    if !have_git() {
        eprintln!("git not installed; skipped");
        return;
    }
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    for case in 0..120 {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        git(dir, &["init", "-q"], None);
        let root = gen_file(&mut rng, true);
        let sub_macros = rng.below(3) == 0;
        let sub = gen_file(&mut rng, sub_macros);
        let deep = gen_file(&mut rng, false);
        let local = if rng.below(3) == 0 { Some(gen_file(&mut rng, true)) } else { None };
        std::fs::write(dir.join(".gitattributes"), &root).unwrap();
        std::fs::create_dir_all(dir.join("sub/deep")).unwrap();
        std::fs::write(dir.join("sub/.gitattributes"), &sub).unwrap();
        std::fs::write(dir.join("sub/deep/.gitattributes"), &deep).unwrap();
        if let Some(l) = &local {
            std::fs::create_dir_all(dir.join(".git/info")).unwrap();
            std::fs::write(dir.join(".git/info/attributes"), l).unwrap();
        }
        let disk = DiskBackend::new(dir);
        let attrs = Attrs::with_source(Box::new(BackendSource(&disk)), local.as_deref().map(str::as_bytes));
        let want = git_check_attr(dir, PATHS);
        let got = veil_check_attr(&attrs, PATHS);
        for (i, p) in PATHS.iter().enumerate() {
            assert_eq!(
                got[i], want[i],
                "case {case}, path {p:?}\nroot:\n{root}\nsub:\n{sub}\nsub/deep:\n{deep}\nlocal:\n{local:?}"
            );
        }
    }
}

/// Content shapes the conversion tests draw from.
fn gen_content(rng: &mut Rng) -> Vec<u8> {
    let mut out = Vec::new();
    let kind = rng.below(8);
    let lines = rng.below(6);
    for i in 0..lines {
        out.extend_from_slice(format!("line {i}").as_bytes());
        let eol: &[u8] = match kind {
            0 => b"\n",
            1 => b"\r\n",
            2 => {
                if rng.below(2) == 0 {
                    b"\n"
                } else {
                    b"\r\n"
                }
            }
            3 => {
                if i == 0 {
                    b"\r"
                } else {
                    b"\r\n"
                }
            }
            4 => b"\r\n",
            5 => b"\r\n",
            _ => b"\n",
        };
        out.extend_from_slice(eol);
        if kind == 4 && i == 0 {
            out.push(0);
        }
        if kind == 5 && i == 0 {
            out.extend_from_slice(&[1, 2, 3, 4, 5, 6]);
        }
    }
    if rng.below(5) == 0 {
        out.extend_from_slice(b"no final newline");
    }
    out
}

const LINE_ATTRS: &[&str] = &[
    "",
    "text",
    "-text",
    "text=auto",
    "text eol=crlf",
    "text eol=lf",
    "eol=crlf",
    "eol=lf",
    "text=auto eol=crlf",
    "text=auto eol=lf",
    "binary",
    "binary eol=crlf",
    "-text eol=crlf",
    "crlf",
    "-crlf",
    "crlf=input",
    "crlf=input eol=crlf",
];

#[test]
fn line_endings_agree_with_git_add_and_checkout() {
    if !have_git() {
        eprintln!("git not installed; skipped");
        return;
    }
    let mut rng = Rng(0x2545_f491_4f6c_dd1d);
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    git(dir, &["init", "-q"], None);
    let mut ga = String::new();
    let mut files: Vec<(String, Vec<u8>, &str)> = Vec::new();
    for (i, a) in LINE_ATTRS.iter().enumerate() {
        for j in 0..14 {
            let name = format!("f{i}_{j}.dat");
            ga.push_str(&format!("{name} {a}\n"));
            files.push((name, gen_content(&mut rng), a));
        }
    }
    std::fs::write(dir.join(".gitattributes"), &ga).unwrap();
    for (n, c, _) in &files {
        std::fs::write(dir.join(n), c).unwrap();
    }
    git(dir, &["add", "-A"], None);
    let disk = DiskBackend::new(dir);
    let attrs = Attrs::with_source(Box::new(BackendSource(&disk)), None);
    let mut converted = 0;
    let mut lossy = 0;
    for (n, c, a) in &files {
        let blob = git(dir, &["cat-file", "blob", &format!(":{n}")], None);
        let conv = attrs.for_path(&VPath::new(n).unwrap()).conversion;
        match to_odb(c, conv, || false) {
            ToOdb::Unchanged => assert_eq!(&blob, c, "{n} ({a}): Veil records unchanged, Git converted"),
            ToOdb::Converted(v) => {
                converted += 1;
                assert_eq!(blob, v, "{n} ({a}): recorded bytes differ from Git's blob")
            }
            ToOdb::Lossy(_) => {
                // Git converts with a warning; Veil keeps the bytes.
                lossy += 1;
            }
        }
    }
    assert!(converted > 10 && lossy > 0, "the generator covers both: {converted} converted, {lossy} lossy");
    // Checkout: Git writes the blob converted for the working tree.
    git(dir, &["commit", "-q", "-m", "x", "--no-gpg-sign"], None);
    for (n, _, _) in &files {
        std::fs::remove_file(dir.join(n)).unwrap();
    }
    git(dir, &["checkout", "--", "."], None);
    for (n, _, a) in &files {
        let blob = git(dir, &["cat-file", "blob", &format!("HEAD:{n}")], None);
        let conv = attrs.for_path(&VPath::new(n).unwrap()).conversion;
        let want = std::fs::read(dir.join(n)).unwrap();
        let got = to_worktree(&blob, conv).unwrap_or(blob.clone());
        assert_eq!(got, want, "{n} ({a}): checkout bytes differ from Git's");
    }
}

#[test]
fn snapshot_and_checkout_agree_with_git() {
    // The same through a Veil snapshot and checkout of a MemoryBackend
    // working copy: recorded blobs equal Git's where the conversion is
    // lossless, and the checked-out copy equals Git's working tree.
    if !have_git() {
        eprintln!("git not installed; skipped");
        return;
    }
    let mut rng = Rng(0x1234_5678_9abc_def1);
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    git(dir, &["init", "-q"], None);
    let (mut repo, fs, _) = new_repo("alice");
    let mut ga = String::new();
    let mut files = Vec::new();
    for (i, a) in LINE_ATTRS.iter().enumerate() {
        for j in 0..6 {
            let name = format!("d{}/g{i}_{j}.txt", j % 2);
            ga.push_str(&format!("{name} {a}\n"));
            files.push((name, gen_content(&mut rng), *a));
        }
    }
    std::fs::write(dir.join(".gitattributes"), &ga).unwrap();
    fs.write(&p(".gitattributes"), ga.as_bytes()).unwrap();
    for (n, c, _) in &files {
        std::fs::create_dir_all(dir.join(n).parent().unwrap()).unwrap();
        std::fs::write(dir.join(n), c).unwrap();
        fs.write(&p(n), c).unwrap();
    }
    git(dir, &["add", "-A"], None);
    let s = snap(&mut repo, &*fs);
    for (n, c, a) in &files {
        let blob = git(dir, &["cat-file", "blob", &format!(":{n}")], None);
        let rec = read_at(&repo, &s, n);
        let attrs = Attrs::for_backend(repo.store(), &*fs);
        let conv = attrs.for_path(&p(n)).conversion;
        match to_odb(c, conv, || false) {
            ToOdb::Lossy(_) => assert_eq!(&rec, c, "{n} ({a}): a lossy conversion must record the bytes unchanged"),
            _ => assert_eq!(rec, blob, "{n} ({a}): recorded bytes differ from Git's blob"),
        }
    }
    // A fresh checkout of the snapshot into an empty working copy.
    let fresh = Arc::new(veil_core::MemoryBackend::new());
    let tree = repo.snapshot(&s).unwrap().tree;
    repo.checkout_tree(&*fresh, None, &tree).unwrap();
    git(dir, &["commit", "-q", "-m", "x", "--no-gpg-sign"], None);
    for (n, _, _) in &files {
        std::fs::remove_file(dir.join(n)).unwrap();
    }
    git(dir, &["checkout", "--", "."], None);
    for (n, c, a) in &files {
        let git_wt = std::fs::read(dir.join(n)).unwrap();
        let ours = fresh.read(&p(n)).unwrap();
        let conv = Attrs::for_backend(repo.store(), &*fs).for_path(&p(n)).conversion;
        if matches!(to_odb(c, conv, || false), ToOdb::Lossy(_)) {
            // Recorded as is, so checked out as is (Git's blob differs).
            continue;
        }
        assert_eq!(ours, git_wt, "{n} ({a}): checked-out bytes differ from Git's working tree");
    }
}
