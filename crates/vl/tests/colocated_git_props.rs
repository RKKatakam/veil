//! Colocated Git mode, property test (design threat 7, the round's top
//! adversarial item): random interleavings of `git` and `vl` commands in
//! one directory.
//!
//! Git side: `add -A`, `commit`, `commit -a`, branch `checkout`, `stash`,
//! `stash -u`, `stash pop`, `reset --hard`, `reset --soft HEAD~1`,
//! `rebase`, and the hostile and destructive ones of the round-9 fix wave:
//! `git pull` of a contributor's commit writing `.veil/…` (a forged
//! accepted-policy pin with a weakened `.veilpolicy`) or a file named
//! `.veil`, a `.gitignore` negating Veil's excludes (`!secrets/`, `!.env`,
//! `!*.md`), `git clean -ffdx`, `git stash -a`. Veil side: edits of public,
//! cloaked and isolated files, edits on a cloaked line (workspace `p`),
//! `vl new`, `vl commit`, `vl restore`, `vl cloak`, an embargoed merge,
//! `vl ws switch`, `vl status`.
//!
//! Every sealed write carries a unique marker. After **every** step:
//!
//! * **I0** the Veil repository (`.git/veil`) is there and its
//!   accepted-policy pin is the one it started with: nothing Git wrote
//!   decides policy;
//! * **I1** no object of `.git` (loose or packed, `git cat-file
//!   --batch-all-objects`) holds a marker. Once Git was told to take
//!   protected files anyway (a `.gitignore` negation, `git stash -a`: the
//!   guide's documented limitations), the weaker form: every branch whose
//!   history holds a marker is refused by the `pre-push` gate, so whatever
//!   `git push` could send is clean;
//!
//! at the end of every case:
//!
//! * **I1** `vl git push` to a bare remote and `vl push` to a public Veil
//!   mirror carry no marker (the remote's objects; a clone of the mirror
//!   by another member);
//! * **I2** no snapshot a workspace or tag names records a public file
//!   holding a marker;
//! * **I3** the operation log and `vl fsck` are intact;
//! * **I4** after `git stash clear`, `git reset` and
//!   `vl git colocate --prune`, `.git` holds no marker at all.
//!
//! `VEIL_COLOCATED_CASES` sets the number of cases (default 10).

mod colocated_support;

use std::path::Path;

use colocated_support::*;
use proptest::prelude::*;

const OPS: u8 = 30;

struct World<'a> {
    env: &'a Env,
    dir: std::path::PathBuf,
    markers: Vec<String>,
    n: usize,
    in_p: bool,
    embargoed: bool,
    log: Vec<String>,
    /// Git was told to take protected files (a negation, `stash -a`).
    leaky: bool,
    /// The contributor's clone of the Git remote.
    contributor: std::path::PathBuf,
    hostile: usize,
}

impl World<'_> {
    fn mark(&mut self, kind: &str) -> String {
        self.n += 1;
        let m = format!("SEALMARK-{kind}-{}", self.n);
        self.markers.push(m.clone());
        m
    }

    fn vl(&mut self, args: &[&str]) {
        self.log.push(format!("vl {}", args.join(" ")));
        let out = self.env.vl(&self.dir, args);
        let t = text(&out);
        if std::env::var_os("VEIL_COLOCATED_TRACE").is_some() {
            eprintln!("$ vl {}\n{t}", args.join(" "));
        }
        assert!(!t.contains("panicked"), "vl {args:?} panicked:\n{t}\n{}", self.log.join("\n"));
        for m in &self.markers {
            assert!(!t.contains(m.as_str()), "vl {args:?} printed sealed content {m}:\n{t}");
        }
    }

    fn git(&mut self, args: &[&str]) {
        self.log.push(format!("git {}", args.join(" ")));
        let out = self.env.git(&self.dir, args);
        if std::env::var_os("VEIL_COLOCATED_TRACE").is_some() {
            eprintln!("$ git {} ({})\n{}", args.join(" "), out.status, text(&out));
        }
    }

    fn write(&mut self, path: &str, text: &str) {
        self.log.push(format!("write {path}"));
        self.env.write(&self.dir, path, text);
    }

    fn step(&mut self, op: u8, i: usize) {
        match op {
            0 => self.git(&["add", "-A"]),
            1 => self.git(&["commit", "-q", "-m", &format!("git {i}")]),
            2 => self.git(&["commit", "-q", "-a", "-m", &format!("git -a {i}")]),
            3 => {
                let b = format!("b{}", i % 3);
                let exists = self.env.git(&self.dir, &["rev-parse", "-q", "--verify", &format!("refs/heads/{b}")]).status.success();
                if exists {
                    self.git(&["checkout", "-q", &b]);
                } else {
                    self.git(&["checkout", "-q", "-b", &b]);
                }
            }
            4 => self.git(&["checkout", "-q", "main"]),
            5 => self.git(&["stash", "-q"]),
            6 => self.git(&["stash", "-q", "-u"]),
            7 => self.git(&["stash", "pop", "-q"]),
            8 => self.git(&["reset", "-q", "--hard"]),
            9 => self.git(&["reset", "-q", "--soft", "HEAD~1"]),
            10 => {
                let ok = self.env.git(&self.dir, &["rebase", "-q", "main"]).status.success();
                self.log.push("git rebase main".into());
                if !ok {
                    self.git(&["rebase", "--abort"]);
                }
            }
            11 => self.write(&format!("notes/n{}.md", i % 4), &format!("public note {i}\n")),
            12 | 13 => {
                // Cloaked by the policy, or an edit on the cloaked line.
                let m = self.mark("cloak");
                self.write(&format!("secrets/s{}.yml", i % 3), &format!("token: {m}\n"));
            }
            14 => {
                let m = self.mark("iso");
                self.write(".env", &format!("API_KEY={m}\n"));
            }
            15 => {
                if self.in_p {
                    let m = self.mark("line");
                    self.write("README.md", &format!("hello\n{m}\n"));
                } else {
                    self.write("README.md", &format!("hello {i}\n"));
                }
            }
            16 => self.vl(&["new"]),
            17 => self.vl(&["commit", "-m", &format!("veil {i}")]),
            18 => self.vl(&["restore", "README.md"]),
            19 => {
                let p = format!("notes/n{}.md", i % 4);
                if self.dir.join(&p).exists() && !self.in_p {
                    self.vl(&["cloak", &p]);
                } else {
                    self.vl(&["status"]);
                }
            }
            20 => {
                self.vl(&["ws", "switch", if self.in_p { "default" } else { "p" }]);
                self.in_p = !self.in_p;
            }
            21 => self.embargo(),
            22 => self.vl(&["tag", "set", "main", "-r", "@-", "--allow-backwards"]),
            24 => {
                // A `.gitignore` that outranks Veil's excludes.
                self.leaky = true;
                self.write(".gitignore", "!secrets/\n!.env\n!*.md\n");
            }
            25 => self.hostile_pull(i, true),
            26 => self.hostile_pull(i, false),
            27 => self.git(&["clean", "-q", "-ffdx"]),
            28 => {
                self.leaky = true;
                self.git(&["stash", "-q", "-a"]);
            }
            _ => self.vl(&["status"]),
        }
    }

    /// A contributor pushes a hostile commit to the Git remote, and it is
    /// pulled here with plain Git: a forged `.veil/local/accepted-policy`
    /// with a `.veilpolicy` making `secrets/` public, or a file `.veil`.
    fn hostile_pull(&mut self, i: usize, pin: bool) {
        self.hostile += 1;
        let c = self.contributor.clone();
        let _ = self.env.git(&c, &["pull", "-q", "--no-rebase", "--no-edit", "origin", "main"]);
        if pin {
            if c.join(".veil").is_file() {
                let _ = self.env.git(&c, &["rm", "-q", "--cached", ".veil"]);
                let _ = std::fs::remove_file(c.join(".veil"));
            }
            let policy = std::fs::read_to_string(c.join(".veilpolicy")).unwrap_or_default().replace("secrets/ cloak", "secrets/ public!");
            self.env.write(&c, ".veilpolicy", &policy);
            self.env.write(&c, ".veil/local/accepted-policy", "secrets/ public!\n");
            let _ = self.env.git(&c, &["add", "-f", ".veilpolicy", ".veil"]);
        } else {
            let _ = self.env.git(&c, &["rm", "-rq", "--cached", ".veil"]);
            let _ = std::fs::remove_dir_all(c.join(".veil"));
            self.env.write(&c, ".veil", &format!("hostile {i}\n"));
            let _ = self.env.git(&c, &["add", "-f", ".veil"]);
        }
        let _ = self.env.git(&c, &["commit", "-q", "-m", &format!("hostile {i}")]);
        let _ = self.env.git(&c, &["push", "-q", "origin", "HEAD:main"]);
        let ok = self.env.git(&self.dir, &["pull", "-q", "--no-rebase", "--no-edit", "origin", "main"]).status.success();
        self.log.push(format!("git pull (hostile {}, {ok})", if pin { "pin" } else { ".veil file" }));
        if !ok {
            let _ = self.env.git(&self.dir, &["merge", "--abort"]);
        }
    }

    /// An embargoed merge of a fix into `main` (once per case).
    fn embargo(&mut self) {
        if self.embargoed || self.in_p {
            self.vl(&["status"]);
            return;
        }
        self.embargoed = true;
        let m = self.mark("emb");
        self.vl(&["ws", "new", "fix", "-r", "main", "--cloak", "team"]);
        self.vl(&["ws", "switch", "fix"]);
        self.write("auth.rs", &format!("fn check() {{ {m}() }}\n"));
        self.vl(&["commit", "-m", "the fix"]);
        self.vl(&["ws", "switch", "default"]);
        self.vl(&["merge", "fix@-", "--into", "main", "--embargo", "-m", "Fix"]);
    }

    /// I0 and I1 after a step.
    fn check_git(&mut self, when: &str) {
        let git = self.dir.join(".git");
        assert!(git.join("veil/repo.json").is_file(), "I0 {when}: the Veil repository is gone\n{}", self.log.join("\n"));
        // (`vl cloak` strengthens it: the member's own edit.)
        let pin = std::fs::read_to_string(git.join("veil/local/accepted-policy")).unwrap_or_default();
        assert!(
            pin.lines().any(|l| l == "secrets/ cloak") && !pin.lines().any(|l| l.starts_with("secrets/ public")),
            "I0 {when}: the accepted-policy pin is not the member's:\n{pin}\n{}",
            self.log.join("\n")
        );
        if self.leaky {
            return self.check_pushable(when);
        }
        let dump = objects(self.env, &git);
        for m in &self.markers {
            assert!(!contains(&dump, m), "I1 {when}: .git holds {m}\n{}", self.log.join("\n"));
        }
    }

    /// I1, weak form: a branch whose history holds a marker is refused by
    /// the `pre-push` gate.
    fn check_pushable(&mut self, when: &str) {
        let refs = self.env.git_ok(&self.dir, &["for-each-ref", "--format=%(refname) %(objectname)", "refs/heads"]);
        for line in refs.lines() {
            let Some((name, oid)) = line.split_once(' ') else { continue };
            let list = self.env.git(&self.dir, &["rev-list", "--objects", oid]);
            let mut input = String::new();
            for l in String::from_utf8_lossy(&list.stdout).lines() {
                input.push_str(l.split(' ').next().unwrap_or(""));
                input.push('\n');
            }
            let out = {
                use std::io::Write;
                let mut child = self
                    .env
                    .git_cmd(&self.dir, &["cat-file", "--batch"])
                    .stdin(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::piped())
                    .spawn()
                    .unwrap();
                let mut stdin = child.stdin.take().unwrap();
                let w = std::thread::spawn(move || stdin.write_all(input.as_bytes()));
                let out = child.wait_with_output().unwrap();
                let _ = w.join();
                out.stdout
            };
            if !self.markers.iter().any(|m| contains(&out, m)) {
                continue;
            }
            let zero = "0".repeat(40);
            let gate = {
                use std::io::Write;
                let mut child = self
                    .env
                    .vl_cmd(&self.dir, &["git", "check-push", "origin"])
                    .stdin(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .spawn()
                    .unwrap();
                let mut stdin = child.stdin.take().unwrap();
                let line = format!("{name} {oid} {name} {zero}\n");
                let w = std::thread::spawn(move || stdin.write_all(line.as_bytes()));
                let out = child.wait_with_output().unwrap();
                let _ = w.join();
                out
            };
            assert!(
                !gate.status.success(),
                "I1 {when}: {name} holds sealed content and the pre-push gate lets it through\n{}",
                self.log.join("\n")
            );
        }
    }

    /// I1–I3 at the end of a case.
    fn check_end(&mut self, remote: &Path, mirror: &Path) {
        if self.in_p {
            self.vl(&["ws", "switch", "default"]);
            self.in_p = false;
        }
        let _ = self.env.git(&self.dir, &["rebase", "--abort"]);
        self.vl(&["status"]);
        self.vl(&["git", "push", "gh", "--force"]);
        self.vl(&["push", "mirror"]);
        let dump = objects(self.env, remote);
        for m in &self.markers {
            assert!(!contains(&dump, m), "I1: the Git remote holds {m}\n{}", self.log.join("\n"));
        }
        // A clone of the public mirror by someone without keys.
        let clone = self.env.root.join(format!("clone-{}", self.n));
        let out = self
            .env
            .vl_cmd(&self.env.root, &["clone", mirror.to_str().unwrap(), clone.to_str().unwrap()])
            .env("VEIL_HOME", self.env.root.join("home-bob"))
            .env("VEIL_USER", "bob")
            .output()
            .unwrap();
        if out.status.success() {
            let grep = std::process::Command::new("grep").args(["-r", "-l", "SEALMARK"]).arg(&clone).output().unwrap();
            assert!(grep.stdout.is_empty(), "I1: the public mirror carries sealed content: {}", text(&grep));
        }
        // I2: what workspaces and tags name.
        for rev in ["default@", "default@-", "p@", "p@-", "main"] {
            let ls = self.env.vl(&self.dir, &["ls", "-r", rev]);
            if !ls.status.success() {
                continue;
            }
            for line in String::from_utf8_lossy(&ls.stdout).lines() {
                let f: Vec<&str> = line.split_whitespace().collect();
                if f.len() < 3 || f[0] != "public" {
                    continue;
                }
                let path = f[2..].join(" ");
                let cat = self.env.vl(&self.dir, &["cat", &path, "-r", rev]);
                let body = String::from_utf8_lossy(&cat.stdout);
                for m in &self.markers {
                    assert!(!body.contains(m.as_str()), "I2: {rev} records public {path} holding {m}\n{}", self.log.join("\n"));
                }
            }
        }
        // I3.
        self.env.ok(&self.dir, &["op", "log", "-n", "5"]);
        let fsck = self.env.vl(&self.dir, &["fsck"]);
        assert!(fsck.status.success(), "I3: {}", text(&fsck));
        // I4: what Git was made to take leaves with the stashes, the index
        // and `--prune`.
        self.git(&["stash", "clear"]);
        self.git(&["reset", "-q"]);
        self.vl(&["status"]);
        self.vl(&["git", "colocate", "--prune"]);
        let dump = objects(self.env, &self.dir.join(".git"));
        for m in &self.markers {
            assert!(!contains(&dump, m), "I4: .git holds {m} after --prune\n{}", self.log.join("\n"));
        }
    }
}

fn run_case(ops: &[u8]) {
    let env = Env::new();
    let dir = env.project("p");
    let remote = env.bare("remote.git");
    let mirror = env.dir("mirror");
    env.ok(&dir, &["git", "remote", "add", "gh", remote.to_str().unwrap()]);
    env.ok(&dir, &["remote", "add", "mirror", mirror.to_str().unwrap(), "--public"]);
    env.ok(&dir, &["ws", "new", "p", "-r", "main", "--cloak", "team"]);
    // Git's own view of the same remote, and a contributor's clone of it.
    env.ok(&dir, &["git", "push", "gh"]);
    env.git_ok(&dir, &["remote", "add", "origin", remote.to_str().unwrap()]);
    env.git_ok(&dir, &["fetch", "-q", "origin"]);
    env.git_ok(&dir, &["branch", "-q", "-u", "origin/main", "main"]);
    let contributor = env.root.join("contributor");
    env.git_ok(&env.root, &["clone", "-q", remote.to_str().unwrap(), contributor.to_str().unwrap()]);
    let mut w = World {
        env: &env,
        dir,
        markers: vec!["CLOAKMARK-base".into()],
        n: 0,
        in_p: false,
        embargoed: false,
        log: Vec::new(),
        leaky: false,
        contributor,
        hostile: 0,
    };
    for (i, op) in ops.iter().enumerate() {
        w.step(*op, i);
        let when = format!("after step {i} ({})", w.log.last().cloned().unwrap_or_default());
        w.check_git(&when);
    }
    w.check_end(&remote, &mirror);
}

fn cases() -> u32 {
    std::env::var("VEIL_COLOCATED_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(10)
}

proptest! {
    #![proptest_config(ProptestConfig { cases: cases(), failure_persistence: None, ..ProptestConfig::default() })]

    #[test]
    fn git_and_vl_interleaved_never_leak_sealed_content(ops in prop::collection::vec(0u8..OPS, 6..16)) {
        run_case(&ops);
    }
}

/// Fixed sequences that once mattered (kept as regressions).
#[test]
fn known_interleavings_stay_clean() {
    // Cloaked-line edit, then Git moves HEAD and stashes.
    run_case(&[20, 15, 0, 2, 9, 5, 7, 20, 23]);
    // Policy-cloaked and isolated files, branch switches, commits on both sides.
    run_case(&[12, 14, 11, 0, 1, 3, 12, 17, 4, 2, 10, 23]);
    // An embargoed merge, then Git and Veil work on top.
    run_case(&[21, 16, 11, 0, 1, 22, 2, 8, 23]);
}

/// The round-9 routes (BUG-740…748), in fixed sequences.
#[test]
fn hostile_pulls_negations_clean_and_stash_stay_clean() {
    // A forged pin and a weakened policy pulled, then secrets written and
    // committed both ways.
    run_case(&[25, 23, 12, 0, 1, 17, 26, 23, 12, 2, 17, 23]);
    // A negating .gitignore, then Git takes what it un-hides.
    run_case(&[24, 17, 12, 14, 0, 1, 6, 23, 7, 2, 17, 23]);
    // `git clean -ffdx` and `git stash -a` on a cloaked line and off it.
    run_case(&[20, 15, 23, 27, 23, 28, 23, 7, 20, 12, 14, 23, 28, 27, 23]);
    // Found by this test (150 cases): under an embargo (frozen, so Git
    // manages no path) a pulled weakening of `.veilpolicy` was recorded as
    // the member's own edit by the follow's first snapshot, and replaced
    // the accepted-policy pin.
    run_case(&[15, 10, 23, 21, 27, 5, 25, 28, 25, 0, 17]);
}

/// The minimal case proptest found: a hostile pull that weakens the policy,
/// then `git reset --soft HEAD~1`, leaves the pulled policy as an uncommitted
/// edit that Veil accepts as the member's own.
#[test]
#[ignore = "BUG-759: a soft reset after a hostile pull makes the pulled policy look like the member's edit"]
fn bug759_a_soft_reset_after_a_hostile_pull_never_unseals_a_cloaked_file() {
    run_case(&[0, 25, 9, 0, 0, 0]);
}
