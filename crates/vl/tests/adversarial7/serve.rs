//! `vl serve --local`.

use std::{
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    process::Child,
    time::Duration,
};

use crate::{
    adversarial_support::{text, wait_for, Env},
    U,
};

/// A running `vl serve --local`, killed when dropped.
struct Server {
    child: Child,
}

impl Server {
    fn start(env: &Env, dir: &Path) -> Server {
        let mut child = env.spawn(U, dir, &["serve", "--local"]);
        let sock: PathBuf = dir.join(".veil/local/sock");
        let up = wait_for(Duration::from_secs(20), || UnixStream::connect(&sock).is_ok());
        if let Ok(Some(_)) = child.try_wait() {
            panic!("vl serve exited early:\n{}", text(&child.wait_with_output().unwrap()));
        }
        assert!(up, "vl serve did not start");
        Server { child }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The server keeps only its repository's path (`Server.root`,
/// `serve.rs:288`) and opens it afresh per request through `Ctx::open`,
/// whose `find_root` walks upward (`serve.rs:1003`, `ctx.rs:253`); its
/// liveness check looks at the socket through the `.veil/local` directory
/// handle, which moves with the repository (`serve.rs:446`). After
/// `mv proj proj-old` and a new repository at `proj`, the server keeps
/// answering on `proj-old/.veil/local/sock`, and every request reads and
/// writes the repository now at `proj`: a `commit` sent from `proj-old`
/// lands in the newcomer, snapshotting and checking out its working copy.
/// (With nothing at the old path, the nearest enclosing repository is
/// served.) The client cannot tell.
#[test]
#[ignore = "BUG-485: a moved repository's server serves whatever repository is at its old path"]
fn a_moved_repositorys_server_never_serves_another_repository() {
    let env = Env::new();
    let proj = env.project(U, "proj", &[("old.txt", "old\n")]);
    let server = Server::start(&env, &proj);
    let moved = env.root.join("proj-old");
    std::fs::rename(&proj, &moved).unwrap();
    let newcomer = env.project(U, "proj", &[("new.txt", "new\n")]);
    // Past the server's once-a-second socket check.
    std::thread::sleep(Duration::from_millis(2500));
    let out = env.vl(U, &moved, &["serve", "--call", "commit", r#"{"message":"meant for old"}"#]);
    let log = env.stdout(U, &newcomer, &["--no-snapshot", "log"]);
    drop(server);
    assert!(!log.contains("meant for old"), "the request was carried out in another repository:\n{}\n{log}", text(&out));
}

/// Control: the same `commit` before the move lands where it was sent.
#[test]
fn a_served_commit_lands_in_the_served_repository() {
    let env = Env::new();
    let proj = env.project(U, "proj", &[("old.txt", "old\n")]);
    let server = Server::start(&env, &proj);
    let out = env.vl(U, &proj, &["serve", "--call", "commit", r#"{"message":"meant for proj"}"#]);
    assert!(out.status.success(), "{}", text(&out));
    drop(server);
    assert!(env.stdout(U, &proj, &["--no-snapshot", "log"]).contains("meant for proj"));
}

/// The command line cannot pass a NUL in `-m` (an argument is a C string),
/// but `describe`, `commit` and `new` over JSON-RPC take any JSON string
/// (`serve.rs:786-812`, `message: String`) and record it. The description
/// then reaches the Git export, where a NUL in a commit object is refused
/// by any Git remote that checks objects (`receive.fsckObjects`,
/// `nulInCommit`), and `vl git push` reports that as "has commits you don't
/// have". A message the CLI could not have given should be refused.
#[test]
#[ignore = "BUG-486: serve records a NUL byte in a description that the CLI cannot give"]
fn serve_refuses_a_nul_in_a_message() {
    let env = Env::new();
    let proj = env.project(U, "proj", &[("a.txt", "a\n")]);
    let server = Server::start(&env, &proj);
    let out = env.vl(U, &proj, &["serve", "--call", "describe", r#"{"rev":"@-","message":"evil\u0000nul"}"#]);
    drop(server);
    let log = env.stdout(U, &proj, &["--no-snapshot", "log", "--json"]);
    assert!(!out.status.success() && !log.contains("\\u0000"), "a NUL was recorded: {}\n{log}", text(&out));
}
