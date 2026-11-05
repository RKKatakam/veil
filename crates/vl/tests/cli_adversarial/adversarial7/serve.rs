//! `vl serve --local`.

use std::{
    io::{BufRead, BufReader, Read, Write},
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    process::{Child, Command},
    time::{Duration, Instant},
};

use super::{
    adversarial_support::{text, wait_for, Env},
    U,
};

/// A running `vl serve --local`, killed when dropped.
struct Server {
    child: Child,
}

impl Server {
    fn start(env: &Env, dir: &Path) -> Server {
        Server::start_cmd(env.cmd(U, dir, &["serve", "--local"]), dir)
    }

    fn start_cmd(mut cmd: Command, dir: &Path) -> Server {
        let mut child = cmd.stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped()).spawn().unwrap();
        let sock: PathBuf = dir.join(".veil/local/sock");
        let up = wait_for(Duration::from_secs(20), || UnixStream::connect(&sock).is_ok());
        if let Ok(Some(_)) = child.try_wait() {
            panic!("vl serve exited early:\n{}", text(&child.wait_with_output().unwrap()));
        }
        assert!(up, "vl serve did not start");
        Server { child }
    }
}

impl Server {
    /// Wait up to `secs` for the server to exit on its own; its standard
    /// error if it did.
    fn exits_within(&mut self, secs: u64) -> Option<String> {
        if !wait_for(Duration::from_secs(secs), || matches!(self.child.try_wait(), Ok(Some(_)))) {
            return None;
        }
        let mut err = String::new();
        self.child.stderr.take().unwrap().read_to_string(&mut err).unwrap();
        Some(err)
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
fn serve_refuses_a_nul_in_a_message() {
    let env = Env::new();
    let proj = env.project(U, "proj", &[("a.txt", "a\n")]);
    let server = Server::start(&env, &proj);
    let out = env.vl(U, &proj, &["serve", "--call", "describe", r#"{"rev":"@-","message":"evil\u0000nul"}"#]);
    drop(server);
    let log = env.stdout(U, &proj, &["--no-snapshot", "log", "--json"]);
    assert!(!out.status.success() && !log.contains("\\u0000"), "a NUL was recorded: {}\n{log}", text(&out));
}

/// BUG-485, the other ways a path stops naming the server's repository:
/// the server stops (and says why) within its once-a-second check, rather
/// than serve whatever the path names now.
#[test]
fn a_server_stops_when_its_repository_or_socket_moves() {
    let env = Env::new();
    // The repository moved, nothing put in its place: the enclosing
    // directory is not served.
    let proj = env.project(U, "proj", &[("a.txt", "a\n")]);
    let mut server = Server::start(&env, &proj);
    std::fs::rename(&proj, env.root.join("moved")).unwrap();
    let err = server.exits_within(10).expect("the server kept running after its repository moved");
    assert!(err.contains("moved or replaced"), "{err}");

    // `.veil/local` moved inside the repository: the socket clients look
    // for is gone, though the server's directory handle still sees it.
    let proj = env.project(U, "proj2", &[("a.txt", "a\n")]);
    let mut server = Server::start(&env, &proj);
    std::fs::rename(proj.join(".veil/local"), proj.join(".veil/local-old")).unwrap();
    let err = server.exits_within(10).expect("the server kept running after its socket moved");
    assert!(err.contains("socket"), "{err}");

    // `.veil` replaced in place by another repository's.
    let proj = env.project(U, "proj3", &[("a.txt", "a\n")]);
    let other = env.project(U, "other", &[("b.txt", "b\n")]);
    let mut server = Server::start(&env, &proj);
    std::fs::rename(proj.join(".veil"), env.root.join("veil-old")).unwrap();
    std::fs::rename(other.join(".veil"), proj.join(".veil")).unwrap();
    let err = server.exits_within(10).expect("the server kept running after .veil was replaced");
    assert!(err.contains("moved or replaced"), "{err}");
    // And it did not leave its socket behind for a new server to trip on.
    let restarted = Server::start(&env, &proj);
    drop(restarted);
}

/// BUG-485: a request that arrives before the once-a-second check is
/// refused by the request's own check, and stops the server.
#[test]
fn a_request_after_a_move_is_refused_at_once() {
    let env = Env::new();
    let proj = env.project(U, "proj", &[("old.txt", "old\n")]);
    let mut server = Server::start(&env, &proj);
    // A connection made before the move goes with the server.
    let mut c = UnixStream::connect(proj.join(".veil/local/sock")).unwrap();
    std::fs::rename(&proj, env.root.join("proj-old")).unwrap();
    let newcomer = env.project(U, "proj", &[("new.txt", "new\n")]);
    c.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"commit\",\"params\":{\"message\":\"meant for old\"}}\n").unwrap();
    let mut answer = String::new();
    BufReader::new(&c).read_line(&mut answer).unwrap();
    assert!(answer.contains("\"error\"") && answer.contains("moved or replaced"), "{answer}");
    assert!(server.exits_within(10).is_some(), "the server kept running");
    let log = env.stdout(U, &newcomer, &["--no-snapshot", "log"]);
    assert!(!log.contains("meant for old"), "{log}");
}

/// A server whose connection timeouts are `idle`, `request` and `evict`
/// milliseconds.
fn start_with_timeouts(env: &Env, dir: &Path, idle: u64, request: u64, evict: u64) -> Server {
    let mut cmd = env.cmd(U, dir, &["serve", "--local"]);
    cmd.env("VEIL_SERVE_IDLE_MS", idle.to_string())
        .env("VEIL_SERVE_REQUEST_MS", request.to_string())
        .env("VEIL_SERVE_EVICT_MS", evict.to_string());
    Server::start_cmd(cmd, dir)
}

fn status_works(sock: &Path) -> bool {
    let Ok(mut c) = UnixStream::connect(sock) else { return false };
    c.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    if c.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"server.info\"}\n").is_err() {
        return false;
    }
    let mut line = String::new();
    BufReader::new(&c).read_line(&mut line).is_ok() && line.contains("\"result\"")
}

/// Was connection `c` refused or closed by the server (it sent something,
/// the `-32001` goodbye, or hung up)? `false` while it holds its slot.
fn hung_up(c: &UnixStream) -> bool {
    c.set_nonblocking(true).unwrap();
    let mut buf = [0u8; 256];
    let gone = !matches!((&*c).read(&mut buf), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock);
    c.set_nonblocking(false).unwrap();
    gone
}

/// BUG-495: 32 connections that never send (and one that sends half a
/// request) used to hold every slot forever, so the user's editor got
/// `-32001 too many clients` until the server restarted. With the default
/// timeouts, a newcomer takes the slot of a connection silent for 10 s.
#[test]
fn silent_connections_never_lock_other_clients_out() {
    let env = Env::new();
    let proj = env.project(U, "proj", &[("a.txt", "a\n")]);
    let server = Server::start(&env, &proj);
    let sock = proj.join(".veil/local/sock");
    let mut hogs: Vec<UnixStream> = Vec::new();
    let mut tries = 0;
    loop {
        // 31 connections that never send and one with half a request.
        hogs.clear();
        hogs.extend((0..31).map(|_| UnixStream::connect(&sock).unwrap()));
        let mut half = UnixStream::connect(&sock).unwrap();
        half.write_all(b"{\"jsonrpc\":\"2.0\",").unwrap();
        hogs.push(half);
        // Full: a newcomer is told so while the others have been quiet
        // briefly.
        std::thread::sleep(Duration::from_millis(500));
        let served = status_works(&sock);
        // Unless the hogs did not all get a slot: one was refused (the
        // connection `Server::start` probed with still held its slot on a
        // loaded machine) and tells us so. Then the observation is made
        // again; served at once with every hog in place is the bug.
        std::thread::sleep(Duration::from_millis(200));
        if !hogs.iter().any(hung_up) {
            assert!(!served, "the 33rd client was served at once");
            break;
        }
        tries += 1;
        assert!(tries < 5, "the hogs never all got a slot");
        hogs.clear();
        std::thread::sleep(Duration::from_millis(500));
    }
    // Past the eviction age, it is served.
    let start = Instant::now();
    assert!(wait_for(Duration::from_secs(25), || status_works(&sock)), "a newcomer is still locked out");
    assert!(start.elapsed() < Duration::from_secs(20));
    drop(server);
    drop(hogs);
}

/// BUG-495: a connection that never asks anything is closed after the
/// first-request timeout, and half a request after the request timeout
/// (told why); a connection between requests stays open.
#[test]
fn idle_and_incomplete_connections_time_out() {
    let env = Env::new();
    let proj = env.project(U, "proj", &[("a.txt", "a\n")]);
    let server = start_with_timeouts(&env, &proj, 400, 400, 60_000);
    let sock = proj.join(".veil/local/sock");
    let closed = |c: &mut UnixStream| {
        c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let mut out = String::new();
        let _ = c.read_to_string(&mut out);
        out
    };
    let mut silent = UnixStream::connect(&sock).unwrap();
    let start = Instant::now();
    assert_eq!(closed(&mut silent), "", "a silent connection is closed without a word");
    assert!(start.elapsed() < Duration::from_secs(5), "{:?}", start.elapsed());

    let mut half = UnixStream::connect(&sock).unwrap();
    half.write_all(b"{\"jsonrpc\":\"2.0\",").unwrap();
    let out = closed(&mut half);
    assert!(out.contains("-32600") && out.contains("incomplete"), "{out}");

    // After its first request, a client may stay quiet.
    let mut kept = UnixStream::connect(&sock).unwrap();
    kept.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"server.info\"}\n").unwrap();
    let mut r = BufReader::new(kept.try_clone().unwrap());
    let mut line = String::new();
    r.read_line(&mut line).unwrap();
    assert!(line.contains("\"result\""), "{line}");
    std::thread::sleep(Duration::from_millis(1500));
    kept.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"server.info\"}\n").unwrap();
    line.clear();
    r.read_line(&mut line).unwrap();
    assert!(line.contains("\"result\""), "a quiet client between requests was cut off: {line}");
    drop(server);
}

/// BUG-495: when the server is full, the newcomer takes the slot of the
/// connection silent longest, never one that is subscribed to `watch`
/// or one that spoke recently.
#[test]
fn a_full_server_evicts_the_quietest_idle_client_only() {
    let env = Env::new();
    let proj = env.project(U, "proj", &[("a.txt", "a\n")]);
    // Eviction after 3 s of silence: wide enough that a loaded machine
    // does not age the client that just spoke past it.
    let evict = Duration::from_millis(3000);
    let server = start_with_timeouts(&env, &proj, 60_000, 60_000, evict.as_millis() as u64);
    let sock = proj.join(".veil/local/sock");
    let ask = |c: &mut UnixStream, line: &str| -> String {
        c.write_all(format!("{line}\n").as_bytes()).unwrap();
        let mut r = BufReader::new(c.try_clone().unwrap());
        let mut out = String::new();
        r.read_line(&mut out).unwrap();
        out
    };
    let info = r#"{"jsonrpc":"2.0","id":1,"method":"server.info"}"#;
    // 31 watchers and one plain client, all quiet.
    let mut watchers: Vec<UnixStream> = (0..31)
        .map(|_| {
            let mut c = UnixStream::connect(&sock).unwrap();
            let out = ask(&mut c, r#"{"jsonrpc":"2.0","id":1,"method":"watch","params":{"interval_ms":60000}}"#);
            assert!(out.contains("\"result\""), "{out}");
            c
        })
        .collect();
    let mut plain = UnixStream::connect(&sock).unwrap();
    let asked = Instant::now();
    let out = ask(&mut plain, info);
    assert!(out.contains("\"result\""), "{out}");
    // The newcomer is served once the plain client has been silent for
    // the eviction age, and not before.
    let mut served = false;
    while !served && asked.elapsed() < Duration::from_secs(30) {
        std::thread::sleep(Duration::from_millis(100));
        served = status_works(&sock);
    }
    assert!(served, "the newcomer was refused");
    assert!(asked.elapsed() >= evict, "a client silent for {:?} only was evicted", asked.elapsed());
    // The plain client lost its slot; the watchers kept theirs.
    plain.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut buf = [0u8; 1];
    assert!(matches!(plain.read(&mut buf), Ok(0)), "the quiet client was not the one evicted");
    // Watchers and a client that just spoke: a newcomer is told the
    // server is full. Should the newcomer get a slot after all, that is
    // right only if the client that spoke was silent for the eviction age
    // by the time the newcomer was answered (the machine stalled for that
    // long): then the observation is made again.
    let mut tries = 0;
    loop {
        let mut recent = UnixStream::connect(&sock).unwrap();
        // The server hears `recent` no earlier than this.
        let spoke = Instant::now();
        let out = ask(&mut recent, info);
        if out.contains("\"result\"") {
            let mut c = UnixStream::connect(&sock).unwrap();
            c.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
            let out = ask(&mut c, info);
            if out.contains("-32001") {
                break;
            }
            assert!(spoke.elapsed() >= evict, "a client that spoke {:?} ago was evicted: {out}", spoke.elapsed());
        }
        // (A refused `recent`: the slot the stalled round's newcomer held
        // was not given back yet.)
        tries += 1;
        assert!(tries < 5, "the server was never seen full: {out}");
        std::thread::sleep(Duration::from_millis(500));
    }
    for w in &mut watchers {
        w.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
        assert!(w.read(&mut buf).is_err(), "a watcher was cut off");
    }
    drop(server);
}
