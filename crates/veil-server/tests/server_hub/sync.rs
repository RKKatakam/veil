//! Sync through the server: clone one directory, pull what others push,
//! secrets keys granted and rotated by group changes, and signatures that
//! verify in every viewer's history.

use std::sync::Arc;

use veil_core::ObjectId;

use crate::support::*;

#[test]
fn clone_one_directory_fetches_only_that_subtree() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let d = p.fin.dir("only");
    p.fin.ok(p.fin.home.path(), &["clone", &hub.url(&p.name), d.to_str().unwrap(), "--only", BILL_DIR]);
    assert!(d.join(BILL_DIR).join("acme/invoice.txt").exists());
    assert!(!d.join("src/lib.rs").exists(), "a file outside --only was written");
    let objects = everything_in(&d);
    assert!(!has_marker(&objects, PUBLIC_MARK), "an object outside --only was fetched");
    // Edit and push from the one-directory clone; the rest is kept.
    write_files(&d, &[(&format!("{BILL_DIR}/acme/invoice.txt") as &str, "from a partial clone")]);
    p.fin.commit_main(&d, "partial edit");
    p.fin.ok(&d, &["push"]);
    p.admin.ok(&p.dir, &["pull"]);
    p.admin.ok(&p.dir, &["new", "main"]);
    assert_eq!(std::fs::read_to_string(p.dir.join("src/lib.rs")).unwrap(), PUBLIC_MARK);
    assert_eq!(std::fs::read_to_string(p.dir.join(BILL_DIR).join("acme/invoice.txt")).unwrap(), "from a partial clone");
}

/// BUG-830 for a one-directory clone: killed during its checkout, the
/// next command finishes it (only the directory, whose objects are the
/// only ones fetched) and records nothing as deleted.
#[test]
fn a_one_directory_clone_killed_during_its_checkout_is_finished() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let files: Vec<String> = (0..3000).map(|i| format!("{BILL_DIR}/bulk/d{:02}/f{i:04}.txt", i / 100)).collect();
    let pairs: Vec<(&str, &str)> = files.iter().map(|f| (f.as_str(), f.as_str())).collect();
    write_files(&p.dir, &pairs);
    p.admin.commit_main(&p.dir, "bulk");
    p.admin.ok(&p.dir, &["push"]);
    let mut interrupted = 0;
    for attempt in 0..8 {
        let d = p.fin.dir(&format!("only{attempt}"));
        let mut child = p
            .fin
            .command(p.fin.home.path(), &["clone", &hub.url(&p.name), d.to_str().unwrap(), "--only", &format!("{BILL_DIR}/bulk")])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
        let started = |d: &std::path::Path| std::fs::read_dir(d).is_ok_and(|r| r.flatten().any(|e| e.file_name() != ".veil"));
        while child.try_wait().unwrap().is_none() && !started(&d) {
            assert!(std::time::Instant::now() < deadline, "the clone neither started its checkout nor ended");
        }
        let _ = child.kill();
        if child.wait().unwrap().success() {
            continue;
        }
        interrupted += 1;
        let status = p.fin.ok(&d, &["status"]);
        assert!(!status.lines().any(|l| l.trim_start().starts_with("D ")), "attempt {attempt}: recorded as deleted:\n{status}");
        for f in &files {
            assert_eq!(std::fs::read_to_string(d.join(f)).ok().as_deref(), Some(f.as_str()), "attempt {attempt}: {f}");
        }
        assert!(!d.join("src/lib.rs").exists() && !d.join(BILL_DIR).join("acme").exists(), "a file outside --only was written");
        assert!(!has_marker(&everything_in(&d), PUBLIC_MARK), "an object outside --only was fetched");
        // Its next push keeps everything outside the directory.
        write_files(&d, &[(files[0].as_str(), "after the crash")]);
        p.fin.commit_main(&d, "edit after a crash");
        p.fin.ok(&d, &["push"]);
        p.admin.ok(&p.dir, &["pull"]);
        p.admin.ok(&p.dir, &["new", "main"]);
        assert_eq!(std::fs::read_to_string(p.dir.join("src/lib.rs")).unwrap(), PUBLIC_MARK);
        assert_eq!(std::fs::read_to_string(p.dir.join(&files[0])).unwrap(), "after the crash");
        assert!(p.dir.join(&files[1]).exists() && p.dir.join(BILL_DIR).join(".env").exists());
        break;
    }
    assert!(interrupted > 0, "no clone was interrupted during its checkout (each finished first)");
}

/// BUG-832. A clone without the project's `.veilpolicy` on disk: one
/// directory (`--only`), or a whole clone by someone who cannot read the
/// policy (the project root is private to admins). The secret was
/// classified by the built-in rules (local-only) and its sealed version
/// recorded as deleted. Harm: the clone's next push deleted the folder's
/// `.env` for everyone. Fixed: a sealed entry is kept as recorded unless
/// the snapshot's own policy edit reclassifies it; an edit of the file in
/// such a view stays local (it is never sealed from a local-only file).
#[test]
fn bug_832_a_one_directory_clone_keeps_the_folders_secrets() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    // fin (no access to the root) in a one-directory clone and a full one;
    // the admin (who reads the policy) in a one-directory clone.
    for (n, (who, only)) in [(&p.fin, true), (&p.fin, false), (&p.admin, true)].into_iter().enumerate() {
        let d = who.dir(&format!("c{n}"));
        let mut args = vec!["clone", "URL", d.to_str().unwrap()];
        let url = hub.url(&p.name);
        args[1] = &url;
        if only {
            args.extend(["--only", BILL_DIR]);
        }
        who.ok(who.home.path(), &args);
        assert!(std::fs::read_to_string(d.join(BILL_DIR).join(".env")).unwrap().contains(ENV_MARK));
        let st = who.ok(&d, &["status"]);
        assert!(!st.contains("D ") && !st.contains("[isolated]"), "clone {n}: {st}");
        // An edit of the secret stays local, and says so; the rest lands.
        write_files(&d, &[(&format!("{BILL_DIR}/.env") as &str, &format!("KEY={ENV_MARK}\nEDIT={n}\n"))]);
        write_files(&d, &[(&format!("{BILL_DIR}/acme/invoice.txt") as &str, &format!("from clone {n}"))]);
        let st = who.ok(&d, &["status"]);
        assert!(st.contains("kept as recorded") && !st.contains("D "), "clone {n}: {st}");
        who.commit_main(&d, "partial edit");
        who.ok(&d, &["push"]);
        p.admin.ok(&p.dir, &["pull"]);
        p.admin.ok(&p.dir, &["new", "main"]);
        let env = std::fs::read_to_string(p.dir.join(BILL_DIR).join(".env")).unwrap_or_default();
        assert!(env.contains(ENV_MARK) && !env.contains("EDIT="), "clone {n}: the push deleted or changed the folder's secret: {env:?}");
        assert_eq!(std::fs::read_to_string(p.dir.join(BILL_DIR).join("acme/invoice.txt")).unwrap(), format!("from clone {n}"));
    }
}

#[test]
fn people_see_each_others_pushes_and_every_signature_verifies() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let d = p.dev.dir("c");
    // Full clones: the test walks every snapshot each one holds.
    p.dev.ok(p.dev.home.path(), &["clone", "--full", &hub.url(&p.name), d.to_str().unwrap()]);
    write_files(&d, &[("src/dev.rs", "fn dev() {}")]);
    p.dev.commit_main(&d, "dev change");
    p.dev.ok(&d, &["push"]);
    let f = p.fin.dir("c");
    p.fin.ok(p.fin.home.path(), &["clone", "--full", &hub.url(&p.name), f.to_str().unwrap()]);
    assert!(f.join("src/dev.rs").exists());
    write_files(&f, &[(&format!("{BILL_DIR}/q.txt") as &str, "q")]);
    p.fin.commit_main(&f, "finance change");
    p.fin.ok(&f, &["push"]);
    p.dev.ok(&d, &["pull"]);
    p.admin.ok(&p.dir, &["pull"]);
    p.admin.ok(&p.dir, &["new", "main"]);
    assert!(p.dir.join(BILL_DIR).join("q.txt").exists() && p.dir.join("src/dev.rs").exists());
    // Every snapshot each viewer holds carries a valid signature: the
    // author's, or the server's on a projection.
    for dir in [&d, &f, &p.dir] {
        let repo = veil_core::Repo::open(Arc::new(veil_core::DiskBackend::new(dir)), None, "test").unwrap();
        let mut stack = vec![repo.view().tags["main"].target];
        let mut seen = 0;
        while let Some(id) = stack.pop() {
            if id == repo.root_id() {
                continue;
            }
            let s = repo.snapshot(&id).unwrap();
            assert_eq!(s.signature_valid(), Some(true), "{} in {}", id.short(), dir.display());
            stack.extend(s.parents.iter().copied());
            seen += 1;
        }
        assert!(seen >= 2, "{seen} snapshots in {}", dir.display());
    }
    // The dev's own snapshot comes back to them with their own signature.
    let repo = veil_core::Repo::open(Arc::new(veil_core::DiskBackend::new(&d)), None, "test").unwrap();
    let mine = (|| {
        let mut stack = vec![repo.view().tags["main"].target];
        while let Some(id) = stack.pop() {
            let s = repo.snapshot(&id).unwrap();
            if matches!(&s.description, veil_core::object::Text::Plain(t) if t.contains("dev change")) {
                return s;
            }
            stack.extend(s.parents.iter().copied());
        }
        panic!("the dev's change is missing")
    })();
    assert_eq!(mine.signature.as_ref().unwrap().key, p.dev.identity().verifying_hex());
}

#[test]
fn group_changes_grant_and_rotate_secret_keys() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    // fin was added by the admin: their device holds the team key.
    let f = p.fin.dir("c");
    p.fin.ok(p.fin.home.path(), &["clone", &hub.url(&p.name), f.to_str().unwrap()]);
    assert!(std::fs::read_to_string(f.join(BILL_DIR).join(".env")).unwrap().contains(ENV_MARK));
    // A manager's addition reaches the server's group, but the key needs a
    // ring admin's signature: until then the secret stays closed.
    p.admin.ok(&p.dir, &["group", "manager", "finance", &p.carol.name]);
    let c = p.carol.dir("c");
    p.carol.ok(p.carol.home.path(), &["clone", &hub.url(&p.name), c.to_str().unwrap()]);
    // Someone in no group yet, so no admin's device ever granted them a key.
    let newbie = hub.person("newbie");
    let out = p.carol.ok(&c, &["group", "add", "finance", &newbie.name]);
    assert!(out.contains("ask a project admin"), "{out}");
    let d = newbie.dir("c");
    newbie.ok(newbie.home.path(), &["clone", &hub.url(&p.name), d.to_str().unwrap()]);
    assert!(d.join(BILL_DIR).join("acme/invoice.txt").exists(), "folder access is the server's record");
    assert!(!d.join(BILL_DIR).join(".env").exists(), "no key without an admin's signature");
    assert_no_marker(&everything_in(&d), &[ENV_MARK], &newbie.name);
    // Removing fin from every group rotates the key away from them.
    let out = p.admin.ok(&p.dir, &["group", "remove", "finance", &p.fin.name]);
    assert!(out.contains("rotated away"), "{out}");
}


/// BUG-830 and BUG-837 through the server, at random points: a clone
/// (whole, and of one directory) killed anywhere is either refused as
/// interrupted, or whole after the next command, with nothing recorded as
/// deleted and the folder's secret in place.
#[test]
fn a_clone_killed_at_any_point_is_refused_or_finished() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let files: Vec<String> = (0..1500).map(|i| format!("{BILL_DIR}/bulk/d{:02}/f{i:04}.txt", i / 100)).collect();
    let pairs: Vec<(&str, &str)> = files.iter().map(|f| (f.as_str(), f.as_str())).collect();
    write_files(&p.dir, &pairs);
    p.admin.commit_main(&p.dir, "bulk");
    p.admin.ok(&p.dir, &["push"]);
    let (mut refused, mut finished) = (0, 0);
    for attempt in 0..16u64 {
        let d = p.fin.dir(&format!("k{attempt}"));
        let url = hub.url(&p.name);
        let mut args = vec!["clone", url.as_str(), d.to_str().unwrap()];
        if attempt % 2 == 1 {
            args.extend(["--only", BILL_DIR]);
        }
        let mut child = p.fin.command(p.fin.home.path(), &args).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn().unwrap();
        // Spread the kills over the clone: 0 to 0.8 s.
        std::thread::sleep(std::time::Duration::from_millis(attempt * 53 % 800));
        let _ = child.kill();
        let _ = child.wait();
        if !d.join(".veil/repo.json").exists() {
            continue;
        }
        let out = p.fin.run(&d, &["status"]);
        let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        if !out.status.success() {
            assert!(text.contains("interrupted"), "attempt {attempt}: {text}");
            refused += 1;
            continue;
        }
        finished += 1;
        assert!(!text.lines().any(|l| l.trim_start().starts_with("D ")), "attempt {attempt}: recorded as deleted:\n{text}");
        assert!(!text.contains("[isolated]"), "attempt {attempt}: {text}");
        for f in [&files[0], &files[files.len() - 1]] {
            assert_eq!(std::fs::read_to_string(d.join(f)).ok().as_deref(), Some(f.as_str()), "attempt {attempt}: {f}");
        }
        assert!(std::fs::read_to_string(d.join(BILL_DIR).join(".env")).unwrap().contains(ENV_MARK), "attempt {attempt}");
    }
    println!("refused {refused}, finished {finished}");
}

/// A new project of `admin`'s in `dir`, with remote `origin` at `hub`.
fn new_project(hub: &TestHub, admin: &Person, dir: &std::path::Path) -> String {
    let name = unique("hist");
    std::fs::create_dir_all(dir).unwrap();
    admin.ok(dir, &["init"]);
    admin.ok(dir, &["remote", "add", "origin", &hub.url(&name)]);
    name
}

/// BUG-857. One push of a history in which a later snapshot holds a tree
/// an earlier one introduced (`docs/` with `a`; then `a` and `b`; then `a`
/// again). The push walked `docs/` once, under the last snapshot against
/// a parent that had `a` already, and never under the first, which
/// introduced `a`: it never sent `a`, and the server refused the push
/// ("missing object"). Every snapshot arrives whole.
#[test]
fn bug_857_a_push_of_a_history_that_reuses_a_tree_is_accepted() {
    let hub = TestHub::start();
    let admin = hub.person("admin");
    let dir = admin.dir("proj");
    let name = new_project(&hub, &admin, &dir);
    write_files(&dir, &[("docs/a.txt", "first file"), ("README", "r")]);
    admin.ok(&dir, &["commit", "-m", "add a"]);
    write_files(&dir, &[("docs/b.txt", "second file")]);
    admin.ok(&dir, &["commit", "-m", "add b"]);
    std::fs::remove_file(dir.join("docs/b.txt")).unwrap();
    admin.commit_main(&dir, "remove b");
    let out = admin.ok(&dir, &["push"]);
    assert!(out.contains("Created project"), "{out}");
    let c = admin.dir("clone");
    admin.ok(admin.home.path(), &["clone", &hub.url(&name), c.to_str().unwrap()]);
    assert_eq!(std::fs::read_to_string(c.join("docs/a.txt")).unwrap(), "first file");
    assert!(!c.join("docs/b.txt").exists());
    // The snapshots before are whole in the clone too.
    assert!(admin.ok(&c, &["cat", "docs/b.txt", "-r", "main-"]).contains("second file"));
    assert!(admin.ok(&c, &["cat", "docs/a.txt", "-r", "main--"]).contains("first file"));
}

/// BUG-857's class, through the real server: random histories (pinned
/// seeds) of files added, changed, removed, put back, copied, and turned
/// into directories and back, each pushed whole in one push. The server
/// accepts each push (nothing it asks a receipt for is left out), and a
/// clone has the last snapshot's files. `hub.rs`'s
/// `a_push_sends_exactly_what_the_server_lacks` checks that nothing more
/// is sent.
#[test]
fn random_histories_pushed_in_one_push_are_accepted() {
    let hub = TestHub::start();
    let admin = hub.person("admin");
    for seed in [0x9e37_79b9_7f4a_7c15u64, 0x2545_f491_4f6c_dd1d, 0xd1b5_4a32_d192_ed03] {
        let mut x = seed;
        let mut rng = move |n: u64| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x % n
        };
        let dir = admin.dir(&format!("p{seed:x}"));
        let name = new_project(&hub, &admin, &dir);
        let paths = ["a", "b", "d/a", "d/b", "d/e/a", "d/e/b", "y", "y/a"];
        let mut files: std::collections::BTreeMap<&str, String> = std::collections::BTreeMap::new();
        for i in 0..24 {
            for _ in 0..1 + rng(3) {
                let p = paths[rng(paths.len() as u64) as usize];
                match rng(4) {
                    0 => {
                        files.remove(p);
                    }
                    // A few contents, shared by every path: copies and moves.
                    _ => {
                        files.insert(p, format!("content {}", rng(4)));
                    }
                }
            }
            // `y` is a file or a directory.
            if files.contains_key("y") && files.contains_key("y/a") {
                files.remove(if rng(2) == 0 { "y" } else { "y/a" });
            }
            for p in paths {
                let _ = std::fs::remove_file(dir.join(p));
            }
            let _ = std::fs::remove_dir_all(dir.join("y"));
            for (p, c) in &files {
                write_files(&dir, &[(p, c.as_str())]);
            }
            write_files(&dir, &[("n", &format!("{i}"))]);
            admin.ok(&dir, &["commit", "-m", &format!("step {i}")]);
        }
        admin.ok(&dir, &["tag", "set", "main", "-r", "@-", "--force"]);
        admin.ok(&dir, &["push"]);
        let c = admin.dir(&format!("c{seed:x}"));
        admin.ok(admin.home.path(), &["clone", &hub.url(&name), c.to_str().unwrap()]);
        for p in paths {
            assert_eq!(std::fs::read_to_string(c.join(p)).ok(), files.get(p).cloned(), "seed {seed:x}: {p}");
        }
    }
}

/// BUG-861. An object store whose connections close before answering, as
/// S3 services close idle keep-alive connections: a proxy in front of
/// MinIO drops every other new connection of the first twelve, the very
/// first included, after reading its request. The server tries each such
/// request again: it starts, a push stores every object and a clone
/// fetches them (before, the first one already failed: HTTP 500).
#[test]
fn bug_861_a_closed_object_store_connection_is_tried_again() {
    let Ok(endpoint) = std::env::var("VEIL_TEST_S3_ENDPOINT") else {
        eprintln!("bug_861: skipped (no VEIL_TEST_S3_ENDPOINT: run scripts/verify-server.sh)");
        return;
    };
    let upstream = endpoint.trim_start_matches("http://").trim_end_matches('/').to_string();
    let proxy = flaky_proxy(upstream, |n| (n < 12 && n % 2 == 0).then_some(&b""[..]));
    let hub = TestHub::start_with_s3(
        &std::env::var("VEIL_TEST_DATABASE_URL").unwrap(),
        std::time::Duration::from_secs(3600),
        Some(proxy),
    );
    let admin = hub.person("admin");
    let dir = admin.dir("proj");
    let name = new_project(&hub, &admin, &dir);
    let files: Vec<(String, String)> = (0..300).map(|i| (format!("src/f{i:03}.txt"), format!("file {i} {}", unique("")))).collect();
    let pairs: Vec<(&str, &str)> = files.iter().map(|(p, c)| (p.as_str(), c.as_str())).collect();
    write_files(&dir, &pairs);
    admin.commit_main(&dir, "many files");
    admin.ok(&dir, &["push"]);
    let c = admin.dir("clone");
    admin.ok(admin.home.path(), &["clone", &hub.url(&name), c.to_str().unwrap()]);
    for (p, content) in &files {
        assert_eq!(&std::fs::read_to_string(c.join(p)).unwrap(), content);
    }
}

/// BUG-1005. An object store that asks the server to slow down (HTTP 429,
/// as S3 and MinIO do under load, seen on the shared MinIO of
/// `verify-server.sh`): the first eight connections are answered 429. The
/// server tries each such request again, as it does a 5xx: it starts, a
/// push stores every object and a clone fetches them (before, the first
/// 429 failed the request: "S3 PUT: HTTP 429").
#[test]
fn bug_1005_an_object_store_asking_to_slow_down_is_tried_again() {
    let Ok(endpoint) = std::env::var("VEIL_TEST_S3_ENDPOINT") else {
        eprintln!("bug_1005: skipped (no VEIL_TEST_S3_ENDPOINT: run scripts/verify-server.sh)");
        return;
    };
    let upstream = endpoint.trim_start_matches("http://").trim_end_matches('/').to_string();
    let slow_down = &b"HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"[..];
    let proxy = flaky_proxy(upstream, move |n| (n < 8).then_some(slow_down));
    let hub = TestHub::start_with_s3(
        &std::env::var("VEIL_TEST_DATABASE_URL").unwrap(),
        std::time::Duration::from_secs(3600),
        Some(proxy),
    );
    let admin = hub.person("admin");
    let dir = admin.dir("proj");
    let name = new_project(&hub, &admin, &dir);
    write_files(&dir, &[("src/a.txt", "slowed down, then stored")]);
    admin.commit_main(&dir, "one file");
    admin.ok(&dir, &["push"]);
    let c = admin.dir("clone");
    admin.ok(admin.home.path(), &["clone", &hub.url(&name), c.to_str().unwrap()]);
    assert_eq!(std::fs::read_to_string(c.join("src/a.txt")).unwrap(), "slowed down, then stored");
}

/// A TCP proxy to `upstream`. New connection `n` is passed through, unless
/// `answer(n)` gives bytes: then, after its first bytes are read, it is
/// answered those bytes (none: nothing) and closed. Returns its URL.
fn flaky_proxy(upstream: String, answer: impl Fn(usize) -> Option<&'static [u8]> + Send + 'static) -> String {
    use std::io::Write;
    use std::{
        io::Read,
        net::{Shutdown, TcpListener, TcpStream},
    };
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    std::thread::spawn(move || {
        for (n, c) in l.incoming().enumerate() {
            let Ok(mut c) = c else { continue };
            if let Some(bytes) = answer(n) {
                let _ = c.set_read_timeout(Some(std::time::Duration::from_secs(5)));
                let _ = c.read(&mut [0u8; 4096]);
                let _ = c.write_all(bytes);
                continue;
            }
            let up = upstream.clone();
            std::thread::spawn(move || {
                let Ok(u) = TcpStream::connect(&up) else { return };
                let (mut c2, mut u2) = (c.try_clone().unwrap(), u.try_clone().unwrap());
                let t = std::thread::spawn(move || {
                    let _ = std::io::copy(&mut c2, &mut u2);
                    let _ = u2.shutdown(Shutdown::Write);
                });
                let (mut u, mut c) = (u, c);
                let _ = std::io::copy(&mut u, &mut c);
                let _ = c.shutdown(Shutdown::Write);
                let _ = t.join();
            });
        }
    });
    format!("http://{addr}")
}

/// The project's id in the server's database.
fn project_id(hub: &TestHub, name: &str) -> i64 {
    hub.rt
        .block_on(sqlx::query_scalar("SELECT id FROM projects WHERE name = $1").bind(name).fetch_one(&hub.hub().db))
        .unwrap()
}

/// S27 (`docs/HUB.md` §13.15): objects are stored compressed, under the id
/// of the uncompressed object, and travel compressed to a `vl` that reads
/// encoded frames. A client from before (plain frames, no `Accept`) gets
/// every object as it always did, and its plain uploads are compressed by
/// the server. Ids, receipts and signatures don't change: a fresh clone
/// has every file, and the pushed history verifies.
#[test]
fn objects_are_compressed_in_storage_and_for_clients_that_read_them() {
    use veil_core::hub::encoding;
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let text = "pub fn compressible() -> u32 { 42 }\n".repeat(2000);
    write_files(&p.dir, &[("src/big.rs", &text)]);
    p.admin.commit_main(&p.dir, "a big file");
    p.admin.ok(&p.dir, &["push"]);
    let (_, id) = real_paths(&p.dir).into_iter().find(|(path, _)| path == "src/big.rs").unwrap();
    let repo = veil_core::Repo::open(Arc::new(veil_core::DiskBackend::new(&p.dir)), None, "test").unwrap();
    let raw = repo.store().get_raw(&id).unwrap();
    let hubref = hub.hub();
    let pid = project_id(&hub, &p.name);
    let stored = hub.rt.block_on(hubref.objects.get_encoded(pid, &id)).unwrap().unwrap();
    assert!(encoding::is_compressed(&stored) && stored.len() * 10 < raw.len(), "{} bytes stored for {}", stored.len(), raw.len());
    // A secret is ciphertext: stored as it is, never compressed.
    let (_, env) = real_paths(&p.dir).into_iter().find(|(path, _)| *path == format!("{BILL_DIR}/.env")).unwrap();
    let env_stored = hub.rt.block_on(hubref.objects.get_encoded(pid, &env)).unwrap().unwrap();
    assert!(!encoding::is_compressed(&env_stored));
    let api = hub.api();
    let token = p.admin.token();
    let tip = api.tips(Some(&token), &p.name).unwrap().branches["main"];
    let fetch = format!("/v1/projects/{}/fetch", p.name);
    let want = serde_json::json!({"snapshot": tip.hex(), "objects": [{"path": "src/big.rs", "id": id.hex()}]});
    // A client from before: plain frames.
    assert_eq!(api.post_json(Some(&token), &fetch, &want).raw_frames(), vec![(id, raw.clone())]);
    // A client that reads encoded frames: the stored encoding, as it is.
    let (r, ct) = api.post_json_encoded(Some(&token), &fetch, &want);
    assert_eq!(ct.as_deref(), Some(encoding::FRAMES));
    assert_eq!(r.raw_frames(), vec![(id, stored.to_vec())]);
    assert_eq!(r.frames(), vec![(id, raw.clone())]);
    let (h, ct) = api.post_json_encoded(Some(&token), &format!("/v1/projects/{}/history", p.name), &serde_json::json!({"tips": [tip.hex()]}));
    assert_eq!(ct.as_deref(), Some(encoding::FRAMES));
    assert!(h.frames().iter().any(|(i, _)| *i == tip));
    // An upload of plain frames (a client from before S27): accepted, and
    // stored compressed.
    let old_text = "fn from_a_client_from_before() {}\n".repeat(1000);
    let old_raw = veil_core::object::Object::Blob(old_text.clone().into_bytes()).encode();
    let mut c = Craft::new(&api, &p.admin, &p.name, "main");
    c.file("src/old.rs", &old_text);
    let r = c.push("main", "from a client from before");
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let old_stored = hub.rt.block_on(hubref.objects.get_encoded(pid, &ObjectId::hash(&old_raw))).unwrap().unwrap();
    assert!(encoding::is_compressed(&old_stored) && old_stored.len() * 10 < old_raw.len());
    // Everyone gets every file they may see, whole.
    let d = p.dev.dir("clone");
    p.dev.ok(p.dev.home.path(), &["clone", &hub.url(&p.name), d.to_str().unwrap()]);
    assert_eq!(std::fs::read_to_string(d.join("src/big.rs")).unwrap(), text);
    assert_eq!(std::fs::read_to_string(d.join("src/old.rs")).unwrap(), old_text);
    let log = p.dev.ok(&d, &["log", "-r", "main", "--json"]);
    assert!(!log.contains("\"signature_valid\":false"), "{log}");
}

/// S27 threat review: hostile compressed uploads (a participant's, so
/// inside the project but outside the server). A zip bomb declaring more
/// than the object size limit, a frame of other content, an unknown
/// marker, bytes after the frame, a frame that does not declare its size,
/// or a request decoding to more than a plain request may carry: each
/// refused from the request alone, quickly, with nothing stored and no
/// receipt; the server answers the next request as usual.
#[test]
fn hostile_compressed_uploads_are_refused() {
    use veil_core::hub::{encoding, wire::put_frame};
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    let token = p.dev.token();
    let raw = veil_core::object::Object::Blob(b"hello compressed world ".repeat(64)).encode();
    let id = ObjectId::hash(&raw);
    let good = encoding::encode(&raw).into_owned();
    assert!(encoding::is_compressed(&good));
    // The header of a zstd frame declaring `size` bytes, and an empty last
    // raw block: refused from its header.
    let declaring = |size: u64| {
        let mut f = vec![encoding::ZSTD, 0x28, 0xb5, 0x2f, 0xfd, 0b1100_0000, 0x50];
        f.extend_from_slice(&size.to_le_bytes());
        f.extend_from_slice(&[0x01, 0x00, 0x00]);
        f
    };
    let other = encoding::encode(&veil_core::object::Object::Blob(b"other content entirely ".repeat(64)).encode()).into_owned();
    let mut trailing = good.clone();
    trailing.extend_from_slice(b"junk");
    let mut marker = good.clone();
    marker[0] = 0x01;
    let undeclared = {
        let mut f = vec![encoding::ZSTD];
        let mut z = good[1..].to_vec();
        // Clear the frame's content-size flag: a frame of another shape,
        // still refused (it no longer declares its size or parses).
        z[4] &= 0b0011_1111;
        f.extend(z);
        f
    };
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("a bomb past the object size limit", declaring((1 << 30) + 1)),
        ("a bomb declaring 2^63", declaring(1 << 63)),
        ("a frame of other content", other),
        ("bytes after the frame", trailing),
        ("an unknown marker", marker),
        ("a frame without its size", undeclared),
        ("only a marker", vec![encoding::ZSTD]),
    ];
    for (what, enc) in cases {
        let mut body = Vec::new();
        // A good object first: the whole request is refused, so even it
        // gets no receipt.
        put_frame(&mut body, &id, &good);
        put_frame(&mut body, &id, &enc);
        let t = std::time::Instant::now();
        let r = api.upload_body(&token, &p.name, &body);
        assert_eq!(r.status, 400, "{what}: {}", String::from_utf8_lossy(&r.body));
        assert!(r.json()["receipts"].is_null(), "{what}");
        assert!(t.elapsed() < std::time::Duration::from_secs(10), "{what} took {:?}", t.elapsed());
    }
    // A request that decodes to more than a plain request may carry (the
    // body limit) is refused once the total passes it: 3 frames of 1 GiB
    // each would be 3 GiB. Shown with the real decoder on a small limit in
    // `veil_core::hub::encoding`'s tests; here, the server still answers.
    let mut body = Vec::new();
    put_frame(&mut body, &id, &good);
    let r = api.upload_body(&token, &p.name, &body);
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["receipts"].as_array().map(|a| a.len()), Some(1));
}

/// S27 threat review: compressed answers carry only what the viewer may
/// see. Every viewer's walk of the project through encoded frames (as a
/// `vl` that reads them) holds no marker of a folder they can't read.
#[test]
fn compressed_answers_hold_nothing_the_viewer_may_not_see() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    let anyone = hub.anyone();
    let cases: Vec<(&Person, Option<String>, Vec<&str>)> = vec![
        (&anyone, None, vec![]),
        (&p.dev, Some(p.dev.token()), vec![]),
        (&p.fin, Some(p.fin.token()), vec![BILL_DIR, BILL_MARK, ENV_MARK, DESC_MARK]),
        (&p.carol, Some(p.carol.token()), vec![PERSON_DIR, PERSON_MARK]),
        (&p.sec, Some(p.sec.token()), vec![NESTED_DIR, NESTED_MARK]),
    ];
    for (who, token, allowed) in &cases {
        let token = token.as_deref();
        let tip = api.tips(token, &p.name).unwrap().branches["main"];
        let (h, _) = api.post_json_encoded(token, &format!("/v1/projects/{}/history", p.name), &serde_json::json!({"tips": [tip.hex()]}));
        let mut got: Vec<(String, Vec<u8>)> = h.frames().into_iter().map(|(i, r)| (format!("snapshot {}", i.short()), r)).collect();
        let veil_core::object::Object::Snapshot(s) = veil_core::object::Object::decode(&got.iter().find(|(n, _)| *n == format!("snapshot {}", tip.short())).unwrap().1).unwrap() else {
            panic!()
        };
        let mut stack = vec![(String::new(), s.tree)];
        while let Some((path, id)) = stack.pop() {
            let (r, _) = api.post_json_encoded(
                token,
                &format!("/v1/projects/{}/fetch", p.name),
                &serde_json::json!({"snapshot": tip.hex(), "objects": [{"path": path, "id": id.hex()}]}),
            );
            let (_, raw) = r.frames().into_iter().next().unwrap();
            if let Ok(veil_core::object::Object::Tree(t)) = veil_core::object::Object::decode(&raw) {
                for e in &t.entries {
                    let child = if path.is_empty() { e.name.clone() } else { format!("{path}/{}", e.name) };
                    got.push((format!("name {child}"), child.clone().into_bytes()));
                    stack.push((child, e.id));
                }
            }
            got.push((format!("object at '{path}'"), raw));
        }
        // Safety first, then liveness.
        let forbidden: Vec<&str> = restricted_markers().into_iter().filter(|m| !allowed.contains(m)).collect();
        assert_no_marker(&got, &forbidden, &who.name);
        assert!(has_marker(&got, PUBLIC_MARK), "{} lacks the public folder", who.name);
    }
}

/// An unreleased embargo never reaches the server: `vl push` sends neither
/// the embargoed merge nor its fix (the tag on them is rejected here, with
/// the reason), so nothing of the fix is uploaded and nobody else sees it.
#[test]
fn an_unreleased_embargo_never_reaches_the_server() {
    const FIX: &str = "EMBARGOED-FIX-MARKER-4471";
    let hub = TestHub::start();
    let p = setup_project(&hub);
    write_files(&p.dir, &[("src/fix.rs", FIX)]);
    p.admin.ok(&p.dir, &["commit", "--no-advance", "-m", "the fix"]);
    p.admin.ok(&p.dir, &["merge", "@-", "--into", "main", "--embargo", "-m", "merge the fix"]);
    let out = p.admin.fails(&p.dir, &["push"]);
    assert!(out.contains("rejected") && out.contains("embargo"), "{out}");
    let d = p.dev.dir("c");
    p.dev.ok(p.dev.home.path(), &["clone", &hub.url(&p.name), d.to_str().unwrap()]);
    assert_no_marker(&everything_in(&d), &[FIX], "dev");
    assert!(!d.join("src/fix.rs").exists(), "the fix reached a clone");
}

/// BUG-1015 (regression on the simplification branch): `vl squash` of the
/// embargoed merge into the fix, with a follow-up on `main`, leaves `main`
/// a plain merge that holds the fix and that no embargo withholds, so the
/// next `vl push` uploads the fix and every member who can read the project
/// gets it before the release.
#[test]
fn squashing_the_embargoed_merge_into_the_fix_never_reaches_the_server() {
    const FIX: &str = "EMBARGOED-FIX-MARKER-5582";
    let hub = TestHub::start();
    let p = setup_project(&hub);
    write_files(&p.dir, &[("src/fix.rs", FIX)]);
    p.admin.ok(&p.dir, &["commit", "--no-advance", "-m", "the fix"]);
    p.admin.ok(&p.dir, &["tag", "set", "fixline", "-r", "@-"]);
    p.admin.ok(&p.dir, &["merge", "fixline", "--into", "main", "--embargo", "-m", "merge the fix"]);
    p.admin.ok(&p.dir, &["new", "main"]);
    write_files(&p.dir, &[("src/follow.rs", "follow-up")]);
    p.admin.ok(&p.dir, &["commit", "-m", "follow-up"]);
    let _ = p.admin.run(&p.dir, &["squash", "-r", "main-", "--into", "fixline"]);
    p.admin.ok(&p.dir, &["tag", "delete", "fixline"]);
    let _ = p.admin.run(&p.dir, &["push"]);
    let d = p.dev.dir("c");
    p.dev.ok(p.dev.home.path(), &["clone", &hub.url(&p.name), d.to_str().unwrap()]);
    assert_no_marker(&everything_in(&d), &[FIX], "dev");
    assert!(!d.join("src/fix.rs").exists(), "the fix reached a clone");
}

/// The window a stored encoding's zstd frame declares, in bytes (`None`:
/// a plain encoding; a single-segment frame's window is its content).
fn stored_window(enc: &[u8]) -> Option<u64> {
    let f = enc.strip_prefix(&[veil_core::hub::encoding::ZSTD][..])?;
    let fhd = f[4];
    if fhd & 0x20 != 0 {
        return Some(veil_core::hub::encoding::decoded_len(enc).unwrap());
    }
    let wd = f[5];
    let base = 1u64 << (10 + (wd >> 3));
    Some(base + (base / 8) * u64::from(wd & 7))
}

/// `enc` (a zstd encoding from `encoding::encode`) with its frame header
/// rewritten to declare a 2 GiB window: same blocks, same content. The
/// format allows it; libzstd's one-shot decoder (objects up to 64 MiB)
/// reads it; the WASM decoder refuses windows above 128 MiB.
fn with_huge_window(enc: &[u8], content: u64) -> Vec<u8> {
    let f = &enc[1..];
    let fhd = f[4];
    let single = fhd & 0x20 != 0;
    let fcs = match fhd >> 6 {
        0 => usize::from(single),
        1 => 2,
        2 => 4,
        _ => 8,
    };
    let dict = [0, 1, 2, 4][usize::from(fhd & 3)];
    let header = 5 + usize::from(!single) + dict + fcs;
    let mut out = vec![veil_core::hub::encoding::ZSTD, 0x28, 0xb5, 0x2f, 0xfd, 0x80 | (fhd & 0x04), 21 << 3];
    out.extend_from_slice(&(content as u32).to_le_bytes());
    out.extend_from_slice(&f[header..]);
    out
}

/// BUG-1008 (S27 adversarial pass). `dev` (no access to billing) knows a
/// file that billing holds too (a licence, a vendored file: the same
/// object). `dev` uploads it as an encoded frame declaring a 2 GiB window:
/// the server checks it (libzstd reads it), answers a receipt, and stores
/// it as sent over the admin's encoding: the object every snapshot with
/// that file names, billing's included, is now one the web client's
/// decoder refuses (windows above 2^27). The server must store only
/// encodings every reader decodes.
#[test]
fn bug_1008_an_upload_cannot_store_a_frame_the_web_client_cannot_read() {
    use veil_core::hub::{encoding, wire::put_frame};
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let shared = "Permission is hereby granted, free of charge, to any person.\n".repeat(300);
    write_files(&p.dir, &[("src/LICENSE", &shared), (&format!("{BILL_DIR}/LICENSE"), &shared)]);
    p.admin.commit_main(&p.dir, "the licence, twice");
    p.admin.ok(&p.dir, &["push"]);
    let paths = real_paths(&p.dir);
    let (_, id) = paths.iter().find(|(path, _)| path == "src/LICENSE").unwrap().clone();
    assert!(paths.iter().any(|(path, i)| *path == format!("{BILL_DIR}/LICENSE") && *i == id));
    let pid = project_id(&hub, &p.name);
    let hubref = hub.hub();
    let before = hub.rt.block_on(hubref.objects.get_encoded(pid, &id)).unwrap().unwrap();
    assert!(stored_window(&before).unwrap() <= 1 << 27);
    let raw = veil_core::object::Object::Blob(shared.into_bytes()).encode();
    assert_eq!(ObjectId::hash(&raw), id);
    let hostile = with_huge_window(&before, raw.len() as u64);
    assert!(hostile.len() < raw.len());
    // libzstd's one-shot decoder reads it; `decode` refuses it, as the web
    // client's decoder does.
    let e = encoding::decode(&id, &hostile, 1 << 30).unwrap_err().to_string();
    assert!(e.contains("window"), "{e}");
    let mut body = Vec::new();
    put_frame(&mut body, &id, &hostile);
    let r = hub.api().upload_encoded_body(&p.dev.token(), &p.name, &body);
    assert_eq!(r.status, 400, "{}", String::from_utf8_lossy(&r.body));
    let after = hub.rt.block_on(hubref.objects.get_encoded(pid, &id)).unwrap().unwrap();
    assert_eq!(after, before, "the stored encoding changed");
    assert!(
        stored_window(&after).is_none_or(|w| w <= 1 << 27),
        "status {}: the server now stores and serves a frame with a {} MiB window",
        r.status,
        stored_window(&after).unwrap() >> 20
    );
}

/// BUG-1009 (S27 adversarial pass). The accepted risk of `docs/HUB.md`
/// §13.15 ("a participant can make the server decode up to 2 GiB per
/// upload request from a small body") is bounded per request only: the
/// server holds each such object decoded (twice for its canonical check:
/// `Object::decode` copies a blob), on a blocking thread, for every
/// request at once. An 8 KiB request decodes 128 MiB here; eight at once
/// (33 KB sent in all) raised this process's peak memory by
/// 1.33 GiB in the S27 pass (one: 262 MiB), and
/// 1 GiB objects from 32 KiB requests exhaust the server's memory with a
/// few dozen requests (before S27 each such object cost the sender its
/// size in upload). The server must not decode far more than a request
/// carries: e.g. refuse a frame expanding more than some fixed ratio, so
/// `vl` sends such an object plain, or bound decoding server-wide.
#[test]
fn bug_1009_a_small_upload_cannot_make_the_server_decode_a_large_object() {
    use veil_core::hub::{encoding, wire::put_frame};
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let raw = veil_core::object::Object::Blob(vec![0u8; 128 << 20]).encode();
    let id = ObjectId::hash(&raw);
    let enc = encoding::encode(&raw).into_owned();
    drop(raw);
    let mut body = Vec::new();
    put_frame(&mut body, &id, &enc);
    assert!(body.len() < 8 << 10, "{} bytes", body.len());
    let r = hub.api().upload_encoded_body(&p.dev.token(), &p.name, &body);
    assert_ne!(r.status, 200, "an upload of {} bytes made the server decode {} MiB", body.len(), 128);
}

/// A zstd frame of `raw` (as an encoding: `z` first) made of raw
/// (uncompressed) blocks of at most `block` bytes: a valid frame no
/// encoder of ours writes, declaring its size and a 2^20-byte window.
fn raw_block_frame(raw: &[u8], block: usize) -> Vec<u8> {
    let mut f = vec![veil_core::hub::encoding::ZSTD, 0x28, 0xb5, 0x2f, 0xfd, 0x80, 10 << 3];
    f.extend_from_slice(&(raw.len() as u32).to_le_bytes());
    let chunks: Vec<&[u8]> = raw.chunks(block).collect();
    for (i, c) in chunks.iter().enumerate() {
        let last = u32::from(i + 1 == chunks.len());
        f.extend_from_slice(&(((c.len() as u32) << 3) | last).to_le_bytes()[..3]);
        f.extend_from_slice(c);
    }
    f
}

/// S27 review: an upload of an already-compressed frame, here one of
/// uncompressed zstd blocks (larger than the object), is decoded, checked
/// and stored as the server's own encoding, never as sent and never
/// compressed a second time: the stored bytes decode to the id, and the
/// object reads back whole.
#[test]
fn an_uploaded_frame_of_raw_blocks_round_trips_to_its_id() {
    use veil_core::hub::{encoding, wire::put_frame};
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let text: String = (0..400).map(|i| format!("line {i} of a file sent in raw blocks\n")).collect();
    let raw = veil_core::object::Object::Blob(text.into_bytes()).encode();
    let id = ObjectId::hash(&raw);
    let frame = raw_block_frame(&raw, 4000);
    assert!(frame.len() > raw.len());
    assert_eq!(&*encoding::decode(&id, &frame, 1 << 20).unwrap(), &raw[..]);
    let mut body = Vec::new();
    put_frame(&mut body, &id, &frame);
    let r = hub.api().upload_encoded_body(&p.dev.token(), &p.name, &body);
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let pid = project_id(&hub, &p.name);
    let hubref = hub.hub();
    let stored = hub.rt.block_on(hubref.objects.get_encoded(pid, &id)).unwrap().unwrap();
    assert_eq!(&stored[..], &encoding::encode(&raw)[..], "stored as the server's own encoding");
    assert_eq!(&*encoding::decode(&id, &stored, 1 << 20).unwrap(), &raw[..]);
    assert_eq!(&hub.rt.block_on(hubref.objects.get(pid, &id)).unwrap().unwrap()[..], &raw[..]);
}

/// This process's resident memory, in bytes.
fn rss() -> u64 {
    let s = std::fs::read_to_string("/proc/self/status").unwrap();
    s.lines().find(|l| l.starts_with("VmRSS:")).and_then(|l| l.split_whitespace().nth(1)).unwrap().parse::<u64>().unwrap() << 10
}

/// BUG-1009, the server-wide bound. Sixteen uploads at once, each of one
/// frame within the ratio (about 1 MiB that decodes to 48 MiB): the server
/// decodes at most `DECODING_IN_FLIGHT` (256 MiB) of them at a time, so
/// its memory rises well under the 768 MiB they decode to together. In a
/// process of its own, so other tests count for nothing.
#[test]
fn compressed_uploads_decode_within_a_server_wide_bound() {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    use veil_core::hub::{encoding, wire::put_frame};
    const CHILD: &str = "VEIL_S27_DECODING_CHILD";
    if std::env::var(CHILD).is_err() {
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "sync::compressed_uploads_decode_within_a_server_wide_bound", "--nocapture"])
            .env(CHILD, "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        println!("{}", stdout.lines().find(|l| l.contains("BUG-1009:")).unwrap_or_default());
        assert!(out.status.success() && stdout.contains("1 passed"), "{stdout}{}", String::from_utf8_lossy(&out.stderr));
        return;
    }
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let token = p.dev.token();
    // 4 KiB blocks of 72 random bytes and zeros: about 50 times smaller.
    let bodies: Vec<Vec<u8>> = (0..16)
        .map(|_| {
            let mut data = Vec::with_capacity(48 << 20);
            while data.len() < 48 << 20 {
                data.extend_from_slice(&veil_core::crypto::random_bytes::<72>());
                data.resize(data.len() + 4096 - 72, 0);
            }
            let raw = veil_core::object::Object::Blob(data).encode();
            let enc = encoding::encode_to_send(&raw).into_owned();
            assert!(encoding::is_compressed(&enc) && encoding::within_ratio(&enc) && enc.len() * 32 < raw.len());
            let mut body = Vec::new();
            put_frame(&mut body, &ObjectId::hash(&raw), &enc);
            body
        })
        .collect();
    let api = Arc::new(hub.api());
    let base = rss();
    let stop = Arc::new(AtomicBool::new(false));
    let s2 = stop.clone();
    let sampler = std::thread::spawn(move || {
        let mut m = 0;
        while !s2.load(Ordering::Relaxed) {
            m = m.max(rss());
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        m
    });
    std::thread::scope(|sc| {
        for body in &bodies {
            let (api, token, name) = (api.clone(), &token, &p.name);
            sc.spawn(move || {
                let r = api.upload_encoded_body(token, name, body);
                assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
            });
        }
    });
    stop.store(true, Ordering::Relaxed);
    let grew = sampler.join().unwrap().max(rss()).saturating_sub(base);
    println!("BUG-1009: 16 uploads decoding 48 MiB each at once: memory rose {} MiB", grew >> 20);
    assert!(grew < 512 << 20, "memory rose {} MiB", grew >> 20);
}
