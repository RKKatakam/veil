//! The landing service under sustained load (BUG-1955): a submitter past
//! what the service lands in time is told to come back, at once and before
//! any work is done for the submit; and a batch built on several cores is
//! the batch built on one.

use std::time::Duration;

use crate::{
    limits::{hold_branch, land_edit, project_id_of, release_branch, wait_ticket},
    support::*,
};

/// Rows of `table` of project `pid`.
fn rows(hub: &TestHub, table: &str, pid: i64) -> i64 {
    hub.rt.block_on(sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table} WHERE project_id = $1")).bind(pid).fetch_one(&hub.hub().db)).unwrap()
}

/// BUG-1955: past the branch's bound a submit is refused at once with
/// `503 queue_full` and when to come back, and nothing was done for it (no
/// queue row, no snapshot, no change ref). The bound is each person's fair
/// share: behind one person's full queue, another person's landing is
/// queued. Once the queue has landed, the refused submit goes in.
#[test]
fn bug_1955_a_full_queue_tells_the_submitter_to_come_back_and_holds_nobody_else_up() {
    let mut settings = TestHub::limits();
    settings.max_branch_waiting = 6;
    let hub = TestHub::start_with_limits(settings);
    let p = setup_project(&hub);
    let pid = project_id_of(&hub, &p.name);
    let api = hub.api();
    let (dev, admin) = (p.dev.token(), p.admin.token());
    let base = api.tips(Some(&dev), &p.name).unwrap().branches["main"];
    let admin_base = api.tips(Some(&admin), &p.name).unwrap().branches["main"];
    let served = |hub: &TestHub| -> i64 {
        hub.rt
            .block_on(sqlx::query_scalar("SELECT served FROM landing_leases WHERE project_id = $1 AND branch = 'main'").bind(pid).fetch_one(&hub.hub().db))
            .unwrap()
    };

    hold_branch(&hub, pid, "main");
    let mut tickets = Vec::new();
    for i in 0..6 {
        let r = land_edit(&api, &dev, &p.name, base, &format!("src/hold/f{i}.rs"), "x\n", false);
        assert_eq!(r.status, 200, "submit {i}: {}", String::from_utf8_lossy(&r.body));
        tickets.push(r.json()["ticket"].as_str().unwrap().to_string());
    }
    // The seventh: told to come back, at once, and nothing was done for it.
    let before = (rows(&hub, "landing_queue", pid), rows(&hub, "snapshots", pid), rows(&hub, "change_refs", pid));
    let asked = std::time::Instant::now();
    let refused = land_edit(&api, &dev, &p.name, base, "src/hold/late.rs", "x\n", true);
    assert_eq!(refused.status, 503, "{}", String::from_utf8_lossy(&refused.body));
    assert!(asked.elapsed() < Duration::from_secs(5), "the refusal took {:?}: it does not wait for the queue", asked.elapsed());
    let v = refused.json();
    assert_eq!(v["code"], "queue_full", "{v}");
    let wait = v["retry_after_ms"].as_u64().expect("the answer says how long to wait");
    assert!((1_000..=5_000).contains(&wait), "{v}");
    assert!(v["message"].as_str().unwrap().contains("'main'"), "{v}");
    assert_eq!((rows(&hub, "landing_queue", pid), rows(&hub, "snapshots", pid), rows(&hub, "change_refs", pid)), before, "a refused submit left something");
    // Another person, behind the six: queued (one of the flood's lands before it).
    let other = land_edit(&api, &admin, &p.name, admin_base, "src/hold/other.rs", "y\n", false);
    assert_eq!(other.status, 200, "{}", String::from_utf8_lossy(&other.body));
    let other = other.json()["ticket"].as_str().unwrap().to_string();
    // And the first person is still refused, however often they ask.
    for _ in 0..3 {
        let r = land_edit(&api, &dev, &p.name, base, "src/hold/late.rs", "x\n", false);
        assert_eq!(r.status, 503, "{}", String::from_utf8_lossy(&r.body));
    }

    // The queue lands; the service counts what it served in its lease row.
    release_branch(&hub, pid, "main");
    let v = wait_ticket(&api, &admin, &p.name, &other);
    assert_eq!(v["state"], "landed", "{v}");
    for t in &tickets {
        let v = wait_ticket(&api, &dev, &p.name, t);
        assert_eq!(v["state"], "landed", "{v}");
    }
    assert_eq!(served(&hub), 7);
    // Now the refused submit goes in (what was read of the queue is used
    // for a tenth of a second).
    std::thread::sleep(Duration::from_millis(150));
    let again = land_edit(&api, &dev, &p.name, base, "src/hold/late.rs", "x\n", true);
    assert_eq!(again.status, 200, "{}", String::from_utf8_lossy(&again.body));
    assert_eq!(again.json()["state"], "landed", "{}", again.json());
    assert_eq!(served(&hub), 8);
}

/// BUG-1955: `vl land` told to come back waits as the answer asks, says
/// what it waits for, and lands once the queue has room.
#[test]
fn bug_1955_vl_land_waits_for_a_full_queue_and_says_so() {
    let mut settings = TestHub::limits();
    settings.max_branch_waiting = 2;
    let hub = TestHub::start_with_limits(settings);
    let p = setup_project(&hub);
    let pid = project_id_of(&hub, &p.name);
    let api = hub.api();
    let admin = p.admin.token();
    let base = api.tips(Some(&admin), &p.name).unwrap().branches["main"];
    write_files(&p.dir, &[("src/held.txt", "held\n")]);
    p.admin.ok(&p.dir, &["commit", "-m", "lands once the queue has room"]);

    hold_branch(&hub, pid, "main");
    let mut tickets = Vec::new();
    for i in 0..2 {
        let r = land_edit(&api, &admin, &p.name, base, &format!("src/full/f{i}.rs"), "x\n", false);
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        tickets.push(r.json()["ticket"].as_str().unwrap().to_string());
    }
    let out = std::thread::scope(|s| {
        s.spawn(|| {
            std::thread::sleep(Duration::from_millis(2_500));
            release_branch(&hub, pid, "main");
        });
        p.admin.ok(&p.dir, &["land"])
    });
    assert!(out.contains("landed main"), "{out}");
    assert!(out.contains("waiting for the server: the landing queue of 'main' is full"), "{out}");
    for t in &tickets {
        let v = wait_ticket(&api, &admin, &p.name, t);
        assert_eq!(v["state"], "landed", "{v}");
    }
}

/// BUG-1955: a batch whose entries are read on several threads is the batch
/// built on one, byte for byte: the same objects, the same snapshots,
/// projections and landing records in the same order, the same tip, and
/// the same answer for every entry. Seeded batches of two people's changes:
/// new files, edits of one shared file (the second of two overlaps: merged
/// in the batch), and two changes adding one path (the second conflicts).
/// And what the service then lands is what the build on one thread said.
#[test]
fn bug_1955_a_batch_read_on_several_threads_is_the_batch_built_on_one() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id_of(&hub, &p.name);
    let api = hub.api();
    let (dev, admin) = (p.dev.token(), p.admin.token());
    let shared: String = (0..40).map(|i| format!("line {i}\n")).collect();
    let made = land_edit(&api, &admin, &p.name, api.tips(Some(&admin), &p.name).unwrap().branches["main"], "src/par/shared.txt", &shared, true);
    assert_eq!(made.status, 200, "{}", String::from_utf8_lossy(&made.body));
    assert_eq!(made.json()["state"], "landed", "{}", made.json());

    for seed in 1..=3u64 {
        let mut state = seed.wrapping_mul(0x9e3779b97f4a7c15);
        let mut next = |n: u64| {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (state >> 33) % n
        };
        hold_branch(&hub, pid, "main");
        let bases = [api.tips(Some(&dev), &p.name).unwrap().branches["main"], api.tips(Some(&admin), &p.name).unwrap().branches["main"]];
        // The shared file as this seed's base has it (the seed before landed
        // edits of it): each overlap edits one line of that.
        let r = api.get(Some(&dev), &format!("/v1/projects/{}/q/file?rev={}&path=src/par/shared.txt", p.name, bases[0].hex()));
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        let shared = String::from_utf8(r.body).unwrap();
        // 90 submits: more than one batch, so the batch is the service's fair choice.
        let mut tickets: Vec<(usize, String)> = Vec::new();
        for i in 0..90 {
            let who = next(2) as usize;
            let (path, text) = match next(100) {
                0..=14 => {
                    let at = next(40) as usize;
                    let text: String = shared.lines().enumerate().map(|(n, l)| if n == at { format!("line {at} of {seed}/{i}\n") } else { format!("{l}\n") }).collect();
                    ("src/par/shared.txt".to_string(), text)
                }
                15..=29 => (format!("src/par/s{seed}/same-{}.txt", next(3)), format!("{seed}/{i}\n")),
                _ => (format!("src/par/s{seed}/f{i:02}.rs"), format!("{seed}/{i}\n")),
            };
            let r = land_edit(&api, [&dev, &admin][who], &p.name, bases[who], &path, &text, false);
            assert_eq!(r.status, 200, "seed {seed}, submit {i}: {}", String::from_utf8_lossy(&r.body));
            tickets.push((who, r.json()["ticket"].as_str().unwrap().to_string()));
        }
        let [one, several] = hub.rt.block_on(veil_server::landing::build_both_ways(&hub.hub(), pid, "main", 8)).expect("the batch builds both ways");
        let count = |what: &str| one.iter().filter(|l| l.contains(what)).count();
        assert!(count("object ") > 100 && count(" landed as ") >= 20, "seed {seed}: {} objects, {} landed", count("object "), count(" landed as "));
        assert!(count(" merged true") >= 1 && count(" conflict ") >= 1, "seed {seed}: {} merged, {} conflicts", count(" merged true"), count(" conflict "));
        assert!(count("memo ") >= 20, "seed {seed}: {} projections", count("memo "));
        for (a, b) in one.iter().zip(&several) {
            assert_eq!(a, b, "seed {seed}");
        }
        assert_eq!(one.len(), several.len(), "seed {seed}");

        // The service lands them (on this machine's threads): every ticket
        // ends, and an admin's landing the one-thread build said lands is
        // answered with the snapshots it said.
        release_branch(&hub, pid, "main");
        for (who, t) in &tickets {
            let token = [&dev, &admin][*who];
            let v = wait_ticket(&api, token, &p.name, t);
            assert!(v["state"] == "landed" || v["state"] == "conflict", "seed {seed}: {v}");
            if let (1, Some(line)) = (*who, one.iter().find(|l| l.starts_with(&format!("{t} landed as ")))) {
                assert_eq!(v["state"], "landed", "seed {seed}: {v}");
                let landed: Vec<String> = v["landed"].as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_string()).collect();
                assert!(line.starts_with(&format!("{t} landed as {landed:?} merged ")), "seed {seed}: {line}");
            }
        }
    }
}

/// Every folder under `root` writable or not (the objects of a server
/// whose objects are in a folder).
fn writable(root: &std::path::Path, yes: bool) {
    use std::os::unix::fs::PermissionsExt;
    let mut dirs = vec![root.to_path_buf()];
    while let Some(d) = dirs.pop() {
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(if yes { 0o755 } else { 0o555 })).unwrap();
        for e in std::fs::read_dir(&d).unwrap().flatten() {
            if e.file_type().unwrap().is_dir() {
                dirs.push(e.path());
            }
        }
    }
}

/// BUG-1955: a batch's objects are stored while its transaction runs, and
/// it commits only once they are: when they cannot be stored, nothing of
/// the batch lands (the branch keeps its tip, the tickets stay queued);
/// once they can, it lands, and what the branch names can be read.
#[test]
fn bug_1955_a_batch_lands_only_once_its_objects_are_stored() {
    let url = std::env::var("VEIL_TEST_DATABASE_URL").expect("VEIL_TEST_DATABASE_URL");
    // Objects in a folder, which can be made unwritable.
    let hub = TestHub::start_with_s3(&url, Duration::from_secs(3600), None);
    let p = setup_project(&hub);
    let pid = project_id_of(&hub, &p.name);
    let api = hub.api();
    let dev = p.dev.token();
    let base = api.tips(Some(&dev), &p.name).unwrap().branches["main"];
    hold_branch(&hub, pid, "main");
    let mut tickets = Vec::new();
    for i in 0..3 {
        let r = land_edit(&api, &dev, &p.name, base, &format!("src/stored/f{i}.rs"), &format!("stored {i}\n"), false);
        assert_eq!(r.status, 200, "submit {i}: {}", String::from_utf8_lossy(&r.body));
        tickets.push(r.json()["ticket"].as_str().unwrap().to_string());
    }
    let objects = hub._dir.path().join("objects");
    writable(&objects, false);
    release_branch(&hub, pid, "main");
    let states = |hub: &TestHub| -> Vec<String> {
        hub.rt
            .block_on(
                sqlx::query_scalar("SELECT state FROM landing_queue WHERE project_id = $1 AND ticket = ANY($2) ORDER BY ticket")
                    .bind(pid)
                    .bind(&tickets)
                    .fetch_all(&hub.hub().db),
            )
            .unwrap()
    };
    // The service tries the batch again and again meanwhile.
    std::thread::sleep(Duration::from_secs(3));
    let failed = hub.hub().landing.stats.batches.load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(states(&hub), vec!["queued"; 3], "a batch whose objects could not be stored changed its tickets");
    assert_eq!(api.tips(Some(&dev), &p.name).unwrap().branches["main"], base, "a batch whose objects could not be stored moved the branch");

    writable(&objects, true);
    for t in &tickets {
        let v = wait_ticket(&api, &dev, &p.name, t);
        assert_eq!(v["state"], "landed", "{v}");
    }
    assert!(hub.hub().landing.stats.batches.load(std::sync::atomic::Ordering::Relaxed) > failed, "the batch committed once stored");
    let tip = api.tips(Some(&dev), &p.name).unwrap().branches["main"];
    assert_ne!(tip, base);
    for i in 0..3 {
        let r = api.get(Some(&dev), &format!("/v1/projects/{}/q/file?rev={}&path=src/stored/f{i}.rs", p.name, tip.hex()));
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        assert_eq!(String::from_utf8_lossy(&r.body), format!("stored {i}\n"));
    }
}

/// BUG-1956: changes that each merge cleanly with all the others (twelve
/// edits of twelve different lines of one file, all on one base) all land.
/// Until the fix a batch landed only the first of them and sent the rest
/// to a merge each; after three rounds the ones left were answered
/// `conflict`, though nothing conflicts.
#[test]
fn bug_1956_clean_overlaps_of_one_file_all_land() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id_of(&hub, &p.name);
    let api = hub.api();
    let dev = p.dev.token();
    let shared: String = (0..40).map(|i| format!("line {i}\n")).collect();
    let made = land_edit(&api, &dev, &p.name, api.tips(Some(&dev), &p.name).unwrap().branches["main"], "src/over/shared.txt", &shared, true);
    assert_eq!(made.status, 200, "{}", String::from_utf8_lossy(&made.body));
    assert_eq!(made.json()["state"], "landed", "{}", made.json());
    let base = api.tips(Some(&dev), &p.name).unwrap().branches["main"];
    hold_branch(&hub, pid, "main");
    let mut tickets = Vec::new();
    for i in 0..12 {
        let text = shared.replace(&format!("line {}\n", 3 * i), &format!("line {} edited\n", 3 * i));
        let r = land_edit(&api, &dev, &p.name, base, "src/over/shared.txt", &text, false);
        assert_eq!(r.status, 200, "submit {i}: {}", String::from_utf8_lossy(&r.body));
        tickets.push(r.json()["ticket"].as_str().unwrap().to_string());
    }
    release_branch(&hub, pid, "main");
    let mut states = Vec::new();
    for t in &tickets {
        let deadline = std::time::Instant::now() + Duration::from_secs(60);
        let state = loop {
            let r = api.get(Some(&dev), &format!("/v1/projects/{}/land/{t}", p.name));
            assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
            let s = r.json()["state"].as_str().unwrap_or_default().to_string();
            if (s != "queued" && s != "merging") || std::time::Instant::now() > deadline {
                break s;
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        states.push(state);
    }
    assert_eq!(states, vec!["landed"; 12], "clean overlaps answered otherwise");
    let tip = api.tips(Some(&dev), &p.name).unwrap().branches["main"];
    let r = api.get(Some(&dev), &format!("/v1/projects/{}/q/file?rev={}&path=src/over/shared.txt", p.name, tip.hex()));
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let want: String = (0..40).map(|i| if i % 3 == 0 && i < 36 { format!("line {i} edited\n") } else { format!("line {i}\n") }).collect();
    assert_eq!(String::from_utf8_lossy(&r.body), want);
}

/// BUG-1956: the queue's answers are a serial landing's. Seeded runs of
/// 80 changes of one person, each editing one or two lines of one of three
/// shared files, all made on one base (so most overlap what lands before
/// them, and some truly conflict): each change is answered `landed` exactly
/// when a three-way merge onto everything landed before it in the queue's
/// order is clean, and `conflict` otherwise; each landed change lands once,
/// in that order (the file at its landed snapshot is the serial result after
/// it); and the branch ends as the serial run does.
#[test]
fn bug_1956_overlapping_landings_are_answered_as_landing_them_one_by_one_in_order() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id_of(&hub, &p.name);
    let api = hub.api();
    let dev = p.dev.token();
    let files: Vec<(String, String)> =
        (0..3).map(|f| (format!("src/serial/f{f}.txt"), (0..30).map(|i| format!("file {f} line {i}\n")).collect())).collect();
    for (path, text) in &files {
        let made = land_edit(&api, &dev, &p.name, api.tips(Some(&dev), &p.name).unwrap().branches["main"], path, text, true);
        assert_eq!(made.status, 200, "{}", String::from_utf8_lossy(&made.body));
        assert_eq!(made.json()["state"], "landed", "{}", made.json());
    }
    for seed in 1..=2u64 {
        let mut state = seed.wrapping_mul(0x9e3779b97f4a7c15);
        let mut next = |n: u64| {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (state >> 33) % n
        };
        let base = api.tips(Some(&dev), &p.name).unwrap().branches["main"];
        let start: Vec<String> = files
            .iter()
            .map(|(path, _)| {
                let r = api.get(Some(&dev), &format!("/v1/projects/{}/q/file?rev={}&path={path}", p.name, base.hex()));
                assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
                String::from_utf8(r.body).unwrap()
            })
            .collect();
        hold_branch(&hub, pid, "main");
        let mut submitted: Vec<(usize, String, String)> = Vec::new();
        for i in 0..80 {
            let f = next(3) as usize;
            let mut lines: Vec<String> = start[f].lines().map(|l| format!("{l}\n")).collect();
            let at = next(30) as usize;
            lines[at] = format!("{seed}/{i} edited line {at}\n");
            if next(3) == 0 {
                let other = next(30) as usize;
                lines[other] = format!("{seed}/{i} edited line {other}\n");
            }
            let text: String = lines.concat();
            let r = land_edit(&api, &dev, &p.name, base, &files[f].0, &text, false);
            assert_eq!(r.status, 200, "seed {seed}, submit {i}: {}", String::from_utf8_lossy(&r.body));
            assert_eq!(r.json()["state"], "queued", "seed {seed}, submit {i}: {}", r.json());
            submitted.push((f, text, r.json()["ticket"].as_str().unwrap().to_string()));
        }
        // The serial reference: each change in the queue's order, merged
        // onto what landed before it.
        let mut now = start.clone();
        let mut want: Vec<Option<String>> = Vec::new();
        for (f, text, _) in &submitted {
            let merged = if now[*f] == start[*f] {
                Ok(text.as_bytes().to_vec())
            } else {
                veil_core::textmerge::merge(start[*f].as_bytes(), now[*f].as_bytes(), text.as_bytes(), 7, veil_core::textmerge::Style::Diff3)
            };
            match merged {
                Ok(m) => {
                    now[*f] = String::from_utf8(m).unwrap();
                    want.push(Some(now[*f].clone()));
                }
                Err(_) => want.push(None),
            }
        }
        let landing = want.iter().filter(|w| w.is_some()).count();
        assert!((20..80).contains(&landing), "seed {seed}: the seed gives {landing} landings of 80, too few or no conflict");
        release_branch(&hub, pid, "main");
        let mut seen = std::collections::HashSet::new();
        for ((f, _, ticket), want) in submitted.iter().zip(&want) {
            let deadline = std::time::Instant::now() + Duration::from_secs(60);
            let v = loop {
                let r = api.get(Some(&dev), &format!("/v1/projects/{}/land/{ticket}", p.name));
                assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
                let v = r.json();
                if v["state"] != "queued" && v["state"] != "merging" {
                    break v;
                }
                assert!(std::time::Instant::now() < deadline, "seed {seed}: {ticket} still {v}");
                std::thread::sleep(Duration::from_millis(25));
            };
            match want {
                Some(text) => {
                    assert_eq!(v["state"], "landed", "seed {seed}: the serial landing lands {ticket}: {v}");
                    let landed = v["landed"].as_array().unwrap();
                    assert_eq!(landed.len(), 1, "{v}");
                    let at = landed[0].as_str().unwrap();
                    assert!(seen.insert(at.to_string()), "seed {seed}: {at} answered twice");
                    let r = api.get(Some(&dev), &format!("/v1/projects/{}/q/file?rev={at}&path={}", p.name, files[*f].0));
                    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
                    assert_eq!(String::from_utf8_lossy(&r.body), *text, "seed {seed}: {ticket} landed in its place");
                }
                None => assert_eq!(v["state"], "conflict", "seed {seed}: the serial landing refuses {ticket}: {v}"),
            }
        }
        let tip = api.tips(Some(&dev), &p.name).unwrap().branches["main"];
        for (f, (path, _)) in files.iter().enumerate() {
            let r = api.get(Some(&dev), &format!("/v1/projects/{}/q/file?rev={}&path={path}", p.name, tip.hex()));
            assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
            assert_eq!(String::from_utf8_lossy(&r.body), now[f], "seed {seed}: {path} at the tip");
        }
    }
}

/// A proxy in front of the test's S3 store that holds every `PUT` while
/// `stall` is set (reads go through): object writes that hang.
fn stalling_s3(stall: std::sync::Arc<std::sync::atomic::AtomicBool>) -> String {
    use std::{
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        sync::atomic::Ordering,
    };
    let upstream = std::env::var("VEIL_TEST_S3_ENDPOINT").expect("VEIL_TEST_S3_ENDPOINT");
    let upstream = upstream.trim_start_matches("http://").trim_end_matches('/').to_string();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let at = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for client in listener.incoming().flatten() {
            let Ok(server) = TcpStream::connect(&upstream) else { continue };
            let (mut c_in, mut s_out) = (client.try_clone().unwrap(), server.try_clone().unwrap());
            let stall = stall.clone();
            std::thread::spawn(move || {
                let mut buf = vec![0u8; 64 << 10];
                while let Ok(n) = c_in.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    while buf.starts_with(b"PUT ") && stall.load(Ordering::SeqCst) {
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    if s_out.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
                let _ = s_out.shutdown(std::net::Shutdown::Write);
            });
            let (mut s_in, mut c_out) = (server, client);
            std::thread::spawn(move || {
                let _ = std::io::copy(&mut s_in, &mut c_out);
                let _ = c_out.shutdown(std::net::Shutdown::Write);
            });
        }
    });
    format!("http://{at}")
}

/// BUG-1982: while a batch's objects are being stored, its transaction
/// holds the branch's lease row only briefly: a store that hangs never
/// keeps the branch's other servers from its lease (they take it once it
/// expires), and nothing of the batch lands until its objects are stored.
/// Once they are, it lands.
#[test]
fn bug_1982_a_hung_object_store_never_holds_the_branchs_lease_row() {
    use std::sync::{atomic::Ordering, Arc};
    let url = std::env::var("VEIL_TEST_DATABASE_URL").expect("VEIL_TEST_DATABASE_URL");
    let stall = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let hub = TestHub::start_with_s3(&url, Duration::from_secs(3600), Some(stalling_s3(stall.clone())));
    let p = setup_project(&hub);
    let pid = project_id_of(&hub, &p.name);
    let api = hub.api();
    let dev = p.dev.token();
    let base = api.tips(Some(&dev), &p.name).unwrap().branches["main"];
    hold_branch(&hub, pid, "main");
    let r = land_edit(&api, &dev, &p.name, base, "src/hung/f.rs", "hung\n", false);
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let ticket = r.json()["ticket"].as_str().unwrap().to_string();
    let landed_here = || hub.hub().landing.stats.landed.load(Ordering::SeqCst);
    let landed_before = landed_here();
    stall.store(true, Ordering::SeqCst);
    release_branch(&hub, pid, "main");
    // The batch is built and its objects' writes hang.
    std::thread::sleep(Duration::from_secs(4));
    let db = hub.hub().db.clone();
    let locked: Result<String, sqlx::Error> = hub.rt.block_on(async {
        let mut tx = db.begin().await?;
        sqlx::query("SET LOCAL lock_timeout = '2s'").execute(&mut *tx).await?;
        let holder: String = sqlx::query_scalar("SELECT holder FROM landing_leases WHERE project_id = $1 AND branch = 'main' FOR UPDATE")
            .bind(pid)
            .fetch_one(&mut *tx)
            .await?;
        tx.rollback().await?;
        Ok(holder)
    });
    let holder = locked.expect("the lease's row was held while the batch's objects were being stored");
    assert_ne!(holder, "test", "the service never took the lease");
    // This server landed nothing whose objects it had not stored. (Another
    // test's server on the same database may take the expired lease over
    // and land the change, as BUG-1982's fix means it to: `landing::resume`
    // serves every queued branch.)
    assert_eq!(landed_here(), landed_before, "a batch whose objects were not stored landed");

    stall.store(false, Ordering::SeqCst);
    let v = wait_ticket(&api, &dev, &p.name, &ticket);
    assert_eq!(v["state"], "landed", "{v}");
    let tip = api.tips(Some(&dev), &p.name).unwrap().branches["main"];
    let r = api.get(Some(&dev), &format!("/v1/projects/{}/q/file?rev={}&path=src/hung/f.rs", p.name, tip.hex()));
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(String::from_utf8_lossy(&r.body), "hung\n");
}

/// BUG-1970: a clean stop ends the batch being committed, then gives the
/// branch's lease up, and another server takes the branch over at once (not
/// after the lease runs out, as after a crash). Two servers on one
/// database: `a` holds `main`'s lease and is committing a batch, held at its
/// entry's row; `a` is stopped (`Running::stop`, what SIGINT and SIGTERM
/// do). The stop waits for that batch, which lands; the lease is then given
/// up with its fencing epoch kept; a landing on `b` takes the lease (the
/// next epoch) and lands well within the lease's time.
#[test]
fn bug_1970_a_clean_stop_ends_its_batch_and_gives_the_lease_up_at_once() {
    let a = TestHub::start();
    let p = setup_project(&a);
    let b = TestHub::beside(&a);
    let pid = project_id_of(&a, &p.name);
    let (api_a, api_b) = (a.api(), b.api());
    let dev = p.dev.token();
    let db = b.hub().db.clone();
    let lease = || -> (String, i64, i64) {
        b.rt.block_on(
            sqlx::query_as("SELECT holder, epoch, expires_at FROM landing_leases WHERE project_id = $1 AND branch = 'main'")
                .bind(pid)
                .fetch_one(&db),
        )
        .unwrap()
    };
    let base = api_a.tips(Some(&dev), &p.name).unwrap().branches["main"];
    hold_branch(&a, pid, "main");
    let r = land_edit(&api_a, &dev, &p.name, base, "src/stop/one.txt", "one\n", false);
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["state"], "queued", "{}", r.json());
    let ticket = r.json()["ticket"].as_str().unwrap().to_string();
    // `a`'s batch is held at the entry's row, which it writes in its commit.
    let mut held = b.rt.block_on(db.begin()).unwrap();
    b.rt.block_on(sqlx::query("SELECT 1 FROM landing_queue WHERE project_id = $1 AND ticket = $2 FOR UPDATE").bind(pid).bind(&ticket).fetch_one(&mut *held)).unwrap();
    release_branch(&a, pid, "main");
    let yugabyte = b.rt.block_on(sqlx::query_scalar::<_, String>("SELECT version()").fetch_one(&db)).unwrap().contains("-YB-");
    let until = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let waiting: i64 = b
            .rt
            .block_on(
                sqlx::query_scalar(if yugabyte {
                    "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND state = 'active' AND query LIKE 'UPDATE landing_queue AS q%'"
                } else {
                    "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock' AND query LIKE 'UPDATE landing_queue AS q%'"
                })
                .fetch_one(&db),
            )
            .unwrap();
        if waiting > 0 {
            break;
        }
        assert!(std::time::Instant::now() < until, "`a`'s batch never reached its entry's row");
        std::thread::sleep(Duration::from_millis(50));
    }
    let (holder_a, epoch_a, _) = lease();
    assert_ne!(holder_a, "test");

    std::thread::scope(|scope| {
        let stopping = scope.spawn(move || drop(a));
        std::thread::sleep(Duration::from_millis(500));
        assert!(!stopping.is_finished(), "the stop waits for the batch being committed");
        let (h, e, expires) = lease();
        assert_eq!((&h, e), (&holder_a, epoch_a));
        assert_ne!(expires, 0, "the lease is kept while its batch commits");
        b.rt.block_on(held.rollback()).unwrap();
        stopping.join().unwrap();
    });
    let (h, e, expires) = lease();
    assert_eq!((&h, e), (&holder_a, epoch_a), "the epoch is kept");
    assert_eq!(expires, 0, "a clean stop gives the lease up");
    let v = wait_ticket(&api_b, &dev, &p.name, &ticket);
    assert_eq!(v["state"], "landed", "the batch being committed at the stop landed: {v}");

    let tip = api_b.tips(Some(&dev), &p.name).unwrap().branches["main"];
    let t = std::time::Instant::now();
    let r = land_edit(&api_b, &dev, &p.name, tip, "src/stop/two.txt", "two\n", true);
    let took = t.elapsed();
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["state"], "landed", "{}", r.json());
    assert!(took < Duration::from_millis(veil_server::landing::LEASE_MS as u64), "`b` took {took:?} to land: as long as the lease");
    let (h2, e2, _) = lease();
    assert_ne!(h2, holder_a);
    assert_eq!(e2, epoch_a + 1, "the next holder fences the stopped one out");
    let tip = api_b.tips(Some(&dev), &p.name).unwrap().branches["main"];
    for (path, text) in [("src/stop/one.txt", "one\n"), ("src/stop/two.txt", "two\n")] {
        let r = api_b.get(Some(&dev), &format!("/v1/projects/{}/q/file?rev={}&path={path}", p.name, tip.hex()));
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        assert_eq!(String::from_utf8_lossy(&r.body), text);
    }
}

/// BUG-2060: a change whose edit the tip already holds merges cleanly, as a
/// three-way merge of it onto everything landed before it does: both sides
/// made the same edit to a file (or the tip's edit includes the change's),
/// added the same file, or deleted the same file. Until the fix the merge
/// kept such a path as an edit that changes nothing, the landing check found
/// the new snapshot's diff without it, and the change was refused as "a bug
/// in the server".
#[test]
fn bug_2060_an_edit_the_tip_already_holds_merges_cleanly() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    let dev = p.dev.token();
    let land = |base: veil_core::ObjectId, edits: serde_json::Value| {
        let r = api.post_json(
            Some(&dev),
            &format!("/v1/projects/{}/land", p.name),
            &serde_json::json!({"onto": "main", "base": base.hex(), "edits": edits, "description": "bug 2060", "wait": true}),
        );
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        r.json()
    };
    let tip = || api.tips(Some(&dev), &p.name).unwrap().branches["main"];
    let file = |path: &str| {
        let r = api.get(Some(&dev), &format!("/v1/projects/{}/q/file?rev={}&path={path}", p.name, tip().hex()));
        (r.status, String::from_utf8_lossy(&r.body).to_string())
    };
    let lines: String = (0..30).map(|i| format!("line {i}\n")).collect();
    let made = land(
        tip(),
        serde_json::json!([{"path": "src/same/f.txt", "put": {"text": lines}}, {"path": "src/same/gone.txt", "put": {"text": "to delete\n"}}]),
    );
    assert_eq!(made["state"], "landed", "{made}");
    let base = tip();
    // The tip: line 3 and line 20 edited, a file added, a file deleted.
    let both = lines.replace("line 3\n", "line 3 edited\n").replace("line 20\n", "line 20 edited\n");
    let first = land(
        base,
        serde_json::json!([
            {"path": "src/same/f.txt", "put": {"text": both}},
            {"path": "src/same/new.txt", "put": {"text": "the same new file\n"}},
            {"path": "src/same/gone.txt", "delete": true},
        ]),
    );
    assert_eq!(first["state"], "landed", "{first}");
    // The change, on the old base: line 3 edited the same way, the same file
    // added, the same file deleted, and one edit of its own.
    let second = land(
        base,
        serde_json::json!([
            {"path": "src/same/f.txt", "put": {"text": lines.replace("line 3\n", "line 3 edited\n")}},
            {"path": "src/same/new.txt", "put": {"text": "the same new file\n"}},
            {"path": "src/same/gone.txt", "delete": true},
            {"path": "src/same/own.txt", "put": {"text": "its own edit\n"}},
        ]),
    );
    assert_eq!(second["state"], "landed", "a clean three-way merge lands: {second}");
    assert_eq!(second["merges"], 1, "{second}");
    assert_eq!(file("src/same/f.txt"), (200, both));
    assert_eq!(file("src/same/new.txt"), (200, "the same new file\n".to_string()));
    assert_eq!(file("src/same/own.txt"), (200, "its own edit\n".to_string()));
    assert_ne!(file("src/same/gone.txt").0, 200, "the deleted file stays deleted");
    // A change whose every edit the tip holds: the merge is clean, and empty.
    let before = tip();
    let third = land(base, serde_json::json!([{"path": "src/same/new.txt", "put": {"text": "the same new file\n"}}]));
    assert_eq!(third["state"], "landed", "a clean three-way merge lands: {third}");
    assert_ne!(tip(), before, "{third}");
    assert_eq!(file("src/same/new.txt"), (200, "the same new file\n".to_string()));
    assert_eq!(file("src/same/own.txt"), (200, "its own edit\n".to_string()));
}
