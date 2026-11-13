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
    let held_pid: i32 = b.rt.block_on(sqlx::query_scalar("SELECT pg_backend_pid()").fetch_one(&mut *held)).unwrap();
    release_branch(&a, pid, "main");
    crate::failover::wait_for_batch_at_row(&b, pid, held_pid);
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

/// A change made with `vl` in `dir` (the person's clone of the project) on
/// `base`, by applying `edits` (in the form of `/land`'s) to its files, and
/// given the tag `name` (for [`vl_land`]): its snapshot id. (`/land`'s
/// edits cannot replace a file by a folder, or a folder by a file, in one
/// change.)
fn vl_change(who: &Person, dir: &std::path::Path, base: veil_core::ObjectId, edits: &[serde_json::Value], name: &str) -> veil_core::ObjectId {
    use std::os::unix::fs::PermissionsExt;
    who.ok(dir, &["new", &base.hex()]);
    for e in edits.iter().filter(|e| e["delete"] == true) {
        let path = dir.join(e["path"].as_str().unwrap());
        std::fs::remove_file(&path).unwrap_or_else(|err| panic!("{}: {err}", path.display()));
        let mut d = path.parent().unwrap().to_path_buf();
        while d != dir && std::fs::read_dir(&d).unwrap().next().is_none() {
            std::fs::remove_dir(&d).unwrap();
            d = d.parent().unwrap().to_path_buf();
        }
    }
    for e in edits.iter().filter(|e| e.get("put").is_some()) {
        let path = dir.join(e["path"].as_str().unwrap());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, e["put"]["text"].as_str().unwrap()).unwrap();
        let mode = if e["put"]["executable"] == true { 0o755 } else { 0o644 };
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    }
    who.ok(dir, &["commit", "-m", name]);
    let log: serde_json::Value = serde_json::from_str(&who.ok(dir, &["log", "-r", "@-", "-n", "1", "--json"])).unwrap();
    let snap = veil_core::ObjectId::from_hex(log["entries"][0]["snapshot_id"].as_str().unwrap()).unwrap();
    who.ok(dir, &["tag", "set", name, "-r", "@-", "--force"]);
    snap
}

/// Submit the change tagged `tag` in `dir` to land on `onto` with `vl land`,
/// not waiting: its ticket.
fn vl_land(who: &Person, dir: &std::path::Path, tag: &str, onto: &str) -> String {
    let out = who.ok(dir, &["land", tag, "--onto", onto, "--no-wait"]);
    out.split("--status ")
        .nth(1)
        .and_then(|r| r.split('`').next())
        .unwrap_or_else(|| panic!("no ticket in: {out}"))
        .trim()
        .to_string()
}

/// Whether `edits` replace a file by a folder or a folder by a file
/// (which only [`vl_change`] makes).
fn swaps_a_folder(edits: &[serde_json::Value]) -> bool {
    let paths = edit_paths(edits);
    paths.iter().any(|a| paths.iter().any(|b| a != b && overlap(a, b)))
}

/// BUG-2070 (BUG-2060's class, left by its fix): an edit the tip already
/// holds is no edit of the merged change whatever the file: a binary file,
/// a file over the 1 MiB merge cap, a `-merge` file, a file whose base was
/// a folder, and the delete of a file the tip replaced with a folder. The
/// tip makes each of those edits; a change on the old base makes the same
/// ones and one of its own: a three-way merge of it is clean, so it lands,
/// and the tip keeps every file as the first change left it.
#[test]
fn bug_2070_an_edit_the_tip_already_holds_merges_cleanly_whatever_the_file() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    let admin = p.admin.token();
    let tip = || api.tips(Some(&admin), &p.name).unwrap().branches["main"];
    let big: String = (0..30_000).map(|i| format!("big line {i:06} of a file over the merge cap\n")).collect();
    assert!(big.len() as u64 > veil_server::landing::merge::MAX_MERGE_FILE_BYTES);
    let r = api.post_json(
        Some(&admin),
        &format!("/v1/projects/{}/land", p.name),
        &serde_json::json!({"onto": "main", "base": tip().hex(), "description": "the files", "wait": true, "edits": [
            {"path": "src/held/.veilattributes", "put": {"text": "*.lock -merge\n"}},
            {"path": "src/held/bin.dat", "put": {"text": "\u{0}BIN 0\n"}},
            {"path": "src/held/big.txt", "put": {"text": big}},
            {"path": "src/held/dep.lock", "put": {"text": "dep 1\ndep 2\n"}},
            {"path": "src/held/node", "put": {"text": "a file\n"}},
            {"path": "src/held/tree/inner.txt", "put": {"text": "in a folder\n"}},
        ]}),
    );
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["state"], "landed", "{}", r.json());
    let base = tip();
    let dir = p.admin.dir("held-2070");
    p.admin.ok(p.admin.home.path(), &["clone", &hub.url(&p.name), dir.to_str().unwrap()]);
    let edits = vec![
        serde_json::json!({"path": "src/held/bin.dat", "put": {"text": "\u{0}BIN 1\n"}}),
        serde_json::json!({"path": "src/held/big.txt", "put": {"text": big.replacen("big line 000007 ", "big line 000007 edited ", 1)}}),
        serde_json::json!({"path": "src/held/dep.lock", "put": {"text": "dep 1\ndep 3\n"}}),
        serde_json::json!({"path": "src/held/node", "delete": true}),
        serde_json::json!({"path": "src/held/node/inner.txt", "put": {"text": "now a folder\n"}}),
        serde_json::json!({"path": "src/held/tree/inner.txt", "delete": true}),
        serde_json::json!({"path": "src/held/tree", "put": {"text": "now a file\n"}}),
    ];
    let mut own = edits.clone();
    own.push(serde_json::json!({"path": "src/held/own.txt", "put": {"text": "its own edit\n"}}));
    vl_change(&p.admin, &dir, base, &edits, "held-first");
    vl_change(&p.admin, &dir, base, &own, "held-second");
    vl_change(&p.admin, &dir, base, &edits, "held-third");
    let land = |tag: &str| settled(&api, &admin, &p.name, &vl_land(&p.admin, &dir, tag, "main"));
    let landed = land("held-first");
    assert_eq!(landed["state"], "landed", "{landed}");
    let after_first = tip();
    let landed = land("held-second");
    assert_eq!(landed["state"], "landed", "a clean three-way merge lands: {landed}");
    assert_eq!(landed["merges"], 1, "{landed}");
    let file = |rev: veil_core::ObjectId, path: &str| {
        let r = api.get(Some(&admin), &format!("/v1/projects/{}/q/file?rev={}&path={path}", p.name, rev.hex()));
        (r.status, r.body)
    };
    let now = tip();
    for path in ["src/held/bin.dat", "src/held/big.txt", "src/held/dep.lock", "src/held/node/inner.txt", "src/held/tree"] {
        let (got, want) = (file(now, path), file(after_first, path));
        assert_eq!(want.0, 200, "{path}");
        assert!(got == want, "{path} changed by the second change");
    }
    assert_eq!(file(now, "src/held/own.txt"), (200, b"its own edit\n".to_vec()));
    // Every edit held by the tip: the change lands, empty.
    let landed = land("held-third");
    assert_eq!(landed["state"], "landed", "a clean three-way merge lands: {landed}");
    assert_eq!(
        api.get(Some(&admin), &format!("/v1/projects/{}/q/tree?rev={}", p.name, tip().hex())).json()["id"],
        api.get(Some(&admin), &format!("/v1/projects/{}/q/tree?rev={}", p.name, now.hex())).json()["id"],
        "an empty change"
    );
}

/// One change of [`bug_1956_every_kind_of_edit_lands_as_landing_them_one_by_one`]:
/// who submits it, on which base, and its edits.
#[derive(Clone)]
struct Planned {
    person: usize,
    /// 0: the first base, 1: the later one.
    base: usize,
    edits: Vec<serde_json::Value>,
    /// The index of the earlier change it repeats exactly (an edit the tip
    /// may already hold, BUG-2060).
    repeats: Option<usize>,
    /// Made with `vl` (it replaces a file by a folder or back): the tags of
    /// its two copies, for the batch and for the one-by-one run.
    made: Option<(String, String)>,
}

fn kinds_put(path: &str, text: &str, executable: bool) -> serde_json::Value {
    if executable {
        serde_json::json!({"path": path, "put": {"text": text, "executable": true}})
    } else {
        serde_json::json!({"path": path, "put": {"text": text}})
    }
}

fn kinds_delete(path: &str) -> serde_json::Value {
    serde_json::json!({"path": path, "delete": true})
}

fn edit_paths(edits: &[serde_json::Value]) -> Vec<String> {
    edits.iter().map(|e| e["path"].as_str().unwrap().to_string()).collect()
}

fn overlap(a: &str, b: &str) -> bool {
    a == b || a.starts_with(&format!("{b}/")) || b.starts_with(&format!("{a}/"))
}

/// The landing answer of a ticket once it is no longer queued.
fn settled(api: &Api, token: &str, project: &str, ticket: &str) -> serde_json::Value {
    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    loop {
        let r = api.get(Some(token), &format!("/v1/projects/{project}/land/{ticket}"));
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        let v = r.json();
        if v["state"] != "queued" && v["state"] != "merging" {
            return v;
        }
        assert!(std::time::Instant::now() < deadline, "{ticket} still {v}");
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// The id of the root tree of snapshot `rev`, as the holder of `token` reads it.
fn root_tree(api: &Api, token: &str, project: &str, rev: &str) -> String {
    let r = api.get(Some(token), &format!("/v1/projects/{project}/q/tree?rev={rev}"));
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    r.json()["id"].as_str().unwrap().to_string()
}

/// BUG-1956: a batch's answers and trees are those of landing its changes
/// one by one in the queue's order, for every kind of edit: line edits of
/// text files, deletes, renames, a file replaced by a folder and a folder
/// by a file (and a folder made from a file turned back into one, on a
/// later base), binary files, the executable bit, a file over the 1 MiB
/// merge cap, `.veilattributes` rules (`merge=union`, `-merge`), changes
/// repeated exactly (an edit the tip already holds, BUG-2060), and three
/// people submitting in an uneven mix (the batch takes them in fair-share
/// order: round-robin over people by their first entry, each person's in
/// order). Seeded runs of 60 changes on two bases, queued while the branch
/// is held so that they land in one batch; then the same changes land one
/// at a time onto a branch at the same tip, in the fair-share order. Each
/// is answered the same both ways, and each landed one's tree is the same;
/// a change repeated with nothing landed on its paths between lands.
#[test]
fn bug_1956_every_kind_of_edit_lands_as_landing_them_one_by_one() {
    let hub = TestHub::start();
    for seed in 1..=2u64 {
        every_kind_of_edit_run(&hub, seed);
    }
}

fn every_kind_of_edit_run(hub: &TestHub, seed: u64) {
    const K: &str = "src/k";
    let p = setup_project(hub);
    let pid = project_id_of(hub, &p.name);
    let api = hub.api();
    p.admin.ok(&p.dir, &["group", "add", "devs", &p.carol.name, "--confirm", &p.carol.fingerprint()]);
    let tokens = [p.dev.token(), p.admin.token(), p.carol.token()];
    let admin = tokens[1].clone();
    let text30 = |tag: &str| -> String { (0..30).map(|i| format!("{tag} line {i}\n")).collect() };
    let big: String = (0..30_000).map(|i| format!("big line {i:06} of a file over the merge cap\n")).collect();
    assert!(big.len() as u64 > veil_server::landing::merge::MAX_MERGE_FILE_BYTES, "{}", big.len());
    let run_text = |r: usize| format!("#!/bin/sh\necho run {r}\n");
    let mut made = vec![kinds_put(&format!("{K}/.veilattributes"), "*.union merge=union\n*.lock -merge\n", false)];
    for f in 0..4 {
        made.push(kinds_put(&format!("{K}/t{f}.txt"), &text30(&format!("t{f}")), false));
        made.push(kinds_put(&format!("{K}/old{f}.txt"), &text30(&format!("old{f}")), false));
    }
    for i in 0..2 {
        made.push(kinds_put(&format!("{K}/bin{i}.dat"), &format!("\u{0}BIN {i}\n"), false));
        made.push(kinds_put(&format!("{K}/run{i}.sh"), &run_text(i), false));
        made.push(kinds_put(&format!("{K}/node{i}"), &format!("node {i}\n"), false));
        made.push(kinds_put(&format!("{K}/tree{i}/inner.txt"), &format!("tree {i}\n"), false));
    }
    made.push(kinds_put(&format!("{K}/big.txt"), &big, false));
    made.push(kinds_put(&format!("{K}/log.union"), "entry 0\nentry 1\n", false));
    made.push(kinds_put(&format!("{K}/dep.lock"), &text30("dep"), false));
    let tip = |api: &Api| api.tips(Some(&admin), &p.name).unwrap().branches["main"];
    let r = api.post_json(
        Some(&admin),
        &format!("/v1/projects/{}/land", p.name),
        &serde_json::json!({"onto": "main", "base": tip(&api).hex(), "edits": made, "description": "the files", "wait": true}),
    );
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["state"], "landed", "{}", r.json());
    // Each base as each person sees it (a submit names its base in the
    // submitter's own ids).
    let seen = || -> Vec<veil_core::ObjectId> { tokens.iter().map(|t| api.tips(Some(t), &p.name).unwrap().branches["main"]).collect() };
    let x = tip(&api);
    let x_seen = seen();
    // The later base: `node1` is a folder there, and `t0`'s first line is another.
    let dir = p.admin.dir(&format!("kinds-{seed}"));
    p.admin.ok(p.admin.home.path(), &["clone", &hub.url(&p.name), dir.to_str().unwrap()]);
    let to_y = [
        kinds_delete(&format!("{K}/node1")),
        kinds_put(&format!("{K}/node1/inner.txt"), "made a folder\n", false),
        kinds_put(&format!("{K}/t0.txt"), &text30("t0").replacen("t0 line 0\n", "t0 line 0 on y\n", 1), false),
    ];
    vl_change(&p.admin, &dir, x, &to_y, &format!("y{seed}"));
    let made_y = settled(&api, &admin, &p.name, &vl_land(&p.admin, &dir, &format!("y{seed}"), "main"));
    assert_eq!(made_y["state"], "landed", "{made_y}");
    let y = tip(&api);
    let bases = [x_seen, seen()];

    let mut state = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ 0x2070;
    let mut next = |n: u64| {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (state >> 33) % n
    };
    let mut plan: Vec<Planned> = Vec::new();
    let mut bigs = 0;
    for i in 0..60 {
        let person = match next(10) {
            0..=4 => 0,
            5..=7 => 1,
            _ => 2,
        };
        let on_y = next(4) == 0;
        let base = usize::from(on_y);
        let mut op = |next: &mut dyn FnMut(u64) -> u64, kind: u64| -> Vec<serde_json::Value> {
            match kind {
                0 => {
                    let f = next(4) as usize;
                    let mut lines: Vec<String> = text30(&format!("t{f}")).lines().map(|l| format!("{l}\n")).collect();
                    if on_y && f == 0 {
                        lines[0] = "t0 line 0 on y\n".into();
                    }
                    let at = next(30) as usize;
                    lines[at] = format!("{seed}/{i} edited line {at}\n");
                    if next(3) == 0 {
                        let other = next(30) as usize;
                        lines[other] = format!("{seed}/{i} edited line {other}\n");
                    }
                    vec![kinds_put(&format!("{K}/t{f}.txt"), &lines.concat(), false)]
                }
                1 => vec![kinds_delete(&format!("{K}/old{}.txt", next(4)))],
                2 => {
                    let o = next(4);
                    vec![kinds_delete(&format!("{K}/old{o}.txt")), kinds_put(&format!("{K}/ren{o}_{seed}_{i}.txt"), &text30(&format!("old{o}")), false)]
                }
                3 if on_y => vec![kinds_delete(&format!("{K}/node1/inner.txt")), kinds_put(&format!("{K}/node1"), &format!("{seed}/{i} a file again\n"), false)],
                3 => {
                    let n = next(2);
                    vec![kinds_delete(&format!("{K}/node{n}")), kinds_put(&format!("{K}/node{n}/inner.txt"), &format!("{seed}/{i} a folder\n"), false)]
                }
                4 => {
                    let t = next(2);
                    vec![kinds_delete(&format!("{K}/tree{t}/inner.txt")), kinds_put(&format!("{K}/tree{t}"), &format!("{seed}/{i} a file\n"), false)]
                }
                5 => vec![kinds_put(&format!("{K}/bin{}.dat", next(2)), &format!("\u{0}{seed}/{i} BIN\n"), false)],
                6 => {
                    let r = next(2) as usize;
                    let text = if next(2) == 0 { run_text(r) } else { format!("{}echo {seed}/{i}\n", run_text(r)) };
                    vec![kinds_put(&format!("{K}/run{r}.sh"), &text, true)]
                }
                7 if bigs < 3 => {
                    bigs += 1;
                    let at = next(30_000) as usize;
                    let edited = big.replacen(&format!("big line {at:06} "), &format!("big line {at:06} {seed}/{i} "), 1);
                    vec![kinds_put(&format!("{K}/big.txt"), &edited, false)]
                }
                8 => vec![kinds_put(&format!("{K}/log.union"), &format!("entry 0\nentry 1\n{seed}/{i} entry\n"), false)],
                _ => {
                    let mut lines: Vec<String> = text30("dep").lines().map(|l| format!("{l}\n")).collect();
                    let at = next(30) as usize;
                    lines[at] = format!("{seed}/{i} dep {at}\n");
                    vec![kinds_put(&format!("{K}/dep.lock"), &lines.concat(), false)]
                }
            }
        };
        // About one in six repeats an earlier change exactly.
        let earlier: Vec<usize> = (0..plan.len()).filter(|&j| plan[j].base == base && plan[j].repeats.is_none()).collect();
        if !earlier.is_empty() && next(6) == 0 {
            let j = earlier[next(earlier.len() as u64) as usize];
            plan.push(Planned { person, base, edits: plan[j].edits.clone(), repeats: Some(j), made: None });
            continue;
        }
        let kind = next(10);
        let mut edits = op(&mut next, kind);
        if next(4) == 0 {
            let more = op(&mut next, next_kind(kind));
            if !edit_paths(&more).iter().any(|a| edit_paths(&edits).iter().any(|b| overlap(a, b))) {
                edits.extend(more);
            }
        }
        plan.push(Planned { person, base, edits, repeats: None, made: None });
    }
    // The changes that replace a file by a folder or back, made with `vl` by
    // the admin, twice each.
    for (i, c) in plan.iter_mut().enumerate() {
        if swaps_a_folder(&c.edits) {
            c.person = 1;
            let (one, two) = (format!("c{seed}b{i}"), format!("c{seed}s{i}"));
            vl_change(&p.admin, &dir, bases[c.base][1], &c.edits, &one);
            vl_change(&p.admin, &dir, bases[c.base][1], &c.edits, &two);
            c.made = Some((one, two));
        }
    }
    assert!(plan.iter().filter(|c| c.made.is_some()).count() >= 3, "seed {seed}: too few folder changes");

    // Queued while the branch is held: one batch.
    hold_branch(hub, pid, "main");
    let mut tickets = Vec::new();
    for (i, c) in plan.iter().enumerate() {
        if let Some((one, _)) = &c.made {
            tickets.push(vl_land(&p.admin, &dir, one, "main"));
            continue;
        }
        let ask = serde_json::json!({"onto": "main", "base": bases[c.base][c.person].hex(), "edits": c.edits, "description": format!("change {i}"), "wait": false});
        let r = api.post_json(Some(&tokens[c.person]), &format!("/v1/projects/{}/land", p.name), &ask);
        assert_eq!(r.status, 200, "seed {seed}, submit {i}: {}", String::from_utf8_lossy(&r.body));
        assert_eq!(r.json()["state"], "queued", "seed {seed}, submit {i}: {}", r.json());
        tickets.push(r.json()["ticket"].as_str().unwrap().to_string());
    }
    release_branch(hub, pid, "main");
    let answers: Vec<serde_json::Value> = tickets.iter().zip(&plan).map(|(t, c)| settled(&api, &tokens[c.person], &p.name, t)).collect();
    let batches: i64 = hub
        .rt
        .block_on(
            sqlx::query_scalar("SELECT COUNT(DISTINCT done_at) FROM landing_queue WHERE project_id = $1 AND ticket = ANY($2)")
                .bind(pid)
                .bind(&tickets)
                .fetch_one(&hub.hub().db),
        )
        .unwrap();
    assert_eq!(batches, 1, "seed {seed}: the changes landed in more than one batch (the reference's order assumes one)");

    // The fair-share order: round-robin over people by their first change.
    let mut people: Vec<usize> = Vec::new();
    for c in &plan {
        if !people.contains(&c.person) {
            people.push(c.person);
        }
    }
    let mut queues: Vec<std::collections::VecDeque<usize>> = people.iter().map(|who| (0..plan.len()).filter(|&i| plan[i].person == *who).collect()).collect();
    let mut order = Vec::new();
    while queues.iter().any(|q| !q.is_empty()) {
        for q in queues.iter_mut() {
            if let Some(i) = q.pop_front() {
                order.push(i);
            }
        }
    }

    // One by one, onto a branch at the batch's starting tip, in that order.
    let r = api.post_json(
        Some(&admin),
        &format!("/v1/projects/{}/push", p.name),
        &serde_json::json!({"updates": [{"branch": "serial", "expected": null, "new": y.hex()}], "force": false}),
    );
    assert_eq!(r.json()["results"][0]["ok"], true, "{}", r.json());
    let mut serial: Vec<Option<serde_json::Value>> = vec![None; plan.len()];
    for &i in &order {
        let c = &plan[i];
        if let Some((_, two)) = &c.made {
            serial[i] = Some(settled(&api, &admin, &p.name, &vl_land(&p.admin, &dir, two, "serial")));
            continue;
        }
        let ask = serde_json::json!({"onto": "serial", "base": bases[c.base][c.person].hex(), "edits": c.edits, "description": format!("change {i}"), "wait": true});
        let r = api.post_json(Some(&tokens[c.person]), &format!("/v1/projects/{}/land", p.name), &ask);
        assert_eq!(r.status, 200, "seed {seed}, serial {i}: {}", String::from_utf8_lossy(&r.body));
        serial[i] = Some(r.json());
    }
    let mut kinds = std::collections::BTreeMap::new();
    for (pos, &i) in order.iter().enumerate() {
        let (got, want) = (&answers[i], serial[i].as_ref().unwrap());
        *kinds.entry(want["state"].as_str().unwrap_or("?").to_string()).or_insert(0) += 1;
        assert_eq!(got["state"], want["state"], "seed {seed}: change {i} (place {pos}, {:?}) answered otherwise in the batch: {got} / one by one: {want}", edit_paths(&plan[i].edits));
        if want["state"] == "landed" {
            let (g, w) = (got["landed"].as_array().unwrap(), want["landed"].as_array().unwrap());
            assert_eq!(g.len(), 1, "{got}");
            assert_eq!(w.len(), 1, "{want}");
            // (In the submitter's ids, which its answers name.)
            let token = &tokens[plan[i].person];
            assert_eq!(
                root_tree(&api, token, &p.name, g[0].as_str().unwrap()),
                root_tree(&api, token, &p.name, w[0].as_str().unwrap()),
                "seed {seed}: change {i} (place {pos}) landed another tree in the batch"
            );
        }
        // A change repeated with nothing landed on its paths since the one it repeats lands (BUG-2060).
        if let Some(j) = plan[i].repeats {
            let first = order.iter().position(|&k| k == j).unwrap();
            let paths = edit_paths(&plan[i].edits);
            let touched_between = order[first + 1..pos]
                .iter()
                .any(|&k| answers[k]["state"] == "landed" && edit_paths(&plan[k].edits).iter().any(|a| paths.iter().any(|b| overlap(a, b))));
            if first < pos && answers[j]["state"] == "landed" && !touched_between {
                assert_eq!(got["state"], "landed", "seed {seed}: change {i} repeats {j}, which landed, with nothing landed on {paths:?} since: {got}");
            }
        }
    }
    let main_tip = tip(&api);
    let serial_tip = api.tips(Some(&admin), &p.name).unwrap().branches["serial"];
    assert_eq!(root_tree(&api, &admin, &p.name, &main_tip.hex()), root_tree(&api, &admin, &p.name, &serial_tip.hex()), "seed {seed}: the tips differ");
    let landed = kinds.get("landed").copied().unwrap_or(0);
    assert!(landed >= 15 && kinds.get("conflict").copied().unwrap_or(0) >= 5, "seed {seed}: a mix too thin to test: {kinds:?}");
}

/// Another kind of edit than `kind` for a change's second edit.
fn next_kind(kind: u64) -> u64 {
    (kind + 3) % 10
}

/// BUG-2220: a batch's conflict reports are built once the batch is, on its
/// threads, and each still tells what its change was judged on: the tip as
/// everything before it in the queue's order left it, not the tip the
/// batch ends on. In one batch, on one base: an edit of a file lands, a
/// second edit of it conflicts, a new file lands, and a third edit of the
/// file conflicts. The second's report is onto the first's landed
/// snapshot, the third's onto the new file's; both name the first as what
/// landed on the file since their base, and the path with its three
/// versions.
#[test]
fn bug_2220_a_conflict_report_tells_the_tip_its_change_was_judged_on() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id_of(&hub, &p.name);
    let api = hub.api();
    let dev = p.dev.token();
    let made = land_edit(&api, &dev, &p.name, api.tips(Some(&dev), &p.name).unwrap().branches["main"], "src/rep/hot.txt", "v0\n", true);
    assert_eq!(made.status, 200, "{}", String::from_utf8_lossy(&made.body));
    assert_eq!(made.json()["state"], "landed", "{}", made.json());
    let base = api.tips(Some(&dev), &p.name).unwrap().branches["main"];
    hold_branch(&hub, pid, "main");
    let mut tickets = Vec::new();
    for (path, text) in [("src/rep/hot.txt", "a\n"), ("src/rep/hot.txt", "b\n"), ("src/rep/later.txt", "later\n"), ("src/rep/hot.txt", "c\n")] {
        let r = land_edit(&api, &dev, &p.name, base, path, text, false);
        assert_eq!(r.status, 200, "{path}: {}", String::from_utf8_lossy(&r.body));
        tickets.push(r.json()["ticket"].as_str().unwrap().to_string());
    }
    release_branch(&hub, pid, "main");
    let answers: Vec<serde_json::Value> = tickets
        .iter()
        .map(|t| {
            let deadline = std::time::Instant::now() + Duration::from_secs(60);
            loop {
                let r = api.get(Some(&dev), &format!("/v1/projects/{}/land/{t}", p.name));
                assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
                let v = r.json();
                if (v["state"] != "queued" && v["state"] != "merging") || std::time::Instant::now() > deadline {
                    break v;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        })
        .collect();
    let states: Vec<&str> = answers.iter().map(|v| v["state"].as_str().unwrap_or_default()).collect();
    assert_eq!(states, ["landed", "conflict", "landed", "conflict"], "{answers:?}");
    let landed = |v: &serde_json::Value| v["landed"].as_array().and_then(|l| l.last()).and_then(|x| x.as_str()).unwrap().to_string();
    let (first, later) = (landed(&answers[0]), landed(&answers[2]));
    assert_ne!(first, later);
    // The two landed one after the other: the conflict between them moved nothing.
    let r = api.get(Some(&dev), &format!("/v1/projects/{}/q/file?rev={later}&path=src/rep/hot.txt", p.name));
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(String::from_utf8_lossy(&r.body), "a\n");
    for (v, onto) in [(&answers[1], &first), (&answers[3], &later)] {
        assert_eq!(v["onto"].as_str(), Some(onto.as_str()), "{v}");
        assert_eq!(v["base"].as_str(), Some(base.hex().as_str()), "{v}");
        assert_eq!(v["landed_since"], serde_json::json!([first]), "{v}");
        assert_eq!(v["paths"], serde_json::json!(["src/rep/hot.txt"]), "{v}");
        let c = &v["conflicts"][0];
        assert_eq!(c["path"], "src/rep/hot.txt", "{v}");
        assert!(c["base"].is_string() && c["main"].is_string() && c["yours"].is_string(), "{v}");
        assert_ne!(c["main"], c["yours"], "{v}");
        assert_ne!(c["base"], c["main"], "{v}");
    }
    assert_ne!(answers[1]["conflicts"][0]["yours"], answers[3]["conflicts"][0]["yours"]);
    assert_eq!(answers[1]["conflicts"][0]["main"], answers[3]["conflicts"][0]["main"]);
}

/// BUG-2362: the trees a submit's checks graft (the full trees of a change
/// made by someone who cannot see everything: here `src/` holds a folder
/// only security sees) are held while the checks run and stored with the
/// change's other objects, all at once, instead of one at a time as they
/// were made. Every one of them is stored before the change is queued: the
/// landed snapshot's whole tree is in the store, and the change reads back
/// whole for an admin, hidden folder and all.
#[test]
fn bug_2362_a_submits_grafted_trees_are_stored_with_its_objects() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id_of(&hub, &p.name);
    let api = hub.api();
    let (dev, admin) = (p.dev.token(), p.admin.token());
    let base = api.tips(Some(&dev), &p.name).unwrap().branches["main"];
    let r = land_edit(&api, &dev, &p.name, base, "src/grafted/deep/a.rs", "grafted\n", true);
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let v = r.json();
    assert_eq!(v["state"], "landed", "{v}");
    let tip = api.tips(Some(&admin), &p.name).unwrap().branches["main"];
    // The landed snapshot's every tree and blob, from the store itself.
    let store = hub.hub().objects.blob_store().clone();
    let mut todo = vec![hub.rt.block_on(hub.hub().objects.get(pid, &tip)).unwrap().map(|raw| match veil_core::object::Object::decode(&raw).unwrap() {
        veil_core::object::Object::Snapshot(s) => s.tree,
        _ => panic!("the tip is a snapshot"),
    })
    .expect("the landed snapshot is stored")];
    let mut trees = 0;
    while let Some(t) = todo.pop() {
        let key = veil_server::store::object_key(pid, &t);
        assert!(hub.rt.block_on(store.exists(&key)).unwrap(), "tree {} of the landed snapshot is stored", t.short());
        let raw = hub.rt.block_on(hub.hub().objects.get(pid, &t)).unwrap().unwrap();
        let veil_core::object::Object::Tree(tree) = veil_core::object::Object::decode(&raw).unwrap() else { panic!("a tree") };
        trees += 1;
        for e in &tree.entries {
            if e.kind == veil_core::object::EntryKind::Dir {
                todo.push(e.id);
            } else {
                assert!(hub.rt.block_on(store.exists(&veil_server::store::object_key(pid, &e.id))).unwrap(), "{} is stored", e.id.short());
            }
        }
    }
    assert!(trees >= 5, "the root, src/, the hidden folder and the two new ones: {trees}");
    for (path, want) in [("src/grafted/deep/a.rs", "grafted\n".to_string()), (&format!("src/{NESTED_DIR}/key.txt") as &str, NESTED_MARK.to_string())] {
        let r = api.get(Some(&admin), &format!("/v1/projects/{}/q/file?rev={}&path={path}", p.name, tip.hex()));
        assert_eq!((r.status, String::from_utf8_lossy(&r.body).to_string()), (200, want), "{path} at the landed tip");
    }
}
