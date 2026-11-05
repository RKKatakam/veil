//! SSH remotes through a stand-in `ssh` (`VEIL_SSH`) that serves the local
//! `sftp-server` from `<root>/sshhome`: URL forms reaching `ssh`, clone,
//! empty remotes, public remotes, corruption and dropped connections.
//! Each test is skipped (passes with a message) without an `sftp-server`.

use super::support::*;

macro_rules! sftp_env {
    () => {
        match Env::with_sftp() {
            Some(e) => e,
            None => return,
        }
    };
}

// Scenario from git t5601-clone.sh / t5603 over ssh: scp-style `host:path` is relative to
// the login directory; push creates it, clone and pull work.
#[test]
fn scp_style_remote_round_trip() {
    let env = sftp_env!();
    let proj = env.project("alice", "proj", &[("hello.txt", "over ssh\n")]);
    env.ok(
        "alice",
        &proj,
        &["remote", "add", "origin", "alice@fakehost:repos/team"],
    );
    let out = env.ok("alice", &proj, &["push"]);
    assert!(out.contains("pushed main"), "{out}");
    let remote = env.path("sshhome/repos/team");
    assert!(
        remote.join(".veil/repo.json").exists(),
        "relative to the login directory"
    );
    let log = env.ssh_log();
    assert!(
        log.contains("-l alice") && log.contains("-- fakehost sftp"),
        "{log}"
    );
    let work = env.dir("work");
    env.ok("bob", &work, &["clone", "bob@fakehost:repos/team"]);
    let bob = work.join("team");
    assert_eq!(read(&bob, "hello.txt"), "over ssh\n");
    env.commit("bob", &bob, "bob", &[("b.txt", "b\n")]);
    env.ok("bob", &bob, &["push"]);
    let out = env.ok("alice", &proj, &["pull"]);
    assert!(out.contains("updated main"), "{out}");
    let (code, f) = env.code(
        "alice",
        &env.root,
        &["fsck", "-R", remote.to_str().unwrap()],
    );
    assert_eq!(code, 0, "{f}");
}

// Scenario from git t9904-url-parse.sh / t5601 ("ssh://user@host:port/path"): user and port reach ssh.
#[test]
fn ssh_url_user_and_port_reach_ssh_and_the_path_is_absolute() {
    let env = sftp_env!();
    let proj = env.project("alice", "proj", &[("a", "a\n")]);
    let abs = env.path("srv/abs.veil");
    let url = format!("ssh://deploy@fakehost:2222{}", abs.display());
    env.ok("alice", &proj, &["remote", "add", "origin", &url]);
    env.ok("alice", &proj, &["push"]);
    assert!(abs.join(".veil/repo.json").exists());
    let log = env.ssh_log();
    assert!(
        log.contains("-p 2222") && log.contains("-l deploy") && log.contains("fakehost"),
        "{log}"
    );
}

// Scenario from git t5601 ("ssh://host/~/path"): `/~/` is the login directory.
#[test]
fn ssh_url_tilde_path_is_relative_to_the_login_directory() {
    let env = sftp_env!();
    let proj = env.project("alice", "proj", &[("a", "a\n")]);
    env.ok(
        "alice",
        &proj,
        &["remote", "add", "origin", "ssh://fakehost/~/home-rel"],
    );
    env.ok("alice", &proj, &["push"]);
    assert!(env.path("sshhome/home-rel/.veil/repo.json").exists());
}

// Scenario from git t5603-clone-dirname.sh over ssh: the default directory name.
#[test]
fn clone_over_ssh_derives_the_directory_name_or_asks_for_one() {
    let env = sftp_env!();
    let proj = env.project("alice", "proj", &[("a", "a\n")]);
    env.ok(
        "alice",
        &proj,
        &["remote", "add", "origin", "fakehost:nested/dir/team-x/"],
    );
    env.ok("alice", &proj, &["push"]);
    let work = env.dir("work");
    env.ok("bob", &work, &["clone", "fakehost:nested/dir/team-x/"]);
    assert!(work.join("team-x/a").exists());
    // `host:` (the login directory itself) has no name: give one.
    let out = env.fails("bob", &work, &["clone", "fakehost:"]);
    assert!(out.contains("directory name"), "{out}");
}

// Scenario from git t5605 ("clone empty repository") over ssh.
#[test]
fn clone_of_an_empty_ssh_remote_and_push_back() {
    let env = sftp_env!();
    let proj = env.dir("proj");
    env.ok("alice", &proj, &["init"]);
    env.ok(
        "alice",
        &proj,
        &["remote", "add", "origin", "fakehost:empty"],
    );
    env.ok("alice", &proj, &["push"]);
    let work = env.dir("work");
    env.ok("bob", &work, &["clone", "fakehost:empty", "e"]);
    let e = work.join("e");
    env.commit("bob", &e, "first", &[("x", "x\n")]);
    env.ok("bob", &e, &["tag", "set", "main", "-r", "@-"]);
    env.ok("bob", &e, &["push"]);
    assert!(open_repo(&env.path("sshhome/empty"))
        .view()
        .tags
        .contains_key("main"));
}

// Veil: a public SSH remote receives no cloaked plaintext and no key rings; a team SSH
// remote holds only ciphertext.
#[test]
fn ssh_public_and_team_remotes_are_filtered() {
    let env = sftp_env!();
    let proj = env.dir("proj");
    env.ok("alice", &proj, &["init"]);
    env.ok("alice", &proj, &["cloak", "secrets/"]);
    write(&proj, "secrets/s.txt", "SFTP-CLOAKED-3141\n");
    write(&proj, ".env", "SFTP-ISOLATED-3141=1\n");
    write(&proj, "pub.txt", "public\n");
    env.ok("alice", &proj, &["commit", "-m", "c"]);
    env.ok("alice", &proj, &["tag", "set", "main", "-r", "@-"]);
    env.ok("alice", &proj, &["remote", "add", "team", "fakehost:team"]);
    env.ok(
        "alice",
        &proj,
        &["remote", "add", "mirror", "fakehost:mirror", "--public"],
    );
    env.ok("alice", &proj, &["push", "team"]);
    env.ok("alice", &proj, &["push", "mirror"]);
    let team = env.path("sshhome/team");
    let mirror = env.path("sshhome/mirror");
    for d in [&team, &mirror] {
        assert_absent(d, "SFTP-CLOAKED-3141", "ssh remote");
        assert_absent(d, "SFTP-ISOLATED-3141", "ssh remote");
    }
    assert!(keyrings(&mirror).is_empty());
    assert!(!keyrings(&team).is_empty());
}

// Veil: a corrupted object on an SSH remote is detected by clone; nothing is left behind.
#[test]
fn a_corrupt_object_on_an_ssh_remote_is_detected_by_clone() {
    let env = sftp_env!();
    let proj = env.project(
        "alice",
        "proj",
        &[("big.txt", &"payload over ssh ".repeat(300))],
    );
    env.ok(
        "alice",
        &proj,
        &["remote", "add", "origin", "fakehost:team"],
    );
    env.ok("alice", &proj, &["push"]);
    let pack = packs(&env.path("sshhome/team")).pop().unwrap();
    let len = std::fs::metadata(&pack).unwrap().len() as isize;
    flip_byte(&pack, len / 2);
    let work = env.dir("work");
    let out = env.fails("bob", &work, &["clone", "fakehost:team", "t"]);
    assert!(out.contains("corrupt"), "{out}");
    assert!(!work.join("t").exists());
}

// Interrupted transfer: the connection drops mid-push (the server's replies are cut off);
// the push fails cleanly, the remote stays consistent, and the next push completes.
#[test]
fn a_connection_dropped_mid_push_leaves_a_consistent_remote() {
    let mut env = sftp_env!();
    let good = env.ssh.clone();
    let proj = env.project("alice", "proj", &[("a", "a\n")]);
    env.ok(
        "alice",
        &proj,
        &["remote", "add", "origin", "fakehost:team"],
    );
    env.ok("alice", &proj, &["push"]);
    for i in 0..6 {
        write_bytes(&proj, &format!("bulk/{i}.bin"), &noise(300_000, 300 + i));
    }
    env.ok("alice", &proj, &["commit", "-m", "bulk"]);
    // Server→client cut after 2 KB and 20 KB (the server then stops answering: the
    // documented timeout applies, shortened here), and client→server cut after 30 KB.
    env.envs.push(("VEIL_SFTP_TIMEOUT".into(), "3".into()));
    let server = sftp_server().unwrap();
    let cut_input = env.root.join("cut-input-ssh");
    std::fs::write(
        &cut_input,
        format!(
            "#!/bin/sh\ncd '{}' || exit 255\nhead -c 30000 | {}\n",
            env.path("sshhome").display(),
            server.display()
        ),
    )
    .unwrap();
    set_mode(&cut_input, 0o755);
    let scripts = [
        env.sftp_script("drop-ssh-1", "| head -c 2000"),
        env.sftp_script("drop-ssh-2", "| head -c 20000"),
        cut_input.display().to_string(),
    ];
    for script in scripts {
        env.ssh = Some(script.clone());
        let start = std::time::Instant::now();
        let out = env.vl("alice", &proj, &["--no-snapshot", "push"]);
        assert!(exited_cleanly(&out), "{}", text(&out));
        assert!(
            start.elapsed() < std::time::Duration::from_secs(30),
            "{script}: {:?}",
            start.elapsed()
        );
        env.ssh = good.clone();
        let remote = env.path("sshhome/team");
        let (code, f) = env.code(
            "alice",
            &env.root,
            &["fsck", "-R", remote.to_str().unwrap()],
        );
        assert_eq!(code, 0, "after a dropped connection ({script}): {f}");
    }
    env.ssh = good;
    let start = std::time::Instant::now();
    env.ok("alice", &proj, &["push"]);
    assert!(
        start.elapsed() < std::time::Duration::from_secs(60),
        "{:?}",
        start.elapsed()
    );
    let work = env.dir("work");
    env.ok("bob", &work, &["clone", "fakehost:team", "t"]);
    assert_eq!(
        std::fs::read(work.join("t/bulk/5.bin")).unwrap(),
        noise(300_000, 305)
    );
}

// Interrupted transfer: the connection drops mid-clone; the clone fails and leaves nothing.
#[test]
fn a_connection_dropped_mid_clone_leaves_nothing() {
    let mut env = sftp_env!();
    let proj = env.project("alice", "proj", &[("a", "a\n")]);
    for i in 0..4 {
        write_bytes(&proj, &format!("bulk/{i}.bin"), &noise(300_000, 400 + i));
    }
    env.ok("alice", &proj, &["commit", "-m", "bulk"]);
    env.ok(
        "alice",
        &proj,
        &["remote", "add", "origin", "fakehost:team"],
    );
    env.ok("alice", &proj, &["push"]);
    env.ssh = Some(env.sftp_script("drop-ssh", "| head -c 50000"));
    let work = env.dir("work");
    let out = env.vl("bob", &work, &["clone", "fakehost:team", "t"]);
    assert!(!out.status.success(), "{}", text(&out));
    assert!(exited_cleanly(&out), "{}", text(&out));
    assert!(!work.join("t").exists(), "{:?}", listing(&work));
}

// Scenario from git t5601 ("clone with ssh failing"): ssh exits 255.
#[test]
fn an_ssh_that_cannot_connect_fails_clone_push_and_pull_cleanly() {
    let mut env = sftp_env!();
    let s = env.root.join("dead-ssh");
    std::fs::write(&s, "#!/bin/sh\necho 'ssh: connect to host fakehost port 22: Connection refused' >&2\nexit 255\n").unwrap();
    set_mode(&s, 0o755);
    env.ssh = Some(s.display().to_string());
    let proj = env.project("alice", "proj", &[("a", "a\n")]);
    env.ok(
        "alice",
        &proj,
        &["remote", "add", "origin", "fakehost:team"],
    );
    let out = env.fails("alice", &proj, &["push"]);
    assert!(out.contains("fakehost"), "{out}");
    env.fails("alice", &proj, &["pull"]);
    let work = env.dir("work");
    env.fails("bob", &work, &["clone", "fakehost:team", "t"]);
    assert!(!work.join("t").exists());
}

// Scenario from jj test_concurrent_operations.rs over SFTP: two pushes of different tags.
#[test]
fn two_concurrent_ssh_pushes_both_land() {
    let env = sftp_env!();
    let a = env.project("alice", "a", &[("a", "a\n")]);
    env.ok("alice", &a, &["remote", "add", "origin", "fakehost:team"]);
    env.ok("alice", &a, &["push"]);
    let work = env.dir("work");
    env.ok("bob", &work, &["clone", "fakehost:team", "b"]);
    let b = work.join("b");
    env.ok("alice", &a, &["tag", "set", "ta", "-r", "main"]);
    env.ok("bob", &b, &["tag", "set", "tb", "-r", "main"]);
    let k1 = env.spawn("alice", &a, &["--no-snapshot", "push", "-t", "ta"]);
    let k2 = env.spawn("bob", &b, &["--no-snapshot", "push", "-t", "tb"]);
    for (k, who, dir, t) in [(k1, "alice", &a, "ta"), (k2, "bob", &b, "tb")] {
        let out = k.wait_with_output().unwrap();
        assert!(exited_cleanly(&out), "{}", text(&out));
        if !out.status.success() {
            env.ok(who, dir, &["push", "-t", t]);
        }
    }
    let tags = open_repo(&env.path("sshhome/team")).view().tags.clone();
    assert!(
        tags.contains_key("ta") && tags.contains_key("tb"),
        "{:?}",
        tags.keys()
    );
}

// Veil: a connection that stops answering is reported as such, not as missing data.
#[test]
fn a_server_that_stops_answering_is_reported_as_a_lost_connection() {
    let mut env = sftp_env!();
    let proj = env.project("alice", "proj", &[("a", "a\n")]);
    env.ok(
        "alice",
        &proj,
        &["remote", "add", "origin", "fakehost:team"],
    );
    env.ok("alice", &proj, &["push"]);
    for i in 0..4 {
        write_bytes(&proj, &format!("bulk/{i}.bin"), &noise(300_000, 500 + i));
    }
    env.ok("alice", &proj, &["commit", "-m", "bulk"]);
    env.envs.push(("VEIL_SFTP_TIMEOUT".into(), "2".into()));
    env.ssh = Some(env.sftp_script("mute-ssh", "| head -c 2000"));
    let out = env.fails("alice", &proj, &["--no-snapshot", "push"]);
    assert!(
        !out.contains("not found: operation"),
        "a lost connection reported as missing data: {out}"
    );
    assert!(out.contains("SFTP") || out.contains("connection"), "{out}");
}
