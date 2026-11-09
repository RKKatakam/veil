//! Milestone S11 (`docs/HUB.md` §13.27; phase 2 §5.6;
//! `docs/design/scale/7-agent-attribution.md`): agent attribution on
//! snapshots and attempts (recorded dead ends), in the engine.
//!
//! Guarantees, each tested here:
//! * attribution is set only by the process (`Repo::set_attribution`), is
//!   kept by rebases and duplicates, and is covered by the signature;
//! * hostile or unbounded attribution and attempts are `Corrupt` on decode
//!   and are never written;
//! * attempts never land and never enter ancestry: never a head, a
//!   workspace's change, a tag's target or a parent;
//! * at most 32 attempts per change, 64 KiB of reason each; they stay with
//!   the change through gc, and go with it;
//! * `task`, `prompt` and reasons are withheld with an embargoed change.

use crate::adversarial_support;

use std::{sync::Arc, time::Duration};

use adversarial_support::*;
use veil_core::{
    commands::EmbargoSpec,
    gc::{gc, GcOptions},
    object::{Attribution, Object, Snapshot, MAX_ATTEMPTS, MAX_REASON},
    remote, revset, MemoryBackend, ObjectId, Repo, StorageBackend, VeilError,
};

fn claude(task: &str) -> Attribution {
    Attribution {
        agent: "claude-code/2.3 opus-5.5".into(),
        task: Some(task.into()),
        prompt: Some("transcript:7f3a".into()),
        run: Some("run-41".into()),
    }
}

/// A change by an agent on `main`: (repo, fs, main, the agent's change).
fn agent_change(task: &str) -> (Repo, Arc<MemoryBackend>, ObjectId, ObjectId) {
    let (mut r, fs, _) = new_repo("alice");
    let main = commit_files(&mut r, &*fs, &[("README", "v1\n")], "v1");
    r.set_tag("main", main, false).unwrap();
    r.set_attribution(Some(claude(task)));
    let c = commit_files(&mut r, &*fs, &[("src/api.rs", "fn handler() {}\n")], "api handler");
    r.set_attribution(None);
    (r, fs, main, c)
}

// ---- who sets it ----------------------------------------------------------------

#[test]
fn the_process_stamps_what_it_creates_and_rebases_and_duplicates_keep_each_changes_own() {
    let (mut r, fs, main, c) = agent_change("task 1");
    assert_eq!(r.snapshot(&c).unwrap().agent, Some(claude("task 1")), "the commit carries the process's attribution");
    assert_eq!(r.snapshot(&main).unwrap().agent, None, "a person's commit carries none");
    // The empty change `commit` started is not the agent's: a person fills it.
    let wc = r.workspace_wc(WS).unwrap();
    assert_eq!(r.snapshot(&wc).unwrap().agent, None, "the empty change the agent's commit started is stamped");
    r.new_change(WS, vec![main], "").unwrap();
    let other = commit_files(&mut r, &*fs, &[("b.txt", "b\n")], "person's work");
    assert_eq!(r.snapshot(&other).unwrap().agent, None);
    // A rebase by another agent's process moves the change: it keeps its own.
    r.set_attribution(Some(Attribution { agent: "other-agent".into(), task: None, prompt: None, run: None }));
    let moved = r.rebase(c, vec![other]).unwrap();
    assert_eq!(r.snapshot(&moved).unwrap().agent, Some(claude("task 1")), "a rebase re-stamped the change");
    let copies = r.duplicate(&[moved], &[main], &Default::default()).unwrap();
    assert_eq!(copies.len(), 1);
    assert_eq!(r.snapshot(&copies[0].duplicate).unwrap().agent, Some(claude("task 1")), "a duplicate re-stamped the copy");
    // A describe by this process produces the change's new content: stamped.
    let d = r.describe(moved, "api handler, described").unwrap();
    assert_eq!(r.snapshot(&d).unwrap().agent.as_ref().unwrap().agent, "other-agent");
}

#[test]
fn attribution_is_covered_by_the_signature_and_the_id() {
    let (r, _fs, _main, c) = agent_change("task 1");
    let s = r.snapshot(&c).unwrap();
    assert_eq!(s.signature_valid(), Some(true));
    for forge in [
        |s: &mut Snapshot| s.agent.as_mut().unwrap().agent = "a-person".into(),
        |s: &mut Snapshot| s.agent.as_mut().unwrap().task = Some("another task".into()),
        |s: &mut Snapshot| s.agent = None,
        |s: &mut Snapshot| s.attempts.push(ObjectId([7; 32])),
    ] {
        let mut f = (*s).clone();
        forge(&mut f);
        let id = ObjectId::hash(&Object::Snapshot(f.clone()).encode());
        assert_ne!(id, c, "a changed attribution kept the id");
        assert_eq!(f.signature_valid(), Some(false), "the signature still verifies over a changed attribution");
    }
}

// ---- hostile input --------------------------------------------------------------

/// The canonical bytes of an attributed snapshot after `edit`, as a
/// hostile writer would make them (`Object::encode` writes any value).
fn raw_with(r: &Repo, edit: impl FnOnce(&mut Snapshot)) -> Vec<u8> {
    let mut s = (*r.snapshot(&r.root_id()).unwrap()).clone();
    s.agent = Some(claude("t"));
    edit(&mut s);
    Object::Snapshot(s).encode()
}

#[test]
fn hostile_or_unbounded_attribution_and_attempts_are_corrupt_and_never_written() {
    let (r, _fs, _, _) = agent_change("t");
    let control = raw_with(&r, |_| {});
    assert!(matches!(Object::decode(&control), Ok(Object::Snapshot(_))), "control: a valid attributed snapshot decodes");
    let ids: Vec<ObjectId> = (0..=MAX_ATTEMPTS).map(|i| ObjectId([i as u8; 32])).collect();
    type Edit = Box<dyn Fn(&mut Snapshot)>;
    let cases: Vec<(&str, Edit)> = vec![
        ("an ANSI escape in agent", Box::new(|s| s.agent.as_mut().unwrap().agent = "evil\u{1b}[2J".into())),
        ("an OSC 8 link in task", Box::new(|s| s.agent.as_mut().unwrap().task = Some("\u{1b}]8;;https://x\u{7}t".into()))),
        ("an empty agent", Box::new(|s| s.agent.as_mut().unwrap().agent = "".into())),
        ("a 129-character agent", Box::new(|s| s.agent.as_mut().unwrap().agent = "a".repeat(129))),
        ("a 4097-byte prompt", Box::new(|s| s.agent.as_mut().unwrap().prompt = Some("p".repeat(4097)))),
        ("a run id with a space", Box::new(|s| s.agent.as_mut().unwrap().run = Some("run 1".into()))),
        ("an empty reason", Box::new(|s| s.abandoned = Some(" ".into()))),
        ("a reason over 64 KiB", Box::new(|s| s.abandoned = Some("x".repeat(MAX_REASON + 1)))),
        ("a reason with a control character", Box::new(|s| s.abandoned = Some("dead\u{8}end".into()))),
        ("33 attempts", Box::new(move |s| s.attempts = ids.clone())),
        ("an attempt named twice", Box::new(|s| s.attempts = vec![ObjectId([1; 32]), ObjectId([1; 32])])),
        ("an abandoned snapshot with attempts", Box::new(|s| {
            s.abandoned = Some("why".into());
            s.attempts = vec![ObjectId([1; 32])];
        })),
    ];
    let unknown = String::from_utf8(control.clone()).unwrap().replacen("{\"agent\":\"", "{\"model\":\"x\",\"agent\":\"", 1).into_bytes();
    assert_ne!(unknown, control);
    let mut raws: Vec<(&str, Vec<u8>, Option<Snapshot>)> = vec![("an unknown attribution field", unknown, None)];
    for (what, edit) in &cases {
        let mut s = (*r.snapshot(&r.root_id()).unwrap()).clone();
        s.agent = Some(claude("t"));
        edit(&mut s);
        raws.push((what, raw_with(&r, |x| edit(x)), Some(s)));
    }
    for (what, raw, value) in raws {
        match Object::decode(&raw) {
            Err(VeilError::Corrupt(..)) | Err(VeilError::Json(_)) => {}
            other => panic!("{what}: decoded as {other:?}"),
        }
        // Copied in as raw bytes (a pull), it is refused when read.
        let id = ObjectId::hash(&raw);
        let _ = r.store().put_raw(&id, &raw);
        assert!(!matches!(r.exact().snapshot(&id), Ok(Some(_))), "{what}: read back as a snapshot");
        // The engine cannot write one either.
        if let Some(v) = value {
            assert!(r.store().put_snapshot(&v).is_err(), "{what}: the engine stored it");
        }
    }
}

// ---- attempts --------------------------------------------------------------------

#[test]
fn an_attempt_is_recorded_and_the_change_starts_again_from_its_parents() {
    let (mut r, fs, main, _) = agent_change("t");
    r.new_change(WS, vec![main], "try the lease").unwrap();
    fs.write(&p("src/lease.rs"), b"fn hold_lease() { /* deadlocks */ }\n").unwrap();
    let tried = snap(&mut r, &*fs);
    r.set_attribution(Some(claude("lease")));
    let out = r.drop_attempt(tried, "deadlocks holding the lease across memo_tips").unwrap();
    r.set_attribution(None);
    let a = r.snapshot(&out.attempt).unwrap();
    assert_eq!(a.abandoned.as_deref(), Some("deadlocks holding the lease across memo_tips"));
    assert_eq!(a.tree, r.snapshot(&tried).unwrap().tree, "the attempt keeps what was tried");
    assert_eq!(a.signature_valid(), Some(true));
    let n = r.snapshot(&out.change).unwrap();
    assert_eq!(n.change_id, a.change_id, "the same change goes on");
    assert_eq!(n.tree, r.snapshot(&main).unwrap().tree, "the change starts again from its parent");
    assert_eq!(n.attempts, vec![out.attempt]);
    assert_eq!(n.predecessors, vec![out.attempt], "the evolution log passes through the attempt");
    assert_eq!(r.workspace_wc(WS).unwrap(), out.change, "the working copy moved on");
    assert_eq!(n.agent, Some(claude("lease")));
    // A second attempt is listed after the first.
    fs.write(&p("src/lease.rs"), b"fn hold_lease_v2() {}\n").unwrap();
    let again = snap(&mut r, &*fs);
    let out2 = r.drop_attempt(again, "second try: same deadlock").unwrap();
    assert_eq!(r.snapshot(&out2.change).unwrap().attempts, vec![out.attempt, out2.attempt]);
}

#[test]
fn attempts_never_land_and_never_enter_ancestry() {
    let (mut r, fs, main, _) = agent_change("t");
    r.new_change(WS, vec![main], "x").unwrap();
    fs.write(&p("x.txt"), b"dead end\n").unwrap();
    let tried = snap(&mut r, &*fs);
    let out = r.drop_attempt(tried, "dead end").unwrap();
    let a = out.attempt;
    assert!(!r.view().refs().contains(&a), "the attempt is visible");
    assert!(!r.exact().ancestors(&out.change).unwrap().contains(&a), "the attempt is an ancestor of its change");
    let refusal = |e: VeilError| {
        let m = e.to_string();
        assert!(m.contains("abandoned attempt"), "{m}");
    };
    refusal(r.new_change(WS, vec![a], "on the attempt").unwrap_err());
    refusal(r.set_tag("land", a, true).unwrap_err());
    refusal(r.edit(WS, a).unwrap_err());
    refusal(r.rebase(out.change, vec![a]).unwrap_err());
    refusal(r.merge(WS, main, vec![a], "merge it", None).unwrap_err());
    assert!(!r.view().tags.contains_key("land"));
    for spec in ["::@", "root..@", "agent(*)"] {
        let set = revset::resolve_set(&r, spec, WS).unwrap();
        assert!(!set.contains(&a), "{spec} reaches the attempt");
    }
}

#[test]
fn attempts_are_bounded() {
    let (mut r, fs, main, _) = agent_change("t");
    r.new_change(WS, vec![main], "x").unwrap();
    let mut last = None;
    for i in 0..MAX_ATTEMPTS {
        fs.write(&p("x.txt"), format!("try {i}\n").as_bytes()).unwrap();
        let tried = snap(&mut r, &*fs);
        last = Some(r.drop_attempt(tried, &format!("try {i} failed")).unwrap());
    }
    let change = last.unwrap().change;
    assert_eq!(r.snapshot(&change).unwrap().attempts.len(), MAX_ATTEMPTS);
    fs.write(&p("x.txt"), b"one more\n").unwrap();
    let tried = snap(&mut r, &*fs);
    let e = r.drop_attempt(tried, "33rd").unwrap_err().to_string();
    assert!(e.contains("32 attempts"), "{e}");
    let e = r.drop_attempt(tried, &"r".repeat(MAX_REASON + 1)).unwrap_err().to_string();
    assert!(e.contains("longer than"), "{e}");
    let e = r.drop_attempt(tried, "  ").unwrap_err().to_string();
    assert!(e.contains("empty"), "{e}");
    let e = r.drop_attempt(tried, "bad \u{1b}[2J").unwrap_err().to_string();
    assert!(e.contains("control character") && !e.contains('\u{1b}'), "{e}");
    // An empty change has nothing to drop.
    let empty = r.new_change(WS, vec![main], "").unwrap();
    let e = r.drop_attempt(empty, "nothing").unwrap_err().to_string();
    assert!(e.contains("empty"), "{e}");
}

#[test]
fn attempts_stay_through_gc_and_go_with_their_change() {
    let (mut r, fs, main, _) = agent_change("t");
    r.new_change(WS, vec![main], "x").unwrap();
    fs.write(&p("x.txt"), b"ATTEMPT-CONTENT-5521\n").unwrap();
    let tried = snap(&mut r, &*fs);
    let out = r.drop_attempt(tried, "dead end").unwrap();
    let opts = GcOptions { grace: Duration::ZERO, keep_ops: Some(Duration::ZERO), ..GcOptions::default() };
    gc(&mut r, &opts).unwrap();
    assert!(r.store().has(&out.attempt), "gc removed an attempt of a living change");
    assert!(!backend_contains(&*fs, b"ATTEMPT-CONTENT-5521").is_empty() || r.store().has(&r.snapshot(&out.attempt).unwrap().tree));
    // Abandon the change (a new working copy first), then gc: the attempt goes.
    r.new_change(WS, vec![main], "").unwrap();
    r.abandon(out.change).unwrap();
    // One more operation: `vl undo` of the abandon is then no longer kept.
    commit_files(&mut r, &*fs, &[("later.txt", "later\n")], "later");
    gc(&mut r, &opts).unwrap();
    assert!(!r.store().has(&out.attempt), "the attempt outlived its change");
}

#[test]
fn the_agent_revset_and_filter_match_by_name_or_glob() {
    let (mut r, fs, main, c) = agent_change("t");
    r.set_attribution(Some(Attribution { agent: "codex/1".into(), task: None, prompt: None, run: None }));
    let d = commit_files(&mut r, &*fs, &[("d.txt", "d\n")], "by codex");
    r.set_attribution(None);
    let all = |spec: &str| revset::resolve_set(&r, spec, WS).unwrap();
    assert_eq!(all("agent(claude-*)"), vec![c]);
    assert_eq!(all("agent(codex/1)"), vec![d]);
    let mut both = all("agent(*)");
    both.sort();
    let mut want = vec![c, d];
    want.sort();
    assert_eq!(both, want);
    assert!(all("agent(nobody)").is_empty());
    assert!(!all("agent(*)").contains(&main));
    for bad in ["agent()", &format!("agent({})", "x".repeat(257)), "agent([)"] {
        assert!(matches!(revset::resolve_set(&r, bad, WS), Err(VeilError::Revset(_))), "{bad}");
    }
}

// ---- visibility ------------------------------------------------------------------

/// `7-agent-attribution.md` threats 1 and 2: an embargoed fix made by an
/// agent, with an attempt on it, pushed to a public mirror: the task, the
/// prompt and the reason reach nobody outside the embargo. Control: the
/// same push without an embargo carries them.
#[test]
fn task_prompt_and_reasons_are_withheld_with_an_embargoed_change() {
    for embargoed in [true, false] {
        let (mut r, fs, _) = new_repo("alice");
        let main = commit_files(&mut r, &*fs, &[("auth.rs", "v1\n")], "v1");
        r.set_tag("main", main, false).unwrap();
        r.create_workspace("fix", vec![main]).unwrap();
        let ov = r.workspace_overlay("fix").unwrap();
        r.set_attribution(Some(Attribution {
            agent: "claude-code".into(),
            task: Some("fix CVE-2026-1234 in auth".into()),
            prompt: Some("PROMPT-REF-8812".into()),
            run: None,
        }));
        ov.write(&p("auth.rs"), b"first try\n").unwrap();
        let tried = r.snapshot_workspace("fix", &ov).unwrap().snapshot;
        let out = r.drop_attempt(tried, "REASON-7731: breaks token refresh").unwrap();
        r.edit("fix", out.change).unwrap();
        let ov = r.workspace_overlay("fix").unwrap();
        ov.write(&p("auth.rs"), b"v2\n").unwrap();
        let fix = r.snapshot_workspace("fix", &ov).unwrap().snapshot;
        r.set_attribution(None);
        assert_eq!(r.snapshot(&fix).unwrap().attempts, vec![out.attempt]);
        let spec = embargoed.then(|| EmbargoSpec { scope: "team".into(), until: None });
        r.merge(WS, main, vec![fix], "merge", spec).unwrap();
        let mirror = Arc::new(MemoryBackend::new());
        remote::push(&mut r, mirror.clone(), true, &["main".to_string()], false).unwrap();
        for secret in [&b"CVE-2026-1234"[..], b"PROMPT-REF-8812", b"REASON-7731"] {
            let hits = backend_contains(&*mirror, secret);
            assert_eq!(hits.is_empty(), embargoed, "embargoed {embargoed}: {:?} on the mirror: {hits:?}", String::from_utf8_lossy(secret));
        }
        if !embargoed {
            // The mirror holds the attempt with its change, and a clone reads it.
            let mut clone = Repo::init_for_clone(Arc::new(MemoryBackend::new()), None, "anon").unwrap();
            remote::pull(&mut clone, "origin", mirror.clone()).unwrap();
            let a = clone.snapshot(&out.attempt).unwrap();
            assert_eq!(a.abandoned.as_deref(), Some("REASON-7731: breaks token refresh"));
            let report = veil_core::fsck::fsck(mirror.clone() as Arc<dyn StorageBackend>, None).unwrap();
            assert!(report.is_ok(), "{:?}", report.findings);
        }
    }
}
