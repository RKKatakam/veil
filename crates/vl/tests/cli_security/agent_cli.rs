//! Milestone S11 through `vl` (`docs/HUB.md` §13.27;
//! `docs/design/scale/7-agent-attribution.md`): attribution comes only
//! from `vl`'s own arguments and environment, never from inside a sandbox;
//! hostile values are refused without being echoed; `vl log --agent`,
//! `vl show` and `vl evolog` show attribution and recorded attempts.

use crate::adversarial_support;

use std::{path::Path, process::Stdio};

use adversarial_support::*;
use serde_json::Value;

fn json(env: &Env, cwd: &Path, args: &[&str]) -> Value {
    serde_json::from_str(&env.stdout("alice", cwd, args)).unwrap()
}

/// `vl args…` with the agent environment `vars`.
fn with_env(env: &Env, cwd: &Path, vars: &[(&str, &str)], args: &[&str]) -> std::process::Output {
    let mut c = env.cmd("alice", cwd, args);
    for (k, v) in vars {
        c.env(k, v);
    }
    c.stdin(Stdio::null()).output().unwrap()
}

const AGENT: &[(&str, &str)] = &[
    ("VEIL_AGENT", "claude-code/2.3"),
    ("VEIL_AGENT_TASK", "TASK-5521 add the handler"),
    ("VEIL_AGENT_PROMPT_REF", "transcript:7f3a"),
    ("VEIL_AGENT_RUN", "run-41"),
];

#[test]
fn an_agents_commits_carry_its_attribution_from_vls_environment() {
    let env = Env::new();
    let proj = env.project("alice", "p", &[("README", "hi\n")]);
    write(&proj, "src/api.rs", "fn handler() {}\n");
    let out = with_env(&env, &proj, AGENT, &["commit", "-m", "api handler"]);
    assert!(out.status.success(), "{}", text(&out));
    write(&proj, "notes.txt", "a person's notes\n");
    env.ok("alice", &proj, &["commit", "-m", "notes"]);

    let log = json(&env, &proj, &["log", "--json", "--agent", "claude-*"]);
    let entries = log["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1, "{log}");
    assert_eq!(entries[0]["description"], "api handler");
    assert_eq!(entries[0]["agent"]["agent"], "claude-code/2.3");
    assert_eq!(entries[0]["agent"]["task"], "TASK-5521 add the handler");
    assert_eq!(entries[0]["agent"]["prompt"], "transcript:7f3a");
    assert_eq!(entries[0]["agent"]["run"], "run-41");
    // The revset says the same; nobody else matches.
    let by_revset = json(&env, &proj, &["log", "--json", "-r", "agent(claude-code/2.3)"]);
    assert_eq!(by_revset["entries"].as_array().unwrap().len(), 1, "{by_revset}");
    let none = json(&env, &proj, &["log", "--json", "--agent", "codex*"]);
    assert!(none["entries"].as_array().unwrap().is_empty(), "{none}");
    // The person's commit carries none.
    let all = json(&env, &proj, &["log", "--json"]);
    let notes = all["entries"].as_array().unwrap().iter().find(|e| e["description"] == "notes").unwrap().clone();
    assert!(notes.get("agent").is_none(), "{notes}");
    // Text: `vl log` and `vl show`.
    let text_log = env.stdout("alice", &proj, &["log", "--agent", "claude-*"]);
    assert!(text_log.contains("agent: claude-code/2.3 · task: TASK-5521 add the handler · run: run-41"), "{text_log}");
    let show = env.stdout("alice", &proj, &["show", entries[0]["snapshot_id"].as_str().unwrap()]);
    assert!(show.contains("Agent     : claude-code/2.3") && show.contains("Task      : TASK-5521") && show.contains("Prompt    : transcript:7f3a"), "{show}");
}

#[test]
fn hostile_attribution_in_the_environment_is_refused_without_echoing_it() {
    let env = Env::new();
    let proj = env.project("alice", "p", &[("README", "hi\n")]);
    write(&proj, "x.txt", "x\n");
    let long = "t".repeat(5 * 1024);
    let wide = "a".repeat(129);
    let cases: Vec<Vec<(&str, &str)>> = vec![
        vec![("VEIL_AGENT", "evil\u{1b}[2J\u{1b}]8;;https://x\u{7}")],
        vec![("VEIL_AGENT", "ok"), ("VEIL_AGENT_TASK", "task \u{1b}[31m red")],
        vec![("VEIL_AGENT", "ok"), ("VEIL_AGENT_TASK", &long)],
        vec![("VEIL_AGENT", "ok"), ("VEIL_AGENT_RUN", "run with spaces")],
        vec![("VEIL_AGENT", &wide)],
        vec![("VEIL_AGENT_TASK", "a task without an agent")],
    ];
    for vars in cases {
        let out = with_env(&env, &proj, &vars, &["commit", "-m", "hostile"]);
        let t = text(&out);
        assert!(!out.status.success(), "{vars:?}: accepted:\n{t}");
        assert!(t.contains("VEIL_AGENT"), "{vars:?}: the refusal names no variable: {t}");
        assert!(!t.contains('\u{1b}'), "{vars:?}: the refusal echoes an escape");
        assert!(!t.contains(&"t".repeat(100)), "{vars:?}: the refusal echoes the value");
    }
    let log = env.stdout("alice", &proj, &["log"]);
    assert!(!log.contains("hostile"), "a refused commit was recorded:\n{log}");
}

/// Threat 3 (and phase 2 §6 row 6): a command inside `vl ws exec` sets
/// `VEIL_AGENT`, writes a file that looks like attribution and runs `vl
/// describe`. The recorded snapshot carries the harness's attribution, from
/// the workspace `vl`'s flags (which win over its environment).
#[test]
fn a_command_inside_the_sandbox_cannot_forge_or_strip_attribution() {
    let env = Env::new();
    let proj = env.project("alice", "p", &[("README", "hi\n")]);
    env.ok("alice", &proj, &["ws", "new", "agent", "-r", "main"]);
    let vl = env!("CARGO_BIN_EXE_vl");
    let script = format!(
        "export VEIL_AGENT=evil VEIL_AGENT_TASK=forged; echo 'agent: evil' > .veil-agent; \
         {vl} describe -m forged >/dev/null 2>&1; {vl} -R {} describe -m forged >/dev/null 2>&1; echo work > out.txt",
        proj.display()
    );
    let out = with_env(
        &env,
        &proj,
        &[("VEIL_AGENT", "outer-environment")],
        &["ws", "exec", "agent", "--agent", "harness/1", "--task", "TASK-77", "--run", "r-1", "--", "sh", "-c", &script],
    );
    assert!(out.status.success(), "{}", text(&out));
    let show = json(&env, &proj, &["show", "--json", "agent@"]);
    assert_eq!(show["agent"]["agent"], "harness/1", "{show}");
    assert_eq!(show["agent"]["task"], "TASK-77", "{show}");
    assert_eq!(show["agent"]["run"], "r-1", "{show}");
    assert_ne!(show["description"], "forged", "the sandbox described the change");
    let files: Vec<&str> = show["diff"]["files"].as_array().unwrap().iter().filter_map(|f| f["path"].as_str()).collect();
    assert!(files.contains(&"out.txt"), "the run was not recorded: {files:?}");
    // Nothing anywhere names the forged agent.
    let log = env.stdout("alice", &proj, &["log", "--json"]);
    assert!(!log.contains("\"agent\":\"evil\"") && !log.contains("forged\""), "{log}");
    // Without the flags, the workspace vl's own environment decides.
    let out = with_env(&env, &proj, &[("VEIL_AGENT", "outer-environment")], &["ws", "exec", "agent", "--", "sh", "-c", "echo more >> out.txt"]);
    assert!(out.status.success(), "{}", text(&out));
    let show = json(&env, &proj, &["show", "--json", "agent@"]);
    assert_eq!(show["agent"]["agent"], "outer-environment", "{show}");
}

#[test]
fn a_dropped_attempt_is_kept_shown_and_never_built_on() {
    let env = Env::new();
    let proj = env.project("alice", "p", &[("README", "hi\n")]);
    write(&proj, "src/lease.rs", "fn hold_lease() {}\n");
    let out = with_env(&env, &proj, AGENT, &["attempt", "drop", "--reason", "deadlocks holding the lease across memo_tips"]);
    assert!(out.status.success(), "{}", text(&out));
    assert!(!proj.join("src/lease.rs").exists(), "the working copy kept the dropped attempt");
    let show = json(&env, &proj, &["show", "--json"]);
    let attempts = show["attempts"].as_array().unwrap();
    assert_eq!(attempts.len(), 1, "{show}");
    assert_eq!(attempts[0]["reason"], "deadlocks holding the lease across memo_tips");
    assert_eq!(attempts[0]["files"], serde_json::json!(["src/lease.rs"]));
    assert_eq!(attempts[0]["agent"]["agent"], "claude-code/2.3");
    let text_show = env.stdout("alice", &proj, &["show"]);
    assert!(text_show.contains("Discarded attempts (1):") && text_show.contains("deadlocks holding the lease"), "{text_show}");
    let evolog = env.stdout("alice", &proj, &["evolog"]);
    assert!(evolog.contains("abandoned attempt:") && evolog.contains("deadlocks holding the lease"), "{evolog}");
    // Never built on, never a tag's target, never in the log.
    let id = attempts[0]["snapshot_id"].as_str().unwrap();
    for args in [vec!["new", id], vec!["tag", "set", "landed", "-r", id], vec!["edit", id]] {
        let out = env.vl("alice", &proj, &args);
        assert!(!out.status.success(), "{args:?} accepted an attempt: {}", text(&out));
        assert!(text(&out).contains("abandoned attempt"), "{args:?}: {}", text(&out));
    }
    let log = env.stdout("alice", &proj, &["log", "--json"]);
    assert!(!log.contains(id), "the attempt is in the log");
    // A hostile reason is refused, not echoed.
    write(&proj, "y.txt", "y\n");
    let out = env.vl("alice", &proj, &["attempt", "drop", "--reason", "bad \u{1b}[2J"]);
    assert!(!out.status.success(), "{}", text(&out));
    assert!(!text(&out).contains('\u{1b}'));
}

#[test]
fn bug_1837_squash_carries_attempts_and_show_prints_them() {
    let env = Env::new();
    let proj = env.project("alice", "p", &[("README", "hi\n")]);

    // Destination change with one attempt by claude-code.
    write(&proj, "src/dest_try.rs", "fn dest_dead_end() {}\n");
    let out = with_env(&env, &proj, &[("VEIL_AGENT", "claude-code/1"), ("VEIL_AGENT_TASK", "dest-task")], &["attempt", "drop", "--reason", "dest dead end"]);
    assert!(out.status.success(), "{}", text(&out));
    write(&proj, "src/dest.rs", "pub fn dest() {}\n");
    let out = env.vl("alice", &proj, &["commit", "-m", "dest change"]);
    assert!(out.status.success(), "{}", text(&out));

    // Source change (`@` on `dest`) with one attempt by codex.
    write(&proj, "src/src_try.rs", "fn src_dead_end() {}\n");
    let out = with_env(&env, &proj, &[("VEIL_AGENT", "codex/2"), ("VEIL_AGENT_TASK", "src-task")], &["attempt", "drop", "--reason", "src dead end"]);
    assert!(out.status.success(), "{}", text(&out));
    write(&proj, "src/src.rs", "pub fn src() {}\n");
    let out = env.vl("alice", &proj, &["describe", "-m", "src change"]);
    assert!(out.status.success(), "{}", text(&out));

    // Squash `@` into `@-`: `vl show @-` prints both attempts in order.
    let out = env.vl("alice", &proj, &["squash"]);
    assert!(out.status.success(), "{}", text(&out));

    let show_json = json(&env, &proj, &["show", "--json", "@-"]);
    let attempts = show_json["attempts"].as_array().unwrap();
    assert_eq!(attempts.len(), 2, "{show_json}");
    assert_eq!(attempts[0]["reason"], "dest dead end");
    assert_eq!(attempts[0]["agent"]["agent"], "claude-code/1");
    assert_eq!(attempts[0]["files"], serde_json::json!(["src/dest_try.rs"]));
    assert_eq!(attempts[1]["reason"], "src dead end");
    assert_eq!(attempts[1]["agent"]["agent"], "codex/2");
    assert_eq!(attempts[1]["files"], serde_json::json!(["src/src_try.rs"]));

    let text_show = env.stdout("alice", &proj, &["show", "@-"]);
    assert!(text_show.contains("Discarded attempts (2):"), "{text_show}");
    let p_dest = text_show.find("dest dead end").expect("dest reason in show");
    let p_src = text_show.find("src dead end").expect("src reason in show");
    assert!(p_dest < p_src, "dest attempt printed before src attempt:\n{text_show}");
    assert!(text_show.contains("changed: src/dest_try.rs") && text_show.contains("changed: src/src_try.rs"), "{text_show}");

    // `vl undo` restores both changes' attempts.
    let out = env.vl("alice", &proj, &["undo"]);
    assert!(out.status.success(), "{}", text(&out));
    let dest_after = json(&env, &proj, &["show", "--json", "@-"]);
    let src_after = json(&env, &proj, &["show", "--json", "@"]);
    assert_eq!(dest_after["attempts"].as_array().unwrap().len(), 1);
    assert_eq!(src_after["attempts"].as_array().unwrap().len(), 1);
}

