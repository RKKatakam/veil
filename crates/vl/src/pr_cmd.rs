//! `vl pr`: PRs and review on the Veil server (`docs/HUB.md` §13.24).
//!
//! Everything is the server's: a PR is a record on it, made from changes
//! already pushed, and every answer is what the signed-in person may see
//! (a PR touching a folder they cannot read does not exist for them).
//! Reviews are signed by this device over the revision's patch, so an
//! approval stops counting when the files change.

use anyhow::{anyhow, bail, Result};
use serde_json::{json, Value};
use veil_core::{crypto::domains::SIG_CONTEXT_HUB_PR_REVIEW, hub::pr::review_message};

use crate::{
    api,
    cli::PrCmd,
    ctx::{load_identity, Ctx},
    hub::Client,
    render::{bold, cyan, dim, fmt_time, green, red, safe, safe_content_line, yellow},
};

fn client(ctx: &Ctx) -> Result<Client> {
    Ok(crate::hub_cmd::client_for(ctx, "origin")?.0)
}

/// `s` for a URL's query.
fn q(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// The PR id as a path segment: the server answers anything malformed as
/// no PR, so only refuse what could change the path.
fn pr_path(id: &str, rest: &str) -> Result<String> {
    if id.is_empty() || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        bail!("no such PR that you can see");
    }
    Ok(format!("/prs/{id}{rest}"))
}

/// The snapshot id REV names here: the server takes ids of your history.
fn head_of(ctx: &Ctx, rev: &str) -> Result<String> {
    Ok(ctx.rev(rev)?.hex())
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str().unwrap_or("")
}

fn risk(r: &str) -> String {
    match r {
        "low" => green(r),
        "high" => red(r),
        _ => yellow(r),
    }
}

fn print_pr(v: &Value, threads: Option<&Value>) {
    println!("{}  {}", bold(&safe(s(v, "id"))), bold(&safe(s(v, "title"))));
    println!(
        "  {}  {} risk  revision {}  by {}  onto {}",
        s(v, "state"),
        risk(s(v, "risk")),
        v["revision"],
        safe(s(v, "author")),
        safe(s(v, "target"))
    );
    for r in v["reasons"].as_array().into_iter().flatten() {
        println!("  {}", dim(&safe(r.as_str().unwrap_or(""))));
    }
    if let Some(cur) = v["revisions"].as_array().and_then(|rs| rs.iter().find(|r| r["n"] == v["revision"])) {
        println!("  {} files, base {}", v["files"], dim(&s(cur, "base")[..12.min(s(cur, "base").len())]));
        for c in cur["changes"].as_array().into_iter().flatten() {
            println!("    {} {}", cyan(&s(c, "change_id")[..12.min(s(c, "change_id").len())]), dim(&s(c, "snapshot_id")[..12.min(s(c, "snapshot_id").len())]));
        }
    }
    let body = s(v, "body");
    if !body.is_empty() {
        println!();
        for l in body.lines() {
            println!("  {}", safe(l));
        }
    }
    let r = &v["review"];
    println!();
    println!(
        "  review: {}/{} approval{}{}  {}",
        r["approvals"],
        r["needs"]["approvals"],
        if r["needs"]["approvals"] == 1 { "" } else { "s" },
        if r["needs"]["people_only"] == true { " (people)" } else { "" },
        if r["ready"] == true { green("ready to land") } else { yellow("not ready") }
    );
    for x in r["reasons"].as_array().into_iter().flatten() {
        println!("    {}", dim(&safe(x.as_str().unwrap_or(""))));
    }
    for x in r["reviews"].as_array().into_iter().flatten() {
        let mark = match (s(x, "verdict"), x["counted"] == true) {
            ("approve", true) => green("approved"),
            ("approve", false) => dim("approved (not counted)"),
            ("dismissed", _) => dim("asked for changes (dismissed by an admin)"),
            _ => red("asked for changes"),
        };
        println!("    {} {mark} on revision {}{}", safe(s(x, "by")), x["revision"], if x["current"] == true { "" } else { " (files changed since)" });
        if !s(x, "body").is_empty() {
            println!("      {}", safe(s(x, "body")));
        }
    }
    println!("  {} open thread{}", v["open_threads"], if v["open_threads"] == 1 { "" } else { "s" });
    if let Some(t) = threads {
        print_threads(t);
    }
}

fn print_threads(t: &Value) {
    for th in t["threads"].as_array().into_iter().flatten() {
        println!();
        let place = match th["anchor"].as_object() {
            None => "on the PR".to_string(),
            Some(a) => {
                let (path, start, end) = (a["path"].as_str().unwrap_or(""), a["start"].as_u64().unwrap_or(0), a["end"].as_u64().unwrap_or(0));
                let lines = if start == end { format!("{start}") } else { format!("{start}-{end}") };
                let side = if a["side"] == "old" { " (old side)" } else { "" };
                let now = match th["now"].as_object() {
                    Some(n) if n["start"] != a["start"] || n["revision"] != a["revision"] => format!(", now line {} of revision {}", n["start"], n["revision"]),
                    Some(_) => String::new(),
                    None => " (outdated)".into(),
                };
                format!("{}:{lines}{side} at revision {}{now}", safe(path), a["revision"])
            }
        };
        println!("  thread {}  {}  {}", dim(s(th, "id")), place, if th["state"] == "resolved" { dim("resolved") } else { String::new() });
        for c in th["comments"].as_array().into_iter().flatten() {
            println!("    {} {}:", bold(&safe(s(c, "author"))), dim(&fmt_time(c["at"].as_i64().unwrap_or(0))));
            for l in s(c, "body").lines() {
                println!("      {}", safe(l));
            }
        }
    }
}

fn print_diff(v: &Value) {
    for f in v["files"].as_array().into_iter().flatten() {
        let from = f["from"].as_str().map(|p| format!(" (from {})", safe(p))).unwrap_or_default();
        println!("{} {}{from}", bold(s(f, "status")), bold(&safe(s(f, "path"))));
        let c = &f["content"];
        if c["binary"] == true {
            println!("  {}", dim("binary or secret: not shown"));
        } else if c["too_large"] == true || c["omitted"] == true {
            println!("  {}", dim("too large to show"));
        }
        for h in c["hunks"].as_array().into_iter().flatten() {
            println!("{}", cyan(&format!("@@ -{},{} +{},{} @@", h["old_start"], h["old_lines"], h["new_start"], h["new_lines"])));
            for l in h["lines"].as_array().into_iter().flatten() {
                let l = l.as_str().unwrap_or("");
                let l = l.strip_suffix('\n').unwrap_or(l);
                let line = safe_content_line(l);
                match l.chars().next() {
                    Some('+') => println!("{}", green(&line)),
                    Some('-') => println!("{}", red(&line)),
                    _ => println!("{line}"),
                }
            }
        }
    }
    if v["truncated"] == true {
        println!("{}", dim("(more files than one answer holds)"));
    }
}

fn emit(v: &Value, json_out: bool, text: impl FnOnce(&Value)) -> Result<()> {
    if json_out {
        api::emit_json(v)
    } else {
        text(v);
        Ok(())
    }
}

pub fn run(ctx: &mut Ctx, cmd: &PrCmd) -> Result<()> {
    let c = client(ctx)?;
    match cmd {
        PrCmd::Create { rev, onto, title, body, out } => {
            let mut req = json!({ "head": head_of(ctx, rev)?, "title": title });
            if let Some(o) = onto {
                req["onto"] = json!(o);
            }
            if let Some(b) = body {
                req["body"] = json!(b);
            }
            let v = c.project_json("POST", "/prs", Some(&req)).map_err(hint_push)?;
            emit(&v, out.json, |v| {
                println!("Created {}", bold(s(v, "id")));
                print_pr(v, None);
            })
        }
        PrCmd::List { state, all, search, out } => {
            let state = if *all { "all".to_string() } else { state.clone().unwrap_or_else(|| "open".into()) };
            let mut path = format!("/prs?state={}", q(&state));
            if let Some(s) = search {
                path.push_str(&format!("&q={}", q(s)));
            }
            let v = c.project_json("GET", &path, None)?;
            emit(&v, out.json, |v| {
                let prs = v["prs"].as_array().cloned().unwrap_or_default();
                if prs.is_empty() {
                    println!("No PRs.");
                }
                for p in &prs {
                    println!(
                        "{}  {:<6} {:<6}  {}  {}",
                        bold(s(p, "id")),
                        s(p, "state"),
                        risk(s(p, "risk")),
                        safe(s(p, "title")),
                        dim(&format!("{} · {}", safe(s(p, "author")), fmt_time(p["updated_at"].as_i64().unwrap_or(0))))
                    );
                }
                if v["count"].as_u64().unwrap_or(0) > prs.len() as u64 {
                    println!("{}", dim(&format!("{} of {}", prs.len(), v["count"])));
                }
            })
        }
        PrCmd::Show { id, threads, out } => {
            let v = c.project_json("GET", &pr_path(id, "")?, None)?;
            let t = if *threads { Some(all_threads(&c, id)?) } else { None };
            if out.json {
                let mut v = v;
                if *threads {
                    v["threads"] = t.map(|t| t["threads"].clone()).unwrap_or_default();
                }
                return api::emit_json(&v);
            }
            print_pr(&v, t.as_ref());
            Ok(())
        }
        PrCmd::Diff { id, revision, change, stat, out } => {
            let mut path = pr_path(id, "/diff?")?;
            if let Some(n) = revision {
                path.push_str(&format!("revision={n}&"));
            }
            if let Some(ch) = change {
                path.push_str(&format!("change={}&", q(ch)));
            }
            if *stat {
                path.push_str("stat=true");
            }
            let v = c.project_json("GET", &path, None)?;
            emit(&v, out.json, print_diff)
        }
        PrCmd::Update { id, rev, out } => {
            let v = c.project_json("POST", &pr_path(id, "/revisions")?, Some(&json!({ "head": head_of(ctx, rev)? }))).map_err(hint_push)?;
            emit(&v, out.json, |v| {
                println!("{} is at revision {}", bold(s(v, "id")), v["revision"]);
                print_pr(v, None);
            })
        }
        PrCmd::Comment { id, message, path, line, end, old, change, thread, out } => {
            let v = match (thread, path) {
                (Some(t), None) => {
                    if !t.bytes().all(|b| b.is_ascii_hexdigit()) {
                        bail!("no such thread in this PR");
                    }
                    c.project_json("POST", &pr_path(id, &format!("/threads/{t}"))?, Some(&json!({ "body": message })))?
                }
                (Some(_), Some(_)) => bail!("reply to a thread, or comment on a line: not both"),
                (None, p) => {
                    let mut req = json!({ "body": message });
                    if let Some(p) = p {
                        let start = line.ok_or_else(|| anyhow!("--path needs --line N"))?;
                        req["anchor"] = json!({
                            "path": p.trim_start_matches("./"),
                            "start": start,
                            "end": end.unwrap_or(start),
                            "side": if *old { "old" } else { "new" },
                            "change": change,
                        });
                    } else if line.is_some() {
                        bail!("--line needs --path");
                    }
                    c.project_json("POST", &pr_path(id, "/threads")?, Some(&req))?
                }
            };
            emit(&v, out.json, |_| println!("Commented on {}", bold(id)))
        }
        PrCmd::Resolve { id, thread, reopen } => {
            if !thread.bytes().all(|b| b.is_ascii_hexdigit()) {
                bail!("no such thread in this PR");
            }
            c.project_json("POST", &pr_path(id, &format!("/threads/{thread}"))?, Some(&json!({ "state": if *reopen { "open" } else { "resolved" } })))?;
            println!("Thread {} {}", thread, if *reopen { "reopened" } else { "resolved" });
            Ok(())
        }
        PrCmd::Review { id, approve, request_changes, message, out } => {
            let verdict = match (approve, request_changes) {
                (true, false) => "approve",
                (false, true) => "request-changes",
                _ => bail!("give --approve or --request-changes"),
            };
            let pr = c.project_json("GET", &pr_path(id, "")?, None)?;
            let (revision, patch) = (pr["revision"].clone(), s(&pr, "patch").to_string());
            let project = c.url.project.clone();
            let sig = load_identity()?.sign(SIG_CONTEXT_HUB_PR_REVIEW, &review_message(&project, s(&pr, "id"), &patch, verdict));
            let req = json!({ "patch": patch, "verdict": verdict, "body": message, "signature": sig });
            let v = c.project_json("POST", &pr_path(id, "/reviews")?, Some(&req))?;
            emit(&v, out.json, |v| {
                println!("{} revision {} of {}", if verdict == "approve" { green("Approved") } else { red("Asked for changes on") }, revision, bold(id));
                println!("  review: {}/{}  {}", v["review"]["approvals"], v["review"]["needs"]["approvals"], if v["review"]["ready"] == true { green("ready to land") } else { yellow("not ready") });
            })
        }
        PrCmd::Dismiss { id, person } => {
            c.project_json("POST", &pr_path(id, "/reviews/dismiss")?, Some(&json!({ "person": person })))?;
            println!("Dismissed {}'s request for changes on {}", safe(person), bold(id));
            Ok(())
        }
        PrCmd::Close { id } => {
            c.project_json("POST", &pr_path(id, "/close")?, None)?;
            println!("Closed {}", bold(id));
            Ok(())
        }
        PrCmd::Land { id } => {
            let v = c.project_json("POST", &pr_path(id, "/land")?, None)?;
            println!("Landed {} ({})", bold(id), safe(&v.to_string()));
            Ok(())
        }
    }
}

/// Every thread of a PR with every comment, page by page (the server
/// answers about 1 MiB of comments at a time).
fn all_threads(c: &Client, id: &str) -> Result<Value> {
    let mut threads: Vec<Value> = Vec::new();
    let mut after: Option<String> = None;
    loop {
        let path = match &after {
            None => pr_path(id, "/threads")?,
            Some(a) => pr_path(id, &format!("/threads?after={}", q(a)))?,
        };
        let page = c.project_json("GET", &path, None)?;
        for mut t in page["threads"].as_array().cloned().unwrap_or_default() {
            let mut more = t["comments_next"].as_str().map(str::to_string);
            while let Some(m) = more {
                let tid = s(&t, "id").to_string();
                if !tid.bytes().all(|b| b.is_ascii_hexdigit()) {
                    break;
                }
                let rest = c.project_json("GET", &pr_path(id, &format!("/threads/{tid}?after={}", q(&m)))?, None)?;
                if let (Some(have), Some(new)) = (t["comments"].as_array_mut(), rest["comments"].as_array()) {
                    have.extend(new.iter().cloned());
                }
                more = rest["comments_next"].as_str().map(str::to_string);
            }
            t["comments_next"] = Value::Null;
            threads.push(t);
        }
        after = page["next"].as_str().map(str::to_string);
        if after.is_none() {
            return Ok(json!({ "threads": threads }));
        }
    }
}

/// A revision the server does not know is one this clone has not pushed.
fn hint_push(e: anyhow::Error) -> anyhow::Error {
    let m = e.to_string();
    if m.contains("no such revision") {
        anyhow!("{m}\n  hint: push the changes first (`vl push`): a PR is made from changes on the server")
    } else {
        e
    }
}
