//! `vl search`: ranked search of a project on its Veil server (milestone
//! S15, `docs/HUB.md` §13.23). The server searches only what the caller
//! may see; `vl` prints its answer.

use std::{process::ExitCode, time::Duration};

use anyhow::{bail, Result};
use clap::Args;
use serde_json::Value;

use crate::{
    cli::JsonOut,
    ctx::Ctx,
    hub_cmd::client_for,
    render::{bold, dim, safe},
};

/// `vl search WORDS… [--path] [--lang LANG] [-r BRANCH] [-n N] [--json] [-- PATH]`.
#[derive(Args, Debug)]
pub struct SearchArgs {
    /// Words to find (all must occur; any case).
    #[arg(required = true)]
    pub words: Vec<String>,
    /// Search file names over all of the project's history, not code.
    #[arg(long)]
    pub path: bool,
    /// Only files of this language (by extension: rust, python, go, …).
    #[arg(long, value_name = "LANG")]
    pub lang: Option<String>,
    /// The branch whose tip to search (default: the project's default branch).
    #[arg(short, long, value_name = "BRANCH")]
    pub rev: Option<String>,
    /// Results to show.
    #[arg(short = 'n', long, default_value_t = 20)]
    pub limit: usize,
    /// Only files at or under this path.
    #[arg(last = true, value_name = "PATH")]
    pub under: Option<String>,
    #[command(flatten)]
    pub out: JsonOut,
}

/// Run `vl search`: exit 0 when something matched, 1 when nothing did.
pub fn search(ctx: &mut Ctx, a: &SearchArgs) -> Result<ExitCode> {
    let (client, _) = client_for(ctx, "origin")?;
    let mut params = vec![("q", a.words.join(" ")), ("n", a.limit.clamp(1, 100).to_string())];
    if a.path {
        params.push(("kind", "path".into()));
    }
    if let Some(l) = &a.lang {
        params.push(("lang", l.clone()));
    }
    if let Some(r) = &a.rev {
        params.push(("rev", r.clone()));
    }
    if let Some(u) = &a.under {
        params.push(("path", u.trim_start_matches("./").to_string()));
    }
    // A branch just pushed, or under a new policy, is indexed in the
    // background: wait for it a little.
    let mut tries = 0;
    let v: Value = loop {
        match client.query("search", &params)? {
            Ok(v) => break v,
            Err((code, _)) if code == "indexing" && tries < 30 => {
                tries += 1;
                std::thread::sleep(Duration::from_millis(500));
            }
            Err((code, message)) => bail!("{} (server: {})", message, safe(&code)),
        }
    };
    let results = v["results"].as_array().cloned().unwrap_or_default();
    if a.out.json {
        println!("{v}");
    } else {
        for r in &results {
            let path = safe(r["path"].as_str().unwrap_or(""));
            if a.path {
                let gone = if r["at_rev"].as_bool() == Some(true) { String::new() } else { dim("  (not at this revision)") };
                println!("{}{gone}", bold(&path));
                continue;
            }
            println!("{}  {}", bold(&path), dim(&format!("{} matching lines", r["matches"])));
            for l in r["lines"].as_array().into_iter().flatten() {
                println!("  {}: {}", dim(&l["line"].to_string()), safe(l["text"].as_str().unwrap_or("")));
            }
        }
        if v["behind"].as_bool() == Some(true) {
            eprintln!("{}", dim("The index is still catching up with the branch tip: these results are from an earlier snapshot."));
        }
        if results.is_empty() {
            eprintln!("Nothing found.");
        } else if v["truncated"].as_bool() == Some(true) || v["complete"].as_bool() == Some(false) {
            eprintln!("{}", dim(&format!("{} files matched; showing the best {}.", v["files"], results.len())));
        }
    }
    Ok(if results.is_empty() { ExitCode::from(1) } else { ExitCode::SUCCESS })
}
