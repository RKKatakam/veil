//! `veil-bench`: the scale benchmark harness (see
//! `docs/design/scale/9-scale-benchmark.md` and `scripts/bench-scale.sh`).
//!
//! ```text
//! veil-bench gen    --profile tiny|small|1g|5g [--cloaked] --seed N --dir DIR --vl PATH
//! veil-bench run    --profile … --seed N --dir DIR --vl PATH --out RESULTS.json [--agents 4,16,64] …
//!                   [--server PATH --database-url URL [--s3-endpoint URL --s3-bucket B]]
//! veil-bench report RESULTS.json
//! veil-bench openscion --vl PATH --server PATH --database-url URL [--s3-…] --dir DIR --out RESULTS.json
//! veil-bench openscion-memory --out RESULTS.json
//! veil-bench load --mode pull|land|api (--server PATH --database-url URL | --url URL [--ca PEM])
//!                 --projects 1,10 --clients 10,100 [--rates 0.35,3.5,max] --out RESULTS.json
//! ```
//!
//! `scripts/bench-server.sh [1g|openscion|load]` starts the server's
//! containers and runs these against it.
//!
//! Every measured command is a separate process of the release `vl`
//! binary; histories are built in-process through `veil_core`. Everything
//! the run creates lives under `--dir` and is deleted at the end unless
//! `--keep`.

mod agents;
mod content;
mod gen;
mod load;
mod openscion;
mod proc;
mod report;
mod run;
mod server;
mod shim;
mod trace;

use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use serde_json::json;

#[derive(Parser)]
#[command(name = "veil-bench", about = "Scale benchmark harness for Veil")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(clap::Args, Clone)]
struct GenArgs {
    /// Data profile: tiny (smoke test), small, 1g, 5g.
    #[arg(long, default_value = "small")]
    profile: String,
    /// 85 % of the files under cloak rules (the `cloaked-*` profiles).
    #[arg(long)]
    cloaked: bool,
    /// What the server accepts: no cloak rules, no `isolate` rule, no
    /// cloaked fix line, no scopes (set by `run --server`).
    #[arg(long)]
    plain: bool,
    #[arg(long, default_value_t = 1)]
    seed: u64,
    /// Bench directory: the run creates everything below it.
    #[arg(long)]
    dir: PathBuf,
    /// The `vl` binary to measure (a release build).
    #[arg(long)]
    vl: PathBuf,
    /// Stop when free disk would drop below this many GB.
    #[arg(long, default_value_t = 8.0)]
    min_free_gb: f64,
    /// Pack the store every N generated snapshots (0: never; the local
    /// cases then run on a partly packed store, and snapshot counts are
    /// not available).
    #[arg(long, default_value_t = 0)]
    pack_every: usize,
}

#[derive(Subcommand)]
enum Cmd {
    /// The OpenScion speed gates (docs/OVERVIEW.md): 4 KiB-file repositories,
    /// import, clone everything and one directory through the server,
    /// commit one changed file; Git on the same machine as the reference.
    Openscion {
        /// The `vl` binary (a release build).
        #[arg(long)]
        vl: PathBuf,
        #[command(flatten)]
        server: server::ServerArgs,
        /// Bench directory (created; everything is written below it).
        #[arg(long)]
        dir: PathBuf,
        /// Repository sizes, in 4 KiB files.
        #[arg(long, value_delimiter = ',', default_value = "1000,10000")]
        files: Vec<usize>,
        /// Repetitions per case (the median is reported).
        #[arg(long, default_value_t = 5)]
        runs: usize,
        /// Results JSON (a Markdown table is written beside it).
        #[arg(long)]
        out: PathBuf,
    },
    /// The OpenScion workloads as OpenScion measures them: in one process,
    /// in memory (no process start, no disk, no fsync).
    OpenscionMemory {
        /// Repository sizes, in 4 KiB files.
        #[arg(long, value_delimiter = ',', default_value = "1000,10000")]
        files: Vec<usize>,
        /// Repetitions per case (the median is reported).
        #[arg(long, default_value_t = 5)]
        runs: usize,
        /// Results JSON (a Markdown table is written beside it).
        #[arg(long)]
        out: PathBuf,
    },
    /// The server under load: simulated agents pulling and landing
    /// changes, ramped over clients, projects and rates; one row per
    /// point of each curve (docs/design/scale/LOAD.md).
    Load {
        /// `pull` (agents pull in a closed loop), `land` (agents land
        /// changes on `main` by pull and push) or `api` (agents land them
        /// through `POST …/changes`, letting the server rebase).
        #[arg(long)]
        mode: String,
        /// A running server (`https://host:port`); else `--server` starts one here.
        #[arg(long)]
        url: Option<String>,
        /// The running server's certificate (PEM), when self-signed.
        #[arg(long)]
        ca: Option<PathBuf>,
        /// The server to start here (`--database-url` also serves the
        /// statement counts).
        #[command(flatten)]
        server: server::ServerArgs,
        /// Database connections of the server started here.
        #[arg(long, default_value_t = 64)]
        db_connections: u32,
        /// The server's process id, for its CPU (default: the one started here).
        #[arg(long)]
        server_pid: Option<u32>,
        /// Projects, one curve point each.
        #[arg(long, value_delimiter = ',', default_value = "1")]
        projects: Vec<usize>,
        /// Concurrent agents (spread over the projects), one curve point each.
        #[arg(long, value_delimiter = ',', default_value = "10,100")]
        clients: Vec<usize>,
        /// `land`: target landings per second in all (a number), or `max`.
        #[arg(long, value_delimiter = ',', default_value = "max")]
        rates: Vec<String>,
        /// Seconds measured per point.
        #[arg(long, default_value_t = 20.0)]
        duration: f64,
        /// Seconds of warm-up before each point.
        #[arg(long, default_value_t = 3.0)]
        warmup: f64,
        /// `pull`: landings per second per project moving `main` meanwhile.
        #[arg(long, default_value_t = 2.0)]
        background: f64,
        /// Count only this container's database processes (a container id prefix).
        #[arg(long)]
        db_container: Option<String>,
        /// Bench directory (the server started here keeps its data there).
        #[arg(long)]
        dir: PathBuf,
        /// Results JSON (a Markdown table is written beside it).
        #[arg(long)]
        out: PathBuf,
    },
    /// Generate a repository (and keep it).
    Gen(GenArgs),
    /// Generate, run every case, write results, clean up.
    Run {
        #[command(flatten)]
        gen: GenArgs,
        /// Results JSON (a Markdown rendering is written beside it).
        #[arg(long)]
        out: PathBuf,
        /// Repetitions per case (the median is reported).
        #[arg(long, default_value_t = 3)]
        runs: usize,
        /// Agent counts for the N-agents profile (empty: skip it).
        #[arg(long, value_delimiter = ',', default_value = "4,16,64")]
        agents: Vec<usize>,
        /// Iterations per agent.
        #[arg(long, default_value_t = 10)]
        agent_iters: usize,
        /// Iterations per agent in the traced repetition (0: none).
        #[arg(long, default_value_t = 2)]
        agent_trace_iters: usize,
        /// RTTs (ms) for the SFTP cases.
        #[arg(long, value_delimiter = ',', default_value = "0")]
        rtt: Vec<u64>,
        /// Kill a single command after this many seconds.
        #[arg(long, default_value_t = 1800)]
        timeout: u64,
        /// Repeat a case only while one run takes less than this (seconds).
        #[arg(long, default_value_t = 120.0)]
        long_secs: f64,
        /// Skip cases whose name starts with this (repeatable).
        #[arg(long)]
        skip: Vec<String>,
        /// Skip whole phases: import, local, remote-path, server, gc, packed, sftp, agents.
        #[arg(long, value_delimiter = ',')]
        skip_phase: Vec<String>,
        /// Source checkout, for the commit recorded with the results.
        #[arg(long)]
        src: Option<PathBuf>,
        /// Keep the generated repository.
        #[arg(long)]
        keep: bool,
        /// Start this server and run the `server` phase against it (the
        /// repository is generated `--plain`).
        #[command(flatten)]
        server: server::ServerArgs,
    },
    /// (internal) Generate into an existing bench directory (`run` does
    /// this in a child process, so the harness stays small: see
    /// `proc::spawn_measured` on the RSS floor).
    #[command(hide = true)]
    GenInto {
        #[command(flatten)]
        gen: GenArgs,
        #[arg(long)]
        exact_dir: PathBuf,
    },
    /// Render RESULTS.json as Markdown on stdout.
    Report { results: PathBuf },
    /// (internal) Relay stdio to a command with a fixed delay each way.
    #[command(hide = true)]
    SftpShim {
        #[arg(long)]
        rtt_ms: u64,
        #[arg(last = true)]
        cmd: Vec<String>,
    },
}

fn log_line(s: &str) {
    eprintln!("[{}] {s}", chrono_now());
}

fn chrono_now() -> String {
    let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
    format!("{:02}:{:02}:{:02}", (t / 3600) % 24, (t / 60) % 60, t % 60)
}

fn absolute(p: &Path) -> Result<PathBuf> {
    Ok(if p.is_absolute() { p.to_path_buf() } else { std::env::current_dir()?.join(p) })
}

/// `vl init` and the scopes, then the in-process history.
fn generate(g: &GenArgs, dir: &Path, env: &proc::VlEnv) -> Result<serde_json::Value> {
    let profile = gen::Profile::named(&g.profile, g.cloaked, g.plain)?;
    let repo = dir.join("repo");
    std::fs::create_dir_all(&repo)?;
    std::fs::create_dir_all(&env.home)?;
    env.ok(&repo, &["init"])?;
    if !g.plain {
        env.ok(&repo, &["scope", "create", "a"])?;
        env.ok(&repo, &["scope", "create", "b"])?;
    }
    log_line(&format!(
        "generating {}: {} files, {:.1} GB, {} snapshots (seed {})",
        profile.name,
        profile.files,
        profile.bytes as f64 / (1u64 << 30) as f64,
        profile.snapshots,
        g.seed
    ));
    let generated = gen::generate(&profile, g.seed, &repo, &env.home, g.pack_every, &mut |s| log_line(s))?;
    Ok(generated.manifest)
}

fn setup_dirs(g: &GenArgs) -> Result<(PathBuf, proc::VlEnv)> {
    let base = absolute(&g.dir)?;
    let dir = base.join(format!("{}{}-seed{}", if g.cloaked { "cloaked-" } else if g.plain { "plain-" } else { "" }, g.profile, g.seed));
    if dir.exists() {
        return Err(anyhow!("{} exists: remove it first (or pick another seed)", dir.display()));
    }
    std::fs::create_dir_all(&dir)?;
    let logs = dir.join("logs");
    let tmp = dir.join("tmp");
    std::fs::create_dir_all(&logs)?;
    std::fs::create_dir_all(&tmp)?;
    let env = proc::VlEnv {
        vl: absolute(&g.vl)?,
        home: dir.join("home"),
        tmp,
        ssh: None,
        logs,
    };
    Ok((dir, env))
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Openscion { vl, server, dir, files, runs, out } => {
            let v = openscion::run_all(&openscion::Args {
                vl,
                server,
                dir,
                sizes: files,
                runs,
            })?;
            std::fs::write(&out, serde_json::to_vec_pretty(&v)?)?;
            let md = openscion::markdown(&v)?;
            std::fs::write(out.with_extension("md"), &md)?;
            print!("{md}");
            Ok(())
        }
        Cmd::Load {
            mode,
            url,
            ca,
            mut server,
            db_connections,
            server_pid,
            projects,
            clients,
            rates,
            duration,
            warmup,
            background,
            db_container,
            dir,
            out,
        } => {
            let mode = match mode.as_str() {
                "pull" => load::Mode::Pull,
                "land" => load::Mode::Land,
                "api" => load::Mode::Api,
                m => return Err(anyhow!("--mode {m}: pull, land or api")),
            };
            let rates = rates.iter().map(|r| r.parse::<load::Rate>().map_err(|e| anyhow!(e))).collect::<Result<_>>()?;
            let v = load::run_all(&load::Args {
                url,
                ca,
                server: {
                    server.server = server.server.as_deref().map(absolute).transpose()?;
                    server
                },
                db_connections,
                server_pid,
                dir: absolute(&dir)?,
                mode,
                projects,
                clients,
                rates,
                duration: Duration::from_secs_f64(duration),
                warmup: Duration::from_secs_f64(warmup),
                background,
                db_container,
            })?;
            std::fs::write(&out, serde_json::to_vec_pretty(&v)?)?;
            let md = load::markdown(&v)?;
            std::fs::write(out.with_extension("md"), &md)?;
            print!("{md}");
            Ok(())
        }
        Cmd::OpenscionMemory { files, runs, out } => {
            let v = openscion::run_in_memory(&files, runs)?;
            std::fs::write(&out, serde_json::to_vec_pretty(&v)?)?;
            let md = openscion::markdown_in_memory(&v)?;
            std::fs::write(out.with_extension("md"), &md)?;
            print!("{md}");
            Ok(())
        }
        Cmd::SftpShim { rtt_ms, cmd } => shim::run(Duration::from_millis(rtt_ms) / 2, &cmd),
        Cmd::Report { results } => {
            let r: serde_json::Value = serde_json::from_slice(&std::fs::read(&results)?)?;
            print!("{}", report::markdown(&r));
            Ok(())
        }
        Cmd::GenInto { gen: g, exact_dir } => {
            let env = proc::VlEnv {
                vl: absolute(&g.vl)?,
                home: exact_dir.join("home"),
                tmp: exact_dir.join("tmp"),
                ssh: None,
                logs: exact_dir.join("logs"),
            };
            generate(&g, &exact_dir, &env)?;
            Ok(())
        }
        Cmd::Gen(g) => {
            proc::install_signal_handlers();
            let (dir, env) = setup_dirs(&g)?;
            let m = generate(&g, &dir, &env)?;
            log_line(&format!("generated in {} (manifest: {}/manifest.json)", dir.display(), dir.display()));
            let _ = m;
            Ok(())
        }
        Cmd::Run {
            gen: mut g,
            out,
            runs,
            agents: ns,
            agent_iters,
            agent_trace_iters,
            rtt,
            timeout,
            long_secs,
            skip,
            skip_phase,
            src,
            keep,
            server,
        } => {
            proc::install_signal_handlers();
            if server.server.is_some() {
                if g.cloaked {
                    return Err(anyhow!("--cloaked cannot go through the server (it refuses cloaked content)"));
                }
                g.plain = true;
            }
            let out = absolute(&out)?;
            let min_free = (g.min_free_gb * 1e9) as u64;
            let base = absolute(&g.dir)?;
            std::fs::create_dir_all(&base)?;
            let free = proc::free_bytes(&base)?;
            let need = match g.profile.as_str() {
                "5g" => 16_000_000_000u64,
                "1g" => 6_000_000_000,
                _ => 1_000_000_000,
            };
            if free < min_free + need {
                return Err(anyhow!(
                    "not starting: {:.1} GB free, profile {} needs about {:.1} GB above the {:.1} GB floor",
                    free as f64 / 1e9,
                    g.profile,
                    need as f64 / 1e9,
                    min_free as f64 / 1e9
                ));
            }
            let (dir, mut env) = setup_dirs(&g)?;
            let me = absolute(&std::env::current_exe()?)?;
            let sftp = run::sftp_server();
            if let Some(server) = &sftp {
                env.ssh = Some(run::write_fake_ssh(&dir, server, &me)?);
            }
            let started = Instant::now();
            let machine = run::machine_facts(&env.vl, src.as_deref());
            let result = (|| -> Result<run::Bench> {
                // In a child: the generator's memory must not become the
                // harness's (every child's ru_maxrss starts at the
                // harness's peak RSS).
                let st = std::process::Command::new(&me)
                    .arg("gen-into")
                    .args(["--profile", &g.profile, "--seed", &g.seed.to_string(), "--dir"])
                    .arg(&g.dir)
                    .arg("--vl")
                    .arg(&env.vl)
                    .args(if g.cloaked { &["--cloaked"][..] } else { &[][..] })
                    .args(if g.plain { &["--plain"][..] } else { &[][..] })
                    .args(["--pack-every", &g.pack_every.to_string()])
                    .arg("--exact-dir")
                    .arg(&dir)
                    .status()?;
                if !st.success() {
                    return Err(anyhow!("generation failed ({st})"));
                }
                let manifest: serde_json::Value = serde_json::from_slice(&std::fs::read(dir.join("manifest.json"))?)?;
                let snapshots = run::read_snapshots(&dir)?;
                let mut b = run::Bench {
                    repo: dir.join("repo"),
                    dir: dir.clone(),
                    env: env.clone(),
                    snapshots,
                    manifest,
                    cases: Vec::new(),
                    notes: Vec::new(),
                    opts: run::Options {
                        runs,
                        long_secs,
                        timeout: Duration::from_secs(timeout),
                        min_free,
                        rtts: rtt.clone(),
                        sftp_server: sftp.clone(),
                        skip,
                    },
                    edit_seq: 0,
                    log: Box::new(log_line),
                    server_pid: None,
                };
                let phase = |p: &str| !skip_phase.iter().any(|s| s == p);
                let r = (|| -> Result<()> {
                    run::setup(&mut b)?;
                    if phase("import") {
                        run::import(&mut b)?;
                    }
                    if phase("local") {
                        let label = if g.pack_every > 0 { "partly packed store" } else { "loose store" };
                        run::local(&mut b, label, true)?;
                    }
                    if phase("remote-path") {
                        run::remote(&mut b, "path", 0, true)?;
                    }
                    if phase("server") && server.server.is_some() {
                        let srv = server::Server::start(&server, &b.dir.join("server"), 32)?;
                        run::server(&mut b, &srv)?;
                    }
                    if phase("gc") {
                        run::gc(&mut b)?;
                        if phase("packed") {
                            run::local(&mut b, "packed store", false)?;
                        }
                        run::gc_incremental(&mut b)?;
                    }
                    if phase("sftp") {
                        if b.opts.sftp_server.is_none() {
                            b.note("no sftp-server found: SFTP cases skipped");
                        } else {
                            for r in b.opts.rtts.clone() {
                                run::remote(&mut b, "sftp", r, false)?;
                            }
                        }
                    }
                    if phase("agents") && !ns.is_empty() {
                        let a = agents::run(&mut b, &ns, agent_iters, agent_trace_iters)?;
                        b.manifest["__agents"] = json!(a);
                    }
                    Ok(())
                })();
                if let Err(e) = r {
                    b.note(format!("run stopped early: {e:#}"));
                }
                Ok(b)
            })();
            let mut b = match result {
                Ok(b) => b,
                Err(e) => {
                    if !keep {
                        let _ = proc::remove_tree(&dir, &base);
                    }
                    return Err(e);
                }
            };
            let agents = b.manifest.as_object_mut().and_then(|m| m.remove("__agents")).unwrap_or(json!([]));
            let results = json!({
                "schema": "veil.bench/1",
                "machine": machine,
                "fs": run::fs_type(&dir),
                "manifest": b.manifest,
                "cases": b.cases,
                "agents": agents,
                "notes": b.notes,
                "total_secs": started.elapsed().as_secs_f64(),
                "rss_floor_mib": proc::own_hwm_kib() as f64 / 1024.0,
            });
            if let Some(p) = out.parent() {
                std::fs::create_dir_all(p)?;
            }
            std::fs::write(&out, serde_json::to_vec_pretty(&results)?).with_context(|| out.display().to_string())?;
            let md = out.with_extension("md");
            std::fs::write(&md, report::markdown(&results))?;
            log_line(&format!("results: {} and {} ({})", out.display(), md.display(), run::elapsed(started)));
            if keep {
                log_line(&format!("kept {}", dir.display()));
            } else {
                proc::remove_tree(&dir, &base)?;
                log_line(&format!("removed {}", dir.display()));
            }
            Ok(())
        }
    }
}
