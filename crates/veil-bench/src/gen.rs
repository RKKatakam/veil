//! The repository generator: a realistic, seeded history built through
//! `veil_core`'s API in-process (ephemeral workspaces), so 10,000 snapshots take minutes rather than hours of CLI runs.
//!
//! Shape (see `docs/design/scale/9-scale-benchmark.md`):
//! * a directory tree of fan-out up to 20 and depth up to 8;
//! * text file sizes log-normal; 70 % of the bytes synthetic source, 20 %
//!   JSON/YAML, 10 % incompressible binaries of 100 KB–20 MB (plus the
//!   `5g` profile's four 200–400 MB binaries);
//! * an import in chunks, then 1–20 edited files per snapshot, renames and
//!   deletions at about 2 % each, new files trickling in, a hot set of
//!   files that changes often (blame), and a `log -S` needle;
//! * a side branch merged every `merge_every` snapshots, 20 tags;
//! * `.veilpolicy` access lines for groups `a` and `b` over a fraction of
//!   the files (3 %, or 85 % for `--cloaked`, a historical name: only
//!   secret files are ever encrypted), and `*.env isolate`;
//! * a `release` line with a fix line of 50 snapshots, merged into
//!   `release` under an unreleased embargo (through the CLI afterwards:
//!   see `run::setup_embargo`).
//!
//! The generator writes `manifest.json` (what the cases need: the hot
//! file, the needle, tags, sizes) and `snapshots.txt` (every snapshot id,
//! for the walk detector) beside the repository.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::Arc,
    time::Instant,
};

use anyhow::{anyhow, Context, Result};
use veil_core::{DiskBackend, Identity, ObjectId, Repo};

use crate::content::{self, Rng};

#[derive(Clone, Debug)]
pub struct Profile {
    pub name: String,
    /// Files in the final tree (approximately).
    pub files: usize,
    /// Bytes in the final tree (approximately).
    pub bytes: u64,
    /// Snapshots on `main` (imports, edits and merges).
    pub snapshots: usize,
    pub merge_every: usize,
    pub tags: usize,
    /// Extra large binaries (bytes each).
    pub big_binaries: Vec<u64>,
    /// Fraction of the files under access lines for groups `a` and `b`.
    pub cloaked: f64,
    /// What the server accepts (`--plain`): no access lines, no `isolate`
    /// rule and no fix line (the server does not run embargoes yet,
    /// `docs/HUB.md` §13.8).
    pub plain: bool,
}

impl Profile {
    pub fn named(name: &str, cloaked: bool, plain: bool) -> Result<Profile> {
        let mb = 1u64 << 20;
        let mut p = match name {
            // A smoke test: seconds to generate.
            "tiny" => Profile {
                name: name.into(),
                files: 400,
                bytes: 10 * mb,
                snapshots: 200,
                merge_every: 50,
                tags: 4,
                big_binaries: vec![],
                cloaked: 0.03,
                plain: false,
            },
            "small" => Profile {
                name: name.into(),
                files: 3_500,
                bytes: 100 * mb,
                snapshots: 1_000,
                merge_every: 50,
                tags: 20,
                big_binaries: vec![],
                cloaked: 0.03,
                plain: false,
            },
            "1g" => Profile {
                name: name.into(),
                files: 35_000,
                bytes: 1024 * mb,
                snapshots: 10_000,
                merge_every: 50,
                tags: 20,
                big_binaries: vec![],
                cloaked: 0.03,
                plain: false,
            },
            "5g" => Profile {
                name: name.into(),
                files: 150_000,
                bytes: 4 * 1024 * mb,
                snapshots: 20_000,
                merge_every: 50,
                tags: 20,
                big_binaries: vec![200 * mb, 260 * mb, 330 * mb, 400 * mb],
                cloaked: 0.03,
                plain: false,
            },
            other => return Err(anyhow!("unknown profile {other:?} (tiny, small, 1g, 5g)")),
        };
        if cloaked && plain {
            return Err(anyhow!("--cloaked and --plain exclude each other"));
        }
        if cloaked {
            p.cloaked = 0.85;
            p.name = format!("cloaked-{}", p.name);
        }
        if plain {
            p.cloaked = 0.0;
            p.plain = true;
        }
        Ok(p)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    Source,
    Config,
    Binary,
}

#[derive(Clone, Debug)]
struct File {
    path: String,
    kind: Kind,
    ext: &'static str,
    size: usize,
    /// Seed of the file's first version.
    seed: u64,
}

/// The planned final layout.
struct Layout {
    dirs: Vec<String>,
    files: Vec<File>,
    /// Cloak rules: (directory, scope).
    cloak_rules: Vec<(String, &'static str)>,
}

const TOP: &[&str] = &["src", "lib", "crates", "web", "docs", "config", "assets", "tests", "vendor", "tools"];

fn plan_dirs(rng: &mut Rng, count: usize) -> Vec<String> {
    let mut dirs: Vec<(String, usize, usize)> = TOP.iter().map(|t| (t.to_string(), 1, 0)).collect();
    let mut names = BTreeSet::new();
    while dirs.len() < count {
        // Prefer shallow parents a little, so the tree is both wide and deep.
        let i = rng.below(dirs.len());
        let (parent, depth, kids) = dirs[i].clone();
        if depth >= 8 || kids >= 20 {
            continue;
        }
        if depth >= 4 && rng.chance(0.4) {
            continue;
        }
        let name = format!("{parent}/{}_{}", rng.pick(WORDS_DIR), rng.below(100));
        if !names.insert(name.clone()) {
            continue;
        }
        dirs[i].2 += 1;
        dirs.push((name, depth + 1, 0));
    }
    dirs.into_iter().map(|d| d.0).collect()
}

const WORDS_DIR: &[&str] = &[
    "core", "util", "net", "io", "fs", "db", "api", "ui", "app", "model", "view", "store", "auth", "crypto",
    "parse", "render", "sched", "proto", "codec", "cache", "http", "rpc", "cli", "test", "bench", "mock", "gen",
];

fn plan(p: &Profile, seed: u64) -> Layout {
    let mut rng = Rng::fork(seed, 1);
    let dirs = plan_dirs(&mut rng, (p.files / 12).max(TOP.len() + 4));
    let n_bin = (p.files / 1000).max(3);
    let n_cfg = p.files * 15 / 100;
    let n_src = p.files - n_bin - n_cfg;
    let total = p.bytes as f64;
    let mut files = Vec::with_capacity(p.files);
    // Sizes first, then scaled per group to the byte shares.
    let mut groups: Vec<(Kind, usize, f64)> = vec![(Kind::Source, n_src, 0.70), (Kind::Config, n_cfg, 0.20), (Kind::Binary, n_bin, 0.10)];
    let asset_dirs: Vec<String> = dirs.iter().filter(|d| d.starts_with("assets")).cloned().collect();
    let config_dirs: Vec<String> = dirs.iter().filter(|d| d.starts_with("config") || d.starts_with("web")).cloned().collect();
    let mut idx = 0usize;
    for (kind, n, share) in groups.drain(..) {
        let raw: Vec<f64> = (0..n)
            .map(|_| match kind {
                // 100 KB – 20 MB, log-uniform.
                Kind::Binary => (100e3f64.ln() + rng.unit() * (20e6f64.ln() - 100e3f64.ln())).exp(),
                _ => rng.log_normal(12_000.0, 1.1),
            })
            .collect();
        let sum: f64 = raw.iter().sum();
        let scale = total * share / sum;
        for r in raw {
            let size = match kind {
                Kind::Binary => (r * scale).clamp(100e3, 20e6) as usize,
                _ => (r * scale).clamp(200.0, 1e6) as usize,
            };
            let (ext, dir): (&'static str, &String) = match kind {
                Kind::Source => (*rng.pick(&["rs", "rs", "py", "ts"]), rng.pick(&dirs)),
                Kind::Config => (
                    *rng.pick(&["json", "yaml"]),
                    if rng.chance(0.5) && !config_dirs.is_empty() { rng.pick(&config_dirs) } else { rng.pick(&dirs) },
                ),
                Kind::Binary => (*rng.pick(&["bin", "png"]), if asset_dirs.is_empty() { rng.pick(&dirs) } else { rng.pick(&asset_dirs) }),
            };
            let word = rng.pick(WORDS_DIR);
            files.push(File {
                path: format!("{dir}/{word}_{idx}.{ext}"),
                kind,
                ext,
                size,
                seed: rng.next(),
            });
            idx += 1;
        }
    }
    for (i, &b) in p.big_binaries.iter().enumerate() {
        files.push(File {
            path: format!("assets/large/blob_{i}.bin"),
            kind: Kind::Binary,
            ext: "bin",
            size: b as usize,
            seed: rng.next(),
        });
    }
    let cloak_rules = plan_cloak(&mut rng, &dirs, &files, p.cloaked);
    Layout { dirs, files, cloak_rules }
}

/// Pick disjoint subtrees until about `fraction` of the files are under
/// access lines, alternating groups `a` and `b`.
fn plan_cloak(rng: &mut Rng, dirs: &[String], files: &[File], fraction: f64) -> Vec<(String, &'static str)> {
    let want = (files.len() as f64 * fraction) as usize;
    let under = |d: &str| {
        let pre = format!("{d}/");
        files.iter().filter(|f| f.path.starts_with(&pre)).count()
    };
    let mut order: Vec<&String> = dirs.iter().collect();
    // Shuffle, then try top-level directories first for big fractions.
    for i in (1..order.len()).rev() {
        let j = rng.below(i + 1);
        order.swap(i, j);
    }
    order.sort_by_key(|d| if fraction > 0.5 { d.matches('/').count() } else { 0 });
    let mut chosen: Vec<(String, &'static str)> = Vec::new();
    let mut got = 0;
    for d in order {
        if got >= want {
            break;
        }
        if chosen.iter().any(|(c, _)| d.starts_with(&format!("{c}/")) || c.starts_with(&format!("{d}/")) || c == d) {
            continue;
        }
        let n = under(d);
        if n == 0 || got + n > want + want / 10 + 5 {
            continue;
        }
        got += n;
        let scope = if chosen.len().is_multiple_of(2) { "a" } else { "b" };
        chosen.push((d.clone(), scope));
    }
    chosen
}

pub struct Generated {
    pub manifest: serde_json::Value,
}

struct Live {
    /// Path → index into `files`.
    by_path: BTreeMap<String, usize>,
    files: Vec<File>,
    edits: Vec<u32>,
}

impl Live {
    fn text_paths(&self) -> Vec<String> {
        self.by_path.iter().filter(|(_, &i)| self.files[i].kind != Kind::Binary).map(|(p, _)| p.clone()).collect()
    }
}

fn first_version(f: &File) -> Vec<u8> {
    let mut r = Rng::new(f.seed);
    match f.kind {
        Kind::Source => content::source_file(&mut r, f.ext, f.size),
        Kind::Config => content::config_file(&mut r, f.ext == "yaml", f.size),
        Kind::Binary => content::binary_file(&mut r, f.size),
    }
}

fn commit_ws(repo: &mut Repo, ws: &veil_core::workspace::EphemeralWorkspace, msg: &str, all: &mut Vec<ObjectId>) -> Result<ObjectId> {
    let (id, _) = repo.commit_ephemeral(ws, msg).with_context(|| format!("commit {msg:?}"))?;
    all.push(id);
    Ok(id)
}

/// Generate the repository at `root` (already `vl init`ed, scopes `a` and
/// `b` created, identity in `home`).
///
/// `pack_every` > 0 packs the store in-process every that many snapshots
/// (for `5g`: its loose store would otherwise pass 15 GB before the first
/// `vl gc`).
pub fn generate(p: &Profile, seed: u64, root: &Path, home: &Path, pack_every: usize, log: &mut dyn FnMut(&str)) -> Result<Generated> {
    let t0 = Instant::now();
    let layout = plan(p, seed);
    let id_json = std::fs::read_to_string(home.join("identity.json")).context("identity.json")?;
    let identity = Identity::from_json(&id_json)?;
    let mut repo = Repo::open(Arc::new(DiskBackend::new(root)), Some(identity), "bench")?;
    let mut all: Vec<ObjectId> = vec![repo.root_id()];
    let mut rng = Rng::fork(seed, 2);

    // Which files are in the import, and which arrive later.
    let mut import: Vec<usize> = Vec::new();
    let mut later: Vec<usize> = Vec::new();
    for (i, f) in layout.files.iter().enumerate() {
        if f.size > 50_000_000 || rng.chance(0.4) {
            later.push(i);
        } else {
            import.push(i);
        }
    }
    let mut live = Live {
        by_path: BTreeMap::new(),
        files: layout.files.clone(),
        edits: vec![0; layout.files.len()],
    };

    // ---- import --------------------------------------------------------
    let mut tip = repo.root_id();
    // `main`'s first-parent line, oldest first (`mainline.txt`: the
    // server phase can push the history along it in fast-forward steps).
    let mut mainline: Vec<ObjectId> = Vec::new();
    let mut policy = String::new();
    {
        let ws = repo.ephemeral_workspace(tip)?;
        if let Ok(existing) = ws.read(".veilpolicy") {
            policy = String::from_utf8_lossy(&existing).into_owned();
        }
    }
    if !p.plain {
        policy.push_str("\n# veil-bench\n*.env isolate\n");
    }
    for (d, s) in &layout.cloak_rules {
        policy.push_str(&format!("{d}/ {s}\n"));
    }
    let chunk = 2000usize;
    let chunks = import.len().div_ceil(chunk).max(1);
    for (c, part) in import.chunks(chunk).enumerate() {
        let ws = repo.ephemeral_workspace(tip)?;
        if c == 0 {
            ws.write(".veilpolicy", policy.as_bytes())?;
        }
        for &i in part {
            let f = &live.files[i];
            ws.write(&f.path, first_version(f))?;
            live.by_path.insert(f.path.clone(), i);
        }
        tip = commit_ws(&mut repo, &ws, &format!("import part {}/{}", c + 1, chunks), &mut all)?;
        mainline.push(tip);
    }
    log(&format!("import: {} files in {chunks} snapshots ({:.0} s)", import.len(), t0.elapsed().as_secs_f64()));

    // ---- history ---------------------------------------------------------
    // The hot set: public files from the import, edited often, never
    // renamed or deleted (blame's target; the release and fix lines).
    let is_cloaked = |p: &str| layout.cloak_rules.iter().any(|(d, _)| p.starts_with(&format!("{d}/")));
    let hot: Vec<String> = live.text_paths().into_iter().filter(|p| !is_cloaked(p)).take(20).collect();
    let blame_path = hot[0].clone();
    let needle = format!("VEILBENCH_NEEDLE_{seed}");
    let needle_at = p.snapshots * 3 / 10;
    let edit_steps = p.snapshots.saturating_sub(chunks);
    let add_rate = later.len() as f64 / edit_steps.max(1) as f64;
    let mut add_acc = 0.0;
    let mut extra = 0usize;
    let mut tags: Vec<(String, usize)> = Vec::new();
    let tag_every = (p.snapshots / p.tags.max(1)).max(1);
    let release_at = p.snapshots * 9 / 10;
    let mut release_base: Option<ObjectId> = None;
    let mut old_path: Option<String> = None;
    let mut renames = 0usize;
    let mut deletes = 0usize;
    let mut merges = 0usize;
    // An active side branch: (tip, directory it edits, merge at step, the
    // files it may edit: those in that directory when it started).
    let mut branch: Option<(ObjectId, String, usize, Vec<String>)> = None;
    let mut step = chunks;
    let started = Instant::now();
    while step < p.snapshots {
        // Merge a finished branch.
        if let Some((btip, _, at, _)) = &branch {
            if step >= *at {
                let mut tx = repo.transaction("merge branch")?;
                let id = tx.new_change(vec![tip, *btip], &format!("Merge branch at step {step}"))?;
                tx.commit()?;
                all.push(id);
                tip = id;
                mainline.push(tip);
                merges += 1;
                branch = None;
                step += 1;
                continue;
            }
        }
        // Start a branch.
        if branch.is_none() && p.merge_every > 12 && step % p.merge_every == p.merge_every - 10 && step + 10 < p.snapshots {
            let paths = live.text_paths();
            let mut dirs: BTreeMap<String, usize> = BTreeMap::new();
            for path in &paths {
                if hot.contains(path) {
                    continue;
                }
                if let Some((d, _)) = path.rsplit_once('/') {
                    *dirs.entry(d.to_string()).or_default() += 1;
                }
            }
            let good: Vec<&String> = dirs.iter().filter(|(_, &n)| n >= 3).map(|(d, _)| d).collect();
            if !good.is_empty() {
                let d = (*rng.pick(&good)).clone();
                let pre = format!("{d}/");
                let files: Vec<String> = paths.iter().filter(|p| p.starts_with(&pre) && !p[pre.len()..].contains('/') && !hot.contains(p)).cloned().collect();
                branch = Some((tip, d, step + 9, files));
            }
        }
        let on_branch = branch.is_some() && step % 2 == 1;
        let base = if on_branch { branch.as_ref().unwrap().0 } else { tip };
        let branch_dir = branch.as_ref().map(|b| format!("{}/", b.1));
        let ws = repo.ephemeral_workspace(base)?;
        let mut msg = format!("step {step}");
        let paths = live.text_paths();
        let n_edits = (1.0 + rng.log_normal(2.5, 0.9)).min(20.0) as usize;
        for e in 0..n_edits {
            let path = if on_branch {
                rng.pick(&branch.as_ref().unwrap().3).clone()
            } else if rng.chance(0.25) {
                rng.pick(&hot).clone()
            } else {
                let mut tries = 0;
                loop {
                    let c = rng.pick(&paths).clone();
                    tries += 1;
                    if branch_dir.as_deref().is_none_or(|pre| !c.starts_with(pre)) {
                        break c;
                    }
                    if tries > 20 {
                        break rng.pick(&hot).clone();
                    }
                }
            };
            let i = live.by_path[&path];
            let plant = step == needle_at && e == 0;
            let structural = !on_branch && branch.is_none() && !hot.contains(&path) && !plant;
            if structural && rng.chance(0.02) {
                // Rename into another directory.
                let dir = rng.pick(&layout.dirs).clone();
                let name = path.rsplit('/').next().unwrap().to_string();
                let to = format!("{dir}/{name}");
                if !live.by_path.contains_key(&to) {
                    let data = ws.read(&path)?;
                    ws.remove(&path)?;
                    ws.write(&to, &data)?;
                    live.by_path.remove(&path);
                    live.by_path.insert(to.clone(), i);
                    live.files[i].path = to;
                    if old_path.is_none() {
                        old_path = Some(path.clone());
                    }
                    renames += 1;
                    continue;
                }
            }
            if structural && rng.chance(0.02) {
                ws.remove(&path)?;
                live.by_path.remove(&path);
                deletes += 1;
                // Keep the file count: a new file arrives instead.
                let mut f = live.files[i].clone();
                f.path = format!("{}/new_{extra}.{}", rng.pick(&layout.dirs), f.ext);
                f.seed = rng.next();
                extra += 1;
                live.files.push(f);
                live.edits.push(0);
                later.push(live.files.len() - 1);
                continue;
            }
            let data = ws.read(&path)?;
            let ext = live.files[i].ext;
            let mut er = Rng::fork(seed, (step as u64) << 8 | e as u64);
            let new = content::edit_text(&mut er, &data, ext, plant.then_some(needle.as_str()));
            ws.write(&path, new)?;
            live.edits[i] += 1;
            if plant {
                msg.push_str(" (needle)");
            }
        }
        if !on_branch {
            // New files arrive on main.
            add_acc += add_rate;
            while add_acc >= 1.0 && !later.is_empty() {
                add_acc -= 1.0;
                let i = later.remove(rng.below(later.len()));
                let f = &live.files[i];
                if !live.by_path.contains_key(&f.path) {
                    ws.write(&f.path, first_version(f))?;
                    live.by_path.insert(f.path.clone(), i);
                }
            }
            // Now and then a binary is replaced.
            if step % 500 == 250 {
                let bins: Vec<(String, usize)> =
                    live.by_path.iter().filter(|(_, &i)| live.files[i].kind == Kind::Binary && live.files[i].size < 30_000_000).map(|(p, &i)| (p.clone(), i)).collect();
                if !bins.is_empty() {
                    let (path, i) = rng.pick(&bins).clone();
                    let mut f = live.files[i].clone();
                    f.seed = rng.next();
                    ws.write(&path, first_version(&f))?;
                }
            }
        }
        let id = commit_ws(&mut repo, &ws, &msg, &mut all)?;
        if on_branch {
            branch.as_mut().unwrap().0 = id;
        } else {
            tip = id;
            mainline.push(tip);
            if step.is_multiple_of(tag_every) && tags.len() < p.tags {
                let name = format!("rel-{:03}", tags.len() + 1);
                repo.set_tag(&name, tip, false)?;
                tags.push((name, step));
            }
            if step >= release_at && release_base.is_none() {
                release_base = Some(tip);
            }
        }
        step += 1;
        if pack_every > 0 && step.is_multiple_of(pack_every) {
            let t = Instant::now();
            veil_core::gc::gc(&mut repo, &veil_core::gc::GcOptions::default())?;
            log(&format!("packed the store at snapshot {step} ({:.0} s)", t.elapsed().as_secs_f64()));
        }
        if step.is_multiple_of(500) {
            let done = (step - chunks) as f64 / edit_steps.max(1) as f64;
            let el = started.elapsed().as_secs_f64();
            log(&format!("history: {step}/{} snapshots ({:.0} s, eta {:.0} s)", p.snapshots, el, el / done.max(1e-9) * (1.0 - done)));
        }
    }
    // Whatever has not arrived yet arrives now.
    if !later.is_empty() {
        let ws = repo.ephemeral_workspace(tip)?;
        for i in later.drain(..) {
            let f = &live.files[i];
            if !live.by_path.contains_key(&f.path) {
                ws.write(&f.path, first_version(f))?;
                live.by_path.insert(f.path.clone(), i);
            }
        }
        tip = commit_ws(&mut repo, &ws, "late files", &mut all)?;
        mainline.push(tip);
    }
    repo.set_tag("main", tip, false)?;

    // ---- the release line and the cloaked fix line ------------------------
    let mut rtip = release_base.unwrap_or(tip);
    // Files that exist on every line: the hot set, imported and never
    // renamed or deleted.
    let paths = hot.clone();
    for k in 0..20 {
        let ws = repo.ephemeral_workspace(rtip)?;
        let path = rng.pick(&paths).clone();
        let data = ws.read(&path)?;
        let ext = live.files[live.by_path[&path]].ext;
        ws.write(&path, content::edit_text(&mut Rng::fork(seed, 900_000 + k), &data, ext, None))?;
        rtip = commit_ws(&mut repo, &ws, &format!("release fix {k}"), &mut all)?;
    }
    repo.set_tag("release", rtip, false)?;
    let mut ftip = None;
    if !p.plain {
        ftip = Some(fix_line(&mut repo, &mut rng, seed, rtip, &hot, &live, &layout, &mut all)?);
    }

    // ---- manifest ------------------------------------------------------------
    let (mut bytes, mut nfiles) = (0u64, 0usize);
    {
        // Sizes of the final tree, from the plan (exact sizes after edits
        // drift by a few lines; `run` measures the checked-out tree).
        for &i in live.by_path.values() {
            bytes += live.files[i].size as u64;
            nfiles += 1;
        }
    }
    let most_edited = live
        .by_path
        .iter()
        .max_by_key(|(_, &i)| live.edits[i])
        .map(|(p, &i)| (p.clone(), live.edits[i]))
        .unwrap();
    let blame_edits = live.by_path.get(&blame_path).map(|&i| live.edits[i]).unwrap_or(0);
    let mut snaps = String::new();
    for id in &all {
        snaps.push_str(&id.hex());
        snaps.push('\n');
    }
    let manifest = serde_json::json!({
        "profile": p.name,
        "seed": seed,
        "snapshots_main": p.snapshots,
        "snapshots_total": all.len(),
        "files_planned": nfiles,
        "bytes_planned": bytes,
        "import_snapshots": chunks,
        "merges": merges,
        "renames": renames,
        "deletes": deletes,
        "tags": tags.iter().map(|t| &t.0).collect::<Vec<_>>(),
        "oldest_tag": tags.first().map(|t| t.0.clone()),
        "blame_path": if live.by_path.contains_key(&blame_path) { blame_path.clone() } else { most_edited.0.clone() },
        "blame_path_edits": blame_edits,
        "most_edited": most_edited.0,
        "most_edited_edits": most_edited.1,
        "renamed_away": old_path,
        "needle": needle,
        "access_lines": layout.cloak_rules.iter().map(|(d, s)| format!("{d}/ {s}")).collect::<Vec<_>>(),
        "main": tip.hex(),
        "release": rtip.hex(),
        "fix_tip": ftip.map(|f| f.hex()),
        "generate_seconds": t0.elapsed().as_secs_f64(),
        "pack_every": pack_every,
        "sample_paths": live.by_path.keys().step_by((live.by_path.len() / 200).max(1)).cloned().collect::<Vec<_>>(),
    });
    let dir = root.parent().unwrap_or(root);
    std::fs::write(dir.join("snapshots.txt"), snaps)?;
    std::fs::write(dir.join("mainline.txt"), mainline.iter().map(|id| format!("{}\n", id.hex())).collect::<String>())?;
    std::fs::write(dir.join("manifest.json"), serde_json::to_vec_pretty(&manifest)?)?;
    Ok(Generated { manifest })
}

/// The fix line: 50 snapshots in workspace `fix-sec` on top of
/// `release`, merged later under an embargo (`run::setup`). Its tip.
#[allow(clippy::too_many_arguments)]
fn fix_line(repo: &mut Repo, rng: &mut Rng, seed: u64, rtip: ObjectId, hot: &[String], live: &Live, layout: &Layout, all: &mut Vec<ObjectId>) -> Result<ObjectId> {
    let paths = hot.to_vec();
    let fix_base = repo.create_workspace("fix-sec", vec![rtip])?;
    all.push(fix_base);
    let mut ftip = fix_base;
    // The fix touches files outside the access lines only.
    let public: Vec<String> = live
        .text_paths()
        .into_iter()
        .filter(|p| !layout.cloak_rules.iter().any(|(d, _)| p.starts_with(&format!("{d}/"))))
        .filter(|p| hot.contains(p))
        .collect();
    let public = if public.is_empty() { paths.clone() } else { public };
    let fix_files: Vec<String> = (0..5).map(|_| rng.pick(&public).clone()).collect();
    for k in 0..50u64 {
        let ws = repo.ephemeral_workspace(ftip)?;
        let path = &fix_files[k as usize % fix_files.len()];
        let data = ws.read(path)?;
        let ext = live.files[live.by_path[path]].ext;
        ws.write(path, content::edit_text(&mut Rng::fork(seed, 950_000 + k), &data, ext, None))?;
        ftip = commit_ws(repo, &ws, &format!("embargoed fix step {k}"), all)?;
    }
    Ok(ftip)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_plan_is_deterministic_and_sized() {
        let p = Profile::named("small", false, false).unwrap();
        let a = plan(&p, 7);
        let b = plan(&p, 7);
        assert_eq!(a.files.len(), b.files.len());
        assert!(a.files.iter().zip(&b.files).all(|(x, y)| x.path == y.path && x.size == y.size && x.seed == y.seed));
        let total: u64 = a.files.iter().map(|f| f.size as u64).sum();
        let want = p.bytes as f64;
        assert!((total as f64) > want * 0.85 && (total as f64) < want * 1.15, "{total}");
        let depth = a.dirs.iter().map(|d| d.matches('/').count() + 1).max().unwrap();
        assert!(depth <= 8, "{depth}");
        let paths: BTreeSet<&String> = a.files.iter().map(|f| &f.path).collect();
        assert_eq!(paths.len(), a.files.len(), "paths are unique");
    }

    #[test]
    fn a_plain_profile_has_nothing_the_server_refuses() {
        let p = Profile::named("small", false, true).unwrap();
        assert!(p.plain && p.cloaked == 0.0);
        assert!(plan(&p, 3).cloak_rules.is_empty());
        assert!(Profile::named("small", true, true).is_err(), "--cloaked and --plain exclude each other");
    }

    #[test]
    fn cloak_rules_cover_about_the_fraction() {
        for (cloaked, lo, hi) in [(false, 0.0, 0.08), (true, 0.70, 0.95)] {
            let p = Profile::named("small", cloaked, false).unwrap();
            let l = plan(&p, 3);
            let n = l
                .files
                .iter()
                .filter(|f| l.cloak_rules.iter().any(|(d, _)| f.path.starts_with(&format!("{d}/"))))
                .count();
            let frac = n as f64 / l.files.len() as f64;
            assert!(frac >= lo && frac <= hi, "{cloaked}: {frac}");
        }
    }
}
