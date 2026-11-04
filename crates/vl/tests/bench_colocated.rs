//! `vl status` with and without colocated Git mode on a 20,000-file working
//! copy (design threat 20: within 15 % of the plain repository; ignored by
//! default).
//!
//! ```sh
//! cargo test --release -p vl --test bench_colocated -- --ignored --nocapture
//! ```

mod colocated_support;

use std::{path::Path, time::Instant};

use colocated_support::*;

const FILES: usize = 20_000;
const RUNS: usize = 8;

fn populate(env: &Env, dir: &Path) {
    for i in 0..FILES {
        env.write(dir, &format!("src/m{:03}/f{:03}.rs", i / 100, i % 100), &format!("// file {i}\npub fn f{i}() {{}}\n"));
    }
    env.write(dir, "secrets/a.yml", "x\n");
}

fn median_status(env: &Env, dir: &Path) -> f64 {
    let mut t: Vec<f64> = (0..RUNS)
        .map(|_| {
            let s = Instant::now();
            env.ok(dir, &["status"]);
            s.elapsed().as_secs_f64() * 1000.0
        })
        .collect();
    t.sort_by(|a, b| a.partial_cmp(b).unwrap());
    t[RUNS / 2]
}

#[test]
#[ignore = "benchmark: run with --ignored --nocapture"]
fn status_with_colocation_stays_close_to_without() {
    let env = Env::new();
    let plain = env.dir("plain");
    env.ok(&plain, &["init"]);
    populate(&env, &plain);
    env.ok(&plain, &["commit", "-m", "all"]);
    env.ok(&plain, &["tag", "set", "main", "-r", "@-"]);
    let colo = env.dir("colo");
    env.ok(&colo, &["init", "--colocate", "--experimental"]);
    populate(&env, &colo);
    env.ok(&colo, &["commit", "-m", "all"]);
    env.ok(&colo, &["tag", "set", "main", "-r", "@-"]);
    env.ok(&colo, &["status"]);
    let a = median_status(&env, &plain);
    let b = median_status(&env, &colo);
    eprintln!("vl status, {FILES} files: plain {a:.1} ms, colocated {b:.1} ms ({:+.1} %)", (b / a - 1.0) * 100.0);
    let s = Instant::now();
    env.ok(&colo, &["describe", "-m", "touch the op log"]);
    eprintln!("vl describe (full mirror, index re-check) {:.1} ms", s.elapsed().as_secs_f64() * 1000.0);
}
