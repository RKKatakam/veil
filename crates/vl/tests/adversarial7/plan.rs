//! `vl ls` tier marks and `vl push --dry-run` against what a push really
//! sends.

use veil_core::object::Visibility;

use crate::{
    adversarial_support::{blob, evil_remote_on_disk, file, raw_tree, Env},
    all_files, U,
};

const PLAIN: &str = "PLAINTEXT-UNDER-A-CLOAKED-LABEL\n";

/// A remote whose `main` holds `notes.txt` labelled `cloaked:team` whose
/// object is a plaintext blob (any writer of a remote, or an import, can
/// record such a tree; BUG-103 made labels claims). Alice clones it and
/// adds a public mirror `pub`.
fn forged(env: &Env) -> std::path::PathBuf {
    let evil = env.root.join("evil");
    evil_remote_on_disk(&evil, "contribution", &["main"], |r| {
        let mut e = file("notes.txt", blob(r, PLAIN.as_bytes()));
        e.size = PLAIN.len() as u64;
        e.visibility = Visibility::Cloaked { scope: "team".into() };
        raw_tree(r, vec![e])
    });
    env.ok(U, &env.root, &["clone", evil.to_str().unwrap(), "proj"]);
    let proj = env.root.join("proj");
    let pubdir = env.root.join("pub");
    env.ok(U, &proj, &["remote", "add", "pub", pubdir.to_str().unwrap(), "--public"]);
    proj
}

/// `push_plan::public_files` decides what a public reader sees from the
/// entry's label (`seen_as_public`, `push_plan.rs:382`), and `vl ls` its
/// tier from the label too (`api::entry_tier`: a `cloaked` label whose
/// object opens is `cloaked`). The push itself decides on the object
/// (`remote.rs`, `allowed(&raw)`): a plaintext blob goes out. So the dry
/// run says the file is withheld, `vl ls` says it is cloaked, and the push
/// publishes it. The dry run exists to be read before a push.
#[test]
#[ignore = "BUG-482: push --dry-run and vl ls trust a forged cloaked label the push ignores"]
fn the_dry_run_never_calls_withheld_what_the_push_publishes() {
    let env = Env::new();
    let proj = forged(&env);
    let ls: serde_json::Value = serde_json::from_str(&env.stdout(U, &proj, &["ls", "-r", "main", "--json"])).unwrap();
    let tier = ls["entries"].as_array().unwrap().iter().find(|e| e["path"] == "notes.txt").unwrap()["tier"].clone();
    let plan: serde_json::Value =
        serde_json::from_str(&env.stdout(U, &proj, &["push", "--dry-run", "pub", "--json"])).unwrap();
    let files = &plan["remotes"][0]["files"];
    let withheld = files["withheld"].as_array().unwrap().iter().any(|w| w["path"] == "notes.txt");
    let published = files["published"].as_array().unwrap().iter().any(|w| w["path"] == "notes.txt");

    env.ok(U, &proj, &["push", "pub"]);
    let pubdir = env.root.join("pub");
    env.ok("carol", &env.root, &["clone", pubdir.to_str().unwrap(), "carol"]);
    let carol = env.root.join("carol");
    let public = all_files(&carol).contains(PLAIN.trim());
    assert!(public, "setup: the push sends the plaintext blob");
    assert!(
        published && !withheld && tier != "cloaked",
        "the push published notes.txt, but the dry run said published={published} withheld={withheld} and `vl ls` said tier {tier}"
    );
}
