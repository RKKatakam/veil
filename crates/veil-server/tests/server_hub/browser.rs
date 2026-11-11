//! The web client in a real browser (`docs/HUB.md` §13.39, §13.40).
//!
//! Every other web test speaks to the server with a client written for the
//! test: none runs the pages' JavaScript. This one starts a server, makes a
//! person and a project with `vl`, and hands them to
//! `scripts/web-browser-smoke.mjs`, which drives a headless Chromium over
//! the DevTools protocol with a virtual WebAuthn authenticator: enroll, sign
//! in, a file page, sign out, sign in again, and (with PRF) "Show secret",
//! then "Remove this browser".
//!
//! Ignored: it needs a Chromium (`VEIL_CHROMIUM`), node 22 and the WASM
//! examples built. `scripts/web-browser-smoke.sh` finds or builds them and
//! runs it.

use std::process::Command;

use crate::{support::*, web_secrets::catch_up};

const PUBLIC_TEXT: &str = "SMOKE_PUBLIC_TEXT_7131";
const SECRET_TEXT: &str = "SMOKE_SECRET=opened-in-a-real-browser\n";

#[test]
#[ignore = "needs a headless Chromium, node 22 and the WASM examples: run scripts/web-browser-smoke.sh"]
fn a_real_browser_enrolls_signs_in_signs_out_and_shows_a_secret() {
    let chromium = std::env::var("VEIL_CHROMIUM").expect("VEIL_CHROMIUM (run scripts/web-browser-smoke.sh)");
    let hub = TestHub::start();
    let alice = hub.person("alice");
    let proj = unique("browser");
    let dir = alice.dir("b");
    std::fs::create_dir_all(&dir).unwrap();
    alice.ok(&dir, &["init"]);
    alice.ok(&dir, &["remote", "add", "origin", &hub.url(&proj)]);
    write_files(&dir, &[("public/hello.txt", &format!("{PUBLIC_TEXT}\n")), (".env", SECRET_TEXT)]);
    alice.commit_main(&dir, "a public file and a secret");
    alice.ok(&dir, &["push"]);
    alice.ok(&dir, &["access", "public/", "public"]);
    catch_up(&hub, &proj);
    // The secret is in the project, sealed.
    let listed = hub.api().get(Some(&alice.token()), &format!("/v1/projects/{proj}/q/file?rev=main&path=.env"));
    assert_eq!(listed.status, 200, "{}", String::from_utf8_lossy(&listed.body));
    assert!(listed.body.starts_with(b"veil:sea"), "the secret is not sealed on the server");
    assert!(!String::from_utf8_lossy(&listed.body).contains("opened-in-a-real-browser"));

    // `vl` as Alice, for the script: the same environment `Person::command` gives.
    let vl = alice.command(&dir, &[]);
    let out = Command::new("node")
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/../../scripts/web-browser-smoke.mjs"))
        .envs(vl.get_envs().filter_map(|(k, v)| Some((k, v?))))
        .env("VEIL_CHROMIUM", &chromium)
        // WebAuthn's relying party is a host name, never an IP address.
        .env("VEIL_SMOKE_ORIGIN", format!("https://localhost:{}", hub.authority().rsplit(':').next().unwrap()))
        .env("VEIL_SMOKE_PROJECT", &proj)
        .env("VEIL_SMOKE_PERSON", &alice.name)
        .env("VEIL_SMOKE_REPO", &dir)
        .env("VEIL_SMOKE_VL", vl_bin())
        .env("VEIL_SMOKE_PUBLIC_TEXT", PUBLIC_TEXT)
        .env("VEIL_SMOKE_SECRET_TEXT", SECRET_TEXT)
        .output()
        .expect("node (22 or later) runs the smoke script");
    let (stdout, stderr) = (String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    println!("{stdout}");
    assert!(out.status.success(), "the browser smoke failed:\n{stdout}\n{stderr}");
    // Every step ran, the ones with secrets too: this Chromium's virtual
    // authenticator has PRF.
    for step in [
        "ok: the browser speaks HTTP/2 to the server",
        "ok: enrolled a passkey with a vl web code (with PRF",
        "ok: \"Your devices\" and vl identity list show the passkey",
        "ok: opened a file page",
        "ok: signed out: the session is over",
        "ok: signed in again with the passkey",
        "ok: browser secrets on; the browser device confirmed from vl",
        "ok: \"Show secret\" decrypted the secret in the Worker",
        "ok: after signing out and in again, \"Show secret\" still works",
        "ok: \"Remove this browser\": the passkey no longer signs in",
        "ok: the whole smoke, with secrets",
    ] {
        assert!(stdout.contains(step), "the step `{step}` did not run:\n{stdout}\n{stderr}");
    }
}
