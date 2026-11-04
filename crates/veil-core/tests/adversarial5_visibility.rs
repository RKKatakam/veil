//! Round-5 adversarial tests: what the automatic snapshot records next to
//! isolated files.
//!
//! Every `#[ignore = "BUG-NNN: …"]` test asserts the secure behaviour and
//! currently fails; see `docs/BUGS.md` ("Round 5 findings").

mod adversarial_support;

use std::sync::Arc;

use adversarial_support::*;
use veil_core::{remote, secrets::scan, MemoryBackend, StorageBackend};

/// An OpenSSH private key (test material, never used anywhere).
const KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBGqZt3YkVvQ2mR8sXlN0pWcF4hTj7uK9eAoD1bLyS6xQAAAJgVb1oKFW9a
ChAAAAtzc2gtZWQyNTUxOQAAACBGqZt3YkVvQ2mR8sXlN0pWcF4hTj7uK9eAoD1bLyS6xQ
-----END OPENSSH PRIVATE KEY-----
";

/// One line of key material, to look for in what was recorded.
const KEY_LINE: &str = "QyNTUxOQAAACBGqZt3YkVvQ2mR8sXlN0pWcF4hTj7uK9eAoD1bLyS6xQAAAJgVb1oKFW9a";

/// What Vim keeps next to a file it is editing (`.<name>.swp`): a binary
/// "b0VIM" block-0 header, pointer and data blocks, and the text, one
/// NUL-terminated line after another. Every `vl` command snapshots the
/// working copy, so the swap file is recorded while the editor is open.
fn vim_swap(text: &str) -> Vec<u8> {
    let mut b0 = b"b0VIM 9.1".to_vec();
    b0.resize(4096, 0);
    let mut data = b"tp".to_vec();
    data.resize(64, 0);
    data.extend_from_slice(b"ad");
    data.resize(4096, 0);
    let mut lines: Vec<u8> = text.lines().flat_map(|l| l.bytes().chain(std::iter::once(0))).collect();
    let mut block = vec![0u8; 4096 - lines.len().min(4096)];
    block.append(&mut lines);
    [b0, data, block].concat()
}

/// Control: the key itself, and a text backup (`id_ed25519~`, Emacs
/// `#id_ed25519#`), are kept out of history.
#[test]
fn the_key_and_its_text_backups_stay_local() {
    let (mut repo, fs, _) = new_repo("alice");
    fs.write(&p("deploy/id_ed25519"), KEY.as_bytes()).unwrap();
    fs.write(&p("deploy/id_ed25519~"), KEY.as_bytes()).unwrap();
    fs.write(&p("README"), b"hi\n").unwrap();
    let s = snap(&mut repo, &*fs);
    assert!(file_entry(&repo, &s, "deploy/id_ed25519").is_none());
    assert!(file_entry(&repo, &s, "deploy/id_ed25519~").is_none());
}

/// `id_ed25519` (and `*.pem`, `*.key`, or any path the user isolates) is
/// local-only, but the swap file Vim writes beside it while it is open,
/// `.id_ed25519.swp`, matches no built-in rule, so it is an ordinary public
/// file. The scanner does not catch the key in it either: the PEM header
/// sits in binary data (NUL bytes nearby), where `Check::PemHeader` needs a
/// newline and key material right after it (`pem_body_follows`,
/// `secrets.rs`), and Vim separates lines with NUL, not newline (the
/// NUL-stripped pass glues the lines together, so there is no newline
/// either). The private key enters history in plaintext and is pushed to
/// every remote, public mirrors included. The same holds for the contents
/// of any user-isolated file (`notes/private.md` → `.private.md.swp`),
/// which no scanner rule covers. Git users are protected by `git add`;
/// Veil snapshots on every command, so the window is any `vl` command run
/// (by the user or an agent) while the editor has the file open.
#[test]
#[ignore = "BUG-098: Vim swap files of isolated files (.id_ed25519.swp, .server.pem.swp) are recorded and pushed in plaintext"]
fn a_swap_file_of_an_isolated_key_is_not_recorded() {
    let (mut repo, fs, _) = new_repo("alice");
    fs.write(&p("deploy/id_ed25519"), KEY.as_bytes()).unwrap();
    fs.write(&p("deploy/.id_ed25519.swp"), &vim_swap(KEY)).unwrap();
    fs.write(&p("deploy/server.pem"), KEY.as_bytes()).unwrap();
    fs.write(&p("deploy/.server.pem.swp"), &vim_swap(KEY)).unwrap();
    fs.write(&p("README"), b"hi\n").unwrap();
    let scanned = scan(&vim_swap(KEY));
    snap(&mut repo, &*fs);
    let main = repo.commit_working_copy(WS, "deploy notes").unwrap().0;
    repo.set_tag("main", main, None, false).unwrap();

    let mirror = Arc::new(MemoryBackend::new());
    remote::push(&mut repo, mirror.clone(), true, &["main".to_string()], false).unwrap();
    let hits = backend_contains(&*mirror, KEY_LINE.as_bytes());
    assert!(
        hits.is_empty(),
        "private-key material is on the public mirror: {hits:?} (scanner findings on the swap file: {scanned:?})"
    );
}

/// The same gap for text backups of `.env`: Emacs writes `.env~` on the
/// first save of every session (by default), Vim does with `backup` set.
/// `.env~` matches neither `.env` nor `.env.*`, so it is public, and only
/// the scanner stands between `.env`'s values and history. It misses
/// common ones (`APP_KEY`, `RAILS_MASTER_KEY`, `ENCRYPTION_KEY`: `key` alone
/// is no keyword; see BUG-092), so `.env`'s content is recorded and pushed.
#[test]
#[ignore = "BUG-098: an editor backup of .env (.env~) is recorded and pushed in plaintext"]
fn an_editor_backup_of_dotenv_is_not_recorded() {
    let (mut repo, fs, _) = new_repo("alice");
    let env = "APP_KEY=base64:Zq8vXk9mQ2vL7pR4wZt8aB3cD5eF7gH9jK1mN3pQ5sU=\nRAILS_MASTER_KEY=9f86d081884c7d659a2feaa0c55ad015\n";
    fs.write(&p(".env"), env.as_bytes()).unwrap();
    fs.write(&p(".env~"), env.as_bytes()).unwrap();
    let s = snap(&mut repo, &*fs);
    assert!(file_entry(&repo, &s, ".env").is_none(), "control: .env is isolated");
    assert!(file_entry(&repo, &s, ".env~").is_none(), ".env~ (with .env's values) was recorded as a public file");
}
