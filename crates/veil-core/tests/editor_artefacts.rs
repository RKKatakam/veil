//! BUG-098: editor swap, backup and lock files of protected files take
//! their protection (`policy::editor_artefact`), whatever editor wrote them
//! and at any depth, and editor scratch files are never recorded as public.

mod adversarial_support;

use std::sync::Arc;

use adversarial_support::*;
use veil_core::{object::Visibility, policy::POLICY_FILE, remote, MemoryBackend, StorageBackend};

const KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBGqZt3YkVvQ2mR8sXlN0pWcF4hTj7uK9eAoD1bLyS6xQAAAJgVb1oKFW9a
-----END OPENSSH PRIVATE KEY-----
";

/// Text no scanner rule matches: only the policy protects it.
const NOTE: &str = "the acquisition closes on friday; tell nobody\n";

/// Every editor pattern, for base `base` in directory `dir`.
fn artefacts(dir: &str, base: &str) -> Vec<String> {
    let at = |n: String| match dir {
        "" => n,
        d => format!("{d}/{n}"),
    };
    let dotted = base.strip_prefix('.').unwrap_or(base);
    [
        format!(".{dotted}.swp"),
        format!(".{dotted}.swo"),
        format!(".{dotted}.swn"),
        format!(".{dotted}.un~"),
        format!(".{dotted}.kate-swp"),
        format!("{base}~"),
        format!("{base}.~3~"),
        format!("#{base}#"),
        format!(".#{base}"),
        format!("{base}___jb_tmp___"),
        format!("{base}___jb_old___"),
        format!(".~lock.{base}#"),
        format!("{base}.orig"),
        format!("{base}.bak"),
        format!("{base}.tmp"),
        format!("{base}.save.1"),
        format!("{base}.bak~"),
    ]
    .into_iter()
    .map(at)
    .collect()
}

#[test]
fn artefacts_of_isolated_files_stay_local_at_any_depth() {
    let (mut repo, fs, _) = new_repo("alice");
    fs.write(&p(POLICY_FILE), b"notes/** public\nnotes/deep/er/private.md isolate\n").unwrap();
    let cases = [("", ".env", "APP_KEY=base64:Zq8vXk9mQ2vL7pR4wZt8aB3cD5eF7gH9jK1mN3pQ5sU=\n"), ("deploy", "id_ed25519", KEY), ("a/b/c", "server.pem", KEY), ("notes/deep/er", "private.md", NOTE)];
    let mut all = Vec::new();
    for (dir, base, content) in cases {
        let at = match dir {
            "" => base.to_string(),
            d => format!("{d}/{base}"),
        };
        fs.write(&p(&at), content.as_bytes()).unwrap();
        for a in artefacts(dir, base) {
            fs.write(&p(&a), content.as_bytes()).unwrap();
            all.push(a);
        }
    }
    fs.write(&p("README"), b"hi\n").unwrap();
    let out = repo.snapshot_workspace(WS, &*fs).unwrap();
    let s = out.snapshot;
    for a in &all {
        assert!(file_entry(&repo, &s, a).is_none(), "{a} was recorded");
        assert!(out.report.isolated.contains(&p(a)), "{a} is not listed as local-only: {:?}", out.report.isolated);
    }
    let main = repo.commit_working_copy(WS, "notes").unwrap().0;
    repo.set_tag("main", main, None, false).unwrap();
    let mirror = Arc::new(MemoryBackend::new());
    remote::push(&mut repo, mirror.clone(), true, &["main".to_string()], false).unwrap();
    for needle in ["QyNTUxOQAAACBGqZt3YkVvQ2mR8sXlN0pWcF4hTj7uK9eAoD1bLyS6xQ", "acquisition closes", "Zq8vXk9mQ2vL7pR4"] {
        assert!(backend_contains(&*mirror, needle.as_bytes()).is_empty(), "{needle} reached the mirror");
    }
}

#[test]
fn artefacts_of_cloaked_files_keep_the_scope() {
    let (mut repo, fs, _) = new_repo("alice");
    fs.write(&p(POLICY_FILE), b"plans/ cloak team\n").unwrap();
    fs.write(&p("plans/q3/launch.md"), NOTE.as_bytes()).unwrap();
    // Backup copies are recorded under the same scope.
    for a in ["plans/q3/launch.md.orig", "plans/q3/launch.md.bak", "plans/q3/launch.md.tmp"] {
        fs.write(&p(a), NOTE.as_bytes()).unwrap();
    }
    // Scratch files are not recorded at all.
    for a in ["plans/q3/.launch.md.swp", "plans/q3/launch.md~", "plans/q3/#launch.md#"] {
        fs.write(&p(a), NOTE.as_bytes()).unwrap();
    }
    let s = snap(&mut repo, &*fs);
    for a in ["plans/q3/launch.md", "plans/q3/launch.md.orig", "plans/q3/launch.md.bak", "plans/q3/launch.md.tmp"] {
        let e = file_entry(&repo, &s, a).unwrap_or_else(|| panic!("{a} missing"));
        assert_eq!(e.visibility, Visibility::Cloaked { scope: "team".into() }, "{a}");
    }
    for a in ["plans/q3/.launch.md.swp", "plans/q3/launch.md~", "plans/q3/#launch.md#"] {
        assert!(file_entry(&repo, &s, a).is_none(), "{a} was recorded");
    }
    // A rule naming scratch files publishes those of public files, not those
    // of cloaked ones: they keep the base's scope.
    fs.write(&p(POLICY_FILE), b"plans/ cloak team\n*.sw? public!\n*~ public!\n").unwrap();
    fs.write(&p("src/.main.rs.swp"), b"fn main() {}\0").unwrap();
    let s = snap(&mut repo, &*fs);
    assert_eq!(file_entry(&repo, &s, "src/.main.rs.swp").unwrap().visibility, Visibility::Public);
    for a in ["plans/q3/.launch.md.swp", "plans/q3/launch.md~"] {
        let e = file_entry(&repo, &s, a).unwrap_or_else(|| panic!("{a} missing"));
        assert_eq!(e.visibility, Visibility::Cloaked { scope: "team".into() }, "{a}");
    }
}

#[test]
fn scratch_files_of_public_files_are_ignored() {
    let (mut repo, fs, _) = new_repo("alice");
    fs.write(&p(POLICY_FILE), b"** public\n").unwrap();
    for a in ["src/main.rs", "src/.main.rs.swp", "src/main.rs~", "src/#main.rs#", "src/main.rs___jb_old___", "src/main.rs.orig"] {
        fs.write(&p(a), b"fn main() {}\n").unwrap();
    }
    let s = snap(&mut repo, &*fs);
    for a in ["src/.main.rs.swp", "src/main.rs~", "src/#main.rs#", "src/main.rs___jb_old___"] {
        assert!(file_entry(&repo, &s, a).is_none(), "{a} was recorded");
    }
    assert!(file_entry(&repo, &s, "src/main.rs").is_some());
    assert!(file_entry(&repo, &s, "src/main.rs.orig").is_some(), "a backup copy of a public file is an ordinary file");
}

/// The swap file of an isolated file is caught by name, and also by the
/// scanner, which reads NUL-separated text (lines last to first, as Vim
/// stores them) as defence in depth.
#[test]
fn the_scanner_finds_a_key_in_a_vim_swap_file() {
    let mut swap = b"b0VIM 9.1".to_vec();
    swap.resize(4096, 0);
    for line in KEY.lines().rev() {
        swap.extend_from_slice(line.as_bytes());
        swap.push(0);
    }
    let f = veil_core::secrets::scan(&swap);
    assert!(f.iter().any(|f| f.rule == "private-key"), "{f:?}");
}

/// The accepted policy pins artefacts too: an incoming `.veilpolicy` that
/// would publish the swap file of the member's key is held back.
#[test]
fn an_incoming_policy_cannot_publish_an_artefact() {
    let (mut repo, fs, _) = new_repo("alice");
    fs.write(&p("deploy/id_ed25519"), KEY.as_bytes()).unwrap();
    let main = commit_files(&mut repo, &*fs, &[("README", "hi\n")], "v1");
    let ws = repo.ephemeral_workspace(main).unwrap();
    ws.write(POLICY_FILE, "*.swp public!\n*.bak public!\n").unwrap();
    let pr = repo.commit_ephemeral(&ws, "incoming").unwrap().0;
    let old = repo.snapshot(&repo.workspace_wc(WS).unwrap()).unwrap().tree;
    let wc = repo.new_change(WS, vec![pr], "").unwrap();
    let new = repo.snapshot(&wc).unwrap().tree;
    repo.checkout_tree(&*fs, Some(&old), &new).unwrap();
    fs.write(&p("deploy/.id_ed25519.swp"), KEY.as_bytes()).unwrap();
    fs.write(&p("src/.main.rs.swp"), b"fn main() {}\0").unwrap();
    let out = repo.snapshot_workspace(WS, &*fs).unwrap();
    assert!(file_entry(&repo, &out.snapshot, "deploy/.id_ed25519.swp").is_none());
    let held: Vec<&str> = out.report.policy_held_back.iter().map(|h| h.path.as_str()).collect();
    assert!(held.contains(&"src/.main.rs.swp"), "lifting the scratch rule is a weakening: {held:?}");
    assert!(file_entry(&repo, &out.snapshot, "src/.main.rs.swp").is_none());
}
