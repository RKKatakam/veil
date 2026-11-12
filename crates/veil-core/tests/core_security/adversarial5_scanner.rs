//! Round-5 adversarial tests: scanner v3 (`secrets.rs`, `RULES_VERSION` 3),
//! and the scanner v6 rules (`RULES_VERSION` 6).
//!
//! Every `#[ignore = "BUG-NNN: …"]` test asserts the secure behaviour and
//! currently fails; see `docs/BUGS.md` ("Round 5 findings"). The documented
//! known misses (word-only passphrases, weak passwords, XML attributes,
//! camelCase generic tokens, URL passwords that are words or numbers) are
//! not reported again.
//!
//! The false-positive measurement on real code is
//! `VEIL_FP_DIR=~/.cargo/registry/src cargo test --release -p veil-core
//! --test core_security -- --ignored --nocapture
//! adversarial5_scanner::scanner_false_positive_rate`.

use std::{sync::mpsc, thread, time::Duration};

use veil_core::secrets::scan;

/// Small deterministic generator (xorshift64), so failures reproduce.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn pick(&mut self, set: &[u8]) -> u8 {
        set[(self.next() % set.len() as u64) as usize]
    }
}

fn found(data: &[u8]) -> bool {
    !scan(data).is_empty()
}

fn utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
}

fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Runs `scan` on another thread and gives up after `limit`.
fn scan_within(data: Vec<u8>, limit: Duration) -> Option<Duration> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let t = std::time::Instant::now();
        scan(&data);
        let _ = tx.send(t.elapsed());
    });
    rx.recv_timeout(limit).ok()
}

// ---------------------------------------------------------------------------
// BUG-090: quadratic scanning time
// ---------------------------------------------------------------------------

/// Control: ordinary text of the same size scans in milliseconds.
#[test]
fn ordinary_text_scans_quickly() {
    let data = "let token = compute(x);\n".repeat((256 << 10) / 24).into_bytes();
    assert!(scan_within(data, Duration::from_secs(10)).is_some());
}

/// When a candidate match is rejected because of the byte before it
/// (`Edge::Alnum`) or because its key is not a credential, `search_with`
/// restarts the search one byte after the *start* of the rejected match
/// (`at = whole.start() + 1`). Unbounded token patterns
/// (`github_pat_[A-Za-z0-9_]{60,}`, `sk-…{32,}`, `glpat-…{20,}`) and the
/// unquoted assignment value (`[…=:…]{12,}`) can contain their own prefix,
/// so a run like `xgithub_pat_xgithub_pat_…` yields one rejected match per
/// repetition, each as long as the rest of the run, and their capture
/// groups are computed every time. The token pass is not chunked, so the
/// cost is quadratic in the file size: 64 KiB takes ~14 s in a release
/// build, 1 MiB about an hour. Every snapshot (`vl status`, `vl commit`)
/// and `vl scan` in CI stalls on one such public file.
#[test]
fn crafted_token_runs_do_not_make_the_scanner_quadratic() {
    for (name, unit) in [("github_pat", "xgithub_pat_"), ("openai", "xsk-"), ("assignment", "xtoken=")] {
        let data = unit.repeat((256 << 10) / unit.len()).into_bytes();
        assert!(
            scan_within(data, Duration::from_secs(10)).is_some(),
            "{name}: scanning 256 KiB of `{unit}…` took more than 10 s"
        );
    }
}

// ---------------------------------------------------------------------------
// BUG-091: strong random passwords
// ---------------------------------------------------------------------------

const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

type Format = (&'static str, fn(&str) -> String);

/// Realistic places a generated password is pasted, each with the escaping
/// that file format requires.
const FORMATS: &[Format] = &[
    ("dotenv", |p| format!("DB_PASSWORD=\"{}\"\n", json_escape(p))),
    ("yaml", |p| format!("database:\n  host: db.internal\n  password: '{}'\n", p.replace('\'', "''"))),
    ("json", |p| format!("{{\n  \"user\": \"app\",\n  \"api_key\": \"{}\"\n}}\n", json_escape(p))),
    ("properties", |p| format!("spring.datasource.url=jdbc:postgresql://db/app\nspring.datasource.password={p}\n")),
];

/// Fraction of `n` random passwords (from `set`, `len` long) that the
/// scanner misses in each format, plus a few examples.
fn miss_rate(seed: u64, set: &[u8], len: usize, n: usize) -> Vec<(&'static str, f64, Vec<String>)> {
    let mut r = Rng(seed);
    FORMATS
        .iter()
        .map(|(name, fmt)| {
            let mut missed = Vec::new();
            for _ in 0..n {
                let pw: String = (0..len).map(|_| r.pick(set) as char).collect();
                if !found(fmt(&pw).as_bytes()) {
                    missed.push(pw);
                }
            }
            let rate = missed.len() as f64 / n as f64;
            missed.truncate(3);
            (*name, rate, missed)
        })
        .collect()
}

/// Control: 24-character random alphanumeric passwords are always found.
#[test]
fn long_random_alphanumeric_passwords_are_found() {
    for (fmt, rate, ex) in miss_rate(0x5eed_0001, ALNUM, 24, 500) {
        assert_eq!(rate, 0.0, "{fmt}: missed {ex:?}");
    }
}

/// Passwords from a password manager with symbols switched on. Not weak,
/// not words: 16 to 24 random characters. Three heuristics drop them:
///
/// * `plausible_value` rejects any value that *starts* with `$ % & * @ <
///   {` or contains `${`, `{{`, `#{`, `%(` (taken for references): about
///   1 in 13 passwords drawn from `A-Za-z0-9!@#$%^&*`;
/// * the quoted value class `[!#-&(-~\x80-\xff]` excludes `"`, `'` and
///   space, so a password containing a (correctly escaped) quote is not a
///   match at all;
/// * the unquoted value class excludes `, ; ( ) [ ] { } < > ' " \` and
///   backquote and must be followed by a terminator, so most passwords with
///   symbols in a `.properties` file are missed.
///
/// Measured miss rates (2,000 passwords per cell): `A-Za-z0-9!@#$%^&*`:
/// 6–8 % in every format; all printable ASCII: ~28 % in dotenv/YAML/JSON
/// and ~90 % in `.properties`. Even 16 random alphanumerics are missed
/// ~0.6 % of the time (a mixed-case run with no two capitals in a row is a
/// "camelCase word"), and a Google app password (16 random lower-case
/// letters) always is.
#[test]
fn strong_random_passwords_are_found() {
    let symbols: Vec<u8> = [ALNUM, b"!@#$%^&*"].concat();
    let printable: Vec<u8> = (0x21u8..=0x7e).collect();
    let mut report = Vec::new();
    for (set_name, set) in [("A-Za-z0-9!@#$%^&*", &symbols[..]), ("printable ASCII", &printable[..])] {
        for len in [16, 24] {
            for (fmt, rate, ex) in miss_rate(0x5eed_0002 ^ len as u64, set, len, 400) {
                if rate > 0.0 {
                    report.push(format!("{set_name} len {len} in {fmt}: {:.1}% missed, e.g. {ex:?}", rate * 100.0));
                }
            }
        }
    }
    for (what, line) in [
        ("leading `$`", "DB_PASSWORD=\"$Xk9mQ2vL7pR4wZt8\"\n"),
        ("leading `@`", "password: '@Xk9mQ2vL7pR4wZt8'\n"),
        ("contains `%(`", "password = \"Xk9m%(Q2vL7pR4wZt8\"\n"),
        ("escaped quote", "{\"password\": \"Xk9\\\"mQ2vL7pR4wZt8\"}\n"),
        ("Google app password", "SMTP_PASSWORD=qzvxkwprmtfhjlnb\n"),
    ] {
        if !found(line.as_bytes()) {
            report.push(format!("{what}: {line:?} missed"));
        }
    }
    assert!(report.is_empty(), "strong passwords missed:\n{}", report.join("\n"));
}

// ---------------------------------------------------------------------------
// BUG-092: credential keys the assignment rule does not see
// ---------------------------------------------------------------------------

/// Control: the documented shapes.
#[test]
fn documented_assignment_shapes_are_found() {
    for line in [
        "DB_PASSWORD=Xk9mQ2vL7pR4wZt8\n",
        "'password' => 'Xk9mQ2vL7pR4wZt8',\n",
        "\"Server=db;User Id=sa;Password=Xk9mQ2vL7pR4wZt8;\"\n",
        "<password>Xk9mQ2vL7pR4wZt8</password>\n",
        "headers = {\"X-Api-Key\": \"Xk9mQ2vL7pR4wZt8\"}\n",
    ] {
        assert!(found(line.as_bytes()), "{line:?}");
    }
}

/// The assignment rule needs the separator (`=`, `:`, `:=`, `=>`, `>`)
/// right after the keyword, an optional quote and up to three suffix
/// words. Very common shapes put a quote *and* `,` / `]` / a call between
/// the key and the value, or a digit or plural `s` after the keyword, and
/// are never matched. WordPress's `wp-config.php` (`define( 'DB_PASSWORD',
/// '…' )`) is the classic leaked file; it is missed, as are its eight
/// `AUTH_KEY`/`…_SALT` secrets. `key` alone is no keyword, so
/// `APP_KEY` (Laravel), `RAILS_MASTER_KEY` and `ENCRYPTION_KEY` never count.
#[test]
fn common_credential_shapes_are_found() {
    let cases = [
        ("wp-config.php", "define( 'DB_PASSWORD', 'Xk9mQ2vL7pR4wZt8' );\n"),
        ("wp-config.php salt", "define('AUTH_KEY', 'q8|Zp]x%Wc+Ly~Bv&Hn4Rt7Dj2Mk9Gs5Ef1Aw6Uz');\n"),
        ("python environ", "os.environ[\"API_KEY\"] = \"Xk9mQ2vL7pR4wZt8\"\n"),
        ("js index", "config['password'] = 'Xk9mQ2vL7pR4wZt8';\n"),
        ("ruby ENV.fetch", "ENV.fetch('SECRET_KEY', 'Xk9mQ2vL7pR4wZt8')\n"),
        ("java property", "System.setProperty(\"db.password\", \"Xk9mQ2vL7pR4wZt8\");\n"),
        ("kubernetes env", "env:\n  - name: DB_PASSWORD\n    value: \"Xk9mQ2vL7pR4wZt8\"\n"),
        ("numbered key", "PASSWORD2=Xk9mQ2vL7pR4wZt8\n"),
        ("plural key", "API_KEYS=\"Xk9mQ2vL7pR4wZt8\"\n"),
        ("four suffix words", "DB_PASSWORD_PROD_EU_WEST_1=Xk9mQ2vL7pR4wZt8\n"),
        ("XML element with an attribute", "<password type=\"plain\">Xk9mQ2vL7pR4wZt8</password>\n"),
        ("XML CDATA", "<password><![CDATA[Xk9mQ2vL7pR4wZt8]]></password>\n"),
        ("plist", "<key>Password</key>\n<string>Xk9mQ2vL7pR4wZt8</string>\n"),
        ("SQL", "ALTER USER app WITH PASSWORD 'Xk9mQ2vL7pR4wZt8';\n"),
        ("Laravel APP_KEY", "APP_KEY=base64:Zq8vXk9mQ2vL7pR4wZt8aB3cD5eF7gH9jK1mN3pQ5sU=\n"),
        ("Rails master key", "RAILS_MASTER_KEY=9f86d081884c7d659a2feaa0c55ad015\n"),
        ("encryption key", "ENCRYPTION_KEY: \"Zq8vXk9mQ2vL7pR4wZt8aB3c\"\n"),
    ];
    let missed: Vec<_> = cases.iter().filter(|(_, c)| !found(c.as_bytes())).map(|(n, c)| format!("{n}: {c:?}")).collect();
    assert!(missed.is_empty(), "{} of {} shapes missed:\n{}", missed.len(), cases.len(), missed.join("\n"));
}

// ---------------------------------------------------------------------------
// BUG-093: URL passwords
// ---------------------------------------------------------------------------

/// Control.
#[test]
fn url_passwords_in_the_documented_form_are_found() {
    assert!(found(b"DATABASE_URL=postgres://app:Xk9mQ2vL7pR4@db.example.com/app\n"));
    assert!(found(b"DATABASE_URL=postgres://app:Xk9%21mQ2vL7@db.example.com/app\n"));
}

/// The URL rule is matched from the literal `://` and its password class
/// excludes `:`; `plausible_url_password` takes a leading `%` for a
/// reference. So:
///
/// * a password whose first character is special (and so, as RFC 3986
///   requires, percent-encoded: `!` → `%21`) is never reported;
/// * JSON written by PHP's `json_encode` (and others) escapes `/` as `\/`,
///   so `postgres:\/\/…` has no `://`;
/// * userinfo may contain more `:` (the password is everything after the
///   first), e.g. `redis://:Xk9mQ2:vL7pR4wZ@cache`;
/// * a user name longer than 64 characters (`{0,64}`) hides the password.
#[test]
fn url_password_variants_are_found() {
    let long_user = format!("U=https://{}:Xk9mQ2vL7pR4@h.example.com\n", "service-account-for-the-nightly-build-in-region-eu-west-1-x");
    let cases = [
        ("percent-encoded first character", "DATABASE_URL=postgres://app:%21Xk9mQ2vL7@db.example.com/app\n".to_string()),
        ("JSON with \\/ escapes", "{\"database_url\":\"postgres:\\/\\/app:Xk9mQ2vL7pR4@db.example.com\\/app\"}\n".to_string()),
        ("':' inside the password", "REDIS_URL=redis://:Xk9mQ2:vL7pR4wZ@cache.internal:6379\n".to_string()),
        ("long user name", long_user),
    ];
    let missed: Vec<_> = cases.iter().filter(|(_, c)| !found(c.as_bytes())).map(|(n, c)| format!("{n}: {c:?}")).collect();
    assert!(missed.is_empty(), "missed:\n{}", missed.join("\n"));
}

// ---------------------------------------------------------------------------
// BUG-094: UTF-16 / UTF-32 text in CJK scripts
// ---------------------------------------------------------------------------

fn with_bom(s: &str) -> Vec<u8> {
    let mut d = vec![0xff, 0xfe];
    d.extend(utf16le(s));
    d
}

/// Control: the same text in UTF-8, and in UTF-16 with a space before the
/// token, is found.
#[test]
fn cjk_text_before_a_token_is_found_in_utf8_and_spaced_utf16() {
    assert!(found("アクセスキーAKIAIOSFODNN7EXAMPLE\n".as_bytes()));
    assert!(found("令牌ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ\n".as_bytes()));
    assert!(found(&with_bom("アクセスキー AKIAIOSFODNN7EXAMPLE\r\n")));
}

/// The NUL-padded pass deletes NUL bytes instead of decoding, so the
/// non-NUL byte of a neighbouring non-ASCII code unit becomes an "ASCII"
/// neighbour of the token. In UTF-16LE that byte is the high byte: `0`–`9`
/// for kana (U+30xx–U+39xx), `N`–`Z` and `a`–`z` for about half the CJK
/// ideographs (U+4Exx–U+5Axx, U+61xx–U+7Axx). The token-boundary check
/// (`Edge::Alnum`, `Edge::UpperDigit`) then rejects the token. CJK text
/// does not put spaces between words and Latin tokens (`令牌ghp_…`), and
/// Windows tools write UTF-16LE (Notepad "Unicode", Excel "Unicode text",
/// PowerShell 5 `>` redirection). UTF-32 has the same problem.
#[test]
fn cjk_text_glued_to_a_token_in_utf16_is_found() {
    let mut missed = Vec::new();
    for s in ["アクセスキーAKIAIOSFODNN7EXAMPLE\r\n", "令牌ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ\r\n"] {
        if !found(&with_bom(s)) {
            missed.push(format!("UTF-16LE with BOM: {s:?}"));
        }
        if !found(&utf16le(&format!("{}{s}", "設定ファイル\r\n".repeat(4)))) {
            missed.push(format!("UTF-16LE without BOM: {s:?}"));
        }
        let utf32: Vec<u8> = s.chars().flat_map(|c| (c as u32).to_le_bytes()).collect();
        if !found(&utf32) {
            missed.push(format!("UTF-32LE: {s:?}"));
        }
    }
    assert!(missed.is_empty(), "missed:\n{}", missed.join("\n"));
}

// ---------------------------------------------------------------------------
// BUG-095: a service-account key inside binary data
// ---------------------------------------------------------------------------

const GCP_KEY: &str = r#"{
  "type": "service_account",
  "project_id": "prod-billing",
  "private_key_id": "3f1c9a7e2b8d4f6a0c5e9b1d7a3f8c2e6b4d0a9f",
  "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj\nMzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu\n-----END PRIVATE KEY-----\n",
  "client_email": "billing@prod-billing.iam.gserviceaccount.com"
}
"#;

/// A minimal ustar header for one file (512 bytes, NUL-padded).
fn tar_header(name: &str, size: usize) -> Vec<u8> {
    let mut h = vec![0u8; 512];
    h[..name.len()].copy_from_slice(name.as_bytes());
    h[100..107].copy_from_slice(b"0000644");
    h[124..135].copy_from_slice(format!("{size:011o}").as_bytes());
    h[156] = b'0';
    h[257..262].copy_from_slice(b"ustar");
    h
}

/// Control: the key file itself is found.
#[test]
fn a_service_account_key_file_is_found() {
    assert!(found(GCP_KEY.as_bytes()));
}

/// A PEM header with NUL bytes within 256 bytes counts as "inside binary
/// data" and must be followed by a real newline and key material
/// (`pem_body_follows`). In JSON the newline is the two characters `\n`,
/// and the assignment rule cannot match `"private_key": "-----BEGIN …"`
/// (the quoted value class has no space). So a Google Cloud service-account
/// key is missed as soon as it sits in an uncompressed archive (`.tar`, the
/// header's NUL padding comes right before the content), a SQLite database
/// or a core dump.
#[test]
fn a_service_account_key_inside_a_tar_is_found() {
    let mut tar = tar_header("deploy/sa.json", GCP_KEY.len());
    tar.extend_from_slice(GCP_KEY.as_bytes());
    tar.resize(tar.len().div_ceil(512) * 512 + 1024, 0);
    assert!(found(&tar), "service-account key in a tar archive not found");
}

// ---------------------------------------------------------------------------
// Scanner v6 (`RULES_VERSION` 6): camelCase keys and generic `<WORD>_KEY`
// ---------------------------------------------------------------------------

/// Places a random token is pasted under a key found by a v6 rule: a
/// camelCase key in JSON, YAML, a JS object, a TS property and a template
/// literal; a generic `<WORD>_KEY` in dotenv and JSON; `Pwd=` in a
/// connection string. (Tokens: no quotes or backslashes to escape.)
const V6_FORMATS: &[Format] = &[
    ("json githubToken", |p| format!("{{\n  \"githubToken\": \"{p}\"\n}}\n")),
    ("yaml stripeSecret", |p| format!("stripe:\n  stripeSecret: '{p}'\n")),
    ("js authToken", |p| format!("const c = {{ authToken: \"{p}\", retries: 3 }};\n")),
    ("ts accessKey", |p| format!("  private accessKey: string = \"{p}\";\n")),
    ("js template clientSecret", |p| format!("export const clientSecret = `{p}`;\n")),
    ("dotenv MAPBOX_KEY", |p| format!("MAPBOX_KEY={p}\n")),
    ("json SENDGRID_KEY", |p| format!("{{\"SENDGRID_KEY\": \"{p}\"}}\n")),
    ("connection string Pwd", |p| format!("<add name=\"db\" connectionString=\"Server=db;User ID=sa;Pwd={p}\" />\n")),
];

fn v6_miss_rate(seed: u64, set: &[u8], len: usize, n: usize) -> Vec<(&'static str, f64, Vec<String>)> {
    let mut r = Rng(seed);
    V6_FORMATS
        .iter()
        .map(|(name, fmt)| {
            let mut missed = Vec::new();
            for _ in 0..n {
                let pw: String = (0..len).map(|_| r.pick(set) as char).collect();
                if !found(fmt(&pw).as_bytes()) {
                    missed.push(pw);
                }
            }
            let rate = missed.len() as f64 / n as f64;
            missed.truncate(3);
            (*name, rate, missed)
        })
        .collect()
}

/// Random tokens under the v6 keys are found: the extra checks of those
/// rules (the value is not made of words) cost little. Measured over 4,000
/// tokens per cell: A-Za-z0-9 0.15–0.35 % missed at 16 characters, ≤ 0.1 %
/// at 20, 0 at 32; base64url ≤ 0.03 % at 24; hex 0; upper-case and digits
/// only (held to looser bars) up to 1.3 % at 20 and 0.25 % at 32. The
/// legacy keys (`authToken`, `clientSecret`) miss nothing.
#[test]
fn random_tokens_under_v6_keys_are_found() {
    let hex = b"0123456789abcdef";
    let upnum = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let b64url = [ALNUM, b"-_"].concat();
    let mut report = Vec::new();
    for (set_name, set, len, bar) in [
        ("A-Za-z0-9", ALNUM, 16, 0.01),
        ("A-Za-z0-9", ALNUM, 20, 0.0025),
        ("A-Za-z0-9", ALNUM, 32, 0.0025),
        ("base64url", &b64url[..], 24, 0.0025),
        ("hex", &hex[..], 32, 0.0),
        ("hex", &hex[..], 40, 0.0),
        ("A-Z0-9", &upnum[..], 20, 0.02),
        ("A-Z0-9", &upnum[..], 32, 0.005),
    ] {
        for (fmt, rate, ex) in v6_miss_rate(0x5eed_0600 ^ len as u64 ^ set.len() as u64, set, len, 4000) {
            println!("{set_name} len {len} in {fmt}: {:.3}% missed", rate * 100.0);
            if rate > bar {
                report.push(format!("{set_name} len {len} in {fmt}: {:.2}% missed (bar {:.2}%), e.g. {ex:?}", rate * 100.0, bar * 100.0));
            }
        }
    }
    assert!(report.is_empty(), "random tokens missed:\n{}", report.join("\n"));
}

// ---------------------------------------------------------------------------
// False-positive measurement (not a bug test)
// ---------------------------------------------------------------------------

/// Scans every file under `$VEIL_FP_DIR` and prints the flagged files and
/// the rate. Round 5 on `~/.cargo/registry/src` (329 crates, 12,941 files,
/// 155 MiB): 22 files flagged (0.17 %); 13 of them hold real test or doc
/// private keys, leaving 9 files (0.07 %) of genuine false positives
/// (`windows-sys` constant types such as `D3DVSD_TOKENTYPE`, a URL
/// crate's test URLs).
#[test]
#[ignore = "measurement: VEIL_FP_DIR=<dir>"]
fn scanner_false_positive_rate() {
    let Ok(dir) = std::env::var("VEIL_FP_DIR") else { return };
    let mut stack = vec![std::path::PathBuf::from(dir)];
    let (mut files, mut flagged) = (0usize, 0usize);
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap().flatten() {
            let ft = e.file_type().unwrap();
            if ft.is_dir() {
                stack.push(e.path());
            } else if ft.is_file() {
                let Ok(data) = std::fs::read(e.path()) else { continue };
                files += 1;
                let f = scan(&data);
                if !f.is_empty() {
                    flagged += 1;
                    for x in f {
                        println!("finding: {} {}:{} {}", x.rule, e.path().display(), x.line, x.excerpt);
                    }
                }
            }
        }
    }
    println!("{files} files, {flagged} flagged ({:.3} %)", 100.0 * flagged as f64 / files.max(1) as f64);
}

/// BUG-1985: random binary data (compressed, encrypted or random files) is
/// not a URL with a password. These 68 bytes come from a 12 MiB file of
/// random bytes (`daemon::the_daemons_memory_stays_within_its_budget`'s
/// kind, BUG-1980): `://`, then any bytes but the rule's few excluded ones,
/// a `:`, eight or more bytes, `@` and a letter. About one such file in
/// 1,400 matches (11 of 15,000 measured), and the file is quarantined:
/// kept local, reported, never recorded.
#[test]
fn bug_1985_random_bytes_are_not_a_url_password() {
    let hex = "155a96f6c76843cd3a2f2f641a8342768e7eb7e79503483a8cd60489138f0eb0b130f3d453dc588a3d8494aaa6b32e51c4d1f3fedf934db59ef3043894d493dd40732df5";
    let bytes: Vec<u8> = (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect();
    assert_eq!(bytes.len(), 68);
    let found = scan(&bytes);
    assert!(found.is_empty(), "random bytes taken for a secret: {:?}", found.iter().map(|f| f.rule).collect::<Vec<_>>());
}

/// The URL rule's findings in `data`.
fn url_passwords(data: &[u8]) -> usize {
    scan(data).iter().filter(|f| f.rule == "url-password").count()
}

/// BUG-1985 control: the URL passwords the rule exists for are still found
/// in every form a file holds them: ASCII and UTF-8 text, a Latin-1 file,
/// UTF-16, the start and end of a file, a long line, JSON (and its `\/`
/// escapes), YAML, TOML, `.env`, CRLF line ends, and a URL compiled into a
/// binary between NUL bytes and random data.
#[test]
fn bug_1985_url_passwords_in_files_are_still_found() {
    let url = "postgres://app:Xk9mQ2vL7pR4@db.example.com:5432/app";
    let mut random = Rng(0x1985);
    let noise = |n: usize, rng: &mut Rng| -> Vec<u8> { (0..n).map(|_| rng.next() as u8).collect() };
    let mut binary = b"\x7fELF\x02\x01\x01\0\0\0\0\0\0\0\0\0".to_vec();
    binary.extend(noise(4096, &mut random));
    binary.extend(b"\0\0\0");
    binary.extend(url.as_bytes());
    binary.extend(b"\0\0");
    binary.extend(noise(4096, &mut random));
    let mut long_line = "x".repeat(200_000);
    long_line.push_str(&format!(" {url} "));
    long_line.push_str(&"y".repeat(200_000));
    let cases: Vec<(&str, Vec<u8>)> = vec![
        (".env", format!("PORT=8080\nDATABASE_URL={url}\nDEBUG=0\n").into()),
        (".env, CRLF", format!("PORT=8080\r\nDATABASE_URL={url}\r\nDEBUG=0\r\n").into()),
        ("start of the file", url.into()),
        ("end of the file, no newline", b"# config\nREDIS=redis://:Xk9mQ2vL7pR4wZ@c".to_vec()),
        ("only the URL, host of one letter", b"amqp://svc:Zt8nB3cXk9mQ2vL7@m".to_vec()),
        ("long line", long_line.into()),
        ("JSON", format!("{{\"db\": {{\"url\": \"{url}\", \"pool\": 5}}}}\n").into()),
        ("JSON with \\/ escapes", b"{\"url\":\"mongodb+srv:\\/\\/svc:Zt8nB3cXk9mQ2vL7@cluster0.example.net\\/app\"}\n".to_vec()),
        ("YAML", b"database:\n  url: \"amqps://svc:Zt8nB3cXk9mQ2vL7@mq.example.com:5671\"\n".to_vec()),
        ("YAML, CRLF", b"database:\r\n  url: amqps://svc:Zt8nB3cXk9mQ2vL7@mq.example.com:5671\r\n".to_vec()),
        ("TOML", b"[database]\nurl = \"mysql://root:Xk9mQ2vL7pR4@127.0.0.1:3306/app\"\n".to_vec()),
        ("a percent-encoded user", b"git clone https://deploy%40corp:s3cr3tP4ssw0rd@git.example.com/r.git\n".to_vec()),
        ("an IPv6 host", b"U=postgres://app:Xk9mQ2vL7pR4@[::1]:5432/app\n".to_vec()),
        ("UTF-8 text around", format!("# Datenbank für die Produktion — prüfen ✓\nDATABASE_URL={url}\n# 数据库\n").into()),
        ("a UTF-8 password", "DATABASE_URL=postgres://app:Pässwört-X9k2q@db.example.com/app\n".into()),
        ("a UTF-8 user", "DATABASE_URL=postgres://jürgen:Xk9mQ2vL7pR4@db.example.com/app\n".into()),
        ("Latin-1 text around", b"# Datenbank f\xfcr die Produktion\nDATABASE_URL=postgres://app:Xk9mQ2vL7pR4@db\n".to_vec()),
        ("a Latin-1 password", b"# Datenbank f\xfcr die Produktion\nDATABASE_URL=postgres://app:P\xe4\xdfwort-X9k2q@db\n".to_vec()),
        ("UTF-16LE with a BOM", with_bom(&format!("DATABASE_URL={url}\r\n"))),
        ("compiled into a binary", binary),
    ];
    for (name, data) in &cases {
        assert_eq!(url_passwords(data), 1, "{name}: {:?}", scan(data).iter().map(|f| f.rule).collect::<Vec<_>>());
    }
}

/// BUG-1985: seeded random buffers with `://` planted every 256 to 767
/// bytes (once in two right after a scheme letter), so that the rest of a
/// URL is random bytes: none is taken for a URL password. Before the fix
/// the rule matched about once per 1,000 of these `://`, so this run of
/// about 25,000 found some 25.
#[test]
fn bug_1985_random_buffers_hold_no_url_password() {
    let mut rng = Rng(0x5eed_1985);
    let mut planted = 0;
    for i in 0..48 {
        let mut data: Vec<u8> = (0..256 << 10).map(|_| rng.next() as u8).collect();
        let mut at = 0;
        loop {
            at += 256 + (rng.next() % 512) as usize;
            if at + 3 > data.len() {
                break;
            }
            data[at..at + 3].copy_from_slice(b"://");
            if planted % 2 == 0 {
                data[at - 1] = rng.pick(b"abcdefghijklmnopqrstuvwxyz0123456789");
            }
            planted += 1;
        }
        let found = scan(&data);
        assert!(found.is_empty(), "buffer {i}: {:?}", found.iter().map(|f| f.rule).collect::<Vec<_>>());
    }
    assert!(planted > 20_000, "{planted}");
    // And buffers of plain random bytes, the reproduction's kind.
    for i in 0..8 {
        let data: Vec<u8> = (0..1 << 20).map(|_| rng.next() as u8).collect();
        assert_eq!(url_passwords(&data), 0, "plain buffer {i}");
    }
}
