//! Round-2 adversarial tests: secret-scanner bypasses in the chunked and
//! UTF-16 passes, and hostile tree names the decode rules still accept.
//!
//! Every `#[ignore = "BUG-NNN: …"]` test asserts the secure behaviour and
//! currently fails; see `docs/BUGS.md`.

mod adversarial_support;

use adversarial_support::*;
use veil_core::{
    object::{Object, Tree},
    secrets::scan,
};

fn utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
}

/// Control: the documented cases.
#[test]
fn utf16_with_a_bom_and_latin_text_is_scanned() {
    let mut data = vec![0xff, 0xfe];
    data.extend(utf16le("[aws]\r\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\r\n"));
    assert!(!scan(&data).is_empty());
    let data = utf16le(&format!("{}\npassword = \"Xk9mQ2vL7pR4wZt8\"\n", "plain ascii text ".repeat(100)));
    assert!(!scan(&data).is_empty(), "BOM-less UTF-16 with Latin text");
}

/// BOM-less UTF-16 is only recognised by NUL density (1 byte in 32). Text
/// in a non-Latin script has almost no NUL bytes in UTF-16 (`中` is
/// `2D 4E`), so a Chinese or Japanese config file in UTF-16 without a BOM
/// is never decoded, and the credential in it is missed.
#[test]
#[ignore = "BUG-056: BOM-less UTF-16 in non-Latin scripts, and UTF-16 starting mid-chunk, bypass the scanner"]
fn bomless_utf16_with_cjk_text_is_scanned() {
    let comment = "数据库连接设置，请勿修改。生产环境配置文件。".repeat(40);
    let data = utf16le(&format!("{comment}\r\npassword = \"Xk9mQ2vL7pR4wZt8\"\r\n{comment}\r\n"));
    assert!(!scan(&data).is_empty(), "credential in BOM-less UTF-16 CJK text not found");
}

/// The NUL-density test runs per 256 KiB chunk, and a token is only
/// reported by the chunk in which it starts. A UTF-16 token that starts in
/// a chunk that is mostly ASCII (so not treated as UTF-16) and ends in the
/// next is found by neither (e.g. a log that switches encoding).
#[test]
#[ignore = "BUG-056: BOM-less UTF-16 in non-Latin scripts, and UTF-16 starting mid-chunk, bypass the scanner"]
fn utf16_starting_just_before_a_chunk_boundary_is_scanned() {
    const CHUNK: usize = 256 << 10;
    let mut data = b"log line\n".repeat(CHUNK / 9);
    data.truncate(CHUNK - 12);
    data.extend(utf16le("AKIAIOSFODNN7EXAMPLE\r\n"));
    data.extend(utf16le(&"utf-16 log output follows\r\n".repeat(2000)));
    assert!(!scan(&data).is_empty(), "AWS key straddling the chunk boundary not found");
}

/// Common credential assignments the keyword list does not cover. The AWS
/// *secret* access key is the half that matters, and it is usually stored
/// next to (not on the same line as) the key id, often in another file.
#[test]
#[ignore = "BUG-055: common credential keywords (aws_secret_access_key, *_secret, *_token, URL passwords) are not detected"]
fn common_credential_assignments_are_detected() {
    let cases: &[&str] = &[
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n",
        "aws_secret_access_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n",
        "JWT_SECRET=Xk9mQ2vL7pR4wZt8uY3n\n",
        "SESSION_SECRET = \"Xk9mQ2vL7pR4wZt8uY3n\"\n",
        "GITLAB_TOKEN=Xk9mQ2vL7pR4wZt8uY3n\n",
        "DATABASE_URL=postgres://app:Xk9mQ2vL7pR4wZt8@db.internal:5432/prod\n",
    ];
    let missed: Vec<&str> = cases.iter().copied().filter(|c| scan(c.as_bytes()).is_empty()).collect();
    assert!(missed.is_empty(), "missed: {missed:#?}");
}

// ---- reserved names: lookalikes -------------------------------------------------

fn tree_with(name: &str) -> Vec<u8> {
    let mut raw = b"veil:tree\n".to_vec();
    let entry = file(name, veil_core::ObjectId::hash(b"x"));
    raw.extend(serde_json::to_vec(&Tree { entries: vec![entry] }).unwrap());
    raw
}

/// Control: ASCII case variants of `.veil` are refused.
#[test]
fn ascii_case_variants_of_dot_veil_are_refused() {
    for name in [".veil", ".VEIL", ".Veil", ".vEiL"] {
        assert!(Object::decode(&tree_with(name)).is_err(), "{name}");
    }
}

/// HFS+ (still the format of many external and older macOS volumes)
/// ignores some Unicode code points in file names, so `.v\u{200c}eil` *is*
/// `.veil` there. Git refuses these spellings of `.git` for that reason
/// (CVE-2014-9390, `is_hfs_dotgit`). Veil only compares ASCII case, so a
/// remote tree with such an entry is accepted and checkout would write
/// into the repository's own `.veil/` on such a volume (BUG-002 again).
#[test]
fn hfs_ignorable_spellings_of_dot_veil_are_refused() {
    let accepted: Vec<String> = ["\u{200c}", "\u{200d}", "\u{200e}", "\u{200f}", "\u{202a}", "\u{206a}", "\u{feff}"]
        .iter()
        .map(|c| format!(".v{c}eil"))
        .filter(|n| Object::decode(&tree_with(n)).is_ok())
        .map(|n| n.escape_unicode().to_string())
        .collect();
    assert!(accepted.is_empty(), "accepted: {accepted:?}");
}
