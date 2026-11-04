//! Engine-level secret detection.
//!
//! Every *public* file is scanned when it is snapshotted. A hit quarantines
//! the file: it is kept on the local machine (and in the encrypted local
//! vault) but never enters the snapshot graph. This is enforced by the
//! engine — there is no ignore file to forget.
//!
//! **Everything is scanned**, whatever its size or encoding:
//!
//! * The token rules (AWS, GitHub, … keys) search the raw bytes in one
//!   linear pass over the whole file, as one alternation, so the regex
//!   engine's SIMD literal prefilter (`AKIA`, `ghp_`, …) makes one pass for
//!   all of them. There is no size limit. Binary files are not skipped: a
//!   credential compiled into a binary is still a credential.
//! * The `key = value` rule works in 256 KiB chunks (16 KiB overlap) on an
//!   ASCII-lowercased copy of each chunk. Case-insensitive keywords have too
//!   many case variants for the prefilter; lowercasing is cheaper.
//! * Text in a NUL-padded encoding (UTF-16 LE/BE, UTF-32, with or without a
//!   BOM) is searched again, chunk by chunk, with its NUL bytes removed,
//!   which turns the ASCII range of those encodings back into ASCII. This
//!   only happens for chunks that look like such text (a BOM, or at least
//!   1/32 NUL bytes), not for compressed or random binary data.
//!
//! Memory use beyond the input is bounded by the chunk size. Rules are
//! matched on bytes with Unicode disabled, so they behave the same on valid
//! and invalid UTF-8. Token boundaries are checked in code instead of in the
//! patterns, which keeps each literal prefix visible to the prefilter.

use std::sync::OnceLock;

use regex::bytes::Regex;

/// Bumped whenever the rules change, so cached "scanned clean" facts (see
/// `statcache`) from an older scanner are not reused.
pub const RULES_VERSION: u32 = 2;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    pub rule: &'static str,
    pub line: usize,
    /// Redacted excerpt that is safe to print.
    pub excerpt: String,
}

/// Bytes that may not directly precede or follow a token.
#[derive(Clone, Copy)]
enum Edge {
    None,
    /// Not `[A-Za-z0-9]`. `_` and `-` are allowed, so `AWS_KEY_AKIA…` and
    /// `TOKEN_ghp_…` match while `xAKIA…` inside a longer word does not.
    Alnum,
    /// Not `[A-Z0-9]` (AWS key ids: `aws_key=AKIA…`, `"AKIA…"`).
    UpperDigit,
    /// Not `[A-Za-z0-9_-]` (fixed-length base64url tokens).
    Base64Url,
}

impl Edge {
    fn allows(self, b: Option<u8>) -> bool {
        let Some(b) = b else { return true };
        match self {
            Edge::None => true,
            Edge::Alnum => !b.is_ascii_alphanumeric(),
            Edge::UpperDigit => !(b.is_ascii_uppercase() || b.is_ascii_digit()),
            Edge::Base64Url => !(b.is_ascii_alphanumeric() || b == b'_' || b == b'-'),
        }
    }
}

#[derive(Clone, Copy)]
enum Check {
    None,
    /// Minimum Shannon entropy (bits/char) of the token.
    Entropy(f64),
    /// `key = value` assignment: the value must look like a credential, not
    /// like code, a reference or a placeholder (see [`plausible_value`]).
    Assignment,
    /// A PEM private-key header. In text that is enough; inside binary data
    /// (NUL bytes nearby) it must be followed by key material, because
    /// programs that read keys carry the bare header as a string constant.
    PemHeader,
}

struct Rule {
    name: &'static str,
    pattern: String,
    before: Edge,
    after: Edge,
    check: Check,
}

/// Keywords for `key = value` assignments, in lower case: they are matched
/// on lowercased text, so case-insensitively. They match anywhere in an
/// identifier, so `DB_PASSWORD`, `spring.datasource.password` and `$api_key`
/// count, but only when the keyword is directly followed by the separator
/// (`password_hash = …` does not).
const KEYWORDS: &str = r"api[_-]?key|secret[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|private[_-]?key|password|passwd";

struct Rules {
    /// Token rules, searched together: one alternation of literal-prefixed
    /// patterns is a single SIMD-prefiltered pass instead of one per rule.
    /// Capture group `i + 1` is `tokens[i]`.
    tokens: Vec<Rule>,
    token_re: Regex,
    /// `key = value` assignments, run on ASCII-lowercased text: `(?i)`
    /// keywords have too many case variants for the literal prefilter.
    assignment: Rule,
    assignment_re: Regex,
}

fn rules() -> &'static Rules {
    static RULES: OnceLock<Rules> = OnceLock::new();
    RULES.get_or_init(|| {
        let r = |name, pattern: &str, before, after, check| Rule {
            name,
            pattern: pattern.to_string(),
            before,
            after,
            check,
        };
        use Check as C;
        use Edge as E;
        let tokens = vec![
            r("private-key", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----", E::None, E::None, C::PemHeader),
            r("aws-access-key-id", r"(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}", E::UpperDigit, E::UpperDigit, C::None),
            r("github-token", r"gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,}", E::Alnum, E::None, C::None),
            r("gitlab-token", r"glpat-[A-Za-z0-9_\-]{20,}", E::Alnum, E::None, C::None),
            r("slack-token", r"xox[baprs]-[A-Za-z0-9\-]{10,}", E::Alnum, E::None, C::None),
            r("stripe-secret-key", r"[sr]k_live_[0-9A-Za-z]{20,}", E::Alnum, E::None, C::None),
            // Before `openai-api-key`: at the same position the first
            // alternative wins.
            r("anthropic-api-key", r"sk-ant-[A-Za-z0-9_\-]{32,}", E::Alnum, E::None, C::None),
            r("openai-api-key", r"sk-(?:proj-)?[A-Za-z0-9_\-]{32,}", E::Alnum, E::None, C::Entropy(3.5)),
            r("google-api-key", r"AIza[0-9A-Za-z_\-]{35}", E::Alnum, E::Base64Url, C::None),
            r("jwt", r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}", E::Alnum, E::None, C::None),
        ];
        let assignment = r(
            "generic-secret-assignment",
            &format!(
                // Matched on ASCII-lowercased text, so the keywords are
                // case-insensitive.
                //
                // Quoted value: any printable non-space bytes. Unquoted value
                // (YAML, dotenv, .properties, kwargs): a run of credential
                // characters that must end the token (checked in code:
                // whitespace, `,;)]}"'` or end of input).
                r#"(?:{KEYWORDS})["']?(?:\s*(?::=|=>|[:=])\s*["'](?P<q>[!#-&(-~\x80-\xff]{{12,}})["']|[ \t]*(?::=|=>|[:=])[ \t]*(?P<u>[A-Za-z0-9!#$%&*+./:=?@^_~|\-]{{12,}}))"#
            ),
            E::None,
            E::None,
            C::Assignment,
        );
        let alternation: Vec<String> = tokens.iter().map(|t| format!("({})", t.pattern)).collect();
        let compile = |p: &str| Regex::new(&format!("(?-u){p}")).expect("valid secret pattern");
        Rules {
            token_re: compile(&alternation.join("|")),
            assignment_re: compile(&assignment.pattern),
            tokens,
            assignment,
        }
    })
}

pub fn looks_binary(data: &[u8]) -> bool {
    data.iter().take(8000).any(|&b| b == 0)
}

fn shannon_entropy(s: &[u8]) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in s {
        counts[b as usize] += 1;
    }
    let n = s.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

/// One word of an identifier: `get`, `Password`, `API`, `v2`, `accessToken`,
/// `2024`. Random credentials mix case and digits in ways words do not.
fn wordlike(seg: &[u8]) -> bool {
    let letters = seg.iter().take_while(|b| b.is_ascii_alphabetic()).count();
    let (word, digits) = seg.split_at(letters);
    if !digits.iter().all(u8::is_ascii_digit) {
        return false;
    }
    if word.is_empty() || word.iter().all(u8::is_ascii_uppercase) {
        return true;
    }
    // lower, Capitalized or camelCase: no two upper-case letters in a row.
    !word.windows(2).any(|w| w[0].is_ascii_uppercase() && w[1].is_ascii_uppercase())
}

/// Does the value of a `key = value` assignment look like a credential?
///
/// Rejects what ordinary code and configuration put there: references
/// (`$VAR`, `${VAR}`, `%(x)s`, `*yaml_alias`, `@ivar`, `{{ tmpl }}`),
/// placeholders (`<your-key>`), identifiers and paths made of words
/// (`settings.SECRET_KEY`, `os.environ.API_KEY_V2`, `your-api-key-here`,
/// `/run/secrets/db_password`), and low-entropy strings.
fn plausible_value(v: &[u8]) -> bool {
    if matches!(v[0], b'$' | b'%' | b'&' | b'*' | b'@' | b'<' | b'{')
        || v.windows(2).any(|w| matches!(w, b"${" | b"{{" | b"#{" | b"%("))
    {
        return false;
    }
    let identifier = v
        .split(|b| matches!(b, b'.' | b'_' | b'-' | b':' | b'/'))
        .all(wordlike);
    !identifier && shannon_entropy(v) >= 3.2
}

/// Does key material (or an encrypted-PEM header) follow a PEM header?
fn pem_body_follows(rest: &[u8]) -> bool {
    let rest = rest.strip_prefix(b"\r").unwrap_or(rest);
    let Some(rest) = rest.strip_prefix(b"\n") else { return false };
    rest.starts_with(b"Proc-Type:")
        || rest
            .iter()
            .take_while(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
            .count()
            >= 32
}

fn redact(s: &[u8]) -> String {
    let s = String::from_utf8_lossy(s);
    let visible: String = s.chars().take(4).collect();
    format!("{visible}…({} chars)", s.chars().count())
}

const MAX_FINDINGS: usize = 16;
/// Chunk size and overlap of the chunked passes. The overlap is far longer
/// than the minimal match of any rule, so a token straddling a chunk
/// boundary is still found in the chunk where it starts.
const CHUNK: usize = 256 << 10;
const OVERLAP: usize = 16 << 10;

/// A finding before its line number is known: `offset` is into the buffer
/// that was searched.
struct Hit {
    rule: &'static str,
    offset: usize,
    excerpt: String,
}

/// Token rules over `hay`; only matches starting before `limit` are
/// reported (the rest of `hay` is overlap owned by the next chunk).
/// `stripped`: `hay` is NUL-padded data with the NULs removed.
fn search_tokens(hay: &[u8], limit: usize, stripped: bool, out: &mut Vec<Hit>) {
    let rules = rules();
    search_with(&rules.token_re, false, stripped, hay, hay, limit, out, |caps| {
        let i = (1..caps.len()).find(|&g| caps.get(g).is_some()).expect("one alternative matched");
        &rules.tokens[i - 1]
    });
}

/// The assignment rule. `lower` is `text` ASCII-lowercased (same offsets):
/// the keywords are matched there case-sensitively, which keeps the regex
/// prefilter effective, and values are judged on the original `text`.
fn search_assignments(text: &[u8], lower: &[u8], limit: usize, out: &mut Vec<Hit>) {
    let rules = rules();
    search_with(&rules.assignment_re, true, false, lower, text, limit, out, |_| &rules.assignment);
}

/// Run `re` over `hay` and judge each match on `text` (`hay` itself, or the
/// same bytes before lowercasing).
#[allow(clippy::too_many_arguments)]
fn search_with<'r>(
    re: &Regex,
    assignment: bool,
    stripped: bool,
    hay: &[u8],
    text: &[u8],
    limit: usize,
    out: &mut Vec<Hit>,
    rule_of: impl Fn(&regex::bytes::Captures) -> &'r Rule,
) {
    let terminates = |b: Option<u8>| match b {
        None => true,
        Some(b) => b.is_ascii_whitespace() || matches!(b, b',' | b';' | b')' | b']' | b'}' | b'"' | b'\''),
    };
    let mut found = 0;
    let mut at = 0;
    while at < limit {
        // Judge the match span first; capture groups are much slower to
        // compute and only needed for the few matches that survive.
        let Some(whole) = re.find_at(hay, at) else { break };
        if whole.start() >= limit {
            break;
        }
        at = whole.end().max(whole.start() + 1);
        let prev = whole.start().checked_sub(1).map(|i| text[i]);
        let next = text.get(whole.end()).copied();
        // An unquoted assignment value must be the whole token: `x = a(b)`
        // is code, not a credential. (Unquoted values never end in a quote.)
        let quoted = matches!(text[whole.end() - 1], b'"' | b'\'');
        if assignment && !quoted && !terminates(next) {
            continue;
        }
        let caps = re.captures_at(hay, whole.start()).expect("the same match");
        let rule = rule_of(&caps);
        if !rule.before.allows(prev) {
            // A real token may start inside this rejected match.
            at = whole.start() + 1;
            continue;
        }
        if !rule.after.allows(next) {
            continue;
        }
        let span = caps.name("q").or_else(|| caps.name("u")).unwrap_or(whole).range();
        let token = &text[span];
        let ok = match rule.check {
            Check::None => true,
            Check::Entropy(min) => shannon_entropy(token) >= min,
            Check::Assignment => plausible_value(token),
            Check::PemHeader => {
                let around = &text[whole.start().saturating_sub(256)..(whole.end() + 256).min(text.len())];
                let binary = stripped || around.contains(&0);
                !binary || pem_body_follows(&text[whole.end()..])
            }
        };
        if ok {
            out.push(Hit {
                rule: rule.name,
                offset: whole.start(),
                excerpt: redact(token),
            });
            found += 1;
            if found >= MAX_FINDINGS {
                break;
            }
        }
    }
}

fn newlines(s: &[u8]) -> usize {
    s.iter().filter(|&&b| b == b'\n').count()
}

/// Does this chunk look like text in a NUL-padded encoding?
fn nul_padded(chunk: &[u8], bom: bool) -> bool {
    bom || (chunk.contains(&0) && chunk.iter().filter(|&&b| b == 0).count() * 32 >= chunk.len())
}

fn lowercase_into(buf: &mut Vec<u8>, s: &[u8]) {
    buf.clear();
    buf.extend(s.iter().map(u8::to_ascii_lowercase));
}

/// Scan file content for likely credentials.
pub fn scan(data: &[u8]) -> Vec<Finding> {
    // Token rules over the raw bytes, in one go (offsets into `data`).
    let mut hits = Vec::new();
    search_tokens(data, data.len(), false, &mut hits);

    // Chunked passes: assignments over the raw bytes, and every rule over
    // NUL-padded text with the NULs removed. Removing NULs keeps every
    // newline, so line numbers carry over.
    let bom = data.starts_with(&[0xff, 0xfe]) || data.starts_with(&[0xfe, 0xff]);
    let mut stripped_found: Vec<Finding> = Vec::new();
    let (mut pos, mut line) = (0, 1);
    let (mut lower, mut stripped, mut chunk_hits) = (Vec::new(), Vec::new(), Vec::new());
    let mut start = 0;
    while start < data.len() && hits.len() + stripped_found.len() < MAX_FINDINGS {
        let end = (start + CHUNK).min(data.len());
        let window = &data[start..(end + OVERLAP).min(data.len())];
        lowercase_into(&mut lower, window);
        chunk_hits.clear();
        search_assignments(window, &lower, end - start, &mut chunk_hits);
        hits.extend(chunk_hits.drain(..).map(|h| Hit { offset: h.offset + start, ..h }));

        if nul_padded(&data[start..end], bom) {
            stripped.clear();
            stripped.extend(data[start..end].iter().copied().filter(|&b| b != 0));
            let limit = stripped.len();
            stripped.extend(window[end - start..].iter().copied().filter(|&b| b != 0));
            lowercase_into(&mut lower, &stripped);
            search_tokens(&stripped, limit, true, &mut chunk_hits);
            search_assignments(&stripped, &lower, limit, &mut chunk_hits);
            if !chunk_hits.is_empty() {
                line += newlines(&data[pos..start]);
                pos = start;
                for h in chunk_hits.drain(..) {
                    stripped_found.push(Finding {
                        rule: h.rule,
                        line: line + newlines(&stripped[..h.offset]),
                        excerpt: h.excerpt,
                    });
                }
            }
        }
        start = end;
    }

    hits.sort_by_key(|h| h.offset);
    let (mut pos, mut line) = (0, 1);
    let mut found: Vec<Finding> = Vec::new();
    for h in hits {
        line += newlines(&data[pos..h.offset]);
        pos = h.offset;
        found.push(Finding { rule: h.rule, line, excerpt: h.excerpt });
    }
    for f in stripped_found {
        // Text without NULs inside it is found by both passes.
        if !found.contains(&f) {
            found.push(f);
        }
    }
    found.sort_by_key(|f| f.line);
    found.truncate(MAX_FINDINGS);
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_common_secrets() {
        assert_eq!(scan(b"key = AKIAIOSFODNN7EXAMPLE\n")[0].rule, "aws-access-key-id");
        assert_eq!(
            scan(b"x\n-----BEGIN OPENSSH PRIVATE KEY-----\nabc")[0].line,
            2
        );
        assert!(!scan(br#"password = "Xk9#mQ2$vL7pR4wZ""#).is_empty());
        assert!(scan(br#"password = "aaaaaaaaaaaaaaaa""#).is_empty(), "low entropy ignored");
        assert!(scan(b"fn main() { println!(\"hello\"); }").is_empty());
    }

    #[test]
    fn token_edges() {
        assert!(!scan(b"AWS_KEY_AKIAIOSFODNN7EXAMPLE").is_empty());
        assert!(!scan(b"x=AKIAIOSFODNN7EXAMPLE;").is_empty());
        assert!(scan(b"XAKIAIOSFODNN7EXAMPLE").is_empty(), "inside a longer upper-case word");
        assert!(scan(b"AKIAIOSFODNN7EXAMPLEXY").is_empty(), "too long for a key id");
        // A real token right after a rejected look-alike is still found.
        assert!(!scan(b"task-0123456789abcdefghijABCDEFGHIJ_sk-0a9Zb8Yc7Xd6We5Vf4Ug3Th2Si1Rj0Qk").is_empty());
    }

    #[test]
    fn pem_headers_in_binaries_need_key_material() {
        let header = b"-----BEGIN OPENSSH PRIVATE KEY-----";
        let mut constant = b"\x7fELF\0\0".to_vec();
        constant.extend_from_slice(header);
        constant.extend_from_slice(b"\n\0-----END OPENSSH PRIVATE KEY-----\n\0");
        assert!(scan(&constant).is_empty(), "a string constant in a program");
        let mut embedded = b"\x7fELF\0\0".to_vec();
        embedded.extend_from_slice(header);
        embedded.extend_from_slice(b"\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtz\n\0");
        assert!(!scan(&embedded).is_empty(), "a real key compiled into a binary");
    }

    #[test]
    fn assignment_values() {
        for v in [&b"Xk9mQ2vL7pR4wZt8"[..], b"9f86d081884c7d659a2feaa0c55ad015", b"123e4567-e89b-12d3-a456-426614174000"] {
            assert!(plausible_value(v), "{}", String::from_utf8_lossy(v));
        }
        for v in [
            &b"settings.SECRET_KEY"[..],
            b"os.environ.API_KEY_V2",
            b"your-api-key-goes-here",
            b"this.accessToken",
            b"/run/secrets/db_password",
            b"${DB_PASSWORD}",
            b"$OAUTH_CLIENT_SECRET",
            b"*default_password",
            b"<your-password-here>",
            b"aaaaaaaaaaaaaaaa",
            b"Password123456",
            b"getPasswordFromEnv",
        ] {
            assert!(!plausible_value(v), "{}", String::from_utf8_lossy(v));
        }
    }
}
