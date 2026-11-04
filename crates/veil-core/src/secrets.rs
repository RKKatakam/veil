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
//! * The `key = value` rule (also `key: value`, `<key>value</key>`) works
//!   in 256 KiB chunks (16 KiB overlap) on an ASCII-lowercased copy of each
//!   chunk. Case-insensitive keywords have too many case variants for the
//!   prefilter; lowercasing is cheaper. Candidate matches are rejected as
//!   cheaply as possible (the regex itself checks how an unquoted value
//!   ends, and a match made only of words is dropped before its capture
//!   groups are computed), because ordinary code has thousands per MiB.
//! * Text in a NUL-padded encoding (UTF-16 LE/BE, UTF-32, with or without a
//!   BOM) is searched again, chunk by chunk, with its NUL bytes removed,
//!   which turns the ASCII range of those encodings back into ASCII. This
//!   only happens for chunks that look like such text (a BOM, at least 1/32
//!   NUL bytes, or a run of 8 ASCII characters in UTF-16 anywhere in the
//!   chunk or its overlap: text in a non-Latin script has almost no NULs
//!   in UTF-16), not for compressed or random binary data.
//!
//! Memory use beyond the input is bounded by the chunk size. Rules are
//! matched on bytes with Unicode disabled, so they behave the same on valid
//! and invalid UTF-8. Token boundaries are checked in code instead of in the
//! patterns, which keeps each literal prefix visible to the prefilter.

use std::sync::OnceLock;

use regex::bytes::Regex;

/// Bumped whenever the rules change, so cached "scanned clean" facts (see
/// `statcache`) from an older scanner are not reused.
pub const RULES_VERSION: u32 = 3;

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
    /// like code, a reference or a placeholder (see [`plausible_value`]),
    /// and the key must name a credential (see [`credential_key`]).
    Assignment,
    /// The password of a `scheme://user:password@host` URL.
    UrlPassword,
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
/// count. The generic `secret` and `token` only count as a whole word or
/// after `_` / `-` (`JWT_SECRET`, `GITLAB_TOKEN`, not `mytoken`), and not
/// after a word that names something other than a credential
/// ([`TOKEN_NOT_CREDENTIAL`]: `csrf_token`, `next_page_token`).
///
/// The keyword may carry up to three `_x` / `-x` suffix words
/// (`DB_PASSWORD_PROD`, `aws_secret_access_key`), unless one of them says
/// the value is something else ([`NOT_A_CREDENTIAL`]: `password_hash`,
/// `token_url`, `secret_name`).
const KEYWORDS: &str = r"api[_-]?key|secret[_-]?access[_-]?key|secret[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|private[_-]?key|password|passwd|secret|token";

/// Suffix words after a keyword that make the value not a credential: its
/// hash, where it is, what it is called, its policy or metadata.
const NOT_A_CREDENTIAL: &[&str] = &[
    "algo", "algorithm", "arn", "cmd", "command", "count", "desc", "description", "digest", "dir", "enabled", "endpoint", "env",
    "error", "expiration", "expires", "expiry", "field", "file", "flag", "format", "hash", "hashed", "header", "help", "hint", "host",
    "id", "ids", "input", "kind", "label", "len", "length", "location", "max", "message", "method", "min", "mode", "name", "param",
    "path", "pattern", "placeholder", "policy", "prompt", "provider", "ref", "regex", "required", "rule", "salt", "size", "source",
    "store", "text", "timeout", "title", "ttl", "type", "uri", "url", "var", "version",
];

/// Words before `token` that make it not a credential.
const TOKEN_NOT_CREDENTIAL: &[&str] = &[
    "cancel", "cancellation", "continuation", "csrf", "cursor", "device", "idempotency", "lexer", "next", "page", "pagination", "parser",
    "request", "resume", "sync", "xsrf",
];

struct Rules {
    /// Token rules, searched together: one alternation of literal-prefixed
    /// patterns is a single SIMD-prefiltered pass instead of one per rule.
    /// Capture group `token_groups[i]` is `tokens[i]`.
    tokens: Vec<Rule>,
    token_re: Regex,
    token_groups: Vec<usize>,
    /// Groups of `token_re` holding the part to judge and print.
    token_values: Vec<usize>,
    /// `key = value` assignments, run on ASCII-lowercased text: `(?i)`
    /// keywords have too many case variants for the literal prefilter.
    assignment: Rule,
    assignment_re: Regex,
    assign: AssignGroups,
}

/// Capture groups of the assignment rule, by index. (Looking a group up by
/// name hashes the name, and ordinary text has thousands of candidate
/// matches per MiB.)
struct AssignGroups {
    kw: usize,
    sfx: usize,
    /// The value of an XML element.
    x: usize,
    /// Groups that hold the value: quoted, unquoted, XML.
    values: Vec<usize>,
}

fn group(re: &Regex, name: &str) -> usize {
    re.capture_names().position(|n| n == Some(name)).expect("named group")
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
            // `postgres://app:<password>@db`: matched from `://` (a literal
            // for the prefilter); the scheme is not needed.
            r("url-password", r#"://[^\s:/?#@'"<>]{0,64}:(?P<pw>[^\s:/?#@'"<>]{8,128})@[A-Za-z0-9\[]"#, E::None, E::None, C::UrlPassword),
        ];
        let assignment = r(
            "generic-secret-assignment",
            &format!(
                // Matched on ASCII-lowercased text, so the keywords are
                // case-insensitive.
                //
                // Quoted value: any printable non-space bytes. Unquoted value
                // (YAML, dotenv, .properties, kwargs): a run of credential
                // characters that must end the token (whitespace, `,;)]}"'`
                // or the end of the input follow it): `x = a(b)` is code.
                // Checking that here, not in code, keeps `password_hash =
                // user.password_hash()` from even being a match.
                //
                // XML element: `<db_password>value</db_password>`.
                r#"(?P<kw>{KEYWORDS})(?P<sfx>(?:[_-][a-z0-9]+){{0,3}})(?:["']?(?:\s*(?::=|=>|[:=])\s*["'](?P<q>[!#-&(-~\x80-\xff]{{12,}})["']|[ \t]*(?::=|=>|[:=])[ \t]*(?P<u>[A-Za-z0-9!#$%&*+./:=?@^_~|\-]{{12,}})(?:[\s,;)\]}}"']|$))|>[ \t]*(?P<x>[!#-&(-;=?-~\x80-\xff]{{12,}})[ \t]*</)"#
            ),
            E::None,
            E::None,
            C::Assignment,
        );
        let alternation: Vec<String> = tokens.iter().enumerate().map(|(i, t)| format!("(?P<t{i}>{})", t.pattern)).collect();
        let compile = |p: &str| Regex::new(&format!("(?-u){p}")).expect("valid secret pattern");
        let token_re = compile(&alternation.join("|"));
        let assignment_re = compile(&assignment.pattern);
        let assign = AssignGroups {
            kw: group(&assignment_re, "kw"),
            sfx: group(&assignment_re, "sfx"),
            x: group(&assignment_re, "x"),
            values: ["q", "u", "x"].iter().map(|n| group(&assignment_re, n)).collect(),
        };
        Rules {
            token_groups: (0..tokens.len()).map(|i| group(&token_re, &format!("t{i}"))).collect(),
            token_values: vec![group(&token_re, "pw")],
            assignment_re,
            assign,
            token_re,
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

/// Does the key of an assignment name a credential? `caps` is a match of
/// the assignment rule in `lower` (lowercased text). See [`KEYWORDS`].
fn credential_key(caps: &regex::bytes::Captures, g: &AssignGroups, lower: &[u8]) -> bool {
    let kw = caps.get(g.kw).expect("keyword group");
    let ident = |b: &u8| b.is_ascii_alphanumeric();
    if matches!(kw.as_bytes(), b"secret" | b"token") {
        let before = &lower[..kw.start()];
        if before.last().is_some_and(ident) {
            return false; // `mytoken`, `topsecret`
        }
        if kw.as_bytes() == b"token" {
            let before = before.strip_suffix(b"_").or_else(|| before.strip_suffix(b"-")).unwrap_or(&[]);
            let word = &before[before.iter().rposition(|b| !ident(b)).map_or(0, |i| i + 1)..];
            if TOKEN_NOT_CREDENTIAL.iter().any(|w| w.as_bytes() == word) {
                return false;
            }
        }
    }
    let suffix = caps.get(g.sfx).map_or(&b""[..], |m| m.as_bytes());
    if suffix
        .split(|b| matches!(b, b'_' | b'-'))
        .any(|w| NOT_A_CREDENTIAL.iter().any(|n| n.as_bytes() == w))
    {
        return false;
    }
    // An element: the keyword is part of the name of the tag just opened.
    if caps.get(g.x).is_some() {
        let name_start = lower[..kw.start()]
            .iter()
            .rposition(|b| !(ident(b) || matches!(b, b'_' | b'-' | b'.' | b':')))
            .map(|i| lower[i]);
        return name_start == Some(b'<');
    }
    true
}

/// Is the password of a `scheme://user:password@host` URL a credential,
/// not a placeholder (`user:password@`, `postgres:postgres@`,
/// `${USER}:${PASS}@`, `<user>:<password>@`, `****`)?
fn plausible_url_password(v: &[u8]) -> bool {
    if matches!(v[0], b'$' | b'%' | b'&' | b'*' | b'<' | b'{' | b'[') || v.windows(2).any(|w| matches!(w, b"${" | b"{{" | b"%(")) {
        return false;
    }
    // A password a person typed is shorter and less random than a token:
    // a lower bar than `plausible_value`, but never a plain word or number.
    let identifier = v.split(|b| matches!(b, b'.' | b'_' | b'-')).all(wordlike);
    !identifier && shannon_entropy(v) >= 2.5
}

/// Is `s` made only of words (see [`wordlike`]) between `.`, `_`, `-`,
/// `:`, `/`, whitespace and quotes?
fn identifier_like(s: &[u8]) -> bool {
    s.split(|&b| matches!(b, b'.' | b'_' | b'-' | b':' | b'/' | b'"' | b'\'') || b.is_ascii_whitespace())
        .all(wordlike)
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
    search_with(&rules.token_re, &rules.token_values, false, stripped, hay, hay, limit, out, |caps| {
        let i = rules.token_groups.iter().position(|&g| caps.get(g).is_some()).expect("one alternative matched");
        &rules.tokens[i]
    });
}

/// The assignment rule. `lower` is `text` ASCII-lowercased (same offsets):
/// the keywords are matched there case-sensitively, which keeps the regex
/// prefilter effective, and values are judged on the original `text`.
fn search_assignments(text: &[u8], lower: &[u8], limit: usize, out: &mut Vec<Hit>) {
    let rules = rules();
    search_with(&rules.assignment_re, &rules.assign.values, true, false, lower, text, limit, out, |_| &rules.assignment);
}

/// Run `re` over `hay` and judge each match on `text` (`hay` itself, or the
/// same bytes before lowercasing). `values`: capture groups that hold the
/// part of a match to judge (the whole match if none matched).
#[allow(clippy::too_many_arguments)]
fn search_with<'r>(
    re: &Regex,
    values: &[usize],
    assignment: bool,
    stripped: bool,
    hay: &[u8],
    text: &[u8],
    limit: usize,
    out: &mut Vec<Hit>,
    rule_of: impl Fn(&regex::bytes::Captures) -> &'r Rule,
) {
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
        // `accessToken: this.accessToken` (minified code is full of them):
        // if the whole match is made of words, so is its value, which is
        // then not a credential (see `plausible_value`). The value never
        // contains whitespace or quotes, and a separator glued to it
        // (`=`, `>`, `</`) makes that segment not a word, so this never
        // rejects what the full check would accept, nor a match inside it.
        // (An unquoted value's match ends with the byte that ends it.)
        if assignment {
            let m = &text[whole.range()];
            let body = match m.last() {
                Some(b',' | b';' | b')' | b']' | b'}') => &m[..m.len() - 1],
                _ => m,
            };
            if identifier_like(body) {
                continue;
            }
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
        if matches!(rule.check, Check::Assignment) && !credential_key(&caps, &rules().assign, hay) {
            // Another keyword may start inside (`mytoken_password = …`).
            at = whole.start() + 1;
            continue;
        }
        let span = values.iter().find_map(|&g| caps.get(g)).unwrap_or(whole).range();
        let token = &text[span];
        let ok = match rule.check {
            Check::None => true,
            Check::Entropy(min) => shannon_entropy(token) >= min,
            Check::Assignment => plausible_value(token),
            Check::UrlPassword => plausible_url_password(token),
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

/// Does this chunk look like text in a NUL-padded encoding? `window` is
/// the chunk followed by its overlap.
fn nul_padded(chunk: &[u8], window: &[u8], bom: bool) -> bool {
    if bom {
        return true;
    }
    let nuls = chunk.iter().filter(|&&b| b == 0).count();
    nuls > 0 && nuls * 32 >= chunk.len() || utf16_run(window)
}

/// Code units of ASCII text in UTF-16 that make a run.
const UTF16_RUN: usize = 8;

/// Does `data` contain a run of ASCII text in UTF-16 (`p\0a\0s\0s\0…` or
/// big-endian)? Catches UTF-16 that the NUL density misses: text in a
/// non-Latin script (`数` is `70 65`, no NUL) around an ASCII credential,
/// or UTF-16 that starts near the end of a chunk of plain text. Random and
/// compressed data practically never has such a run.
fn utf16_run(data: &[u8]) -> bool {
    let text = |b: u8| matches!(b, b'\t' | b'\n' | b'\r' | 0x20..=0x7e);
    let unit = |z: usize, k: usize, le: bool| {
        let n = z + 2 * k;
        match le {
            true => n < data.len() && data[n] == 0 && text(data[n - 1]),
            false => n + 1 < data.len() && data[n] == 0 && text(data[n + 1]),
        }
    };
    // Both orders need a NUL two bytes on: most NULs fail that at once.
    memchr::memchr_iter(0, data).any(|z| {
        data.get(z + 2) == Some(&0)
            && ((z > 0 && (0..UTF16_RUN).all(|k| unit(z, k, true))) || (0..UTF16_RUN).all(|k| unit(z, k, false)))
    })
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

        if nul_padded(&data[start..end], window, bom) {
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
