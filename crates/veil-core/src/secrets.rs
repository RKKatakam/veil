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
//!   in UTF-16), not for compressed or random binary data. Where the NUL
//!   positions show the encoding (UTF-16/32, either byte order), a
//!   non-ASCII character next to ASCII text becomes a space instead of
//!   leaving one of its bytes glued to a token (`令牌ghp_…`).
//!
//! * Text whose lines end in NUL instead of newline (Vim's swap files) is
//!   searched again with its lines joined by newlines, in file order and in
//!   reverse (see `scan_nul_separated`). This needs up to twice the input
//!   in memory, and only happens when such lines hold at least half of the
//!   file's non-NUL bytes.
//!
//! Memory use beyond the input is otherwise bounded by the chunk size. Rules are
//! matched on bytes with Unicode disabled, so they behave the same on valid
//! and invalid UTF-8. Token boundaries are checked in code instead of in the
//! patterns, which keeps each literal prefix visible to the prefilter.
//!
//! **Time is linear in the input size, whatever the input.** A search for
//! the leftmost match reads on past the match it returns only while an
//! earlier candidate could still grow, and a candidate can only grow over
//! another match through a value, a comment or a token body, which the
//! patterns bound (256 to 512 bytes): so every search reads at most about
//! 1 KiB past its match. Whitespace and key words are not bounded; no
//! match fits in them. A candidate rejected for the byte before it or for
//! its key restarts the search inside itself (a real credential may start
//! there), which crafted input can repeat at every byte. So the work done
//! again is counted, and a search that has spent [`WORK_FACTOR`] times its
//! input on it ends with a `scan-limit` finding, which quarantines the
//! file. Ordinary files do almost none; crafted ones are scanned at 25+
//! MiB/s before they are reported.

use std::sync::OnceLock;

use regex::bytes::Regex;

/// Bumped whenever the rules change, so cached "scanned clean" facts (see
/// `statcache`) from an older scanner are not reused.
pub const RULES_VERSION: u32 = 5;

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
    /// A JSON Web Token: the pattern covers the header and the start of the
    /// payload; the rest of the payload and the signature are checked in
    /// code, so the pattern stays short (see "linear" in the module docs).
    Jwt,
}

struct Rule {
    name: &'static str,
    pattern: String,
    before: Edge,
    after: Edge,
    check: Check,
}

/// Keywords for `key = value` assignments, in lower case: they are matched
/// on lowercased text, so case-insensitively, where `-` is also `_` (see
/// [`lowercase_into`]), so `api_?key` matches `API-KEY`. (Each variant is a
/// literal for the prefilter; past about 60 it is much slower.) They match anywhere in an
/// identifier, so `DB_PASSWORD`, `spring.datasource.password` and `$api_key`
/// count. The generic `secret` and `token` only count as a whole word or
/// after `_` / `-` (`JWT_SECRET`, `GITLAB_TOKEN`, not `mytoken`), and not
/// after a word that names something other than a credential
/// ([`TOKEN_NOT_CREDENTIAL`]: `csrf_token`, `next_page_token`). So do the
/// `…_key` / `…_salt` names of [`KEY_NAMES`], or at a camelCase boundary
/// (`appKey`, `RAILS_MASTER_KEY`, not `whatsappkey`).
///
/// The keyword may be plural or numbered (`API_KEYS`, `PASSWORD2`) and carry
/// up to six `_x` / `-x` suffix words (`DB_PASSWORD_PROD_EU_WEST_1`,
/// `aws_secret_access_key`), unless one of them says the value is something
/// else ([`NOT_A_CREDENTIAL`]: `password_hash`, `token_url`, `secret_name`).
/// `identified by` only counts in SQL (`IDENTIFIED BY '…'`).
const KEYWORDS: &str = r"api_?key|secret_?access_?key|secret_?key|client_?secret|access_?token|auth_?token|private_?key|(?P<kk>KEY_NAMES)|password|passwd|secret|token|identified[ \t]{1,8}by";

/// `*_KEY` / `*_SALT` names that hold a secret (`APP_KEY` of Laravel,
/// `RAILS_MASTER_KEY`, `ENCRYPTION_KEY`, `SIGNING_KEY`, WordPress's
/// `AUTH_KEY` … `NONCE_SALT`, Azure's `AccountKey` and `SharedAccessKey`).
/// `key` alone is not a keyword: most keys are not secrets (`primary_key`,
/// `cache_key`, `public_key`).
const KEY_NAMES: &str = r"(?:app|master|encryption|signing|hmac|account|shared_?access|auth|secure_?auth|logged_?in|nonce)_?key|(?:auth|secure_?auth|logged_?in|nonce)_?salt";

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
    /// `token_re` unbounded, for capture groups (see `assignment_caps`).
    token_caps: Regex,
    token_groups: Vec<usize>,
    /// Groups of `token_re` holding the part to judge and print.
    token_values: Vec<usize>,
    /// `key = value` assignments, run on ASCII-lowercased text: `(?i)`
    /// keywords have too many case variants for the literal prefilter.
    assignment: Rule,
    assignment_re: Regex,
    /// The same pattern with its repetitions unbounded, for the capture
    /// groups of a match already found: its smaller automaton computes them
    /// several times faster on the match alone (where no bound is needed).
    /// The groups are numbered the same.
    assignment_caps: Regex,
    assign: AssignGroups,
}

/// Capture groups of an assignment pattern, by index. (Looking a group up
/// by name hashes the name, and ordinary text has thousands of candidate
/// matches per MiB.)
struct AssignGroups {
    kw: usize,
    /// A [`KEY_NAMES`] keyword (`app_key`, `nonce_salt`).
    kk: usize,
    sfx: usize,
    /// How the value is attached when it is not `key = value` (see
    /// [`assignment_pattern`]): SQL (`WITH PASSWORD '…'`), an element
    /// (`<key …>value</`, `<![CDATA[value]]>`) or a plist entry
    /// (`<key>Password</key><string>value</string>`).
    sql: usize,
    el: usize,
    /// A single-quoted value (the only kind SQL has).
    s: usize,
    /// A Google app password with its spaces ([`app_password`]).
    g: usize,
    /// The rest of a line ([`assignment_pattern`]), whole or truncated.
    line: [usize; 2],
    /// The next line's `value:`, whole or truncated.
    k8s: [usize; 2],
    /// Groups that hold the value.
    values: Vec<usize>,
}

impl AssignGroups {
    fn new(re: &Regex) -> AssignGroups {
        let g = |n| group(re, n);
        AssignGroups {
            kw: g("kw"),
            kk: g("kk"),
            sfx: g("sfx"),
            sql: g("sql"),
            el: g("el"),
            s: g("s"),
            g: g("g"),
            line: [g("l"), g("lt")],
            k8s: [g("kl"), g("klt")],
            values: ["q", "qt", "s", "st", "g", "kl", "klt", "l", "lt", "u", "ut", "xc", "x"].iter().map(|n| g(n)).collect(),
        }
    }
}

fn group(re: &Regex, name: &str) -> usize {
    re.capture_names().position(|n| n == Some(name)).expect("named group")
}

/// The key of an assignment: a keyword, maybe plural or numbered, and
/// suffix words.
fn key_pattern() -> String {
    let keywords = KEYWORDS.replace("KEY_NAMES", KEY_NAMES);
    format!(r"(?P<kw>{keywords})(?:s|[0-9]{{1,3}})?(?P<sfx>(?:[_-][a-z0-9]+){{0,6}})")
}

/// The rest of a line as a value: printable bytes up to the end of the
/// line or a ` #` comment; `VALUEt`: its first 256 bytes, if longer.
const LINE_VALUE: &str = r"(?:(?P<VALUE>[!-~\x80-\xff]{12,256})(?:[ \t]+#[^\r\n]{0,256})?[ \t]*(?:\r?\n|$)|(?P<VALUEt>[!-~\x80-\xff]{256})[!-~\x80-\xff])";

/// The assignment pattern (matched on ASCII-lowercased text, so the
/// keywords are case-insensitive). After the key and its suffix words:
///
/// * a quoted value after `=`, `:`, `:=`, `=>`, or after a quoted key and
///   `,` / `]` (`define('KEY', '…')`, `env["KEY"] = "…"`), or on the next
///   line's `value:` (Kubernetes env lists), in a `value="…"` attribute, or
///   SQL's `PASSWORD '…'`. Quoted values may hold escaped quotes (`\"`,
///   YAML's `''`);
/// * a Google app password as Google shows it (`abcd efgh ijkl mnop`),
///   quoted or not;
/// * an unquoted value on the next line's `value:`, to the end of it;
/// * the rest of the line (`.properties`, dotenv, YAML, INI): any printable
///   bytes up to the end of the line or a ` #` comment. Before the next
///   kind, because it is the whole value in a configuration line; where the
///   key does not start the line (see [`config_line`]), this is code, and
///   only the token the value starts with counts ([`code_token`]);
/// * an unquoted value in code (kwargs, dotenv) made of credential
///   characters, which must end the token (whitespace, `,;)]}"'` or the end
///   follow it): `x = a(b)` is code. Checking that here keeps `password_hash
///   = user.password_hash()` from even being a match;
/// * the text of an XML element (with attributes, or CDATA) or plist entry.
///
/// Every repetition that could hold another match (values, attribute
/// values, comments) is bounded (see "linear" in the module docs); a value
/// longer than its bound is judged on its first 256 bytes.
fn assignment_pattern() -> String {
    let dq = r"(?:\\[!-~]|[!#-~\x80-\xff])"; // one unit of a "…" value
    let sq = r"(?:\\[!-~]|''|[!-&(-~\x80-\xff])"; // one unit of a '…' value
    let uq = r"[a-z0-9!#$%&*+./:=?@^_~|\-]"; // an unquoted value in code
    let uq1 = r"[a-z0-9!#$%&*+./=?@^_~|\-]"; // its first byte: not `:` (`Token::Str`)
    let xt = r"[!-;=?-~\x80-\xff]"; // element text: no `<`, `>`
    let xc = r"[!-\\^-~\x80-\xff]"; // CDATA: no `]`
    let sep = r"(?::=|=>|[:=])";
    let k8s = r#"["']?[ \t]*\r?\n[ \t]*value[ \t]*:"#;
    let attrs = r#"(?:\s+[a-z_:][a-z0-9_:.\-]*\s*=\s*(?:"[^"<>]{0,128}"|'[^'<>]{0,128}')){0,4}"#;
    let key = key_pattern();
    let assign = format!(r#"(?:["']\]?\s*(?:,|{sep})|\]?\s*{sep})\s*"#);
    let connector = format!(r#"{assign}|{k8s}[ \t]*|["'][ \t]+value[ \t]*=[ \t]*|(?P<sql>[ \t]+)"#);
    // As Google shows an app password: `abcd efgh ijkl mnop`.
    let app = format!(r#"{assign}["']?(?P<g>[a-z]{{4}} [a-z]{{4}} [a-z]{{4}} [a-z]{{4}})(?:[\s,;)\]}}"']|$)"#);
    // A value longer than 256 bytes matches as its first 256 (`qt`, `st`,
    // `ut`); see "linear" in the module docs.
    let quoted = format!(r#"(?:{connector})(?:"(?:(?P<q>{dq}{{12,256}})"|(?P<qt>{dq}{{256}}){dq})|'(?:(?P<s>{sq}{{12,256}})'|(?P<st>{sq}{{256}}){sq}))"#);
    let k8s_line = format!("{k8s}[ \\t]*{}", LINE_VALUE.replace("VALUE", "kl"));
    let unquoted = format!(r#"["']?[ \t]*{sep}[ \t]*(?:(?P<u>{uq1}{uq}{{11,255}})(?:[\s,;)\]}}"']|$)|(?P<ut>{uq1}{uq}{{255}}){uq})"#);
    let element = format!(
        r#"(?P<el>{attrs}\s*>|</key>\s*<string>)[ \t]*(?:<!\[cdata\[(?P<xc>{xc}{{12,256}})\]\]>|(?P<x>{xt}{{12,256}})[ \t]*</)"#
    );
    let line = format!(r#"["']?[ \t]*[:=][ \t]*{}"#, LINE_VALUE.replace("VALUE", "l"));
    format!("{key}(?:{quoted}|{app}|{k8s_line}|{line}|{unquoted}|{element})")
}

/// `pattern` with every bounded repetition `{m,n}` made `{m,}` and every
/// `{n}` of 12 or more `{12,}`, for computing the capture groups of a match
/// already found: on the match alone the bounds change nothing (a
/// truncated value matches whole), and the automaton is far smaller.
fn unbounded(pattern: &str) -> String {
    let mut out = String::with_capacity(pattern.len());
    let mut rest = pattern;
    while let Some(i) = rest.find('{') {
        out.push_str(&rest[..i]);
        let after = &rest[i + 1..];
        let end = after.find('}').filter(|&e| after[..e].bytes().all(|b| b.is_ascii_digit() || b == b','));
        match end.map(|e| (&after[..e], e)) {
            Some((body, e)) if !body.is_empty() && !body.starts_with(',') => {
                let (min, max) = body.split_once(',').unwrap_or((body, body));
                let min: usize = min.parse().expect("repetition count");
                match (max.is_empty(), body.contains(','), min >= 12) {
                    (true, _, _) => out.push_str(&format!("{{{min},}}")),
                    (false, true, _) => out.push_str(&format!("{{{min},}}")),
                    (false, false, true) => out.push_str("{12,}"),
                    (false, false, false) => out.push_str(&format!("{{{min}}}")),
                }
                rest = &after[e + 1..];
            }
            _ => {
                out.push('{');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
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
        // Repetitions are bounded (see "linear" in the module docs): a
        // longer token matches its first 255 characters.
        let tokens = vec![
            r("private-key", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----", E::None, E::None, C::PemHeader),
            r("aws-access-key-id", r"(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}", E::UpperDigit, E::UpperDigit, C::None),
            r("github-token", r"gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255}", E::Alnum, E::None, C::None),
            r("gitlab-token", r"glpat-[A-Za-z0-9_\-]{20,255}", E::Alnum, E::None, C::None),
            r("slack-token", r"xox[baprs]-[A-Za-z0-9\-]{10,255}", E::Alnum, E::None, C::None),
            r("stripe-secret-key", r"[sr]k_live_[0-9A-Za-z]{20,255}", E::Alnum, E::None, C::None),
            // Before `openai-api-key`: at the same position the first
            // alternative wins.
            r("anthropic-api-key", r"sk-ant-[A-Za-z0-9_\-]{32,255}", E::Alnum, E::None, C::None),
            r("openai-api-key", r"sk-(?:proj-)?[A-Za-z0-9_\-]{32,255}", E::Alnum, E::None, C::Entropy(3.5)),
            r("google-api-key", r"AIza[0-9A-Za-z_\-]{35}", E::Alnum, E::Base64Url, C::None),
            r("jwt", r"eyJ[A-Za-z0-9_\-]{10,256}\.eyJ[A-Za-z0-9_\-]{10,64}", E::Alnum, E::None, C::Jwt),
            // `postgres://app:<password>@db`: matched from `://` (a literal
            // for the prefilter; also `:\/\/`, JSON's escaped form); the
            // scheme is not needed. The password is everything after the
            // first `:` of the user info, so it may contain `:`.
            r(
                "url-password",
                r#":(?://|\\/\\/)[^\s:/?#@'"<>]{0,128}:(?P<pw>[^\s/?#@'"<>]{8,128})@[A-Za-z0-9\[]"#,
                E::None,
                E::None,
                C::UrlPassword,
            ),
        ];
        let assignment = r("generic-secret-assignment", &assignment_pattern(), E::None, E::None, C::Assignment);
        let alternation: Vec<String> = tokens.iter().enumerate().map(|(i, t)| format!("(?P<t{i}>{})", t.pattern)).collect();
        let compile = |p: &str| {
            regex::bytes::RegexBuilder::new(&format!("(?-u){p}"))
                .size_limit(64 << 20)
                .dfa_size_limit(16 << 20)
                .build()
                .expect("valid secret pattern")
        };
        let token_re = compile(&alternation.join("|"));
        let token_caps = compile(&unbounded(&alternation.join("|")));
        let assignment_re = compile(&assignment.pattern);
        let assignment_caps = compile(&unbounded(&assignment.pattern));
        let assign = AssignGroups::new(&assignment_re);
        Rules {
            token_groups: (0..tokens.len()).map(|i| group(&token_re, &format!("t{i}"))).collect(),
            token_values: vec![group(&token_re, "pw")],
            assignment_re,
            assignment_caps,
            assign,
            token_re,
            token_caps,
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

/// Letters in a word from which [`english_like`] judges it.
const ENGLISH_MIN: usize = 8;

/// How common each pair of letters is inside words, as log2 of its
/// frequency relative to a uniform distribution, clamped to −4…4 and stored
/// as `b'e' + value`. Row: first letter. Counted over the camelCase humps
/// (3+ letters) of the Python standard library's identifiers and prose.
const BIGRAMS: [[u8; 26]; 26] = [
    *b"bfggbcfbfadhghafahghedddea", // a
    *b"fcdbeaaaedafbbecaeeceaaada", // b
    *b"gaecgbbgeaffcchcafdgebaada", // c
    *b"fccehcbagaaeccfbaeecebbaca", // d
    *b"gdghffecdacgfhdfeihhdedgda", // e
    *b"eaccffbagaaeabfbaedeeaaaca", // f
    *b"dabbgaceeaadcedbaeecdaaaaa", // g
    *b"gabbfaaaeabccbfaadcecaaaba", // h
    *b"fegffefababgfigfbfggaeadae", // i
    *b"baaacaaabaaaaacaaabacaaaaa", // j
    *b"dabbfabbeaacabbbabdbbabaaa", // k
    *b"gccehcbbhabgccgdabefecaafa", // l
    *b"gdachaaafabddbffaaeceaaaba", // m
    *b"gbgggehbfbddcefdacgheebaca", // n
    *b"deffbdebdadffhefahfffefdab", // o
    *b"gbccgdbdeaafbbfeagefeabada", // p
    *b"aaaaaaaaaaaaaaaabbbafaaaaa", // q
    *b"hceeidebgaddfehdafggedcaea", // r
    *b"ebfdhccfgadedcffccghfbcaea", // s
    *b"gcedidbghaaedcgeagffebcafb", // t
    *b"efededdaeaaffgcfafffaaaaaa", // u
    *b"faaagaaaeaaaaacaaaaaaaaaaa", // v
    *b"eabbeaaceaabaddaaddaaaaaaa", // w
    *b"cadbdcaadaabcabdaabeaaacca", // x
    *b"bbbbcaaacaaccdbeabddaabaaa", // y
    *b"caaaeaaacaaaaabaaabaaaaaaa", // z
];

/// Do these letters read like words (`getPasswordFromEnv`, `XMLHttpRequest`,
/// `changeme`) rather than random letters (`qzvxkwprmtfhjlnb`, a Google app
/// password)? The mean score of the letter pairs inside each camelCase hump
/// must not be below a uniform distribution's. Random letters pass ~1 % of
/// the time at 16 letters; identifiers fail ~0.7 % of the time (by
/// occurrence: mostly ioctl names and other abbreviations).
fn english_like(letters: &[u8]) -> bool {
    let mut score = 0i32;
    let pairs = letters.len().saturating_sub(1) as i32;
    for (i, w) in letters.windows(2).enumerate() {
        let hump = w[1].is_ascii_uppercase()
            && (w[0].is_ascii_lowercase() || letters.get(i + 2).is_some_and(u8::is_ascii_lowercase));
        if !hump {
            let row = &BIGRAMS[(w[0].to_ascii_lowercase() - b'a') as usize];
            score += i32::from(row[(w[1].to_ascii_lowercase() - b'a') as usize]) - i32::from(b'e');
        }
    }
    // A long run of lower-case letters is held to a higher bar (a mean of
    // 0.5): random ones (Google app passwords) otherwise pass ~2 % of the
    // time (0.2 % with it); compounds in other languages (`adgangskoden`)
    // still pass.
    let lower = letters.len() >= 12 && letters.iter().all(u8::is_ascii_lowercase);
    score * if lower { 2 } else { 1 } >= if lower { pairs } else { 0 }
}

/// Is the capitalisation that of words: lower-case, upper-case, or
/// camelCase humps of 2+ lower-case letters (or a two-letter word: `OnDrop`,
/// `userIdField`; the last hump may be a capital alone: `posX`), maybe
/// after an acronym of 2+ capitals (`CFData`, `getHTTPClient`,
/// `XMLHttpRequest`)? Random letters (`aEMexGAnEbQW`) are not.
fn plain_case(word: &[u8]) -> bool {
    const TWO: &[&[u8; 2]] = &[
        b"on", b"no", b"id", b"of", b"to", b"in", b"by", b"is", b"at", b"or", b"up", b"do", b"go", b"my", b"if", b"as", b"be", b"an", b"it",
        b"we", b"me", b"so", b"us", b"db", b"io", b"ok", b"os", b"ui", b"js", b"ip", b"tx", b"rx", b"ts", b"ms", b"vm", b"fs", b"fn",
    ];
    let runs: Vec<&[u8]> = word.chunk_by(|a, b| a.is_ascii_uppercase() == b.is_ascii_uppercase()).collect();
    runs.iter().enumerate().all(|(i, run)| {
        let last = i + 1 == runs.len();
        match run[0].is_ascii_uppercase() {
            // Followed by lower-case letters: one capital, or an acronym and one.
            true => last || run.len() == 1 || run.len() >= 3,
            false => i == 0 || last || run.len() >= 2 || TWO.iter().any(|w| **w == [runs[i - 1][runs[i - 1].len() - 1].to_ascii_lowercase(), run[0]]),
        }
    })
}

/// One word of an identifier: `get`, `Password`, `API`, `v2`, `accessToken`,
/// `2024`. Random credentials mix case and digits in ways words do not.
/// With `english`, a word of [`ENGLISH_MIN`]+ letters must read like words
/// ([`english_like`]), with acronyms allowed ([`plain_case`]).
fn wordlike(seg: &[u8], english: bool) -> bool {
    if number(seg) {
        return true;
    }
    let letters = seg.iter().take_while(|b| b.is_ascii_alphabetic()).count();
    let (word, digits) = seg.split_at(letters);
    if !digits.iter().all(u8::is_ascii_digit) {
        return false;
    }
    if english && word.len() >= ENGLISH_MIN {
        return plain_case(word) && english_like(word);
    }
    if word.is_empty() || word.iter().all(u8::is_ascii_uppercase) {
        return true;
    }
    // lower, Capitalized or camelCase: no two upper-case letters in a row.
    !word.windows(2).any(|w| w[0].is_ascii_uppercase() && w[1].is_ascii_uppercase())
}

/// A number literal in code: `2147483648u32`, `0x7fff_ffff`, `1e9`,
/// `3.0f64` (split at `.` and `_` before this is asked).
fn number(seg: &[u8]) -> bool {
    let digits = seg.iter().take_while(|b| b.is_ascii_digit()).count();
    let (int, suffix) = seg.split_at(digits);
    if int.is_empty() {
        return false;
    }
    let hex = int == b"0" && suffix.first().is_some_and(|b| matches!(b, b'x' | b'X')) && suffix[1..].iter().all(u8::is_ascii_hexdigit);
    let typed = [&b"u8"[..], b"u16", b"u32", b"u64", b"u128", b"usize", b"i8", b"i16", b"i32", b"i64", b"i128", b"isize", b"f32", b"f64", b"l", b"ul", b"ll", b"ull", b"u", b"f", b"d", b"n"]
        .iter()
        .any(|t| suffix.eq_ignore_ascii_case(t));
    let exp = suffix.first().is_some_and(|b| matches!(b, b'e' | b'E')) && suffix.len() > 1 && suffix[1..].iter().all(u8::is_ascii_digit);
    suffix.is_empty() || hex || typed || exp
}

/// Made of words (see [`wordlike`]) between `.`, `_`, `-`, `:`, `/`?
fn identifier(v: &[u8]) -> bool {
    v.split(|b| matches!(b, b'.' | b'_' | b'-' | b':' | b'/')).all(|s| wordlike(s, true))
}

/// Does the value of a `key = value` assignment look like a credential?
///
/// Rejects what ordinary code and configuration put there: references
/// (`$VAR`, `${VAR}`, `%(x)s`, `*yaml_alias`, `@ivar`, `{{ tmpl }}`, see
/// [`whole_reference`] and [`strip_templates`]), placeholders
/// (`<your-key>`), hashes, encrypted values and code ([`not_a_secret`]),
/// identifiers and paths made of words (`settings.SECRET_KEY`,
/// `os.environ.API_KEY_V2`, `your-api-key-here`, `/run/secrets/db_password`),
/// and low-entropy strings. A sigil or a `${` *inside* a random password
/// (`$Xk9mQ2…`, `Xk9m%(Q2…`) does not make it a reference.
fn plausible_value(v: &[u8]) -> bool {
    let v = unquote(v);
    // Text in another script (`パスワードを変更`), or numbers
    // (`[62,70,27,163]`), not a credential.
    if v.is_empty()
        || v.iter().filter(|&&b| b >= 0x80).count() * 2 >= v.len()
        || !v.iter().any(u8::is_ascii_alphabetic)
        || whole_reference(trim_code_end(v))
        || not_a_secret(v)
    {
        return false;
    }
    // Judged without its templates, but its entropy is the whole value's:
    // the remainder of a random password with a `${x}` in it is short.
    let rest = strip_templates(v);
    let rest = match &rest {
        Some(rest) if rest.len() < 8 => return false,
        Some(rest) => rest.as_slice(),
        None => v,
    };
    // A reference to a path is code too (`&Self::Checkpoint`, `*key`).
    let rest = trim_code_end(rest);
    let rest = rest.strip_prefix(b"&mut ").or_else(|| rest.strip_prefix(b"&")).or_else(|| rest.strip_prefix(b"*")).unwrap_or(rest);
    !identifier(rest) && shannon_entropy(v) >= min_entropy(v)
}

/// Shannon entropy (bits per byte) a value needs to count as random: 3.2
/// from 19 bytes, less for shorter values, whose measured entropy is noisy
/// (3.0 at 16 bytes: about 1 in 20,000 random 16-character passwords from
/// `A-Za-z0-9!@#$%^&*` or printable ASCII measures below). Hex has 16
/// symbols, so less again (2.2 at 16 bytes, 2.9 from 32: a random
/// `RAILS_MASTER_KEY` measures about 3.8); lower-case letters a little
/// less (2.6 at 16: Google app passwords). Repetitive values
/// (`abc123abc123`, `xxxx-xxxx-xxxx`, `deadbeefdeadbeef`) are below.
fn min_entropy(v: &[u8]) -> f64 {
    let len = (v.len() as f64).log2();
    if v.iter().all(u8::is_ascii_hexdigit) {
        (len - 1.8).min(2.9)
    } else if v.iter().all(u8::is_ascii_lowercase) {
        (len - 1.4).min(3.2) // 26 symbols: 2.6 at 16 letters
    } else {
        (len - 1.0).min(3.2)
    }
}

/// `v` without the escaped or HTML-encoded quotes around it (`\"$x\"`,
/// `&#39;…&#39;`, `&quot;…&quot;`).
fn unquote(v: &[u8]) -> &[u8] {
    for q in [&b"\\\""[..], b"\\'", b"&quot;", b"&apos;", b"&#39;", b"&#34;", b"&#x27;", b"&#x22;"] {
        if let Some(inner) = v.strip_prefix(q).and_then(|v| v.strip_suffix(q)) {
            return inner;
        }
    }
    v
}

/// A Google app password as Google shows it, four groups of four
/// lower-case letters (`qzvx kwpr mtfh jlnb`): random, not words (`well
/// done good luck`) or a sample (`abcd efgh ijkl mnop`, `xxxx xxxx …`).
fn app_password(v: &[u8]) -> bool {
    let letters: Vec<u8> = v.iter().copied().filter(|&b| b != b' ').collect();
    let sequence = letters.windows(2).filter(|w| w[1] == w[0].wrapping_add(1)).count();
    letters.iter().all(u8::is_ascii_lowercase)
        && !english_like(&letters)
        && sequence * 2 < letters.len()
        && shannon_entropy(&letters) >= min_entropy(&letters)
}

/// Does `m` end with the shape of an app password ([`app_password`]),
/// maybe quoted?
fn app_password_shape(m: &[u8]) -> bool {
    let m = m.trim_ascii_end();
    let m = m.strip_suffix(b"\"").or_else(|| m.strip_suffix(b"'")).unwrap_or(m);
    m.len() >= 19 && m[m.len() - 19..].iter().enumerate().all(|(i, b)| if i % 5 == 4 { *b == b' ' } else { b.is_ascii_alphabetic() })
}

/// A reference or placeholder as the whole value: `$VAR`, `$this->pw`,
/// `$HOME/.config/x`, `@ivar`, `*yaml_alias`, `&anchor`, `!tag`,
/// `:symbol`, `%VAR%`, `<your-key>`. The name must be made of words, so `$Xk9mQ2vL7pR4` is not
/// one.
fn whole_reference(v: &[u8]) -> bool {
    // A name made of words, from these characters.
    let name = |n: &[u8], extra: &[u8]| {
        !n.is_empty()
            && n.iter().all(|b| b.is_ascii_alphanumeric() || extra.contains(b))
            && n.split(|b| !b.is_ascii_alphanumeric()).all(|s| wordlike(s, true) && plain_case(&s[..s.iter().take_while(|b| b.is_ascii_alphabetic()).count()]))
    };
    match v {
        // `<your-key>`, `<db password>`
        [b'<', inner @ .., b'>'] => name(inner, b"_-. "),
        [b'%', inner @ .., b'%'] => name(inner, b"_"),
        // `$_ENV['X']`, `$this->pw`, `$HOME/.config/x`
        [b'$', rest @ ..] => name(rest, b"_.-:>[]'\"/"),
        [b'@' | b'*' | b'&', rest @ ..] => name(rest, b"_.-/"),
        // YAML tags: `!vault`, `!!binary`, `!GetAtt`
        [b'!', rest @ ..] => {
            let tag = rest.strip_prefix(b"!").unwrap_or(rest);
            (1..=16).contains(&tag.len()) && tag.iter().all(u8::is_ascii_alphabetic) && plain_case(tag) && english_like(tag)
        }
        [b':', rest @ ..] => name(rest, b"_"),
        _ => false,
    }
}

/// `v` without the template expressions in it (`${VAR}`,
/// `${VAR:-default}`, `${{ x }}`, `$(VAR)`, `{{ … }}`, `{% … %}`,
/// `<%= … %>`, `#{…}`, `%{…}`, `@{…}`, `%(name)s`), or `None` if there are
/// none. An expression must be closed, and those that take a name must
/// start with one made of words, followed by the closer or an operator, so
/// the `$(` or `%(` of a random password is left alone.
fn strip_templates(v: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let (mut i, mut any) = (0, false);
    while i < v.len() {
        match template_end(&v[i..]) {
            Some(n) => {
                any = true;
                i += n;
            }
            None => {
                out.push(v[i]);
                i += 1;
            }
        }
    }
    any.then_some(out)
}

/// Length of the template expression at the start of `s`, if there is one
/// (see [`strip_templates`]).
fn template_end(s: &[u8]) -> Option<usize> {
    let close = |open: usize, closer: &[u8]| s[open..].windows(closer.len()).position(|w| w == closer).map(|p| open + p + closer.len());
    // A name made of words right after the opener, then one of `then`.
    let named = |open: usize, then: &[u8]| {
        let rest = &s[open..];
        let n = rest.iter().take_while(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.')).count();
        let name = &rest[..n];
        name.first().is_some_and(|b| !b.is_ascii_digit())
            && name.split(|&b| b == b'.').all(|w| w.is_empty() || identifier(w))
            && rest.get(n).is_some_and(|b| then.contains(b))
    };
    match s {
        [b'{', b'{', ..] | [b'$', b'{', b'{', ..] => close(2, b"}}"),
        [b'{', b'%', ..] => close(2, b"%}"),
        [b'<', b'%', ..] => close(2, b"%>"),
        [b'$', b'{', ..] if named(2, b"}:-=?+#%/^,@[") => close(2, b"}"),
        [b'#' | b'%' | b'@', b'{', ..] if named(2, b"}[(") => close(2, b"}"),
        [b'$', b'(', ..] if named(2, b")") => close(2, b")"),
        [b'%', b'(', ..] if named(2, b")") => close(2, b")").map(|n| n + usize::from(s.get(n).is_some_and(u8::is_ascii_alphabetic))),
        _ => None,
    }
}

/// A value that is not a secret one could use, or not a literal at all: a
/// password hash (`$2b$12$…`, `pbkdf2_sha256$…`, `{SSHA}…`), an encrypted
/// value (`ENC(…)`, Spring's `{cipher}…`, Vault's `vault:v1:…`, AWS KMS's
/// `AQICAH…`), a JSON object or array, or code ([`code_like`]).
fn not_a_secret(v: &[u8]) -> bool {
    const CRYPT: &[&str] = &[
        "1", "2a", "2b", "2x", "2y", "5", "6", "7", "y", "gy", "apr1", "md5", "sha1", "bcrypt", "scrypt", "argon2i", "argon2d", "argon2id",
        "pbkdf2", "pbkdf2-sha1", "pbkdf2-sha256", "pbkdf2-sha512",
    ];
    const DJANGO: &[&str] = &["pbkdf2_sha256", "pbkdf2_sha1", "argon2", "bcrypt_sha256", "bcrypt", "scrypt", "sha1", "md5", "unsalted_md5", "unsalted_sha1", "crypt"];
    const SCHEMES: &[&str] = &[
        "ssha", "sha", "ssha256", "ssha384", "ssha512", "sha256", "sha384", "sha512", "md5", "smd5", "crypt", "bcrypt", "scrypt", "argon2",
        "pbkdf2", "pbkdf2-sha1", "pbkdf2-sha256", "pbkdf2-sha512", "cipher",
    ];
    let prefix = |from: usize, end: u8, names: &[&str]| {
        v[from..].iter().position(|&b| b == end).is_some_and(|n| names.iter().any(|w| w.as_bytes().eq_ignore_ascii_case(&v[from..from + n])))
    };
    // A hash has another `$` field and nothing but its base64 alphabet.
    let hash = || v.iter().filter(|&&b| b == b'$').count() >= 2 && v.iter().all(|b| b.is_ascii_alphanumeric() || b"$./=,+-_".contains(b));
    (v[0] == b'$' && prefix(1, b'$', CRYPT) && hash())
        || (prefix(0, b'$', DJANGO) && hash())
        || (v[0] == b'{' && prefix(1, b'}', SCHEMES))
        || v.starts_with(b"vault:v")
        || v.starts_with(b"AQICAH")
        || (v.starts_with(b"{\"") && v.ends_with(b"}"))
        || (v.starts_with(b"[\"") && v.ends_with(b"]"))
        || code_like(v)
}

/// Code rather than a literal (random passwords practically never have
/// these shapes, which all need names made of words):
///
/// * a method call (`re.compile(…`, `"x".format(…`, `input.parse()?`) or
///   a member of a call's result (`import("m").Name`);
/// * a call that goes on on the next line (`CFDataCreate(alloc,`);
/// * a generic type (`Option<String>,`, `Rc<Cell<T>>`);
/// * a call or index ending the value, brackets balanced, after a name:
///   qualified (`os.getenv("PW")`, `Token::Str("x")`), or one word of 4+
///   letters (`config["db"]`, `Aligned64(x)`, `Some(x)`), or `ENC(…)`
///   (Jasypt), or a slice type (`&[AnsiString<'_>]`).
fn code_like(raw: &[u8]) -> bool {
    let v = trim_code_end(raw);
    let goes_on = matches!(raw.last(), Some(b'(' | b',' | b'\\'));
    let ident = |b: &u8| b.is_ascii_alphanumeric() || *b == b'_';
    let name_before = |end: usize| v[..end].iter().rev().take_while(|b| ident(b)).count();
    // A name made of words: `compile`, `getenv`, `SharedSecret`, `Aligned64`.
    let word = |w: &[u8], min: usize| {
        w.iter().filter(|b| b.is_ascii_alphabetic()).count() >= min
            && w.first().is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_')
            && w.iter().all(ident)
            && w.split(|&b| b == b'_').all(|p| {
                let letters = &p[..p.iter().take_while(|b| b.is_ascii_alphabetic()).count()];
                plain_case(letters) && english_like(letters)
            })
    };
    let closes = |from: usize| goes_on || v[from..].contains(&b')');
    let method = |i: usize| {
        v[i] == b'.' && i > 0 && (ident(&v[i - 1]) || b")]\"'".contains(&v[i - 1])) && {
            let n = v[i + 1..].iter().take_while(|b| b.is_ascii_alphabetic()).count();
            let name = &v[i + 1..i + 1 + n];
            n >= 4 && name[0].is_ascii_lowercase() && word(name, 4) && v.get(i + 1 + n) == Some(&b'(') && closes(i + 1 + n)
        }
    };
    let member = |i: usize| {
        v[i] == b')' && v.get(i + 1) == Some(&b'.') && v[i + 2..].iter().take_while(|b| b.is_ascii_alphabetic()).count() >= 2 && {
            // The call whose result it is: `name(…)`.
            let mut depth = 0usize;
            let open = (0..i).rev().find(|&j| match v[j] {
                b')' => {
                    depth += 1;
                    false
                }
                b'(' if depth == 0 => true,
                b'(' => {
                    depth -= 1;
                    false
                }
                _ => false,
            });
            open.is_some_and(|j| word(&v[j - name_before(j)..j], 3))
        }
    };
    if (0..v.len()).any(|i| method(i) || member(i)) {
        return true;
    }
    if let Some(open) = v.iter().position(|&b| b == b'(') {
        if goes_on && name_before(open) == open && word(&v[..open], ENGLISH_MIN) {
            return true;
        }
    }
    let generic = v.last() == Some(&b'>');
    if !matches!(v.last(), Some(b')' | b']' | b'>')) {
        return false;
    }
    // Brackets balance. `<` and `>` count only in a type (elsewhere they
    // are operators or macro input: `Token![<](span)`).
    let mut depth = Vec::new();
    for (i, &b) in v.iter().enumerate() {
        let arrow = i > 0 && matches!(v[i - 1], b'-' | b'=');
        let closes = match b {
            b'(' | b'[' => {
                depth.push(b);
                None
            }
            b'<' if generic => {
                depth.push(b);
                None
            }
            b')' => Some(b'('),
            b']' => Some(b'['),
            b'>' if generic && !arrow => Some(b'<'),
            _ => None,
        };
        if closes.is_some() && depth.pop() != closes {
            return false;
        }
    }
    if !depth.is_empty() {
        return false;
    }
    let opener = |b: &u8| matches!(b, b'(' | b'[') || (generic && *b == b'<');
    let Some(open) = v.iter().position(opener) else { return false };
    let head = v[..open].strip_prefix(b"&mut ").unwrap_or(&v[..open]);
    let sigils = head.iter().take_while(|b| b"&*<".contains(b)).count();
    let head = &head[sigils..];
    if head.is_empty() {
        return sigils > 0 && v[open] == b'['; // `&[u8]`
    }
    // A path: names joined by `.`, `::` or `->` (a macro name ends in `!`).
    let mut parts = Vec::new();
    let mut rest = head;
    loop {
        let n = rest.iter().take_while(|b| ident(b) || **b == b'$').count();
        let (part, after) = rest.split_at(n);
        parts.push(part.strip_prefix(b"$").unwrap_or(part));
        let after = after.strip_prefix(b"!").unwrap_or(after);
        match [&b"."[..], b"::", b"->"].into_iter().find(|s| after.starts_with(s)) {
            Some(sep) => rest = &after[sep.len()..],
            None if after.is_empty() => break,
            None => return false,
        }
    }
    let type_name = parts.last().is_some_and(|p| p.first().is_some_and(u8::is_ascii_uppercase));
    // A statement (`_wcsdup(password);`): any name.
    if raw.ends_with(b";") && parts.iter().all(|p| p.len() >= 2) && head.len() >= 3 {
        return true;
    }
    match (generic, parts.as_slice()) {
        (true, _) => {
            const SHORT: &[&[u8]] = &[b"Rc", b"Arc", b"Box", b"Vec", b"Cow", b"Fn", b"Ref", b"Pin", b"Map", b"Set", b"std"];
            type_name && parts.iter().all(|p| word(p, 4) || SHORT.contains(p))
        }
        (false, [one]) => word(one, 4) || *one == b"ENC",
        (false, _) => parts.iter().all(|p| !p.is_empty() && (word(p, 0) || p.len() <= 3)),
    }
}

/// `v` without what ends an expression or line of code: `?`, `!`, `,`,
/// `;`, and an opening bracket or `\` the expression continues after.
fn trim_code_end(v: &[u8]) -> &[u8] {
    let n = v.iter().rev().take_while(|b| b"?!,;([{\\".contains(b)).count();
    &v[..v.len() - n]
}

/// Does the key of an assignment name a credential? `caps` is a match of
/// the assignment rule in `lower` (`text` lowercased). See [`KEYWORDS`].
fn credential_key(caps: &regex::bytes::Captures, g: &AssignGroups, lower: &[u8], text: &[u8]) -> bool {
    let kw = caps.get(g.kw).expect("keyword group");
    let k = kw.as_bytes();
    let ident = |b: &u8| b.is_ascii_alphanumeric();
    let prev = kw.start().checked_sub(1).map(|i| lower[i]);
    let after_ident = prev.as_ref().is_some_and(ident);
    // Bounded look-behind (see "linear" in the module docs).
    let before = &lower[kw.start().saturating_sub(256)..kw.start()];
    // SQL: `WITH [ENCRYPTED] PASSWORD '…'`, `IDENTIFIED BY '…'`.
    let identified = k.starts_with(b"identified");
    let sql = caps.get(g.sql);
    if identified || sql.is_some() {
        let Some(sql) = sql else { return false };
        if caps.get(g.s).is_none() || sql.start() != kw.end() || after_ident {
            return false;
        }
        let words = before.trim_ascii_end();
        let word = |w: &[u8]| words.strip_suffix(w).is_some_and(|r| !r.last().is_some_and(ident));
        return identified || (k == b"password" && (word(b"with") || word(b"encrypted")));
    }
    if matches!(k, b"secret" | b"token") {
        if after_ident {
            return false; // `mytoken`, `topsecret`
        }
        if k == b"token" {
            let before = before.strip_suffix(b"_").or_else(|| before.strip_suffix(b"-")).unwrap_or(&[]);
            let word = &before[before.iter().rposition(|b| !ident(b)).map_or(0, |i| i + 1)..];
            if TOKEN_NOT_CREDENTIAL.iter().any(|w| w.as_bytes() == word) {
                return false;
            }
        }
    }
    // `app_key`, `appKey`, `RAILS_MASTER_KEY`, not `whatsappkey`.
    if caps.get(g.kk).is_some() && after_ident && !(text[kw.start()].is_ascii_uppercase() && text[kw.start() - 1].is_ascii_lowercase()) {
        return false;
    }
    let suffix = caps.get(g.sfx).map_or(&b""[..], |m| m.as_bytes());
    if suffix
        .split(|b| matches!(b, b'_' | b'-'))
        .any(|w| NOT_A_CREDENTIAL.iter().any(|n| n.as_bytes() == w))
    {
        return false;
    }
    if let Some(el) = caps.get(g.el) {
        let name = before.iter().rposition(|b| !(ident(b) || matches!(b, b'_' | b'-' | b'.' | b':')));
        return match el.as_bytes().starts_with(b"</key>") {
            // A plist entry: the keyword is (part of) the `<key>`.
            true => name.is_some_and(|i| before[..=i].ends_with(b"<key>")),
            // An element: the keyword is part of the name of the tag just opened.
            false => name.is_some_and(|i| before[i] == b'<'),
        };
    }
    true
}

/// The part of an assignment match to judge (see [`assignment_pattern`]).
/// The rest of a line is the value only in a configuration line; in code,
/// only the token it starts with. A value that runs to the end of the line
/// is judged without its quotes (`- "DB_PASSWORD=…"`, `"token": "…",`).
fn assignment_value(caps: &regex::bytes::Captures, g: &AssignGroups, text: &[u8]) -> Option<std::ops::Range<usize>> {
    let mut span = g.values.iter().find_map(|&i| caps.get(i))?.range();
    let line = g.line.iter().any(|&i| caps.get(i).is_some());
    if line && !config_line(text, caps.get(g.kw).expect("keyword group").start()) {
        span.end = span.start + code_token(&text[span.clone()])?;
    } else if line || g.k8s.iter().any(|&i| caps.get(i).is_some()) {
        let v = &text[span.clone()];
        // `"…",` in JSON-like lines; otherwise a trailing `,` / `;` is kept,
        // as it tells code (`f(x,`, `g(x);`).
        let bare = v.strip_suffix(b",").or_else(|| v.strip_suffix(b";")).unwrap_or(v);
        let quoted = bare.len() > 1 && matches!(bare[0], b'"' | b'\'') && bare.last() == Some(&bare[0]);
        let v = if quoted { &bare[..bare.len() - 1] } else { v.strip_suffix(b"\"").or_else(|| v.strip_suffix(b"'")).unwrap_or(v) };
        span.end = span.start + v.len();
        span.start += usize::from(quoted);
    }
    // `Token::Str(…)` (a path in code) is not `token: value`.
    if text[span.start] == b':' && text[span.start - 1] == b':' {
        return None;
    }
    Some(span)
}

/// The token an unquoted value in code is: the run of credential characters
/// it starts with, which must end the token (`f(password=Xk9…)`; `x = a(b)`
/// is not one). Its length, if 12 or more.
fn code_token(v: &[u8]) -> Option<usize> {
    let n = v.iter().take_while(|b| b.is_ascii_alphanumeric() || b"!#$%&*+./:=?@^_~|-".contains(b)).count();
    (n >= 12 && v.get(n).is_none_or(|b| b.is_ascii_whitespace() || b",;)]}\"'".contains(b))).then_some(n)
}

/// Where the value of a `key = value` match in `m` (lowercased) starts:
/// after the key, a closing quote, blanks, the separator and blanks. `None`
/// if the key is not followed by a separator on the same line (an element,
/// a Kubernetes `value:`, SQL).
fn value_start(m: &[u8]) -> Option<usize> {
    let mut i = m.iter().take_while(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-')).count();
    i += usize::from(matches!(m.get(i), Some(b'"' | b'\'')));
    let blanks = |i: usize| i + m[i..].iter().take_while(|b| matches!(b, b' ' | b'\t')).count();
    i = blanks(i);
    let sep = [&b":="[..], b"=>", b":", b"="].into_iter().find(|s| m[i..].starts_with(s))?;
    Some(blanks(i + sep.len()))
}

/// Does a key starting at `kw` start a configuration line: is the text
/// before it on its line nothing but the rest of the key, maybe indented,
/// quoted, a YAML list item or after `export` (`spring.datasource.`,
/// `  DB_`, `- "`, `export `)? Looks back at most 256 bytes.
fn config_line(text: &[u8], kw: usize) -> bool {
    let from = kw.saturating_sub(256);
    let before = &text[from..kw];
    let line = match before.iter().rposition(|&b| b == b'\n') {
        Some(i) => &before[i + 1..],
        None if from == 0 => before,
        None => return false,
    };
    let mut s = line.trim_ascii_start();
    for p in [&b"export "[..], b"set ", b"-"] {
        if let Some(rest) = s.strip_prefix(p) {
            s = rest.trim_ascii_start();
            break;
        }
    }
    let s = s.strip_prefix(b"\"").or_else(|| s.strip_prefix(b"'")).unwrap_or(s);
    s.iter().all(|&b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

/// Is the password of a `scheme://user:password@host` URL a credential,
/// not a placeholder (`user:password@`, `postgres:postgres@`,
/// `${USER}:${PASS}@`, `<user>:<password>@`, `****`)? It is judged
/// percent-decoded (`%21Xk9…` is `!Xk9…`).
fn plausible_url_password(v: &[u8]) -> bool {
    let decoded = percent_decode(v);
    let v = decoded.as_slice();
    if v.is_empty() || matches!(v[0], b'*' | b'[') || whole_reference(v) {
        return false;
    }
    let stripped = strip_templates(v);
    let v = match &stripped {
        Some(rest) if rest.len() < 4 => return false,
        Some(rest) => rest.as_slice(),
        None => v,
    };
    // A password a person typed is shorter and less random than a token:
    // a lower bar than `plausible_value`, but never a plain word or number.
    let identifier = v.split(|b| matches!(b, b'.' | b'_' | b'-' | b':')).all(|s| wordlike(s, false));
    !identifier && shannon_entropy(v) >= 2.5
}

fn percent_decode(v: &[u8]) -> Vec<u8> {
    let hex = |b: u8| (b as char).to_digit(16);
    let mut out = Vec::with_capacity(v.len());
    let mut i = 0;
    while i < v.len() {
        match (v[i], v.get(i + 1).and_then(|&b| hex(b)), v.get(i + 2).and_then(|&b| hex(b))) {
            (b'%', Some(h), Some(l)) => {
                out.push((h * 16 + l) as u8);
                i += 3;
            }
            (b, ..) => {
                out.push(b);
                i += 1;
            }
        }
    }
    out
}

/// Is `s` made only of words (see [`wordlike`]) between `.`, `_`, `-`,
/// `:`, `/`, whitespace and quotes? (Then so is the value in it, which
/// [`plausible_value`] would reject.)
fn identifier_like(s: &[u8]) -> bool {
    s.split(|&b| matches!(b, b'.' | b'_' | b'-' | b':' | b'/' | b'"' | b'\'') || b.is_ascii_whitespace())
        .all(|s| wordlike(s, true))
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

/// [`pem_body_follows`] for a key inside a string literal, where the
/// newline is the two characters `\n` (a Google Cloud service-account key:
/// `"private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQ…"`), e.g. inside a
/// `.tar` archive or a database file.
fn escaped_pem_body_follows(rest: &[u8]) -> bool {
    let rest = rest.strip_prefix(b"\\r").unwrap_or(rest);
    let Some(rest) = rest.strip_prefix(b"\\n") else { return false };
    rest.iter()
        .take_while(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
        .count()
        >= 32
}

/// Longest JWT payload looked at past the pattern's match.
const JWT_MAX: usize = 64 << 10;

/// Is the rest of a JWT there after the pattern's match (header, `.`, the
/// start of the payload): the rest of the payload, then `.` and a signature
/// of 10+ characters? (Reads at most [`JWT_MAX`]; a payload has no `.`, so
/// the next match starts after what this read.)
fn jwt_tail(rest: &[u8]) -> bool {
    let b64 = |b: &u8| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-');
    let payload = rest.iter().take(JWT_MAX).take_while(|b| b64(b)).count();
    let Some(sig) = rest[payload..].strip_prefix(b".") else { return false };
    sig.iter().take(10).take_while(|b| b64(b)).count() >= 10
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
    search_with(&rules.token_re, &rules.token_caps, &rules.token_values, None, stripped, hay, hay, limit, out, |caps| {
        let i = rules.token_groups.iter().position(|&g| caps.get(g).is_some()).expect("one alternative matched");
        &rules.tokens[i]
    });
}

/// The assignment rule. `lower` is `text` ASCII-lowercased (same offsets):
/// the keywords are matched there case-sensitively, which keeps the regex
/// prefilter effective, and values are judged on the original `text`.
fn search_assignments(text: &[u8], lower: &[u8], limit: usize, out: &mut Vec<Hit>) {
    let rules = rules();
    search_with(&rules.assignment_re, &rules.assignment_caps, &rules.assign.values, Some(&rules.assign), false, lower, text, limit, out, |_| {
        &rules.assignment
    });
}

/// How much work a search may spend *again* (on bytes it has already
/// searched or matched, after restarting inside a rejected match) per byte
/// of its input before `search_with` gives up on it (`scan-limit`).
/// Work is counted in units of about a nanosecond: a byte searched again
/// is 1, starting such a search `FIND_COST` (256), a byte whose capture groups
/// are computed again `CAPTURE_COST` (160). Work done once per byte is bounded
/// by the input itself and not counted. Ordinary text does almost no work
/// again; crafted input that hits the limit is still scanned at 25+ MiB/s.
pub const WORK_FACTOR: usize = 16;
/// Work every search may spend again regardless of its size.
const WORK_SLACK: usize = 4 << 20;
const FIND_COST: usize = 256;
const CAPTURE_COST: usize = 160;

/// Run `re` over `hay` and judge each match on `text` (`hay` itself, or the
/// same bytes before lowercasing). `caps_re` computes the capture groups of
/// a match of `re` (on the match alone). `values`: capture groups that hold
/// the part of a match to judge (the whole match if none matched).
/// `assign`: `re` is an assignment pattern with these groups.
///
/// Worst-case linear (see the module docs): each search reads at most
/// about 1 KiB past the match it returns, and what is done again after a
/// restart inside a rejected match is counted ([`WORK_FACTOR`]). Past the
/// budget a `scan-limit` hit is reported and the search ends.
#[allow(clippy::too_many_arguments)]
fn search_with<'r>(
    re: &Regex,
    caps_re: &Regex,
    values: &[usize],
    assign: Option<&AssignGroups>,
    stripped: bool,
    hay: &[u8],
    text: &[u8],
    limit: usize,
    out: &mut Vec<Hit>,
    rule_of: impl Fn(&regex::bytes::Captures) -> &'r Rule,
) {
    let mut found = 0;
    let mut at = 0;
    let budget = WORK_FACTOR * hay.len() + WORK_SLACK;
    // Work done again so far, and how far the searches and the capture
    // groups computed have reached.
    let (mut work, mut searched, mut captured) = (0usize, 0usize, 0usize);
    while at < limit {
        // Judge the match span first; capture groups are much slower to
        // compute and only needed for the few matches that survive.
        let Some(whole) = re.find_at(hay, at) else { break };
        if whole.start() >= limit {
            break;
        }
        if at < searched {
            work += searched.min(whole.end()) - at + FIND_COST;
        }
        searched = searched.max(whole.end());
        if work > budget {
            // Crafted input: report it (which quarantines the file) rather
            // than spend more time on it.
            out.push(Hit {
                rule: "scan-limit",
                offset: whole.start(),
                excerpt: "crafted input? the scanner's work limit was reached here".to_string(),
            });
            break;
        }
        // Where to go on after a match rejected for its context: inside it,
        // where a real credential may start.
        let restart = whole.start() + 1;
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
        // The rest of a line counts only in a configuration line, and code
        // has many lines like `secret = config.secret_key.clone();`: where
        // the key does not start the line, reject such a match unless its
        // value starts with a token, before computing capture groups. Other
        // keys on the line may still match.
        if assign.is_some() && (hay[whole.end() - 1] == b'\n' || whole.end() == hay.len()) {
            let m = &hay[whole.range()];
            if let Some(v) = value_start(m) {
                if !config_line(text, whole.start()) && code_token(&text[whole.start() + v..whole.end()]).is_none() {
                    at = whole.start() + v;
                    continue;
                }
            }
        }
        if assign.is_some() {
            let m = &text[whole.range()];
            let body = match m.last() {
                Some(b',' | b';' | b')' | b']' | b'}') => &m[..m.len() - 1],
                _ => m,
            };
            // (An app password is words separated by spaces: judge it.)
            if identifier_like(body) && !app_password_shape(body) {
                continue;
            }
        }
        work += CAPTURE_COST * captured.clamp(whole.start(), whole.end()).saturating_sub(whole.start());
        captured = captured.max(whole.end());
        let caps = caps_re.captures_at(&hay[..whole.end()], whole.start()).expect("the same match");
        let rule = rule_of(&caps);
        if !rule.before.allows(prev) {
            // A real token may start inside this rejected match.
            at = restart;
            continue;
        }
        if !rule.after.allows(next) {
            continue;
        }
        if assign.is_some_and(|g| !credential_key(&caps, g, hay, text)) {
            // Another keyword may start inside (`mytoken_password = …`).
            at = restart;
            continue;
        }
        let span = match assign {
            Some(g) => match assignment_value(&caps, g, text) {
                Some(span) => span,
                None => continue,
            },
            None => values.iter().find_map(|&g| caps.get(g)).unwrap_or(whole).range(),
        };
        let token = &text[span];
        let ok = match rule.check {
            Check::None => true,
            Check::Entropy(min) => shannon_entropy(token) >= min,
            Check::Assignment if assign.is_some_and(|g| caps.get(g.g).is_some()) => app_password(token),
            Check::Assignment => plausible_value(token),
            Check::UrlPassword => plausible_url_password(token),
            Check::PemHeader => {
                let around = &text[whole.start().saturating_sub(256)..(whole.end() + 256).min(text.len())];
                let binary = stripped || around.contains(&0);
                let rest = &text[whole.end()..];
                !binary || pem_body_follows(rest) || escaped_pem_body_follows(rest)
            }
            Check::Jwt => jwt_tail(&text[whole.end()..]),
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

/// Code units of NUL-padded text: `size` bytes each, starting at multiples
/// of `size` in the file, ASCII in byte `ascii` (UTF-16LE: 2, 0; UTF-16BE:
/// 2, 1; UTF-32LE: 4, 0; UTF-32BE: 4, 3).
#[derive(Clone, Copy)]
struct Units {
    size: usize,
    ascii: usize,
}

/// The code units that the NUL bytes of `window` (at offset `at` of the
/// file) point to, if they agree on one: in UTF-16LE text the NULs (high
/// bytes of ASCII characters) are at odd offsets, and so on.
fn units_of(window: &[u8], at: usize) -> Option<Units> {
    let mut c = [0usize; 4];
    for z in memchr::memchr_iter(0, window) {
        c[(at + z) % 4] += 1;
    }
    let n: usize = c.iter().sum();
    let few = |k: usize| k * 16 <= n;
    let many = |k: usize| k * 4 >= n;
    let units = |size, ascii| Some(Units { size, ascii });
    match () {
        _ if n < 8 => None,
        _ if few(c[0] + c[2]) => units(2, 0),
        _ if few(c[1] + c[3]) => units(2, 1),
        _ if few(c[0]) && many(c[2]) && many(c[3]) => units(4, 0),
        _ if few(c[3]) && many(c[0]) && many(c[1]) => units(4, 3),
        _ => None,
    }
}

/// Append `data[from..to]` without its NUL bytes to `out`. With `units`,
/// a non-ASCII code unit next to ASCII text becomes one space, so that
/// none of its bytes is glued to a token as an "ASCII" neighbour (`令牌ghp_…`,
/// `キAKIA…` in UTF-16LE); elsewhere bytes are kept as they are, which also
/// keeps UTF-16 at another alignment and plain ASCII readable.
fn strip_nuls(out: &mut Vec<u8>, data: &[u8], from: usize, to: usize, units: Option<Units>) {
    let keep = |out: &mut Vec<u8>, bytes: &[u8]| out.extend(bytes.iter().copied().filter(|&b| b != 0));
    let Some(Units { size, ascii }) = units else {
        return keep(out, &data[from..to]);
    };
    let is_ascii = |unit: &[u8]| unit.iter().enumerate().all(|(i, &b)| i == ascii || b == 0);
    let text = |k: usize| {
        data.get(k..k + size)
            .is_some_and(|unit| is_ascii(unit) && matches!(unit[ascii], b'\t' | b'\n' | b'\r' | 0x20..=0x7e))
    };
    let first = from.next_multiple_of(size).min(to);
    keep(out, &data[from..first]);
    let mut k = first;
    while k + size <= to {
        let unit = &data[k..k + size];
        if is_ascii(unit) {
            if unit[ascii] != 0 {
                out.push(unit[ascii]);
            }
        } else if (k >= size && text(k - size)) || text(k + size) {
            out.push(b' ');
        } else {
            keep(out, unit);
        }
        k += size;
    }
    keep(out, &data[k..to]);
}

/// `s` ASCII-lowercased, with `-` as `_`, for the assignment rule: its
/// keywords then need fewer variants (see [`KEYWORDS`]). Offsets are kept.
fn lowercase_into(buf: &mut Vec<u8>, s: &[u8]) {
    buf.clear();
    buf.extend(s.iter().map(|&b| if b == b'-' { b'_' } else { b.to_ascii_lowercase() }));
}

// ---- NUL-separated text ------------------------------------------------------

/// Is `line` (between two NUL bytes) a line of text: valid UTF-8 without
/// control characters other than tab and CR?
fn text_line(line: &[u8]) -> bool {
    std::str::from_utf8(line).is_ok_and(|s| !s.chars().any(|c| c.is_control() && c != '\t' && c != '\r'))
}

/// The NUL-terminated lines of text in `data`, with their offsets, if such
/// lines carry at least half of its non-NUL bytes. That is text whose lines
/// are separated by NUL instead of newline, as in Vim's swap files
/// (`.name.swp`: each line NUL-terminated, the lines of a block stored last
/// to first, between binary headers and NUL padding), not code or
/// compressed data, nor UTF-16 (whose "lines" are single characters, so
/// only lines of 2 or more bytes count towards the share).
fn nul_separated_lines(data: &[u8]) -> Option<Vec<(usize, &[u8])>> {
    memchr::memchr(0, data)?;
    let (mut lines, mut text, mut other) = (Vec::new(), 0usize, 0usize);
    let mut start = 0;
    for end in memchr::memchr_iter(0, data) {
        let line = &data[start..end];
        if !line.is_empty() {
            if text_line(line) {
                lines.push((start, line));
                if line.len() >= 2 {
                    text += line.len();
                }
            } else {
                other += line.len();
            }
        }
        start = end + 1;
    }
    other += data.len() - start;
    (text > 0 && text >= other).then_some(lines)
}

/// Defence in depth for NUL-separated text ([`nul_separated_lines`]): its
/// lines are searched again joined by newlines, in file order and in
/// reverse (a Vim swap file stores the last line of a block first), so a
/// PEM header followed by its key material, or a `KEY=value` line ended by
/// NUL, is found. The joined text counts as binary data for the PEM rule
/// (key material must follow the header), as the NUL-stripped pass does.
/// Findings carry the line number of the line they start in.
fn scan_nul_separated(data: &[u8]) -> Vec<Finding> {
    let Some(lines) = nul_separated_lines(data) else { return Vec::new() };
    let mut found = Vec::new();
    let (mut lower, mut hits) = (Vec::new(), Vec::new());
    for order in [false, true] {
        let mut text = Vec::new();
        // (offset in `text`, offset in `data`) of every line.
        let mut starts = Vec::with_capacity(lines.len());
        let mut push = |(at, line): &(usize, &[u8])| {
            starts.push((text.len(), *at));
            text.extend_from_slice(line);
            text.push(b'\n');
        };
        match order {
            false => lines.iter().for_each(&mut push),
            true => lines.iter().rev().for_each(&mut push),
        }
        let mut start = 0;
        while start < text.len() && found.len() < MAX_FINDINGS {
            let end = (start + CHUNK).min(text.len());
            let window = &text[start..(end + OVERLAP).min(text.len())];
            hits.clear();
            search_tokens(window, end - start, true, &mut hits);
            lowercase_into(&mut lower, window);
            search_assignments(window, &lower, end - start, &mut hits);
            for h in hits.drain(..) {
                let at = start + h.offset;
                let i = starts.partition_point(|&(t, _)| t <= at) - 1;
                let line = 1 + newlines(&data[..starts[i].1]);
                let f = Finding { rule: h.rule, line, excerpt: h.excerpt };
                if !found.contains(&f) {
                    found.push(f);
                }
            }
            start = end;
        }
    }
    found
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
            let units = units_of(window, start);
            strip_nuls(&mut stripped, data, start, end, units);
            let limit = stripped.len();
            strip_nuls(&mut stripped, data, end, start + window.len(), units);
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

    if hits.len() + stripped_found.len() < MAX_FINDINGS {
        stripped_found.extend(scan_nul_separated(data));
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
    // A line value and the token in it (`KEY=value`) are both matches of
    // the assignment rule: report the line once.
    let mut lines = Vec::new();
    found.retain(|f| {
        if f.rule != rules().assignment.name {
            return true;
        }
        let first = !lines.contains(&f.line);
        lines.push(f.line);
        first
    });
    found.truncate(MAX_FINDINGS);
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    const PEM: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBGqZt3YkVvQ2mR8sXlN0pWcF4hTj7uK9eAoD1bLyS6xQAAAJgVb1oKFW9a
-----END OPENSSH PRIVATE KEY-----
";

    /// A Vim-like swap file: a binary header block, then `text`'s lines
    /// NUL-terminated, in file order or (as Vim stores them) last first.
    fn swap(text: &str, reversed: bool) -> Vec<u8> {
        let mut out = b"b0VIM 9.1".to_vec();
        out.resize(1024, 0);
        out.extend_from_slice(&[b't', b'p', 0, 0, 7, 0, 0, 0, 0x10, 0x20, 0, 0]);
        out.resize(2048, 0);
        let mut lines: Vec<&str> = text.lines().collect();
        if reversed {
            lines.reverse();
        }
        for l in lines {
            out.extend_from_slice(l.as_bytes());
            out.push(0);
        }
        out
    }

    #[test]
    fn nul_separated_text_is_scanned() {
        for reversed in [false, true] {
            let f = scan(&swap(PEM, reversed));
            assert!(f.iter().any(|f| f.rule == "private-key"), "reversed: {reversed}: {f:?}");
            let f = scan(&swap("x = 1\nDB_PASSWORD=Xk9mQ2vL7pR4wZt8\n", reversed));
            assert!(!f.is_empty(), "reversed: {reversed}");
        }
        // A PEM header in binary data still needs key material after it.
        let f = scan(&swap("-----BEGIN RSA PRIVATE KEY-----\nPEM_read_bio\n", false));
        assert!(f.is_empty(), "{f:?}");
        assert!(scan(&swap("hello\nworld\n", true)).is_empty());
        // Not NUL-separated text: code-like binary, and UTF-16.
        let mut bin: Vec<u8> = (0..4096u32).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect();
        bin.extend_from_slice(b"short\0");
        assert!(nul_separated_lines(&bin).is_none());
        let utf16: Vec<u8> = "some text in UTF-16".encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert!(nul_separated_lines(&utf16).is_none());
        assert!(nul_separated_lines(b"no nul at all").is_none());
    }

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
        // A sigil or template syntax inside a random value is no reference.
        for v in [&b"$Xk9mQ2vL7pR4wZt8"[..], b"@Xk9mQ2vL7pR4wZt8", b"Xk9m%(Q2vL7pR4wZt8", b"Xk9m${Q2v}L7pR4wZt8", b"qzvxkwprmtfhjlnb", b"%21Xk9mQ2vL7"] {
            assert!(plausible_value(v), "{}", String::from_utf8_lossy(v));
        }
        for v in [&b"${SECRET_KEY:-development-only}"[..], b"$2b$12$KIXQJbXk9mQ2vL7pR4wZt8eOuLmNp3q", b"ENC(G6N718UuyPE5bHyWKyuLQ)", b"os.getenv(\"DB_PASSWORD\")", b"Option<String>,", b"&#39;Xk&#39;"] {
            assert!(!plausible_value(v), "{}", String::from_utf8_lossy(v));
        }
    }

    #[test]
    fn words_and_random_letters() {
        for w in [&b"getPasswordFromEnv"[..], b"XMLHttpRequest", b"CFDataCreateWithBytesNoCopy", b"defaultpassword", b"userIdField", b"posX"] {
            assert!(plain_case(w) && (w.len() < ENGLISH_MIN || english_like(w)), "{}", String::from_utf8_lossy(w));
        }
        for w in [&b"qzvxkwprmtfhjlnb"[..], b"aEMexGAnEbQWaalh", b"fgbvLiUbhfedusrH"] {
            assert!(!(plain_case(w) && english_like(w)), "{}", String::from_utf8_lossy(w));
        }
        assert!(app_password(b"qzvx kwpr mtfh jlnb"));
        assert!(!app_password(b"abcd efgh ijkl mnop") && !app_password(b"well done good luck"));
    }

    #[test]
    fn code_and_config_lines() {
        for v in [&b"input.parse()?,"[..], b"Token::Str(\"x\"),", b"SharedSecret<Kem>,", b"&[AnsiString<'_>],", b"config[\"db\"]", b"ENC(abc)", b"\"foo\".into()"] {
            assert!(code_like(v), "{}", String::from_utf8_lossy(v));
        }
        for v in [&b"Xk9(mQ2)vL7pR4wZt8"[..], b"aRfbG<I?oiMeN3K>", b"9g.llq(m0_D/Z>eM/0N*b[[M", b"&(OQXSGt}M@b29;DAGSdV:)"] {
            assert!(!code_like(v), "{}", String::from_utf8_lossy(v));
        }
        let at = |t: &[u8]| config_line(t, t.len());
        assert!(at(b"x\nspring.datasource.") && at(b"  - \"DB_") && at(b"export ") && at(b""));
        assert!(!at(b"x\nconnect(host, ") && !at(b"    let "));
    }

    #[test]
    fn entropy_bars() {
        assert!((min_entropy(&[b'X'; 16]) - 3.0).abs() < 1e-9);
        assert!((min_entropy(&[b'x'; 16]) - 2.6).abs() < 1e-9, "lower-case");
        assert!((min_entropy(&[b'a'; 32]) - 2.9).abs() < 1e-9, "hex");
        assert_eq!(min_entropy(&[b'X'; 64]), 3.2);
    }

    #[test]
    fn unbounded_patterns() {
        assert_eq!(unbounded(r"a{12,256}b{256}c{0,4}d{16}e{3}[{]x\{"), r"a{12,}b{12,}c{0,}d{12,}e{3}[{]x\{");
    }

    #[test]
    fn utf16_layouts() {
        let le: Vec<u8> = "キーAKIA".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let units = units_of(&le.repeat(8), 0).expect("utf-16le");
        let mut out = Vec::new();
        strip_nuls(&mut out, &le, 0, le.len(), Some(units));
        assert_eq!(out, b"\xad\x30 AKIA");
    }
}
