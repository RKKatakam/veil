//! Engine-level secret detection.
//!
//! Every *public* file is scanned when it is snapshotted. A hit quarantines
//! the file: it is kept on the local machine (and in the encrypted local
//! vault) but never enters the snapshot graph. This is enforced by the
//! engine — there is no ignore file to forget.

use std::sync::OnceLock;

use regex::bytes::Regex;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    pub rule: &'static str,
    pub line: usize,
    /// Redacted excerpt that is safe to print.
    pub excerpt: String,
}

struct Rule {
    name: &'static str,
    re: Regex,
    /// Minimum Shannon entropy (bits/char) of the `s` capture group.
    min_entropy: Option<f64>,
}

const MAX_SCAN_BYTES: usize = 8 * 1024 * 1024;

fn rules() -> &'static [Rule] {
    static RULES: OnceLock<Vec<Rule>> = OnceLock::new();
    RULES.get_or_init(|| {
        let r = |name, pat: &str, min_entropy| Rule {
            name,
            re: Regex::new(pat).expect("valid secret pattern"),
            min_entropy,
        };
        vec![
            r("private-key", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----", None),
            r("aws-access-key-id", r"\b(?P<s>(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b", None),
            r("github-token", r"\b(?P<s>(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,}))\b", None),
            r("gitlab-token", r"\b(?P<s>glpat-[A-Za-z0-9_\-]{20,})\b", None),
            r("slack-token", r"\b(?P<s>xox[baprs]-[A-Za-z0-9\-]{10,})", None),
            r("stripe-secret-key", r"\b(?P<s>[sr]k_live_[0-9A-Za-z]{20,})\b", None),
            r("anthropic-api-key", r"\b(?P<s>sk-ant-[A-Za-z0-9_\-]{32,})", None),
            r("openai-api-key", r"\b(?P<s>sk-(?:proj-)?[A-Za-z0-9_\-]{32,})", Some(3.5)),
            r("google-api-key", r"\b(?P<s>AIza[0-9A-Za-z_\-]{35})\b", None),
            r("jwt", r"\b(?P<s>eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})\b", None),
            r(
                "generic-secret-assignment",
                r#"(?i)\b(?:api[_-]?key|secret[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|private[_-]?key|password|passwd)\b["']?\s*[:=]\s*["'](?P<s>[^"'\s]{12,})["']"#,
                Some(3.2),
            ),
        ]
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

fn redact(s: &[u8]) -> String {
    let s = String::from_utf8_lossy(s);
    let visible: String = s.chars().take(4).collect();
    format!("{visible}…({} chars)", s.chars().count())
}

/// Scan file content for likely credentials.
pub fn scan(data: &[u8]) -> Vec<Finding> {
    if data.len() > MAX_SCAN_BYTES || looks_binary(data) {
        return vec![];
    }
    let mut out = Vec::new();
    for rule in rules() {
        for caps in rule.re.captures_iter(data) {
            let whole = caps.get(0).unwrap();
            let secret = caps.name("s").unwrap_or(whole);
            if let Some(min) = rule.min_entropy {
                if shannon_entropy(secret.as_bytes()) < min {
                    continue;
                }
            }
            let line = data[..whole.start()].iter().filter(|&&b| b == b'\n').count() + 1;
            out.push(Finding {
                rule: rule.name,
                line,
                excerpt: redact(secret.as_bytes()),
            });
            if out.len() >= 16 {
                return out;
            }
        }
    }
    out.sort_by_key(|f| f.line);
    out
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
}
