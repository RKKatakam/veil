//! PR reviews (`docs/HUB.md` §13.24): what a reviewer's device signs.
//!
//! A review is a verdict on a PR's current **patch** (a hash of every file
//! change of every change in the stack, computed by the server), so an
//! approval stops counting the moment the files change. Revision numbers
//! are not signed: each viewer numbers revisions by what they can see
//! (two revisions that differ only in what they cannot see are one to
//! them). The reviewer's device signs under the context `hub-pr-review`;
//! the server checks the signature with the device the request is signed
//! in with and keeps it with the review.

/// The verdicts a review may give.
pub const VERDICTS: &[&str] = &["approve", "request-changes"];

/// What a review signs (context `hub-pr-review`): the project, the PR, the
/// patch and the verdict, each ended by a zero byte, so no two different
/// reviews sign the same bytes.
pub fn review_message(project: &str, pr: &str, patch: &str, verdict: &str) -> Vec<u8> {
    let mut m = Vec::new();
    for part in [project, pr, patch, verdict] {
        m.extend_from_slice(part.as_bytes());
        m.push(0);
    }
    m
}

/// Is `id` a PR id as the server makes them (`pr-` and 8 lowercase hex
/// digits)? Anything else names no PR, with the same answer as a PR the
/// caller may not see.
pub fn valid_pr_id(id: &str) -> bool {
    id.len() == 11 && id.starts_with("pr-") && id[3..].bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn review_messages_are_unambiguous() {
        let a = review_message("p", "pr-0000000a", "ab", "approve");
        let b = review_message("p", "pr-0000000a", "ab", "request-changes");
        let c = review_message("p", "pr-0000000b", "ab", "approve");
        let d = review_message("p\0pr-0000000a", "", "ab", "approve");
        assert!(a != b && a != c && a != d);
    }

    #[test]
    fn pr_ids() {
        assert!(valid_pr_id("pr-4f2a9c1b"));
        for bad in ["pr-4F2A9C1B", "pr-4f2a9c1", "pr-4f2a9c1bb", "pr_4f2a9c1b", "4f2a9c1b", "pr-4f2a9c1g", "pr-4f2a9c1é"] {
            assert!(!valid_pr_id(bad), "{bad}");
        }
    }
}
