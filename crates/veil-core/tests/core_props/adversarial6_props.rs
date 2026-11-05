//! Round-6 property tests (Fable): the policy pin's own invariant under
//! random policies, and never-panic fuzzing of the parsers and metadata
//! decoders a remote or a user feeds.
//!
//! Every `#[ignore = "BUG-NNN: …"]` test asserts the secure behaviour and
//! currently fails; see `docs/BUGS.md` ("Round 6 findings (Fable)").

use crate::adversarial_support;

use adversarial_support::*;
use proptest::prelude::*;
use veil_core::{
    commands::validate_tag_name,
    id::ChangeId,
    identity::{parse_public_identity, parse_public_key},
    keychain::{validate_scope_name, EmbargoRecord, KeyRing},
    policy::{fold_edit, weakens, Policy},
    workspace::validate_workspace_name,
    SshUrl, VPath,
};

// ---- the policy fold ------------------------------------------------------------------

const PATTERNS: &[&str] = &["a", "a/", "a/*", "a/**", "**/x", "*.env", ".env", "b/c", "b/", "**", "c", "*.pem"];
const TIERS: &[&str] = &["public", "public!", "cloak team", "cloak ops", "isolate", "ignore"];
const PATHS: &[&str] = &["a", "a/x", "a/b/x", "b/c", "b/x", ".env", "x.env", "a/.env", "c", "a/c", "k.pem", "b/c/.env"];

fn rule() -> impl Strategy<Value = String> {
    (0..PATTERNS.len(), 0..TIERS.len()).prop_map(|(p, t)| format!("{} {}", PATTERNS[p], TIERS[t]))
}

fn policy_text() -> impl Strategy<Value = String> {
    prop::collection::vec(rule(), 0..5).prop_map(|rules| rules.iter().map(|r| format!("{r}\n")).collect())
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 600, ..ProptestConfig::default() })]

    /// `fold_edit` documents its own check: the result must classify no
    /// path more weakly than *both* the old accepted policy and the
    /// member's file. Random accepted / parent / member policies over a
    /// handful of overlapping patterns.
    #[test]
    fn a_folded_edit_never_classifies_a_path_weaker_than_both_inputs(acc in policy_text(), par in policy_text(), cur in policy_text()) {
        let (accepted, parent, current) = (Policy::parse(&acc), Policy::parse(&par), Policy::parse(&cur));
        if let Ok(text) = fold_edit(&accepted, &parent, &current) {
            let folded = Policy::parse(&text);
            for path in PATHS {
                let p = VPath::new(path).unwrap();
                let (a, c, f) = (accepted.classify(&p, false), current.classify(&p, false), folded.classify(&p, false));
                prop_assert!(
                    !(weakens(&a, &f) && weakens(&c, &f)),
                    "path {path}: folded {} is weaker than accepted {} and member's {}\naccepted:\n{acc}parent:\n{par}current:\n{cur}folded:\n{text}",
                    f.keyword(), a.keyword(), c.keyword()
                );
            }
        }
    }
}

// ---- parsers never panic ---------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig { cases: 1500, ..ProptestConfig::default() })]

    #[test]
    fn ssh_url_parsing_never_panics_and_never_yields_an_option_like_name(s in "[a-zA-Z0-9@:/\\[\\]~.\\-_ ]{0,40}|.{0,30}") {
        if let Some(Ok(u)) = SshUrl::parse(&s) {
            prop_assert!(!u.host.starts_with('-'), "{s:?} → host {:?}", u.host);
            prop_assert!(u.user.as_deref().is_none_or(|x| !x.starts_with('-')), "{s:?} → user {:?}", u.user);
            let args = u.ssh_args();
            prop_assert!(args.iter().all(|a| !a.is_empty()));
            let _ = u.last_component();
            let _ = u.to_string();
        }
    }

    #[test]
    fn identity_and_id_parsers_never_panic(s in "(veil1)?[0-9a-fA-F]{0,300}|.{0,80}") {
        let _ = parse_public_identity(&s);
        let _ = parse_public_key(&s);
        let _ = ChangeId::reverse_hex_to_hex(&s);
        let _ = veil_core::ObjectId::from_hex(&s);
        let _ = validate_tag_name(&s);
        let _ = validate_workspace_name(&s);
        let _ = validate_scope_name(&s);
        let _ = VPath::new(&s);
    }
}

// ---- metadata decoders under mutation -------------------------------------------------

/// Flip, drop or insert bytes of `raw`.
fn mutate(raw: &[u8], edits: &[(usize, u8, u8)]) -> Vec<u8> {
    let mut out = raw.to_vec();
    for &(at, how, byte) in edits {
        if out.is_empty() {
            break;
        }
        let i = at % out.len();
        match how % 3 {
            0 => out[i] = byte,
            1 => {
                out.remove(i);
            }
            _ => out.insert(i, byte),
        }
    }
    out
}

fn sample_ring() -> (Vec<u8>, KeyRing) {
    let (alice, _, _) = new_repo("alice");
    let bob = veil_core::Identity::generate("bob");
    alice.keys().grant("team", &bob.public_id(), "bob").unwrap();
    alice.keys().rotate("team").unwrap();
    let ring = alice.keys().load_ring("team").unwrap().unwrap();
    (serde_json::to_vec(&ring).unwrap(), ring)
}

fn sample_embargo() -> Vec<u8> {
    let (alice, _, _) = new_repo("alice");
    let id = alice.keys().create_embargo("team", Some(4_102_444_800_000)).unwrap();
    alice.keys().release_embargo(&id).unwrap();
    serde_json::to_vec(&alice.keys().load_embargo(&id).unwrap().unwrap()).unwrap()
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 120, ..ProptestConfig::default() })]

    /// A key ring from a remote is bytes. Whatever they decode to must
    /// either fail to verify or derive the same membership and generations
    /// as the untouched ring: no single mutation may pass verification with
    /// a different state.
    #[test]
    fn a_mutated_ring_verifies_only_to_the_same_state(edits in prop::collection::vec((any::<usize>(), any::<u8>(), any::<u8>()), 1..4)) {
        let (raw, original) = sample_ring();
        let state = original.verify().unwrap();
        let bytes = mutate(&raw, &edits);
        if let Ok(ring) = serde_json::from_slice::<KeyRing>(&bytes) {
            let _ = ring.is_legacy();
            let _ = ring.hashes();
            if let Ok(st) = ring.verify() {
                prop_assert!(
                    st.members == state.members && st.generations == state.generations && st.generation == state.generation,
                    "a mutated ring verifies to a different state: {st:?}"
                );
            }
        }
    }

    #[test]
    fn a_mutated_embargo_record_never_panics(edits in prop::collection::vec((any::<usize>(), any::<u8>(), any::<u8>()), 1..4)) {
        let raw = sample_embargo();
        let bytes = mutate(&raw, &edits);
        if let Ok(rec) = serde_json::from_slice::<EmbargoRecord>(&bytes) {
            let _ = rec.is_released();
            let _ = veil_core::keychain::check_embargo_format(&bytes);
        }
    }
}
