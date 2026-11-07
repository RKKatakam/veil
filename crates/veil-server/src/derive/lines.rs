//! Per-rule history lists (phase-3 design §3.4): for each access line of
//! the accepted policy, the snapshots that changed a path the line decides,
//! so that a viewer's history is read from the lists of the lines they may
//! read, never from hidden work.
//!
//! **Line keys.** A list is named by the set of paths its line decides,
//! not by the policy version: the line's path, and every rule path below it
//! (with whether that rule comes later, and so takes those paths away). A
//! new policy that leaves a line's paths alone (a group renamed, a line
//! added elsewhere) keeps that line's list; only lines whose paths changed
//! are built again, from the changed-paths objects. Paths no line decides
//! are on the `none` list, which only admins read.
//!
//! Who may read a line is not part of its key: that is decided when a
//! viewer asks, from the policy accepted then ([`Lines::readable`]).

use std::collections::BTreeSet;

use veil_core::{
    hub::access::{covers, AccessPolicy, View},
    object::{EntryKind, TreeEntry},
};

/// The keys of one accepted policy's lines.
#[derive(Clone, Debug)]
pub struct Lines {
    pub policy: AccessPolicy,
    /// Per rule: its key, or `None` when a later line decides all its paths.
    keys: Vec<Option<String>>,
    none: String,
}

fn key(parts: &[String]) -> String {
    let mut h = blake3::Hasher::new_derive_key(LINE_KEY_CONTEXT);
    for p in parts {
        h.update(&(p.len() as u64).to_le_bytes());
        h.update(p.as_bytes());
    }
    hex::encode(&h.finalize().as_bytes()[..16])
}

const LINE_KEY_CONTEXT: &str = "veil 2026 hub derive line-key v1";

impl Lines {
    pub fn new(policy: &AccessPolicy) -> Lines {
        let rules = &policy.rules;
        let mut keys = Vec::with_capacity(rules.len());
        for (i, r) in rules.iter().enumerate() {
            // A later line at or above this one decides all of its paths.
            if rules[i + 1..].iter().any(|l| covers(&l.path, &r.path)) {
                keys.push(None);
                continue;
            }
            let below: BTreeSet<String> = rules
                .iter()
                .enumerate()
                .filter(|(_, l)| l.path != r.path && covers(&r.path, &l.path))
                .map(|(j, l)| format!("{}{}", if j > i { '-' } else { '+' }, l.path))
                .collect();
            let mut parts = vec![format!("line {}", r.path)];
            parts.extend(below);
            keys.push(Some(key(&parts)));
        }
        let mut parts = vec!["none".to_string()];
        parts.extend(rules.iter().map(|r| r.path.clone()).collect::<BTreeSet<_>>());
        Lines {
            policy: policy.clone(),
            keys,
            none: key(&parts),
        }
    }

    /// Every list this policy keeps.
    pub fn all(&self) -> Vec<String> {
        let mut out: BTreeSet<String> = self.keys.iter().flatten().cloned().collect();
        out.insert(self.none.clone());
        out.into_iter().collect()
    }

    /// The list of one side of a change at `path`: the line deciding it,
    /// or `none` for what no line decides and for a sealed directory with
    /// a rule below it (only admins see those: `Projector`).
    pub fn key_of(&self, path: &str, side: &TreeEntry) -> &str {
        if side.kind == EntryKind::Dir && self.policy.rule_below(path) {
            return &self.none;
        }
        match self.policy.deciding(path) {
            Some(i) => self.keys[i].as_deref().unwrap_or(&self.none),
            None => &self.none,
        }
    }

    /// The list of a folder that changed with no leaf below it changing:
    /// as for a directory side ([`Lines::key_of`]); the root's is `none`.
    pub fn dir_key(&self, path: &str) -> &str {
        if path.is_empty() || self.policy.rule_below(path) {
            return &self.none;
        }
        match self.policy.deciding(path) {
            Some(i) => self.keys[i].as_deref().unwrap_or(&self.none),
            None => &self.none,
        }
    }

    /// The lists `view` may read (`view` must be of this policy).
    pub fn readable(&self, view: &View) -> Vec<String> {
        if view.admin {
            return self.all();
        }
        let mut out: BTreeSet<String> = BTreeSet::new();
        for (r, k) in self.policy.rules.iter().zip(&self.keys) {
            // An unshadowed line decides its own path.
            if let Some(k) = k {
                if view.read(&r.path) {
                    out.insert(k.clone());
                }
            }
        }
        out.into_iter().collect()
    }

    /// Does `view` see this side of a change (as `Projector` decides)?
    pub fn side_visible(view: &View, path: &str, side: &TreeEntry) -> bool {
        view.read(path) && !(side.kind == EntryKind::Dir && view.rule_below(path))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file() -> TreeEntry {
        TreeEntry {
            name: "x".into(),
            kind: EntryKind::File,
            id: veil_core::ObjectId([0; 32]),
            size: 0,
            executable: false,
            visibility: Default::default(),
            fallback: None,
        }
    }

    #[test]
    fn keys_name_the_paths_a_line_decides() {
        let p = AccessPolicy::parse("src/ public\nsrc/sec/ security\nbilling/ finance\n");
        let l = Lines::new(&p);
        let f = file();
        assert_ne!(l.key_of("src/a", &f), l.key_of("src/sec/a", &f));
        assert_eq!(l.key_of("README", &f), l.key_of(".veilpolicy", &f));
        assert_eq!(l.all().len(), 4);
        // Renaming a group, or adding a line elsewhere, keeps the keys of
        // the lines whose paths did not change.
        let q = Lines::new(&AccessPolicy::parse("src/ public devs\nsrc/sec/ ops\nbilling/ finance\ninfra/ ops\n"));
        assert_eq!(l.key_of("src/a", &f), q.key_of("src/a", &f));
        assert_eq!(l.key_of("billing/a", &f), q.key_of("billing/a", &f));
        assert_ne!(l.key_of("README", &f), q.key_of("README", &f), "infra/ left the none list");
        // A line below another changes the outer line's paths.
        let r = Lines::new(&AccessPolicy::parse("src/ public\nbilling/ finance\n"));
        assert_ne!(l.key_of("src/a", &f), r.key_of("src/a", &f));
        assert_eq!(l.key_of("billing/a", &f), r.key_of("billing/a", &f));
        // A line a later one covers decides nothing.
        let s = Lines::new(&AccessPolicy::parse("src/sec/ security\nsrc/ public\n"));
        assert_eq!(s.all().len(), 2);
    }

    #[test]
    fn readable_lists() {
        let p = AccessPolicy::parse("src/ public\nsrc/sec/ security\nbilling/ finance\n");
        let l = Lines::new(&p);
        let f = file();
        let anon = View::anonymous(&p);
        assert_eq!(l.readable(&anon), vec![l.key_of("src/a", &f).to_string()]);
        let fin = View::new(&p, false, |_, n| n == "finance");
        assert_eq!(l.readable(&fin).len(), 2);
        assert!(!l.readable(&fin).contains(&l.key_of("README", &f).to_string()));
        assert_eq!(l.readable(&View::admin(&p)), l.all());
    }
}
