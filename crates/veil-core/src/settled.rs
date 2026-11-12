//! The settled-heads record (BUG-1960): which operation's heads are known
//! to be apart (none descends from another), and what could join two of
//! them later.
//!
//! A rewrite drops every head that another head descends from
//! (`Transaction::drop_ancestor_heads`). Knowing that the heads it starts
//! from are apart lets it stop at them instead of reading the history
//! between the newest head and the oldest at every commit (BUG-1944). That
//! is a fact about the snapshots held when the operation before was
//! committed: history that arrives later below a head (a withheld parent
//! released and pulled, a thin clone made full) can put one head under
//! another. So the commit that settles heads records, beside the
//! operation's id, every parent the history index took as missing when it
//! computed the heads' entries (none present then). A snapshot's parents
//! never change, so a head's held history grows only when one of those
//! arrives; while none is in the store, the operation's heads are still
//! apart. The record is a cache: written without a barrier, checked by its
//! checksum, and a missing, torn or other operation's record means the
//! walk reads the whole range, as before.
//!
//! File `.veil/index/settled-heads` (integers little-endian):
//!
//! ```text
//! "VEILSH01" | operation id [32] | missing u32 | missing parents [missing × 32]
//! | BLAKE3 of everything before
//! ```

use crate::{id::ObjectId, repo::Repo, vpath::VPath};

const MAGIC: &[u8; 8] = b"VEILSH01";
const PATH: &str = ".veil/index/settled-heads";

fn path() -> VPath {
    VPath::new(PATH).expect("a valid path")
}

fn encode(op: &ObjectId, missing: &[ObjectId]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + 32 + 4 + 32 * missing.len() + 32);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&op.0);
    out.extend_from_slice(&(missing.len() as u32).to_le_bytes());
    for m in missing {
        out.extend_from_slice(&m.0);
    }
    let sum = blake3::hash(&out);
    out.extend_from_slice(sum.as_bytes());
    out
}

fn decode(data: &[u8]) -> Option<(ObjectId, Vec<ObjectId>)> {
    let body = data.len().checked_sub(32)?;
    let (head, sum) = data.split_at(body);
    if blake3::hash(head).as_bytes() != sum || head.len() < 8 + 32 + 4 || &head[..8] != MAGIC {
        return None;
    }
    let op = ObjectId(head[8..40].try_into().ok()?);
    let n = u32::from_le_bytes(head[40..44].try_into().ok()?) as usize;
    let rest = &head[44..];
    if rest.len() != n.checked_mul(32)? {
        return None;
    }
    let missing = rest.as_chunks::<32>().0.iter().map(|c| ObjectId(*c)).collect();
    Some((op, missing))
}

/// After the commit of operation `op`, whose transaction ended with
/// `Transaction::drop_ancestor_heads` (its heads are `repo`'s view's now):
/// record them as apart. Best effort; nothing in a thin clone, nor when
/// the index cannot say what could join them.
pub(crate) fn record(repo: &Repo, op: &ObjectId) {
    if repo.store.is_partial() || !repo.graph_persists() {
        return;
    }
    let heads: Vec<ObjectId> = repo.view.heads.iter().copied().collect();
    let Ok(Some(missing)) = repo.graph_missing_below(&heads) else { return };
    let _ = repo.backend.write_unsynced(&path(), &encode(op, &missing));
}

/// Are the heads of operation `op` known apart still: a record for `op`,
/// and none of the parents it lists in the store?
pub(crate) fn still_apart(repo: &Repo, op: &ObjectId) -> bool {
    let Ok(Some(data)) = repo.backend.read_opt(&path()) else { return false };
    let Some((recorded, missing)) = decode(&data) else { return false };
    recorded == *op && !missing.iter().any(|m| repo.store.has(m))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_record_decodes_as_written_and_a_damaged_one_not_at_all() {
        let op = ObjectId::hash(b"op");
        let missing = vec![ObjectId::hash(b"a"), ObjectId::hash(b"b")];
        let data = encode(&op, &missing);
        assert_eq!(decode(&data), Some((op, missing.clone())));
        assert_eq!(decode(&encode(&op, &[])), Some((op, vec![])));
        for cut in 0..data.len() {
            assert_eq!(decode(&data[..cut]), None, "truncated at {cut}");
        }
        for i in 0..data.len() {
            let mut bad = data.clone();
            bad[i] ^= 1;
            assert_eq!(decode(&bad), None, "byte {i} flipped");
        }
    }
}
