//! Passing a server's answer of object frames on as it arrives, in chunks
//! of any size: frames already sent are dropped, frames are copied to the
//! client as their bytes come, and the objects small enough to keep are
//! collected for the store. Before each frame it sends, it stops and names
//! it, so the cache can first send the objects of its own that come before
//! it: the answer keeps the order of the request, as the server's does.
//! Memory: the frame being collected (at most the store's largest object)
//! and what the caller has not sent yet.

use std::collections::HashSet;

use veil_core::{hub::wire::MAX_FRAME_OBJECT, ObjectId};

const HEADER: usize = 36;

pub struct Relay {
    /// Bytes of a frame's header so far.
    head: Vec<u8>,
    /// The header of the frame just named, written at the next call.
    pending: Vec<u8>,
    /// The frame being read: its id, bytes still to come, whether it is
    /// sent on, and its bytes if it is being kept.
    body: Option<(ObjectId, usize, bool, Option<Vec<u8>>)>,
    /// Ids already sent (by the cache itself, or earlier in this answer).
    pub sent: HashSet<ObjectId>,
    /// Ids that may be kept (those asked for).
    wanted: HashSet<ObjectId>,
    keep_max: usize,
}

impl Relay {
    pub fn new(sent: HashSet<ObjectId>, wanted: HashSet<ObjectId>, keep_max: usize) -> Relay {
        Relay {
            head: Vec::with_capacity(HEADER),
            pending: Vec::new(),
            body: None,
            sent,
            wanted,
            keep_max,
        }
    }

    /// Take bytes from `chunk`: append what is sent on to `out`, and each
    /// whole object to keep to `kept` (unchecked: the store checks it).
    /// Returns `Some(id)` when frame `id` is next to be sent, before any of
    /// it is in `out` (call again, with the rest of `chunk`, to go on);
    /// `None` once `chunk` is used up.
    pub fn feed(&mut self, chunk: &mut &[u8], out: &mut Vec<u8>, kept: &mut Vec<(ObjectId, Vec<u8>)>) -> Result<Option<ObjectId>, &'static str> {
        out.append(&mut self.pending);
        loop {
            if let Some((id, 0, _, keep)) = &mut self.body {
                if let Some(k) = keep.take() {
                    kept.push((*id, k));
                }
                self.body = None;
            }
            if chunk.is_empty() {
                return Ok(None);
            }
            match &mut self.body {
                None => {
                    let n = (HEADER - self.head.len()).min(chunk.len());
                    self.head.extend_from_slice(&chunk[..n]);
                    *chunk = &chunk[n..];
                    if self.head.len() < HEADER {
                        continue;
                    }
                    let id = ObjectId(self.head[..32].try_into().expect("32 bytes"));
                    let len = u32::from_be_bytes(self.head[32..HEADER].try_into().expect("4 bytes")) as usize;
                    if len > MAX_FRAME_OBJECT {
                        return Err("an oversized frame");
                    }
                    let send = self.sent.insert(id);
                    let keep = (send && len <= self.keep_max && self.wanted.contains(&id)).then(|| Vec::with_capacity(len));
                    self.body = Some((id, len, send, keep));
                    if send {
                        self.pending = std::mem::take(&mut self.head);
                        return Ok(Some(id));
                    }
                    self.head.clear();
                }
                Some((_, left, send, keep)) => {
                    let n = (*left).min(chunk.len());
                    if *send {
                        out.extend_from_slice(&chunk[..n]);
                    }
                    if let Some(k) = keep {
                        k.extend_from_slice(&chunk[..n]);
                    }
                    *left -= n;
                    *chunk = &chunk[n..];
                }
            }
        }
    }

    /// Did the answer end between frames?
    pub fn whole(&self) -> bool {
        self.head.is_empty() && self.pending.is_empty() && self.body.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use veil_core::hub::wire::{put_frame, read_frames};

    type Kept = Vec<(ObjectId, Vec<u8>)>;

    /// Feed `body` in chunks of `step`; what was sent, the ids named, and
    /// what was kept.
    fn run(r: &mut Relay, body: &[u8], step: usize) -> (Vec<u8>, Vec<ObjectId>, Kept) {
        let (mut out, mut named, mut kept) = (Vec::new(), Vec::new(), Vec::new());
        for c in body.chunks(step) {
            let mut rest = c;
            while let Some(id) = r.feed(&mut rest, &mut out, &mut kept).unwrap() {
                // Nothing of the frame named is out yet.
                assert!(!out.ends_with(&id.0));
                named.push(id);
            }
        }
        r.feed(&mut &[][..], &mut out, &mut kept).unwrap();
        (out, named, kept)
    }

    #[test]
    fn frames_pass_in_chunks_of_any_size_once_each() {
        let objs: Vec<(ObjectId, Vec<u8>)> = [&b"veil:blob\na"[..], b"", &[7u8; 5000], b"veil:blob\nb"]
            .iter()
            .map(|r| (ObjectId::hash(r), r.to_vec()))
            .collect();
        let mut body = Vec::new();
        for (id, raw) in &objs {
            put_frame(&mut body, id, raw);
        }
        // The second object again: sent once.
        put_frame(&mut body, &objs[1].0, &objs[1].1);
        for step in [1, 3, 35, 36, 37, 1000, body.len()] {
            // The first was sent by the cache already; the third is too
            // large to keep; the fourth was not asked for.
            let mut r = Relay::new([objs[0].0].into(), [objs[0].0, objs[1].0, objs[2].0].into(), 4096);
            let (out, named, kept) = run(&mut r, &body, step);
            assert!(r.whole(), "{step}");
            let got: Vec<ObjectId> = read_frames(&out).unwrap().into_iter().map(|f| f.0).collect();
            assert_eq!(got, vec![objs[1].0, objs[2].0, objs[3].0], "{step}");
            assert_eq!(named, got, "{step}");
            assert_eq!(kept, vec![objs[1].clone()], "{step}");
        }
        let mut r = Relay::new(HashSet::new(), HashSet::new(), 0);
        run(&mut r, &body[..40], 40);
        assert!(!r.whole(), "cut inside a frame");
        let mut bad = vec![0u8; 32];
        bad.extend_from_slice(&u32::MAX.to_be_bytes());
        assert!(Relay::new(HashSet::new(), HashSet::new(), 0).feed(&mut &bad[..], &mut Vec::new(), &mut Vec::new()).is_err());
    }
}
