//! A small, thread-safe, weight-bounded LRU cache keyed by [`ObjectId`].
//!
//! Used by [`crate::store::ObjectStore`] for decoded trees and snapshots and
//! for decompressed delta bases. Each entry has a caller-chosen weight (tree
//! entries, bytes, …). Once the total weight exceeds the capacity, the least
//! recently used entries are evicted. Lookups and inserts are O(log n).

use std::{collections::HashMap, sync::Mutex};

use crate::id::ObjectId;

struct Slot<V> {
    id: ObjectId,
    value: V,
    weight: usize,
    prev: usize,
    next: usize,
}

const NONE: usize = usize::MAX;

struct Inner<V> {
    map: HashMap<ObjectId, usize>,
    slots: Vec<Option<Slot<V>>>,
    free: Vec<usize>,
    /// Oldest entry index (LRU), or `NONE`.
    head: usize,
    /// Newest entry index (MRU), or `NONE`.
    tail: usize,
    weight: usize,
    capacity: usize,
}

impl<V> Inner<V> {
    fn detach(&mut self, idx: usize) {
        let (prev, next) = {
            let s = self.slots[idx].as_ref().unwrap();
            (s.prev, s.next)
        };
        if prev != NONE {
            self.slots[prev].as_mut().unwrap().next = next;
        } else {
            self.head = next;
        }
        if next != NONE {
            self.slots[next].as_mut().unwrap().prev = prev;
        } else {
            self.tail = prev;
        }
    }

    fn push_tail(&mut self, idx: usize) {
        let old_tail = self.tail;
        if let Some(s) = self.slots[idx].as_mut() {
            s.prev = old_tail;
            s.next = NONE;
        }
        if old_tail != NONE {
            self.slots[old_tail].as_mut().unwrap().next = idx;
        } else {
            self.head = idx;
        }
        self.tail = idx;
    }

    fn evict_to(&mut self, limit: usize) {
        while self.weight > limit && self.head != NONE {
            let idx = self.head;
            self.detach(idx);
            let slot = self.slots[idx].take().unwrap();
            self.free.push(idx);
            self.map.remove(&slot.id);
            self.weight -= slot.weight;
        }
    }
}

/// Point-in-time numbers for one cache.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CacheStats {
    pub entries: usize,
    pub weight: usize,
    pub capacity: usize,
}

pub struct LruCache<V> {
    inner: Mutex<Inner<V>>,
}

impl<V: Clone> LruCache<V> {
    pub fn new(capacity: usize) -> Self {
        LruCache {
            inner: Mutex::new(Inner {
                map: HashMap::new(),
                slots: Vec::new(),
                free: Vec::new(),
                head: NONE,
                tail: NONE,
                weight: 0,
                capacity,
            }),
        }
    }

    pub fn get(&self, id: &ObjectId) -> Option<V> {
        let mut g = self.inner.lock().unwrap();
        let inner = &mut *g;
        let idx = *inner.map.get(id)?;
        let val = inner.slots[idx].as_ref().unwrap().value.clone();
        if inner.tail != idx {
            inner.detach(idx);
            inner.push_tail(idx);
        }
        Some(val)
    }

    /// Insert (or replace) an entry. Entries heavier than the whole capacity
    /// are not cached at all.
    pub fn insert(&self, id: ObjectId, value: V, weight: usize) {
        let mut g = self.inner.lock().unwrap();
        let inner = &mut *g;
        if weight > inner.capacity {
            return;
        }
        if let Some(&idx) = inner.map.get(&id) {
            inner.detach(idx);
            let old_w = inner.slots[idx].as_ref().unwrap().weight;
            inner.weight -= old_w;
            inner.evict_to(inner.capacity - weight);
            let s = inner.slots[idx].as_mut().unwrap();
            s.value = value;
            s.weight = weight;
            inner.push_tail(idx);
            inner.weight += weight;
            return;
        }
        inner.evict_to(inner.capacity - weight);
        let slot = Slot {
            id,
            value,
            weight,
            prev: NONE,
            next: NONE,
        };
        let idx = if let Some(free_idx) = inner.free.pop() {
            inner.slots[free_idx] = Some(slot);
            free_idx
        } else {
            let i = inner.slots.len();
            inner.slots.push(Some(slot));
            i
        };
        inner.map.insert(id, idx);
        inner.push_tail(idx);
        inner.weight += weight;
    }

    pub fn set_capacity(&self, capacity: usize) {
        let mut g = self.inner.lock().unwrap();
        g.capacity = capacity;
        g.evict_to(capacity);
    }

    pub fn clear(&self) {
        let mut g = self.inner.lock().unwrap();
        g.map.clear();
        g.slots.clear();
        g.free.clear();
        g.head = NONE;
        g.tail = NONE;
        g.weight = 0;
    }

    pub fn stats(&self) -> CacheStats {
        let g = self.inner.lock().unwrap();
        CacheStats {
            entries: g.map.len(),
            weight: g.weight,
            capacity: g.capacity,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u8) -> ObjectId {
        ObjectId([n; 32])
    }

    #[test]
    fn evicts_least_recently_used_by_weight() {
        let c = LruCache::new(10);
        c.insert(id(1), 1, 4);
        c.insert(id(2), 2, 4);
        assert_eq!(c.get(&id(1)), Some(1)); // 1 is now the most recent
        c.insert(id(3), 3, 4); // evicts 2
        assert_eq!(c.get(&id(2)), None);
        assert_eq!(c.get(&id(1)), Some(1));
        assert_eq!(c.get(&id(3)), Some(3));
        assert_eq!(c.stats().weight, 8);
        c.insert(id(4), 4, 11); // heavier than the capacity: not cached
        assert_eq!(c.get(&id(4)), None);
        c.insert(id(1), 10, 2); // replace keeps the weight accounting exact
        assert_eq!(
            c.stats(),
            CacheStats {
                entries: 2,
                weight: 6,
                capacity: 10
            }
        );
        c.set_capacity(3);
        assert_eq!(c.stats().entries, 1);
        assert_eq!(c.get(&id(1)), Some(10));
    }
}
