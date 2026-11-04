//! A small, thread-safe, weight-bounded LRU cache keyed by [`ObjectId`].
//!
//! Used by [`crate::store::ObjectStore`] for decoded trees and snapshots and
//! for decompressed delta bases. Each entry has a caller-chosen weight (tree
//! entries, bytes, …). Once the total weight exceeds the capacity, the least
//! recently used entries are evicted. Lookups and inserts are O(log n).

use std::{
    collections::{BTreeMap, HashMap},
    sync::Mutex,
};

use crate::id::ObjectId;

struct Slot<V> {
    value: V,
    tick: u64,
    weight: usize,
}

struct Inner<V> {
    map: HashMap<ObjectId, Slot<V>>,
    /// Recency order: oldest tick first.
    order: BTreeMap<u64, ObjectId>,
    tick: u64,
    weight: usize,
    capacity: usize,
}

impl<V> Inner<V> {
    fn evict_to(&mut self, limit: usize) {
        while self.weight > limit {
            let Some((_, id)) = self.order.pop_first() else { break };
            if let Some(slot) = self.map.remove(&id) {
                self.weight -= slot.weight;
            }
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
                order: BTreeMap::new(),
                tick: 0,
                weight: 0,
                capacity,
            }),
        }
    }

    pub fn get(&self, id: &ObjectId) -> Option<V> {
        let mut g = self.inner.lock().unwrap();
        let inner = &mut *g;
        let slot = inner.map.get_mut(id)?;
        inner.tick += 1;
        inner.order.remove(&slot.tick);
        slot.tick = inner.tick;
        inner.order.insert(slot.tick, *id);
        Some(slot.value.clone())
    }

    /// Insert (or replace) an entry. Entries heavier than the whole capacity
    /// are not cached at all.
    pub fn insert(&self, id: ObjectId, value: V, weight: usize) {
        let mut g = self.inner.lock().unwrap();
        let inner = &mut *g;
        if weight > inner.capacity {
            return;
        }
        if let Some(old) = inner.map.remove(&id) {
            inner.order.remove(&old.tick);
            inner.weight -= old.weight;
        }
        inner.evict_to(inner.capacity - weight);
        inner.tick += 1;
        let tick = inner.tick;
        inner.order.insert(tick, id);
        inner.map.insert(id, Slot { value, tick, weight });
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
        g.order.clear();
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
