//! A small, thread-safe, weight-bounded LRU cache keyed by [`ObjectId`].
//!
//! Used by [`crate::store::ObjectStore`] for decoded trees and snapshots and
//! for decompressed delta bases. Each entry has a caller-chosen weight (tree
//! entries, bytes, …). Once the total weight exceeds the capacity, the least
//! recently used entries are evicted. Lookups and inserts are O(log n).

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex, Weak,
    },
};

use crate::id::ObjectId;

struct Slot<V> {
    id: ObjectId,
    value: V,
    weight: usize,
    stamp: u64,
    prev: usize,
    next: usize,
}

const NONE: usize = usize::MAX;

trait Budgeted: Send + Sync {
    fn oldest_stamp(&self) -> Option<u64>;
    fn evict_oldest(&self) -> bool;
}

/// Shared weight ceiling across several [`LruCache`] instances. Each cache
/// still enforces its own capacity; whenever the combined weight exceeds
/// `limit`, the least-recently-used entries across all registered caches are
/// evicted until the sum is back within `limit`.
pub struct CacheBudget {
    limit: usize,
    weight: AtomicUsize,
    clock: AtomicU64,
    members: Mutex<Vec<Weak<dyn Budgeted>>>,
}

impl CacheBudget {
    pub fn new(limit: usize) -> Arc<Self> {
        Arc::new(CacheBudget {
            limit,
            weight: AtomicUsize::new(0),
            clock: AtomicU64::new(1),
            members: Mutex::new(Vec::new()),
        })
    }

    pub fn weight(&self) -> usize {
        self.weight.load(Ordering::Acquire)
    }

    pub fn limit(&self) -> usize {
        self.limit
    }

    fn next_stamp(&self) -> u64 {
        self.clock.fetch_add(1, Ordering::Relaxed)
    }

    fn enforce(&self) {
        if self.weight.load(Ordering::Acquire) <= self.limit {
            return;
        }
        let live: Vec<Arc<dyn Budgeted>> = {
            let mut m = self.members.lock().unwrap();
            let mut out = Vec::with_capacity(m.len());
            m.retain(|w| match w.upgrade() {
                Some(a) => {
                    out.push(a);
                    true
                }
                None => false,
            });
            out
        };
        while self.weight.load(Ordering::Acquire) > self.limit {
            let mut oldest: Option<(u64, usize)> = None;
            for (i, c) in live.iter().enumerate() {
                if let Some(st) = c.oldest_stamp() {
                    if oldest.is_none_or(|(best, _)| st < best) {
                        oldest = Some((st, i));
                    }
                }
            }
            let Some((_, idx)) = oldest else { break };
            let _ = live[idx].evict_oldest();
        }
    }
}

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
    budget: Option<Arc<CacheBudget>>,
}

impl<V> Drop for Inner<V> {
    fn drop(&mut self) {
        if self.weight > 0 {
            if let Some(b) = &self.budget {
                b.weight.fetch_sub(self.weight, Ordering::AcqRel);
            }
        }
    }
}

impl<V> Inner<V> {
    fn add_weight(&mut self, w: usize) {
        self.weight += w;
        if let Some(b) = &self.budget {
            b.weight.fetch_add(w, Ordering::AcqRel);
        }
    }

    fn sub_weight(&mut self, w: usize) {
        self.weight -= w;
        if let Some(b) = &self.budget {
            b.weight.fetch_sub(w, Ordering::AcqRel);
        }
    }

    fn next_stamp(&self) -> u64 {
        self.budget.as_ref().map_or(0, |b| b.next_stamp())
    }

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

    fn pop_head(&mut self) -> Option<V> {
        if self.head == NONE {
            return None;
        }
        let idx = self.head;
        self.detach(idx);
        let slot = self.slots[idx].take().unwrap();
        self.free.push(idx);
        self.map.remove(&slot.id);
        self.sub_weight(slot.weight);
        Some(slot.value)
    }

    fn evict_to(&mut self, limit: usize, evicted: &mut Vec<V>) {
        while self.weight > limit {
            let Some(v) = self.pop_head() else { break };
            evicted.push(v);
        }
    }
}

impl<V: Send + Sync> Budgeted for Mutex<Inner<V>> {
    fn oldest_stamp(&self) -> Option<u64> {
        let g = self.lock().unwrap();
        (g.head != NONE).then(|| g.slots[g.head].as_ref().unwrap().stamp)
    }

    fn evict_oldest(&self) -> bool {
        let dropped = self.lock().unwrap().pop_head();
        let had = dropped.is_some();
        drop(dropped);
        had
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
    inner: Arc<Mutex<Inner<V>>>,
    budget: Option<Arc<CacheBudget>>,
}

impl<V: Clone + Send + Sync + 'static> LruCache<V> {
    pub fn with_budget(capacity: usize, budget: &Arc<CacheBudget>) -> Self {
        let inner = Arc::new(Mutex::new(Inner {
            map: HashMap::new(),
            slots: Vec::new(),
            free: Vec::new(),
            head: NONE,
            tail: NONE,
            weight: 0,
            capacity,
            budget: Some(budget.clone()),
        }));
        let weak: Weak<dyn Budgeted> = Arc::downgrade(&inner) as Weak<dyn Budgeted>;
        budget.members.lock().unwrap().push(weak);
        LruCache {
            inner,
            budget: Some(budget.clone()),
        }
    }
}

impl<V: Clone> LruCache<V> {
    pub fn new(capacity: usize) -> Self {
        LruCache {
            inner: Arc::new(Mutex::new(Inner {
                map: HashMap::new(),
                slots: Vec::new(),
                free: Vec::new(),
                head: NONE,
                tail: NONE,
                weight: 0,
                capacity,
                budget: None,
            })),
            budget: None,
        }
    }

    pub fn get(&self, id: &ObjectId) -> Option<V> {
        let mut g = self.inner.lock().unwrap();
        let inner = &mut *g;
        let idx = *inner.map.get(id)?;
        let stamp = inner.next_stamp();
        let s = inner.slots[idx].as_mut().unwrap();
        s.stamp = stamp;
        let val = s.value.clone();
        if inner.tail != idx {
            inner.detach(idx);
            inner.push_tail(idx);
        }
        Some(val)
    }

    /// Insert (or replace) an entry. Entries heavier than the whole capacity
    /// (or than the shared [`CacheBudget`]) are not cached at all.
    pub fn insert(&self, id: ObjectId, value: V, weight: usize) {
        if self.budget.as_ref().is_some_and(|b| weight > b.limit) {
            return;
        }
        let mut evicted = Vec::new();
        let mut replaced = None;
        {
            let mut g = self.inner.lock().unwrap();
            let inner = &mut *g;
            if weight > inner.capacity {
                return;
            }
            let stamp = inner.next_stamp();
            if let Some(&idx) = inner.map.get(&id) {
                inner.detach(idx);
                let old_w = inner.slots[idx].as_ref().unwrap().weight;
                inner.sub_weight(old_w);
                inner.evict_to(inner.capacity - weight, &mut evicted);
                let s = inner.slots[idx].as_mut().unwrap();
                replaced = Some(std::mem::replace(&mut s.value, value));
                s.weight = weight;
                s.stamp = stamp;
                inner.push_tail(idx);
                inner.add_weight(weight);
            } else {
                inner.evict_to(inner.capacity - weight, &mut evicted);
                let slot = Slot {
                    id,
                    value,
                    weight,
                    stamp,
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
                inner.add_weight(weight);
            }
        }
        drop(replaced);
        drop(evicted);
        if let Some(b) = &self.budget {
            b.enforce();
        }
    }

    pub fn remove(&self, id: &ObjectId) -> bool {
        let dropped = {
            let mut g = self.inner.lock().unwrap();
            let inner = &mut *g;
            match inner.map.remove(id) {
                Some(idx) => {
                    inner.detach(idx);
                    let slot = inner.slots[idx].take().unwrap();
                    inner.free.push(idx);
                    inner.sub_weight(slot.weight);
                    Some(slot.value)
                }
                None => None,
            }
        };
        let had = dropped.is_some();
        drop(dropped);
        had
    }

    pub fn set_capacity(&self, capacity: usize) {
        let mut evicted = Vec::new();
        {
            let mut g = self.inner.lock().unwrap();
            g.capacity = capacity;
            g.evict_to(capacity, &mut evicted);
        }
        drop(evicted);
    }

    pub fn clear(&self) {
        let old_slots = {
            let mut g = self.inner.lock().unwrap();
            g.map.clear();
            g.free.clear();
            g.head = NONE;
            g.tail = NONE;
            let w = g.weight;
            if w > 0 {
                g.sub_weight(w);
            }
            std::mem::take(&mut g.slots)
        };
        drop(old_slots);
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

    #[test]
    fn shared_budget_bounds_sum_and_preserves_subcache_caps() {
        let budget = CacheBudget::new(10);
        let objects = LruCache::with_budget(5, &budget);
        let trees = LruCache::with_budget(5, &budget);
        let segments = LruCache::with_budget(5, &budget);

        // Filling `objects` past its own 5-byte cap evicts within `objects`
        // only and never touches `trees`.
        trees.insert(id(10), 10, 5);
        objects.insert(id(1), 1, 3);
        objects.insert(id(2), 2, 3);
        assert_eq!(objects.get(&id(1)), None);
        assert_eq!(objects.stats().weight, 3);
        assert_eq!(trees.stats().weight, 5);
        assert_eq!(budget.weight(), 8);

        // Touch `trees` so `objects` holds the globally oldest entry, then
        // fill `objects` to 5 (total 10, right at the shared limit).
        assert_eq!(trees.get(&id(10)), Some(10));
        objects.insert(id(3), 3, 2);
        assert_eq!(budget.weight(), 10);

        // Inserting 4 bytes into `segments` pushes total to 14 -> evicts
        // oldest across all three caches (`id(2)` weight 3, then `id(10)`
        // weight 5 -> total becomes 6 <= 10).
        segments.insert(id(20), 20, 4);
        assert!(budget.weight() <= 10, "budget weight {} > 10", budget.weight());
        assert_eq!(
            budget.weight(),
            objects.stats().weight + trees.stats().weight + segments.stats().weight
        );
        assert_eq!(objects.get(&id(2)), None);
        assert_eq!(trees.get(&id(10)), None);
        assert_eq!(objects.get(&id(3)), Some(3));
        assert_eq!(segments.get(&id(20)), Some(20));

        assert!(segments.remove(&id(20)));
        assert_eq!(segments.stats().weight, 0);
        assert_eq!(budget.weight(), 2);

        drop(objects);
        assert_eq!(budget.weight(), 0);
    }
}
