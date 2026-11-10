//! Token buckets in the server's memory (`docs/HUB.md` §13.25): two per
//! key, a short one (`per_second` tokens, refilled `per_second` a second:
//! the burst) and a long one (`per_hour` tokens, refilled over the hour). A
//! request takes one token from both; a full bucket is the same as none,
//! so idle keys are forgotten.

use std::{
    collections::HashMap,
    hash::{BuildHasher, Hash},
    net::IpAddr,
    sync::Mutex,
    time::{Duration, Instant},
};

/// A rate: a burst of `per_second` (refilled at that rate) within
/// `per_hour` an hour.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rate {
    pub per_second: u32,
    pub per_hour: u32,
}

impl Rate {
    /// `60/5000`: a burst of 60 a second within 5,000 an hour.
    pub fn parse(s: &str) -> Result<Rate, String> {
        let bad = || format!("{s}: a rate such as 60/5000 (a burst a second, then an hour's most)");
        let (a, b) = s.split_once('/').ok_or_else(bad)?;
        let (per_second, per_hour) = (a.trim().parse::<u32>().map_err(|_| bad())?, b.trim().parse::<u32>().map_err(|_| bad())?);
        if per_second == 0 || per_hour == 0 {
            return Err(bad());
        }
        Ok(Rate { per_second, per_hour })
    }
}

/// Who a request is counted against.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Key {
    /// A signed-in device (its Ed25519 key), whichever session or grant it
    /// came with.
    Device([u8; 32]),
    /// An agent session (S11, `docs/HUB.md` §13.32): its stored session
    /// hash, at [`super::Settings::device`]'s rate.
    Session([u8; 32]),
    /// A signed-in person (`people.id`): the 10× umbrella bucket over all
    /// of their devices and agent sessions.
    Person(i64),
    /// An address without a known session: IPv4, or an IPv6 /64 (one
    /// subscriber's usual allocation).
    Ip(u128),
}

impl Key {
    pub fn ip(ip: IpAddr) -> Key {
        match ip {
            IpAddr::V4(v4) => Key::Ip(u128::from(u32::from(v4))),
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => Key::Ip(u128::from(u32::from(v4))),
                None => Key::Ip((u128::from(v6) >> 64) << 64 | 1 << 32),
            },
        }
    }

    /// A device by its key in hex; `None` if it is not one.
    pub fn device(hex_key: &str) -> Option<Key> {
        let mut k = [0u8; 32];
        hex::decode_to_slice(hex_key, &mut k).ok()?;
        Some(Key::Device(k))
    }

    /// An agent session by its stored hash in hex; `None` if it is not one.
    pub fn session(hex_hash: &str) -> Option<Key> {
        let mut k = [0u8; 32];
        hex::decode_to_slice(hex_hash, &mut k).ok()?;
        Some(Key::Session(k))
    }

    /// A person's own session (`Key::Device`) or agent session (`Key::Session`).
    pub fn of_person(person: &crate::auth::Person) -> Option<Key> {
        match &person.agent {
            Some(a) => Key::session(&a.session),
            None => Key::device(&person.device_key),
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct Bucket {
    short: f64,
    long: f64,
    at: Instant,
}

impl Bucket {
    fn full(r: Rate, now: Instant) -> Bucket {
        Bucket { short: f64::from(r.per_second), long: f64::from(r.per_hour), at: now }
    }

    fn refill(&mut self, r: Rate, now: Instant) {
        let dt = now.saturating_duration_since(self.at).as_secs_f64();
        self.short = (self.short + dt * f64::from(r.per_second)).min(f64::from(r.per_second));
        self.long = (self.long + dt * f64::from(r.per_hour) / 3600.0).min(f64::from(r.per_hour));
        self.at = now;
    }

    fn is_full(&self, r: Rate) -> bool {
        self.short >= f64::from(r.per_second) && self.long >= f64::from(r.per_hour)
    }

    /// How long until a token is in both buckets.
    fn wait(&self, r: Rate) -> Duration {
        let short = (1.0 - self.short).max(0.0) / f64::from(r.per_second);
        let long = (1.0 - self.long).max(0.0) * 3600.0 / f64::from(r.per_hour);
        Duration::from_secs_f64(short.max(long))
    }
}

/// Most keys a shard keeps; past it, the full (idle) ones go, then the
/// fullest half. A bucket forgotten too early only lets its key start
/// afresh: never a refusal.
const SHARD_KEYS: usize = 1 << 14;
const SHARDS: usize = 16;

/// The buckets of one kind of key (devices, or addresses), at one rate.
pub struct Buckets {
    rate: Rate,
    hasher: std::collections::hash_map::RandomState,
    shards: Vec<Mutex<HashMap<Key, Bucket>>>,
}

impl Buckets {
    pub fn new(rate: Rate) -> Buckets {
        Buckets { rate, hasher: Default::default(), shards: (0..SHARDS).map(|_| Mutex::new(HashMap::new())).collect() }
    }

    fn shard(&self, k: &Key) -> &Mutex<HashMap<Key, Bucket>> {
        &self.shards[self.hasher.hash_one(k) as usize % SHARDS]
    }

    /// Take a token for `k`, or say how long until one is there.
    pub fn take(&self, k: Key) -> Result<(), Duration> {
        self.take_at(k, Instant::now())
    }

    pub(crate) fn take_at(&self, k: Key, now: Instant) -> Result<(), Duration> {
        let r = self.rate;
        let mut m = self.shard(&k).lock().unwrap();
        if m.len() >= SHARD_KEYS && !m.contains_key(&k) {
            m.retain(|_, b| {
                b.refill(r, now);
                !b.is_full(r)
            });
            if m.len() >= SHARD_KEYS {
                let mut longs: Vec<f64> = m.values().map(|b| b.long).collect();
                longs.sort_by(|a, b| a.total_cmp(b));
                let median = longs[longs.len() / 2];
                m.retain(|_, b| b.long < median);
            }
        }
        let b = m.entry(k).or_insert_with(|| Bucket::full(r, now));
        b.refill(r, now);
        if b.short >= 1.0 && b.long >= 1.0 {
            b.short -= 1.0;
            b.long -= 1.0;
            Ok(())
        } else {
            Err(b.wait(r).max(Duration::from_millis(1)))
        }
    }

    /// Keys kept (for tests).
    pub fn len(&self) -> usize {
        self.shards.iter().map(|s| s.lock().unwrap().len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEVICE: Key = Key::Device([7; 32]);

    /// A client within its rate is never refused: 60 a second for an
    /// hour's worth of seconds stays inside the burst, and 5,000 spread over
    /// the hour inside the hour's bucket.
    #[test]
    fn a_client_within_its_rate_is_never_refused() {
        let b = Buckets::new(Rate { per_second: 60, per_hour: 5000 });
        let t0 = Instant::now();
        // The whole burst at once.
        for _ in 0..60 {
            assert_eq!(b.take_at(DEVICE, t0), Ok(()));
        }
        // Then 5,000 an hour, evenly: one every 0.72 s, for two hours.
        let mut k = Key::Device([8; 32]);
        for i in 0..10_000u64 {
            let at = t0 + Duration::from_millis(720 * i);
            assert_eq!(b.take_at(k, at), Ok(()), "request {i}");
        }
        // And someone else's flood never touches it.
        let other = Key::Device([9; 32]);
        for _ in 0..1000 {
            let _ = b.take_at(other, t0);
        }
        k = Key::Device([10; 32]);
        assert_eq!(b.take_at(k, t0), Ok(()));
    }

    /// Past the burst a request is refused with the time until the next
    /// token; past the hour's most, with the time the hour refills one.
    #[test]
    fn past_its_rate_a_client_is_told_when_to_come_back() {
        let b = Buckets::new(Rate { per_second: 10, per_hour: 100 });
        let t0 = Instant::now();
        for _ in 0..10 {
            b.take_at(DEVICE, t0).unwrap();
        }
        let w = b.take_at(DEVICE, t0).unwrap_err();
        assert!(w > Duration::from_millis(50) && w <= Duration::from_millis(100), "{w:?}");
        // After the burst refills, the hour runs out at 100.
        let mut at = t0;
        let mut served = 10;
        loop {
            at += Duration::from_millis(100);
            match b.take_at(DEVICE, at) {
                Ok(()) => served += 1,
                Err(w) => {
                    assert!(w > Duration::from_secs(20) && w <= Duration::from_secs(36), "{w:?}: the hour's bucket, 36 s a token");
                    break;
                }
            }
        }
        assert_eq!(served, 100);
    }

    /// Keys from anywhere (a flood of addresses) keep the map bounded.
    #[test]
    fn many_keys_keep_the_map_bounded() {
        let b = Buckets::new(Rate { per_second: 2, per_hour: 10 });
        let t0 = Instant::now();
        for i in 0..200_000u128 {
            let _ = b.take_at(Key::Ip(i), t0);
        }
        assert!(b.len() <= SHARDS * SHARD_KEYS, "{}", b.len());
    }

    #[test]
    fn rates_and_addresses_parse() {
        assert_eq!(Rate::parse("60/5000"), Ok(Rate { per_second: 60, per_hour: 5000 }));
        assert!(Rate::parse("0/5").is_err() && Rate::parse("60").is_err() && Rate::parse("a/b").is_err());
        let a: IpAddr = "2001:db8::1".parse().unwrap();
        let b: IpAddr = "2001:db8::ffff:2".parse().unwrap();
        let c: IpAddr = "2001:db8:0:1::1".parse().unwrap();
        assert_eq!(Key::ip(a), Key::ip(b), "one /64");
        assert_ne!(Key::ip(a), Key::ip(c));
        let v4: IpAddr = "10.0.0.1".parse().unwrap();
        let mapped: IpAddr = "::ffff:10.0.0.1".parse().unwrap();
        assert_eq!(Key::ip(v4), Key::ip(mapped));
        assert!(Key::device("zz").is_none());
    }
}
