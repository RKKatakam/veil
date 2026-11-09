//! Bulkheads (`docs/HUB.md` §13.25): a gate per project and one for the
//! whole server, each letting at most so many requests run at once. A
//! request waits for its project's gate, then the server's, each for at
//! most its class's wait; a free place goes to the waiting landings first,
//! then pulls, then search and grep, so under overload search is shed
//! first and landings last (design §4.11). A pull that has waited
//! [`AGE`] goes before landings: a steady stream of them never starves the
//! pulls agents need to land again (S24 cycle 2).

use std::{
    collections::{HashMap, VecDeque},
    hash::{BuildHasher, Hash},
    sync::{Arc, Mutex},
    time::Duration,
};

use tokio::sync::oneshot;

/// What a request does, for shedding: the lower, the sooner shed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Class {
    /// `q/search` and `q/grep`.
    Search = 0,
    /// Pulls and every other read: tips, history, fetch, objects, queries.
    Read = 1,
    /// Landings (`push`, `changes`, uploads) and every other change. S17's
    /// `land` joins this class.
    Write = 2,
}

/// How long a pull waits before it goes ahead of newer landings.
pub const AGE: Duration = Duration::from_secs(1);

impl Class {
    /// The longest a request of the class waits for a place.
    pub fn wait(self) -> Duration {
        match self {
            Class::Search => Duration::from_secs(1),
            Class::Read => Duration::from_secs(10),
            Class::Write => Duration::from_secs(20),
        }
    }
}

#[derive(Default)]
struct State {
    running: usize,
    /// Waiting requests by class, each with its ticket.
    queues: [VecDeque<(u64, oneshot::Sender<()>, tokio::time::Instant)>; 3],
    next: u64,
    /// The last place went to an aged pull: the next goes by the normal
    /// order, so aged pulls and landings alternate and neither starves the
    /// other (BUG-1630).
    aged_turn: bool,
}

impl State {
    fn waiting(&self) -> usize {
        self.queues.iter().map(VecDeque::len).sum()
    }
}

/// One gate: `cap` places.
pub struct Gate {
    cap: usize,
    state: Mutex<State>,
}

/// A place in a gate, given back (to the next waiting request, landings
/// first) when dropped.
pub struct Place {
    gate: Arc<Gate>,
    /// The project's map, to forget the gate once nobody is in or waiting.
    map: Option<(Arc<Map>, Key)>,
}

enum Enter {
    In,
    Wait(u64, oneshot::Receiver<()>),
}

impl Gate {
    pub fn new(cap: usize) -> Arc<Gate> {
        Arc::new(Gate { cap: cap.max(1), state: Mutex::new(State::default()) })
    }

    fn enter(&self, class: Class) -> Enter {
        let mut s = self.state.lock().unwrap();
        if s.running < self.cap && s.waiting() == 0 {
            s.running += 1;
            return Enter::In;
        }
        let (tx, rx) = oneshot::channel();
        let t = s.next;
        s.next += 1;
        s.queues[class as usize].push_back((t, tx, tokio::time::Instant::now()));
        Enter::Wait(t, rx)
    }

    /// Give a place back: to a pull that has waited [`AGE`] (unless the last
    /// place went to one: then by the normal order), else the first waiting
    /// landing, else pull, else search; `true` if the gate is now idle.
    fn leave(&self) -> bool {
        let mut s = self.state.lock().unwrap();
        let read = Class::Read as usize;
        let aged = !s.aged_turn && s.queues[read].front().is_some_and(|(_, _, at)| at.elapsed() >= AGE);
        let order: &[usize] = if aged { &[read, 2, 1, 0] } else { &[2, 1, 0] };
        for &c in order {
            while let Some((_, tx, _)) = s.queues[c].pop_front() {
                if tx.send(()).is_ok() {
                    s.aged_turn = aged && c == read;
                    return false;
                }
            }
        }
        s.aged_turn = false;
        s.running -= 1;
        s.running == 0
    }

    /// Requests running, and waiting.
    pub fn load(&self) -> (usize, usize) {
        let s = self.state.lock().unwrap();
        (s.running, s.waiting())
    }

    /// Wait for a place until `deadline`.
    pub async fn place(self: &Arc<Gate>, class: Class, deadline: tokio::time::Instant) -> Option<Place> {
        let got = match self.enter(class) {
            Enter::In => true,
            Enter::Wait(t, rx) => Ticket { gate: self.clone(), class, id: t, rx: Some(rx), map: None }.wait(deadline).await,
        };
        got.then(|| Place { gate: self.clone(), map: None })
    }
}

/// A request waiting in a gate. Dropped while waiting (its client went
/// away), it leaves the queue, or gives back a place handed to it just
/// then: no place is ever lost.
struct Ticket {
    gate: Arc<Gate>,
    class: Class,
    id: u64,
    rx: Option<oneshot::Receiver<()>>,
    map: Option<(Arc<Map>, Key)>,
}

impl Ticket {
    /// Wait until `deadline`: `true` if a place came (it is then the
    /// caller's).
    async fn wait(mut self, deadline: tokio::time::Instant) -> bool {
        let rx = self.rx.as_mut().expect("a ticket waits once");
        if tokio::time::timeout_at(deadline, rx).await.is_ok_and(|r| r.is_ok()) {
            self.rx = None;
            return true;
        }
        let mut s = self.gate.state.lock().unwrap();
        let q = &mut s.queues[self.class as usize];
        let got = match q.iter().position(|(t, _, _)| *t == self.id) {
            Some(i) => {
                q.remove(i);
                false
            }
            // Handed over under the lock: it is ours.
            None => self.rx.as_mut().is_some_and(|rx| rx.try_recv().is_ok()),
        };
        self.rx = None;
        got
    }
}

impl Drop for Ticket {
    fn drop(&mut self) {
        let Some(mut rx) = self.rx.take() else { return };
        let mut s = self.gate.state.lock().unwrap();
        let q = &mut s.queues[self.class as usize];
        if let Some(i) = q.iter().position(|(t, _, _)| *t == self.id) {
            q.remove(i);
            return;
        }
        drop(s);
        if rx.try_recv().is_ok() {
            match &self.map {
                Some((map, key)) => map.leave(key, &self.gate),
                None => {
                    self.gate.leave();
                }
            }
        }
    }
}

impl Drop for Place {
    fn drop(&mut self) {
        match &self.map {
            None => {
                self.gate.leave();
            }
            Some((map, key)) => map.leave(key, &self.gate),
        }
    }
}

/// What a project gate is keyed by.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Key {
    /// A project, by the name the route names: whether a project of that
    /// name exists (or this server knows it) changes nothing here, so
    /// how long a request waits says nothing about hidden projects. Made-up
    /// names get gates of their own; the server's gate bounds them all.
    Project(String),
    /// Routes of no project: sign-in, devices, the epoch feeds.
    Server,
}

const SHARDS: usize = 16;

/// The project gates that have a request in or waiting; a gate is
/// forgotten when it has neither, so the map holds at most one entry per
/// request in flight.
pub struct Map {
    cap: usize,
    hasher: std::collections::hash_map::RandomState,
    shards: Vec<Mutex<HashMap<Key, Arc<Gate>>>>,
}

impl Map {
    pub fn new(cap: usize) -> Arc<Map> {
        Arc::new(Map { cap, hasher: Default::default(), shards: (0..SHARDS).map(|_| Mutex::new(HashMap::new())).collect() })
    }

    fn shard(&self, k: &Key) -> &Mutex<HashMap<Key, Arc<Gate>>> {
        &self.shards[self.hasher.hash_one(k) as usize % SHARDS]
    }

    /// Wait for a place in `key`'s gate until `deadline`.
    pub async fn place(self: &Arc<Map>, key: Key, class: Class, deadline: tokio::time::Instant) -> Option<Place> {
        // Entered under the shard's lock, so a gate is never forgotten while
        // someone is about to enter it.
        let (gate, entered) = {
            let mut m = self.shard(&key).lock().unwrap();
            let gate = m.entry(key.clone()).or_insert_with(|| Gate::new(self.cap)).clone();
            let e = gate.enter(class);
            (gate, e)
        };
        let got = match entered {
            Enter::In => true,
            Enter::Wait(t, rx) => Ticket { gate: gate.clone(), class, id: t, rx: Some(rx), map: Some((self.clone(), key.clone())) }.wait(deadline).await,
        };
        if !got {
            // Nobody may be left in it: forget it then.
            let mut m = self.shard(&key).lock().unwrap();
            if m.get(&key).is_some_and(|g| Arc::ptr_eq(g, &gate)) && gate.load() == (0, 0) {
                m.remove(&key);
            }
            return None;
        }
        Some(Place { gate, map: Some((self.clone(), key)) })
    }

    fn leave(&self, key: &Key, gate: &Arc<Gate>) {
        let mut m = self.shard(key).lock().unwrap();
        if gate.leave() {
            if let Some(g) = m.get(key) {
                if Arc::ptr_eq(g, gate) {
                    m.remove(key);
                }
            }
        }
    }

    /// Gates kept (for tests).
    pub fn len(&self) -> usize {
        self.shards.iter().map(|s| s.lock().unwrap().len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Requests running and waiting in `key`'s gate.
    pub fn load(&self, key: &Key) -> (usize, usize) {
        self.shard(key).lock().unwrap().get(key).map_or((0, 0), |g| g.load())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::Instant;

    fn soon(ms: u64) -> Instant {
        Instant::now() + Duration::from_millis(ms)
    }

    /// A gate lets `cap` in; the next waits, and gets the place given back.
    #[tokio::test]
    async fn a_gate_holds_its_cap_and_hands_places_on() {
        let g = Gate::new(2);
        let a = g.place(Class::Read, soon(10)).await.unwrap();
        let _b = g.place(Class::Read, soon(10)).await.unwrap();
        assert!(g.place(Class::Read, soon(50)).await.is_none(), "a third waits out its deadline");
        assert_eq!(g.load(), (2, 0), "and leaves nothing queued");
        let g2 = g.clone();
        let waiter = tokio::spawn(async move { g2.place(Class::Read, soon(2000)).await.is_some() });
        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(a);
        assert!(waiter.await.unwrap(), "the place given back goes to the waiting request");
    }

    /// Landings get a free place before pulls, and pulls before search,
    /// whatever order they came in.
    #[tokio::test]
    async fn landings_are_let_in_first_and_search_last() {
        let g = Gate::new(1);
        let first = g.place(Class::Read, soon(10)).await.unwrap();
        let order = Arc::new(Mutex::new(Vec::new()));
        let mut tasks = Vec::new();
        for c in [Class::Search, Class::Read, Class::Write] {
            let (g, order) = (g.clone(), order.clone());
            tasks.push(tokio::spawn(async move {
                let p = g.place(c, soon(5000)).await.unwrap();
                order.lock().unwrap().push(c);
                tokio::time::sleep(Duration::from_millis(5)).await;
                drop(p);
            }));
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        drop(first);
        for t in tasks {
            t.await.unwrap();
        }
        assert_eq!(*order.lock().unwrap(), vec![Class::Write, Class::Read, Class::Search]);
    }

    /// Gates are forgotten once idle, timed-out waiters included: the map
    /// holds nothing for names no request is using.
    #[tokio::test]
    async fn idle_gates_are_forgotten() {
        let m = Map::new(1);
        let a = m.place(Key::Project("a".into()), Class::Read, soon(10)).await.unwrap();
        assert!(m.place(Key::Project("a".into()), Class::Read, soon(30)).await.is_none());
        let b = m.place(Key::Project("b".into()), Class::Read, soon(10)).await.unwrap();
        assert_eq!(m.len(), 2);
        drop((a, b));
        assert_eq!(m.len(), 0);
        // Many at once, all given back.
        let mut tasks = Vec::new();
        for i in 0..64 {
            let m = m.clone();
            tasks.push(tokio::spawn(async move {
                if let Some(p) = m.place(Key::Project(format!("p{}", i % 4)), Class::Write, soon(5000)).await {
                    tokio::time::sleep(Duration::from_millis(2)).await;
                    drop(p);
                    true
                } else {
                    false
                }
            }));
        }
        for t in tasks {
            assert!(t.await.unwrap());
        }
        assert_eq!(m.len(), 0);
    }

    /// Under a full gate search gives up first (its wait is the shortest),
    /// pulls next, and landings wait longest.
    #[tokio::test(start_paused = true)]
    async fn search_is_shed_first_and_landings_last() {
        assert!(Class::Search.wait() < Class::Read.wait() && Class::Read.wait() < Class::Write.wait());
        let g = Gate::new(1);
        let _held = g.place(Class::Write, soon(10)).await.unwrap();
        let mut gave_up = Vec::new();
        let start = Instant::now();
        let tasks: Vec<_> = [Class::Write, Class::Read, Class::Search]
            .into_iter()
            .map(|c| {
                let g = g.clone();
                tokio::spawn(async move {
                    let got = g.place(c, Instant::now() + c.wait()).await.is_some();
                    (c, got, start.elapsed())
                })
            })
            .collect();
        for t in tasks {
            gave_up.push(t.await.unwrap());
        }
        gave_up.sort_by_key(|(_, _, at)| *at);
        assert_eq!(gave_up.iter().map(|(c, got, _)| (*c, *got)).collect::<Vec<_>>(), vec![(Class::Search, false), (Class::Read, false), (Class::Write, false)]);
        assert_eq!(g.load(), (1, 0), "no waiter left behind");
    }

    /// Guarantee (design §4.11): landings are shed last. A steady stream of
    /// pulls whose waits all pass [`AGE`] (the queue is longer than a
    /// second's worth of places) must not keep every free place from the
    /// landings: a landing waits for at most a few pulls' turns, not for
    /// the stream to end.
    #[tokio::test(start_paused = true)]
    async fn a_stream_of_aged_pulls_does_not_starve_landings() {
        let g = Gate::new(1);
        let held = g.place(Class::Write, soon(10)).await.unwrap();
        let order = Arc::new(Mutex::new(Vec::new()));
        let mut tasks = Vec::new();
        // 40 pulls queue up at once; a landing comes half a second later.
        for (i, (c, after)) in (0..40).map(|_| (Class::Read, 0u64)).chain([(Class::Write, 500)]).enumerate() {
            let (g, order) = (g.clone(), order.clone());
            tasks.push(tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(after)).await;
                let p = g.place(c, soon(60_000)).await.unwrap();
                order.lock().unwrap().push((i, c));
                // Each request runs 100 ms: forty pulls are four seconds.
                tokio::time::sleep(Duration::from_millis(100)).await;
                drop(p);
            }));
        }
        tokio::time::sleep(Duration::from_millis(1500)).await;
        drop(held);
        for t in tasks {
            t.await.unwrap();
        }
        let order = order.lock().unwrap().clone();
        let landing_at = order.iter().position(|(_, c)| *c == Class::Write).unwrap();
        assert!(landing_at <= 2, "the landing ran {landing_at}th, after {} aged pulls: {order:?}", landing_at);
    }

    /// A pull that has waited [`AGE`] goes before a newer landing: a steady
    /// stream of landings does not starve pulls.
    #[tokio::test(start_paused = true)]
    async fn a_pull_that_waited_goes_before_newer_landings() {
        let g = Gate::new(1);
        let held = g.place(Class::Write, soon(10)).await.unwrap();
        let order = Arc::new(Mutex::new(Vec::new()));
        let mut tasks = Vec::new();
        for (c, after) in [(Class::Read, 0), (Class::Write, 1500)] {
            let (g, order) = (g.clone(), order.clone());
            tasks.push(tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(after)).await;
                let p = g.place(c, soon(30_000)).await.unwrap();
                order.lock().unwrap().push(c);
                drop(p);
            }));
        }
        tokio::time::sleep(Duration::from_millis(2000)).await;
        drop(held);
        for t in tasks {
            t.await.unwrap();
        }
        assert_eq!(*order.lock().unwrap(), vec![Class::Read, Class::Write]);
    }
}
