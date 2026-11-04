//! Round 3 adversarial tests: a hostile SFTP server. The server is an
//! in-process stub speaking SFTP version 3 over a socket pair, so it can
//! send whatever a malicious (or compromised) host would: endless data,
//! endless listings, keep-alive noise instead of answers, malformed
//! packets.

use std::{
    io::{Read, Write},
    os::unix::net::UnixStream,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use veil_core::{vfs::SftpOptions, SftpBackend, StorageBackend, VPath};

fn p(s: &str) -> VPath {
    VPath::new(s).unwrap()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    /// LSTAT says a 16-byte regular file; READ always returns a full chunk.
    EndlessRead,
    /// READDIR always returns another batch of names.
    EndlessListing,
    /// Never answer a request; send an unsolicited reply (unknown id) every
    /// 200 ms so the connection never looks quiet.
    KeepAliveNoise,
    /// Behave, but answer every LSTAT with a NAME packet claiming 2^32-1
    /// entries.
    HugeNameCount,
    /// Answer the first request with a reply of length field `u32::MAX`.
    HugePacket,
    /// Never answer the handshake (a remote shell that prints nothing).
    SilentHandshake,
    /// Never answer and never read: the client's writes back up.
    NeverReads,
    /// Answer everything, but each reply also comes with a duplicate.
    DuplicateReplies,
    /// LSTAT claims a 1 TiB file.
    HugeStatSize,
    /// READDIR returns an empty NAME batch forever.
    EmptyBatches,
    /// Like [`Mode::EndlessListing`], but every entry comes without
    /// permissions, so the client must stat each one.
    UntypedListing,
    /// Status replies carry a message with terminal escapes.
    EscapeStatus,
    /// An honest 2 MiB file on a slow server: every reply takes 40 ms, in
    /// order.
    SlowFile,
    /// Never answer an LSTAT of a path containing `stuck`; answer the rest.
    IgnoreStuck,
    /// Behave, with a clock ten minutes slow (LSTAT reports that mtime).
    SlowClock,
    /// Every directory holds one subdirectory, forever.
    EndlessDepth,
}

const SLOW_FILE: u64 = 2 << 20;

struct Stub {
    /// Bytes of DATA (or names) served so far.
    served: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
}

fn put_u32(v: &mut Vec<u8>, x: u32) {
    v.extend_from_slice(&x.to_be_bytes());
}
fn put_str(v: &mut Vec<u8>, s: &[u8]) {
    put_u32(v, s.len() as u32);
    v.extend_from_slice(s);
}

fn send(w: &mut UnixStream, kind: u8, id: Option<u32>, body: &[u8]) -> std::io::Result<()> {
    let mut pkt = Vec::with_capacity(body.len() + 9);
    let len = 1 + id.map_or(0, |_| 4) + body.len();
    put_u32(&mut pkt, len as u32);
    pkt.push(kind);
    if let Some(id) = id {
        put_u32(&mut pkt, id);
    }
    pkt.extend_from_slice(body);
    w.write_all(&pkt)
}

fn read_pkt(r: &mut UnixStream) -> std::io::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len)?;
    let mut buf = vec![0u8; u32::from_be_bytes(len) as usize];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

fn attrs_regular(size: u64) -> Vec<u8> {
    let mut a = Vec::new();
    put_u32(&mut a, 0x1 | 0x4);
    a.extend_from_slice(&size.to_be_bytes());
    put_u32(&mut a, 0o100644);
    a
}

/// Start the stub; returns the client's ends of the connection.
fn stub(mode: Mode, cap: u64) -> (UnixStream, UnixStream, Stub) {
    let (client, mut server) = UnixStream::pair().unwrap();
    let served = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let (s2, st2) = (served.clone(), stop.clone());
    let mut noise = server.try_clone().unwrap();
    std::thread::spawn(move || {
        // Handshake.
        let Ok(_init) = read_pkt(&mut server) else { return };
        if mode == Mode::SilentHandshake {
            while !st2.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(20));
            }
            return;
        }
        if mode == Mode::NeverReads {
            let mut v = Vec::new();
            put_u32(&mut v, 3);
            let _ = send(&mut server, 2, None, &v);
            // Hold the socket open, reading nothing more.
            while !st2.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(20));
            }
            return;
        }
        let mut v = Vec::new();
        put_u32(&mut v, 3);
        for ext in ["posix-rename@openssh.com", "fsync@openssh.com", "hardlink@openssh.com"] {
            put_str(&mut v, ext.as_bytes());
            put_str(&mut v, b"1");
        }
        if send(&mut server, 2, None, &v).is_err() {
            return;
        }
        if mode == Mode::KeepAliveNoise {
            let st3 = st2.clone();
            std::thread::spawn(move || {
                while !st3.load(Ordering::Relaxed) {
                    let mut b = Vec::new();
                    put_u32(&mut b, 0);
                    put_str(&mut b, b"");
                    put_str(&mut b, b"");
                    if send(&mut noise, 101, Some(0x7fff_fff0), &b).is_err() {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(200));
                }
            });
        }
        let mut names = 0u64;
        loop {
            if st2.load(Ordering::Relaxed) || s2.load(Ordering::Relaxed) >= cap {
                let _ = server.shutdown(std::net::Shutdown::Both);
                return;
            }
            let Ok(pkt) = read_pkt(&mut server) else { return };
            let kind = pkt[0];
            let id = u32::from_be_bytes(pkt[1..5].try_into().unwrap());
            if mode == Mode::KeepAliveNoise {
                continue; // never answer
            }
            if mode == Mode::HugePacket {
                let _ = server.write_all(&u32::MAX.to_be_bytes());
                continue;
            }
            if mode == Mode::DuplicateReplies {
                let mut b = Vec::new();
                put_u32(&mut b, 0);
                put_str(&mut b, b"");
                put_str(&mut b, b"");
                // The duplicate goes first, so the real reply is the stray one.
                let _ = send(&mut server, 101, Some(id), &b);
            }
            if mode == Mode::SlowFile {
                std::thread::sleep(Duration::from_millis(40));
            }
            if mode == Mode::IgnoreStuck && kind == 7 && pkt.windows(5).any(|w| w == b"stuck") {
                continue;
            }
            let r = match kind {
                12 if mode == Mode::EndlessDepth => {
                    names += 1;
                    let mut b = Vec::new();
                    if names % 2 == 1 {
                        put_u32(&mut b, 1);
                        put_str(&mut b, b"d");
                        put_str(&mut b, b"d");
                        put_u32(&mut b, 0x4);
                        put_u32(&mut b, 0o040755);
                        s2.fetch_add(1, Ordering::Relaxed);
                        send(&mut server, 104, Some(id), &b)
                    } else {
                        put_u32(&mut b, 1);
                        put_str(&mut b, b"");
                        put_str(&mut b, b"");
                        send(&mut server, 101, Some(id), &b)
                    }
                }
                7 if mode == Mode::SlowClock => {
                    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
                    let mut a = Vec::new();
                    put_u32(&mut a, 0x1 | 0x4 | 0x8);
                    a.extend_from_slice(&0u64.to_be_bytes());
                    put_u32(&mut a, 0o100644);
                    put_u32(&mut a, (now - 600) as u32);
                    put_u32(&mut a, (now - 600) as u32);
                    send(&mut server, 105, Some(id), &a)
                }
                7 if mode == Mode::SlowFile => send(&mut server, 105, Some(id), &attrs_regular(SLOW_FILE)),
                5 if mode == Mode::SlowFile => {
                    let hl = u32::from_be_bytes(pkt[5..9].try_into().unwrap()) as usize;
                    let off = u64::from_be_bytes(pkt[9 + hl..9 + hl + 8].try_into().unwrap());
                    let n = u32::from_be_bytes(pkt[9 + hl + 8..9 + hl + 12].try_into().unwrap()) as u64;
                    if off >= SLOW_FILE {
                        let mut b = Vec::new();
                        put_u32(&mut b, 1);
                        put_str(&mut b, b"");
                        put_str(&mut b, b"");
                        send(&mut server, 101, Some(id), &b)
                    } else {
                        let k = n.min(SLOW_FILE - off) as usize;
                        let mut b = Vec::with_capacity(k + 4);
                        put_str(&mut b, &vec![(off % 251) as u8; k]);
                        send(&mut server, 103, Some(id), &b)
                    }
                }
                7 if mode == Mode::HugeStatSize => send(&mut server, 105, Some(id), &attrs_regular(1 << 40)),
                7 if mode == Mode::EscapeStatus => {
                    let mut b = Vec::new();
                    put_u32(&mut b, 4);
                    put_str(&mut b, b"\x1b]0;pwned\x07\x1b[2Jdenied");
                    put_str(&mut b, b"");
                    send(&mut server, 101, Some(id), &b)
                }
                12 if mode == Mode::EmptyBatches => {
                    let mut b = Vec::new();
                    put_u32(&mut b, 0);
                    s2.fetch_add(1, Ordering::Relaxed);
                    send(&mut server, 104, Some(id), &b)
                }
                12 if mode == Mode::UntypedListing => {
                    let mut b = Vec::new();
                    put_u32(&mut b, 100);
                    for _ in 0..100 {
                        names += 1;
                        let name = format!("{names:064x}");
                        put_str(&mut b, name.as_bytes());
                        put_str(&mut b, name.as_bytes());
                        put_u32(&mut b, 0); // no attributes at all
                    }
                    s2.fetch_add(100, Ordering::Relaxed);
                    send(&mut server, 104, Some(id), &b)
                }
                7 if mode == Mode::HugeNameCount => {
                    let mut b = Vec::new();
                    put_u32(&mut b, u32::MAX);
                    send(&mut server, 104, Some(id), &b)
                }
                // LSTAT
                7 => {
                    let a = if matches!(
                        mode,
                        Mode::EndlessListing | Mode::UntypedListing | Mode::EmptyBatches | Mode::EndlessDepth
                    ) {
                        let mut a = Vec::new();
                        put_u32(&mut a, 0x4);
                        put_u32(&mut a, 0o040755);
                        a
                    } else {
                        attrs_regular(16)
                    };
                    send(&mut server, 105, Some(id), &a)
                }
                // OPEN, OPENDIR
                3 | 11 => {
                    let mut b = Vec::new();
                    put_str(&mut b, b"h1");
                    send(&mut server, 102, Some(id), &b)
                }
                // READ: handle, offset, len
                5 => {
                    let hl = u32::from_be_bytes(pkt[5..9].try_into().unwrap()) as usize;
                    let at = 9 + hl + 8;
                    let n = u32::from_be_bytes(pkt[at..at + 4].try_into().unwrap()) as usize;
                    s2.fetch_add(n as u64, Ordering::Relaxed);
                    let mut b = Vec::with_capacity(n + 4);
                    put_str(&mut b, &vec![b'A'; n]);
                    send(&mut server, 103, Some(id), &b)
                }
                // READDIR
                12 => {
                    let mut b = Vec::new();
                    put_u32(&mut b, 100);
                    for _ in 0..100 {
                        names += 1;
                        let name = format!("{names:064x}");
                        put_str(&mut b, name.as_bytes());
                        put_str(&mut b, name.as_bytes());
                        b.extend_from_slice(&attrs_regular(1));
                    }
                    s2.fetch_add(100, Ordering::Relaxed);
                    send(&mut server, 104, Some(id), &b)
                }
                // Everything else: OK.
                _ => {
                    let mut b = Vec::new();
                    put_u32(&mut b, 0);
                    put_str(&mut b, b"");
                    put_str(&mut b, b"");
                    send(&mut server, 101, Some(id), &b)
                }
            };
            if r.is_err() {
                return;
            }
        }
    });
    let reader = client.try_clone().unwrap();
    (reader, client, Stub { served, stop })
}

fn connect(mode: Mode, cap: u64) -> (SftpBackend, Stub) {
    connect_with(mode, cap, SftpOptions::default())
}

/// A short request timeout, so tests of the timeout itself run in seconds.
fn short_timeout() -> SftpOptions {
    SftpOptions {
        timeout: Duration::from_secs(2),
        ..SftpOptions::default()
    }
}

fn connect_with(mode: Mode, cap: u64, opts: SftpOptions) -> (SftpBackend, Stub) {
    let (r, w, s) = stub(mode, cap);
    let b = SftpBackend::from_streams_with(r, w, "/srv/repo", "hostile stub", opts).unwrap();
    (b, s)
}

fn error_text(r: veil_core::Result<impl std::fmt::Debug>) -> String {
    match r {
        Ok(v) => panic!("expected an error, got {v:?}"),
        Err(e) => e.to_string(),
    }
}

// ---- BUG-065: a hostile server makes one read or listing grow without bound --------

/// The server says the file is 16 bytes, then never sends EOF. The client
/// keeps reading (`read_handle` probes past the size hint until EOF, with no
/// ceiling) and buffers everything: a hostile or compromised SFTP host can
/// exhaust the client's memory with any file it is asked for (op heads,
/// locks, pack indexes). The stub hangs up after 256 MiB.
#[test]
fn an_endless_file_is_refused_before_exhausting_memory() {
    const CAP: u64 = 256 << 20;
    let (b, stub) = connect(Mode::EndlessRead, CAP);
    let res = b.read(&p(".veil/op_head"));
    let served = stub.served.load(Ordering::Relaxed);
    stub.stop.store(true, Ordering::Relaxed);
    let msg = error_text(res);
    assert!(msg.contains("more than"), "{msg}");
    assert!(
        served < CAP,
        "the client accepted {} MiB for a file the server said was 16 bytes",
        served >> 20
    );
}

/// The same for directory listings: READDIR never answers EOF, and
/// `readdir` accumulates names forever (the stub hangs up after 2,000,000
/// names, about 200 MiB of listing).
#[test]
fn an_endless_listing_is_refused_before_exhausting_memory() {
    const CAP: u64 = 2_000_000;
    let (b, stub) = connect(Mode::EndlessListing, CAP);
    let res = b.list_dir(&p(".veil/objects/ab"));
    let served = stub.served.load(Ordering::Relaxed);
    stub.stop.store(true, Ordering::Relaxed);
    let msg = error_text(res);
    assert!(msg.contains("directory listing passed"), "{msg}");
    assert!(served < CAP, "the client accepted {served} directory entries");
}

// ---- BUG-066: unsolicited replies keep a dead request alive forever ----------------

/// `Pending::wait` timed out only when *no packet at all* arrived for the
/// timeout (300 s): any packet counted, even one answering no request. A
/// server that never answers but sends a stray STATUS every 200 ms hung
/// every Veil command forever (`vl push`, `vl pull`, and the remote lock
/// held meanwhile).
///
/// Adapted from the original (which waited 330 s for the default 300 s
/// timeout): the connection is opened with a 2 s request timeout
/// ([`SftpOptions::timeout`], `VEIL_SFTP_TIMEOUT` for `vl`), and the
/// result must arrive within 30 s, fifteen times that. The stray replies
/// arrive every 200 ms, so they would keep resetting the old timeout just
/// the same.
#[test]
fn stray_replies_do_not_defeat_the_request_timeout() {
    let (b, stub) = connect_with(Mode::KeepAliveNoise, u64::MAX, short_timeout());
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let r = b.metadata(&p(".veil/repo.json"));
        let _ = tx.send(r.is_err());
    });
    let start = Instant::now();
    let got = rx.recv_timeout(Duration::from_secs(30));
    stub.stop.store(true, Ordering::Relaxed);
    assert!(
        got.is_ok(),
        "no result after {:?}: the 2 s timeout never fired",
        start.elapsed()
    );
    assert_eq!(got, Ok(true));
}

/// The same server with the default 300 s timeout: the 17th stray reply
/// (after about 3.4 s) closes the connection as a protocol error, long
/// before any timeout.
#[test]
fn stray_replies_are_a_protocol_error() {
    let (b, stub) = connect(Mode::KeepAliveNoise, u64::MAX);
    let start = Instant::now();
    let msg = error_text(b.metadata(&p(".veil/repo.json")));
    stub.stop.store(true, Ordering::Relaxed);
    assert!(start.elapsed() < Duration::from_secs(30), "took {:?}", start.elapsed());
    assert!(msg.contains("never made"), "{msg}");
    assert!(b.is_disconnected());
}

/// Every reply sent twice: the duplicates are stray, and after a few of
/// them the connection is closed rather than trusted.
#[test]
fn duplicated_replies_close_the_connection() {
    let (b, stub) = connect(Mode::DuplicateReplies, u64::MAX);
    let mut failed = None;
    for i in 0..64 {
        if let Err(e) = b.create_dir_all(&p(&format!("d{i}"))) {
            failed = Some((i, e.to_string()));
            break;
        }
    }
    stub.stop.store(true, Ordering::Relaxed);
    let (i, msg) = failed.expect("a server that answers twice is never caught");
    assert!(i <= 20, "caught only after {i} requests");
    assert!(msg.contains("never made") || msg.contains("connection lost"), "{msg}");
}

/// A server that never answers the version handshake: connecting fails
/// after the timeout instead of hanging.
#[test]
fn a_silent_handshake_times_out() {
    let (r, w, stub) = stub(Mode::SilentHandshake, u64::MAX);
    let start = Instant::now();
    let res = SftpBackend::from_streams_with(r, w, "/srv/repo", "silent stub", short_timeout());
    stub.stop.store(true, Ordering::Relaxed);
    let msg = error_text(res.map(|_| ()));
    assert!(msg.contains("handshake"), "{msg}");
    assert!(start.elapsed() < Duration::from_secs(20), "took {:?}", start.elapsed());
}

/// A server that stops reading: the client's writes back up in the socket.
/// The caller must still get its timeout (the writes block a writer
/// thread, not the caller).
#[test]
fn a_server_that_stops_reading_cannot_block_a_writer() {
    let (b, stub) = connect_with(Mode::NeverReads, u64::MAX, short_timeout());
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        // 8 MiB: far more than a socket buffer holds.
        let r = b.write(&p(".veil/objects/pack/big"), &vec![7u8; 8 << 20]);
        let _ = tx.send(r.is_err());
    });
    let got = rx.recv_timeout(Duration::from_secs(30));
    stub.stop.store(true, Ordering::Relaxed);
    assert_eq!(got, Ok(true), "the write neither failed nor returned");
}

/// A slow but honest server and a deep pipeline: 64 reads in flight, the
/// last answered about 2.6 s after it was sent, with a 1 s timeout. Replies
/// to earlier requests are progress, so nothing times out.
#[test]
fn a_slow_server_with_a_deep_pipeline_does_not_time_out() {
    let opts = SftpOptions {
        timeout: Duration::from_secs(1),
        ..SftpOptions::default()
    };
    let (b, stub) = connect_with(Mode::SlowFile, u64::MAX, opts);
    let start = Instant::now();
    let data = b.read(&p(".veil/objects/pack/x.pack")).unwrap();
    stub.stop.store(true, Ordering::Relaxed);
    assert!(start.elapsed() > Duration::from_secs(2), "the stub was not slow");
    assert_eq!(data.len() as u64, SLOW_FILE);
    for (i, c) in data.chunks(32 * 1024).enumerate() {
        let want = ((i as u64 * 32 * 1024) % 251) as u8;
        assert!(c.iter().all(|&x| x == want), "chunk {i} is wrong");
    }
}

/// One request is never answered while another thread's requests are: the
/// unanswered one still times out (replies to requests sent after it are
/// not progress for it).
#[test]
fn other_threads_replies_do_not_keep_a_dead_request_alive() {
    let b = Arc::new(connect_with(Mode::IgnoreStuck, u64::MAX, short_timeout()));
    let (tx, rx) = std::sync::mpsc::channel();
    let stuck = {
        let b = b.clone();
        std::thread::spawn(move || {
            let r = b.0.metadata(&p("stuck"));
            let _ = tx.send(r.is_err());
        })
    };
    let busy = {
        let b = b.clone();
        std::thread::spawn(move || {
            let mut answered = 0u32;
            while b.0.metadata(&p("ok")).is_ok() && answered < 2_000 {
                answered += 1;
                std::thread::sleep(Duration::from_millis(5));
            }
            answered
        })
    };
    let got = rx.recv_timeout(Duration::from_secs(30));
    b.1.stop.store(true, Ordering::Relaxed);
    assert_eq!(got, Ok(true), "the unanswered request never timed out");
    stuck.join().unwrap();
    assert!(busy.join().unwrap() > 10, "the other thread's requests were not being answered");
}

// ---- clock skew (round 3 hypothesis) -------------------------------------------------

/// `vl doctor --remotes` warns about clock skew using the mtime of a probe
/// file on the server: here the server's clock is ten minutes slow.
#[test]
fn the_servers_clock_offset_is_measured() {
    let (b, stub) = connect(Mode::SlowClock, u64::MAX);
    let offset = b.clock_offset(&p(".veil")).unwrap();
    stub.stop.store(true, Ordering::Relaxed);
    assert!((offset + 600_000).abs() < 2_000, "offset {offset} ms");
}

// ---- other unbounded input ----------------------------------------------------------

/// A packet whose length field says 4 GiB is refused before allocating it.
#[test]
fn a_huge_packet_length_is_refused() {
    let (b, stub) = connect(Mode::HugePacket, u64::MAX);
    let start = Instant::now();
    let msg = error_text(b.metadata(&p("x")));
    stub.stop.store(true, Ordering::Relaxed);
    assert!(start.elapsed() < Duration::from_secs(10));
    assert!(msg.contains("bytes"), "{msg}");
    assert!(b.is_disconnected());
}

/// A file the server says is 1 TiB is refused before any data is read.
#[test]
fn a_huge_stated_size_is_refused_up_front() {
    let (b, stub) = connect(Mode::HugeStatSize, u64::MAX);
    let msg = error_text(b.read(&p(".veil/objects/pack/x.pack")));
    let served = stub.served.load(Ordering::Relaxed);
    stub.stop.store(true, Ordering::Relaxed);
    assert!(msg.contains("VEIL_SFTP_MAX_FILE"), "{msg}");
    assert_eq!(served, 0);
}

/// The file limit is configurable, and also bounds an endless file whose
/// size hint is honest about nothing.
#[test]
fn the_file_limit_is_configurable() {
    let opts = SftpOptions {
        max_file: 1 << 20,
        ..SftpOptions::default()
    };
    let (b, stub) = connect_with(Mode::EndlessRead, 256 << 20, opts);
    assert!(b.read(&p(".veil/op_head")).is_err());
    let served = stub.served.load(Ordering::Relaxed);
    stub.stop.store(true, Ordering::Relaxed);
    // The limit plus at most a window of reads in flight.
    assert!(served < 20 << 20, "served {} MiB", served >> 20);
    // `read_range` beyond the limit is refused without a request.
    assert!(b.read_range(&p("x"), 0, 2 << 20).is_err());
}

/// The listing limit is configurable.
#[test]
fn the_listing_limit_is_configurable() {
    let opts = SftpOptions {
        max_listing: 1_000,
        ..SftpOptions::default()
    };
    let (b, stub) = connect_with(Mode::EndlessListing, 2_000_000, opts);
    assert!(b.list_dir(&p("d")).is_err());
    let served = stub.served.load(Ordering::Relaxed);
    stub.stop.store(true, Ordering::Relaxed);
    assert!(served <= 1_100, "served {served} entries");
}

/// READDIR answering empty batches forever (never EOF) is refused at once.
#[test]
fn empty_directory_batches_are_refused() {
    let (b, stub) = connect(Mode::EmptyBatches, 1_000_000);
    let start = Instant::now();
    assert!(b.list_dir(&p("d")).is_err());
    let served = stub.served.load(Ordering::Relaxed);
    stub.stop.store(true, Ordering::Relaxed);
    assert!(served < 10, "{served} empty batches accepted");
    assert!(start.elapsed() < Duration::from_secs(10));
}

/// An endless listing without attributes (each entry needs its own stat)
/// is bounded the same way, and the stats are pipelined.
#[test]
fn an_endless_untyped_listing_is_refused() {
    let opts = SftpOptions {
        max_listing: 5_000,
        ..SftpOptions::default()
    };
    let (b, stub) = connect_with(Mode::UntypedListing, 2_000_000, opts);
    assert!(b.list_dir(&p("d")).is_err());
    let served = stub.served.load(Ordering::Relaxed);
    stub.stop.store(true, Ordering::Relaxed);
    assert!(served <= 5_100, "served {served} entries");
}

/// `remove_dir_all` on a tree that never ends stops at a depth limit
/// instead of recursing until the stack overflows.
#[test]
fn an_endlessly_deep_tree_is_not_removed_forever() {
    let (b, stub) = connect(Mode::EndlessDepth, 100_000);
    let msg = error_text(b.remove_dir_all(&p("d")));
    let served = stub.served.load(Ordering::Relaxed);
    stub.stop.store(true, Ordering::Relaxed);
    assert!(msg.contains("deeper than"), "{msg}");
    assert!(served < 1_000, "descended {served} levels");
}

/// Status messages are shown to the user: terminal escapes are removed.
#[test]
fn status_messages_cannot_carry_terminal_escapes() {
    let (b, stub) = connect(Mode::EscapeStatus, u64::MAX);
    let msg = error_text(b.metadata(&p("x")));
    stub.stop.store(true, Ordering::Relaxed);
    assert!(msg.contains("denied"), "{msg}");
    assert!(!msg.contains('\x1b') && !msg.contains('\x07'), "{msg:?}");
}

// ---- controls ------------------------------------------------------------------------

/// A NAME reply claiming 2^32-1 entries with no data is rejected without a
/// huge allocation.
#[test]
fn control_a_huge_name_count_is_rejected() {
    let (b, stub) = connect(Mode::HugeNameCount, u64::MAX);
    let start = Instant::now();
    assert!(b.metadata(&p("x")).is_err());
    assert!(start.elapsed() < Duration::from_secs(10));
    stub.stop.store(true, Ordering::Relaxed);
}
