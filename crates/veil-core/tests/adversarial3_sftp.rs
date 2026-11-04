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

use veil_core::{SftpBackend, StorageBackend, VPath};

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
}

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
            let r = match kind {
                7 if mode == Mode::HugeNameCount => {
                    let mut b = Vec::new();
                    put_u32(&mut b, u32::MAX);
                    send(&mut server, 104, Some(id), &b)
                }
                // LSTAT
                7 => {
                    let a = if mode == Mode::EndlessListing {
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
    let (r, w, s) = stub(mode, cap);
    let b = SftpBackend::from_streams(r, w, "/srv/repo", "hostile stub").unwrap();
    (b, s)
}

// ---- BUG-065: a hostile server makes one read or listing grow without bound --------

/// The server says the file is 16 bytes, then never sends EOF. The client
/// keeps reading (`read_handle` probes past the size hint until EOF, with no
/// ceiling) and buffers everything: a hostile or compromised SFTP host can
/// exhaust the client's memory with any file it is asked for (op heads,
/// locks, pack indexes). The stub hangs up after 256 MiB.
#[test]
#[ignore = "BUG-065: a hostile SFTP server makes the client buffer an endless file (no size ceiling in read_handle)"]
fn an_endless_file_is_refused_before_exhausting_memory() {
    const CAP: u64 = 256 << 20;
    let (b, stub) = connect(Mode::EndlessRead, CAP);
    let res = b.read(&p(".veil/op_head"));
    let served = stub.served.load(Ordering::Relaxed);
    stub.stop.store(true, Ordering::Relaxed);
    assert!(res.is_err());
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
#[ignore = "BUG-065: a hostile SFTP server makes the client accumulate an endless directory listing"]
fn an_endless_listing_is_refused_before_exhausting_memory() {
    const CAP: u64 = 2_000_000;
    let (b, stub) = connect(Mode::EndlessListing, CAP);
    let res = b.list_dir(&p(".veil/objects/ab"));
    let served = stub.served.load(Ordering::Relaxed);
    stub.stop.store(true, Ordering::Relaxed);
    assert!(res.is_err());
    assert!(served < CAP, "the client accepted {served} directory entries");
}

// ---- BUG-066: unsolicited replies keep a dead request alive forever ----------------

/// `Pending::wait` times out only when *no packet at all* arrived for the
/// timeout (300 s): any packet counts, even one answering no request. A
/// server that never answers but sends a stray STATUS every 200 ms hangs
/// every Veil command forever (`vl push`, `vl pull`, and the remote lock
/// held meanwhile). Runs for about five and a half minutes.
#[test]
#[ignore = "BUG-066: unsolicited SFTP replies with unknown ids reset the timeout, so a hostile server hangs vl forever (~330 s test)"]
fn stray_replies_do_not_defeat_the_request_timeout() {
    let (b, stub) = connect(Mode::KeepAliveNoise, u64::MAX);
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let r = b.metadata(&p(".veil/repo.json"));
        let _ = tx.send(r.is_err());
    });
    let start = Instant::now();
    let got = rx.recv_timeout(Duration::from_secs(330));
    stub.stop.store(true, Ordering::Relaxed);
    assert!(
        got.is_ok(),
        "no result after {:?}: the 300 s timeout never fired",
        start.elapsed()
    );
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
