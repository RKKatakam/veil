//! `GIT binary patch` data: Git's base85 lines, zlib streams and its
//! delta format, read and written within bounds.
//!
//! * A **line** is a length character (`A`–`Z` for 1–26 bytes, `a`–`z` for
//!   27–52) and base85 digits, five per four bytes (the last group padded).
//! * A **block** (`literal N` or `delta N`) is a zlib stream of the lines'
//!   bytes; `N` is what it inflates to. [`inflate`] never produces more
//!   than `N` bytes, whatever the stream says, and refuses anything but
//!   exactly `N` followed by the end of the stream: memory grows with the
//!   output actually produced, never with a declared size.
//! * A **delta** (Git's pack delta) is the base's size, the result's size
//!   (little-endian base-128 numbers), then copy and insert instructions.
//!   [`apply_delta`] checks the base's size, refuses a result larger than
//!   its limit before allocating, and checks every copy against the base
//!   and the result's remaining room.
//!
//! Errors are plain messages: the caller names the file.

/// Git's base85 alphabet.
const ALPHABET: &[u8; 85] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~";

/// Most bytes one line holds.
#[cfg(feature = "git")]
pub(super) const LINE_BYTES: usize = 52;

fn digit(c: u8) -> Option<u32> {
    ALPHABET.iter().position(|a| *a == c).map(|p| p as u32)
}

/// Is `b` a base85 digit?
pub(super) fn is_digit(b: u8) -> bool {
    ALPHABET.contains(&b)
}

/// The number of bytes a line with length character `c` holds.
fn line_len(c: u8) -> Option<usize> {
    match c {
        b'A'..=b'Z' => Some((c - b'A') as usize + 1),
        b'a'..=b'z' => Some((c - b'a') as usize + 27),
        _ => None,
    }
}

/// The bytes line `l` (without its `\n`) holds, if it is well formed: a
/// length character, then exactly the digits that many bytes need.
pub(super) fn check_line(l: &[u8]) -> Option<usize> {
    let (&c, digits) = l.split_first()?;
    let n = line_len(c)?;
    (digits.len() == n.div_ceil(4) * 5 && digits.iter().all(|b| is_digit(*b))).then_some(n)
}

/// Decode `lines` (well-formed lines, each ended by `\n`).
pub(super) fn decode_lines(lines: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(lines.len() / 5 * 4);
    for l in lines.split(|b| *b == b'\n').filter(|l| !l.is_empty()) {
        let n = check_line(l).ok_or("a malformed line of base85 data")?;
        let mut left = n;
        for group in l[1..].chunks(5) {
            let mut acc: u32 = 0;
            for &c in group {
                let d = digit(c).ok_or("a character outside the base85 alphabet")?;
                acc = acc
                    .checked_mul(85)
                    .and_then(|a| a.checked_add(d))
                    .ok_or("a base85 group out of range")?;
            }
            let take = left.min(4);
            out.extend_from_slice(&acc.to_be_bytes()[..take]);
            left -= take;
        }
    }
    Ok(out)
}

/// `data` as Git writes it: lines of at most [`LINE_BYTES`] bytes.
#[cfg(feature = "git")]
pub(super) fn encode_lines(data: &[u8], out: &mut Vec<u8>) {
    for chunk in data.chunks(LINE_BYTES) {
        let n = chunk.len();
        out.push(if n <= 26 { b'A' + (n as u8 - 1) } else { b'a' + (n as u8 - 27) });
        for group in chunk.chunks(4) {
            let mut b = [0u8; 4];
            b[..group.len()].copy_from_slice(group);
            let mut acc = u32::from_be_bytes(b);
            let mut digits = [0u8; 5];
            for d in digits.iter_mut().rev() {
                *d = ALPHABET[(acc % 85) as usize];
                acc /= 85;
            }
            out.extend_from_slice(&digits);
        }
        out.push(b'\n');
    }
}

/// Inflate the zlib stream `data` into exactly `size` bytes (see the
/// module documentation).
pub(super) fn inflate(data: &[u8], size: usize) -> Result<Vec<u8>, String> {
    use zlib_rs::{Inflate, InflateFlush, Status};
    if data.is_empty() {
        // Git writes an empty stream for `literal 0`; nothing at all is
        // accepted too, for nothing.
        return if size == 0 { Ok(Vec::new()) } else { Err("binary data missing".into()) };
    }
    let mut z = Inflate::new(true, 15);
    let mut out: Vec<u8> = Vec::with_capacity(size.min(1 << 20));
    let mut chunk = vec![0u8; 64 << 10];
    let mut input = data;
    loop {
        // One byte more than may still come, to see a stream that does
        // not stop where it says.
        let room = (size - out.len() + 1).min(chunk.len());
        let before_in = z.total_in();
        let before_out = z.total_out();
        let status = z
            .decompress(input, &mut chunk[..room], InflateFlush::NoFlush)
            .map_err(|e| format!("the binary data is not a valid zlib stream ({})", e.as_str()))?;
        let used = (z.total_in() - before_in) as usize;
        let made = (z.total_out() - before_out) as usize;
        input = &input[used..];
        if out.len() + made > size {
            return Err(format!("the binary data inflates to more than the {size} bytes it declares"));
        }
        out.extend_from_slice(&chunk[..made]);
        match status {
            Status::StreamEnd => break,
            _ if used == 0 && made == 0 => return Err("the binary data ends before its zlib stream does (truncated?)".into()),
            _ => {}
        }
    }
    if !input.is_empty() {
        return Err("data after the end of a binary block's zlib stream".into());
    }
    if out.len() != size {
        return Err(format!("the binary data inflates to {} bytes, not the {size} it declares", out.len()));
    }
    Ok(out)
}

/// `data` as a zlib stream (zlib's default level).
#[cfg(feature = "git")]
pub(super) fn deflate(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; zlib_rs::compress_bound(data.len())];
    let (written, rc) = zlib_rs::compress_slice(&mut out, data, zlib_rs::DeflateConfig::default());
    assert_eq!(rc, zlib_rs::ReturnCode::Ok, "compressing into a buffer of compress_bound bytes");
    let n = written.len();
    out.truncate(n);
    out
}

/// A delta header number at `d[*at..]`.
fn header_size(d: &[u8], at: &mut usize) -> Result<u64, String> {
    let mut v: u64 = 0;
    for shift in (0..64).step_by(7) {
        let b = *d.get(*at).ok_or("a delta that ends inside its header")?;
        *at += 1;
        v |= u64::from(b & 0x7f).checked_shl(shift).filter(|_| shift < 63 || b & 0x7f <= 1).ok_or("a delta size out of range")?;
        if b & 0x80 == 0 {
            return Ok(v);
        }
    }
    Err("a delta size out of range".into())
}

/// `base` patched by Git delta `delta`; the result is at most `limit`
/// bytes (see the module documentation).
pub(super) fn apply_delta(base: &[u8], delta: &[u8], limit: u64) -> Result<Vec<u8>, String> {
    let mut at = 0;
    let src = header_size(delta, &mut at)?;
    if src != base.len() as u64 {
        return Err(format!("the delta is for a file of {src} bytes, and the file has {}", base.len()));
    }
    let dst = header_size(delta, &mut at)?;
    if dst > limit {
        return Err(format!("the delta makes a file of {dst} bytes, more than {limit} (VEIL_MAX_OBJECT)"));
    }
    let dst = dst as usize;
    let mut out: Vec<u8> = Vec::with_capacity(dst.min(1 << 20));
    while at < delta.len() {
        let cmd = delta[at];
        at += 1;
        if cmd & 0x80 != 0 {
            let mut param = |bit: u8, shift: u32| -> Result<u64, String> {
                if cmd & bit == 0 {
                    return Ok(0);
                }
                let b = *delta.get(at).ok_or("a delta that ends inside a copy instruction")?;
                at += 1;
                Ok(u64::from(b) << shift)
            };
            let off = param(0x01, 0)? | param(0x02, 8)? | param(0x04, 16)? | param(0x08, 24)?;
            let mut len = param(0x10, 0)? | param(0x20, 8)? | param(0x40, 16)?;
            if len == 0 {
                len = 0x10000;
            }
            let end = off.checked_add(len).filter(|e| *e <= base.len() as u64);
            let Some(end) = end else {
                return Err("a delta copies from outside the file it applies to".into());
            };
            if len > (dst - out.len()) as u64 {
                return Err("a delta writes more than the size it declares".into());
            }
            out.extend_from_slice(&base[off as usize..end as usize]);
        } else if cmd != 0 {
            let n = cmd as usize;
            let data = delta.get(at..at + n).ok_or("a delta that ends inside inserted data")?;
            if n > dst - out.len() {
                return Err("a delta writes more than the size it declares".into());
            }
            out.extend_from_slice(data);
            at += n;
        } else {
            return Err("a delta holds the reserved instruction 0".into());
        }
    }
    if out.len() != dst {
        return Err(format!("the delta makes {} bytes, not the {dst} it declares", out.len()));
    }
    Ok(out)
}

/// Largest file [`make_delta`] works on (a literal is written past it).
#[cfg(feature = "git")]
pub(super) const MAX_DELTA_INPUT: usize = 16 << 20;

/// Bytes a copy must match at least (and the block size of the index).
#[cfg(feature = "git")]
const BLOCK: usize = 16;

/// A Git delta turning `base` into `target`: copies of 16-byte blocks of
/// `base` found by a rolling hash, extended both ways, and inserts. Linear
/// in the sizes (each target position is hashed once, each match is
/// extended once), for inputs up to [`MAX_DELTA_INPUT`].
#[cfg(feature = "git")]
pub(super) fn make_delta(base: &[u8], target: &[u8]) -> Vec<u8> {
    use std::collections::HashMap;
    let mut out = Vec::new();
    let put_size = |out: &mut Vec<u8>, mut n: u64| loop {
        let b = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            out.push(b);
            break;
        }
        out.push(b | 0x80);
    };
    put_size(&mut out, base.len() as u64);
    put_size(&mut out, target.len() as u64);
    let flush_insert = |out: &mut Vec<u8>, data: &[u8]| {
        for c in data.chunks(127) {
            out.push(c.len() as u8);
            out.extend_from_slice(c);
        }
    };
    let copy = |out: &mut Vec<u8>, mut off: usize, mut len: usize| {
        while len > 0 {
            let n = len.min(0x00ff_ffff);
            let at = out.len();
            out.push(0x80);
            for (i, shift) in [0u32, 8, 16, 24].iter().enumerate() {
                let b = ((off >> shift) & 0xff) as u8;
                if b != 0 {
                    out[at] |= 1 << i;
                    out.push(b);
                }
            }
            if n != 0x10000 {
                for (i, shift) in [0u32, 8, 16].iter().enumerate() {
                    let b = ((n >> shift) & 0xff) as u8;
                    if b != 0 {
                        out[at] |= 0x10 << i;
                        out.push(b);
                    }
                }
            }
            off += n;
            len -= n;
        }
    };
    const P: u64 = 0x0100_0000_01b3;
    let hash = |b: &[u8]| b.iter().fold(0u64, |h, x| h.wrapping_mul(P).wrapping_add(u64::from(*x)));
    let mut index: HashMap<u64, usize> = HashMap::new();
    if base.len() >= BLOCK {
        for off in (0..=base.len() - BLOCK).step_by(BLOCK) {
            index.entry(hash(&base[off..off + BLOCK])).or_insert(off);
        }
    }
    let top = P.wrapping_pow(BLOCK as u32 - 1);
    let mut pending = 0usize; // start of the bytes not yet written
    let mut i = 0usize;
    let mut h = if target.len() >= BLOCK { hash(&target[..BLOCK]) } else { 0 };
    while i + BLOCK <= target.len() {
        let hit = index.get(&h).copied().filter(|&o| base[o..o + BLOCK] == target[i..i + BLOCK]);
        if let Some(o) = hit {
            // Extend backwards into the pending insert, then forwards.
            let mut s = 0;
            while s < i - pending && s < o && base[o - s - 1] == target[i - s - 1] {
                s += 1;
            }
            let (o, start) = (o - s, i - s);
            let mut len = BLOCK + s;
            while start + len < target.len() && o + len < base.len() && base[o + len] == target[start + len] {
                len += 1;
            }
            flush_insert(&mut out, &target[pending..start]);
            copy(&mut out, o, len);
            i = start + len;
            pending = i;
            if i + BLOCK <= target.len() {
                h = hash(&target[i..i + BLOCK]);
            }
            continue;
        }
        if i + BLOCK < target.len() {
            h = h.wrapping_sub(u64::from(target[i]).wrapping_mul(top)).wrapping_mul(P).wrapping_add(u64::from(target[i + BLOCK]));
        }
        i += 1;
    }
    flush_insert(&mut out, &target[pending..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base85_lines_follow_git() {
        // Git's own `literal 0` and a short literal from `git format-patch`.
        let empty = decode_lines(b"HcmV?d00001\n").unwrap();
        assert_eq!(inflate(&empty, 0).unwrap(), b"");
        let six = decode_lines(b"NcmZQzWJ=1+0{{Yf0X+Z!\n").unwrap();
        assert_eq!(inflate(&six, 6).unwrap(), b"\x00\x01\x02bin");
        assert!(check_line(b"HcmV?d0000").is_none(), "one digit short");
        assert!(check_line(b"HcmV?d000011").is_none(), "one digit too many");
        assert!(check_line(b"1cmV?d00001").is_none(), "no length character");
        assert!(decode_lines(b"A~~~~~\n").is_err(), "a group above 2^32");
    }

    #[cfg(feature = "git")]
    #[test]
    fn round_trips() {
        for n in [0usize, 1, 3, 4, 5, 51, 52, 53, 104, 1000] {
            let data: Vec<u8> = (0..n).map(|i| (i * 7 + 3) as u8).collect();
            let mut lines = Vec::new();
            encode_lines(&deflate(&data), &mut lines);
            assert_eq!(inflate(&decode_lines(&lines).unwrap(), n).unwrap(), data);
        }
    }

    #[test]
    fn inflate_is_bounded_by_the_declared_size() {
        // 1 MiB of zeros in about a kilobyte.
        #[cfg(feature = "git")]
        {
            let z = deflate(&vec![0u8; 1 << 20]);
            assert!(z.len() < 2048);
            let e = inflate(&z, 1000).unwrap_err();
            assert!(e.contains("more than the 1000 bytes"), "{e}");
            let e = inflate(&z, (1 << 20) + 1).unwrap_err();
            assert!(e.contains("not the"), "{e}");
            let mut trailing = z.clone();
            trailing.push(0);
            assert!(inflate(&trailing, 1 << 20).unwrap_err().contains("after the end"));
            assert!(inflate(&z[..z.len() / 2], 1 << 20).is_err());
        }
        assert!(inflate(b"not zlib", 10).is_err());
        assert!(inflate(b"", 3).is_err());
    }

    #[cfg(feature = "git")]
    #[test]
    fn deltas_round_trip_and_stay_small() {
        let base: Vec<u8> = (0..100_000u32).flat_map(|i| (i.wrapping_mul(2_654_435_761)).to_le_bytes()).collect();
        let mut target = base.clone();
        target[5000] ^= 1;
        target.splice(70_000..70_000, b"inserted".iter().copied());
        target.truncate(300_000);
        let d = make_delta(&base, &target);
        assert!(d.len() < 200, "{}", d.len());
        assert_eq!(apply_delta(&base, &d, u64::MAX).unwrap(), target);
        for (b, t) in [(&b""[..], &b"abc"[..]), (b"abc", b""), (b"0123456789abcdefXYZ", b"XX0123456789abcdefXYZ")] {
            assert_eq!(apply_delta(b, &make_delta(b, t), 1 << 20).unwrap(), t);
        }
    }

    #[test]
    fn hostile_deltas_are_refused() {
        let base = b"0123456789";
        // Wrong base size; a copy past the base; a result above the limit;
        // more output than declared; the reserved opcode; truncation.
        assert!(apply_delta(base, &[9, 3, 3, b'a', b'b', b'c'], 100).unwrap_err().contains("for a file of 9 bytes"));
        assert!(apply_delta(base, &[10, 4, 0x91, 8, 4], 100).unwrap_err().contains("outside"));
        assert!(apply_delta(base, &[10, 0xff, 0xff, 0xff, 0x7f], 1000).unwrap_err().contains("more than 1000"));
        assert!(apply_delta(base, &[10, 2, 3, b'a', b'b', b'c'], 100).unwrap_err().contains("more than the size"));
        assert!(apply_delta(base, &[10, 1, 0], 100).unwrap_err().contains("reserved"));
        assert!(apply_delta(base, &[10, 3, 3, b'a'], 100).is_err());
        assert!(apply_delta(base, &[10, 3, 0x91, 0], 100).is_err());
        assert!(apply_delta(base, &[0x80; 12], 100).is_err());
        // A copy of the default 0x10000 bytes from a short base.
        assert!(apply_delta(base, &[10, 0x80, 0x80, 0x04, 0x80], 1 << 20).is_err());
    }
}
