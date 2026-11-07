//! How the Veil server stores objects and sends them (`docs/HUB.md`
//! §13.15, milestone S27): an object's **encoding** is either its canonical
//! encoding itself, or a zstd frame of it, told apart by the first byte.
//!
//! ```text
//! 'v' …          the canonical encoding itself (every object starts `veil:`);
//!                every object stored before S27 is one
//! 'z' ‖ frame    one zstd frame of the canonical encoding, declaring its size
//! ```
//!
//! An object's id stays the BLAKE3 of its canonical encoding, so
//! deduplication, receipts and signatures don't change. [`encode`] keeps
//! whichever is smaller: secrets are ciphertext and stay as they are.
//!
//! **Encoded frames** are `id [32] ‖ len u32be ‖ encoding`, written with
//! [`super::wire::put_frame`]. A body of plain object frames is also a body
//! of encoded frames, so a receiver that reads encoded frames reads both.
//!
//! **Decoding is bounded** ([`decode`]): a frame must declare its size, be
//! exactly one frame, declare at most the caller's limit and a window of at
//! most 2^27 bytes (what every decoder reads, the web client's included:
//! BUG-1008); the decoder never produces more than that, and the result
//! must hash to the id. **What a client sends** expands at most
//! [`MAX_RATIO`] times (above [`RATIO_FLOOR`]): [`within_ratio`], which the
//! server checks on upload and [`encode_to_send`] keeps to, so a small
//! request never makes the server decode a large object (BUG-1009).

use std::borrow::Cow;

use crate::{
    error::{Result, VeilError},
    id::ObjectId,
};

/// First byte of a zstd-compressed encoding.
pub const ZSTD: u8 = b'z';
/// First byte of every canonical encoding (`veil:`).
const PLAIN: u8 = b'v';
/// zstd level the encoder uses.
#[cfg_attr(not(feature = "zstd"), allow(dead_code))]
const LEVEL: i32 = 3;

/// The media type of a body of encoded frames: a client that reads them
/// says so in `Accept`, and a server then answers `history` and `fetch`
/// with objects as stored.
pub const FRAMES: &str = "application/x-veil-encoded-frames";

/// The largest window a frame may declare: 2^27 bytes, the most every
/// zstd decoder reads by default (the pure decoder of the WASM web client
/// refuses more; libzstd's one-shot decoder does not check: BUG-1008).
pub const MAX_WINDOW: u64 = 1 << crate::pack::MAX_DELTA_WINDOW_LOG;

/// How many times its own size a frame a client sends may expand
/// ([`within_ratio`]), and the size below which any frame may (BUG-1009).
pub const MAX_RATIO: u64 = 64;
pub const RATIO_FLOOR: u64 = 64 << 10;

/// The encoding of `raw` (a canonical encoding): a zstd frame when that is
/// smaller, else `raw` itself. Without the zstd C library (WASM) always
/// `raw` itself.
pub fn encode(raw: &[u8]) -> Cow<'_, [u8]> {
    #[cfg(feature = "zstd")]
    {
        thread_local! {
            static CCTX: std::cell::RefCell<Option<zstd::bulk::Compressor<'static>>> = const { std::cell::RefCell::new(None) };
        }
        // Not worth a frame header (and never smaller below it).
        if raw.len() < 32 {
            return Cow::Borrowed(raw);
        }
        let z = CCTX.with(|cell| -> Option<Vec<u8>> {
            let mut slot = cell.borrow_mut();
            if slot.is_none() {
                *slot = Some(zstd::bulk::Compressor::new(LEVEL).ok()?);
            }
            let c = slot.as_mut()?;
            // Room for the marker, and at most `raw.len()` bytes in all:
            // anything longer is not kept, so its compression stops early.
            let mut out = vec![0u8; raw.len()];
            out[0] = ZSTD;
            let n = c.compress_to_buffer(raw, &mut out[1..]).ok()?;
            out.truncate(1 + n);
            // Kept, it holds only its own bytes (a cache weighs it by them).
            out.shrink_to_fit();
            Some(out)
        });
        if let Some(z) = z.filter(|z| z.len() < raw.len()) {
            return Cow::Owned(z);
        }
    }
    Cow::Borrowed(raw)
}

/// [`encode`], for sending: a zstd frame only [`within_ratio`] (an object
/// that compresses better goes plain, so its size is the sender's to pay,
/// as before S27). What a server stores is its own [`encode`].
pub fn encode_to_send(raw: &[u8]) -> Cow<'_, [u8]> {
    match encode(raw) {
        Cow::Owned(z) if !within_ratio(&z) => Cow::Borrowed(raw),
        e => e,
    }
}

/// Does `enc` expand to at most [`MAX_RATIO`] times its own size, or to at
/// most [`RATIO_FLOOR`] bytes? (A plain encoding always does.) A server
/// decodes nothing a client sent that does not (BUG-1009).
pub fn within_ratio(enc: &[u8]) -> bool {
    match enc.first() {
        Some(&ZSTD) => decoded_len(enc).is_some_and(|n| n <= RATIO_FLOOR.max(MAX_RATIO.saturating_mul(enc.len() as u64))),
        _ => true,
    }
}

/// The window the zstd frame `frame` declares (a single-segment frame's is
/// its content size), from its header (RFC 8878 §3.1.1.1).
fn frame_window(frame: &[u8]) -> Option<u64> {
    let fhd = *frame.get(4)?;
    if fhd & 0x20 != 0 {
        return crate::pack::frame_content_size(frame);
    }
    let wd = *frame.get(5)?;
    let base = 1u64 << (10 + u32::from(wd >> 3));
    Some(base + (base / 8) * u64::from(wd & 7))
}

/// Is `enc` a compressed encoding?
pub fn is_compressed(enc: &[u8]) -> bool {
    enc.first() == Some(&ZSTD)
}

/// How many first bytes of a stored encoding [`declared_len`] needs: the
/// marker and the longest zstd frame header (18 bytes).
pub const HEADER: usize = 32;

/// The size an encoding says it decodes to, from its first bytes alone
/// (`prefix`, at least [`HEADER`] bytes of it or all of it) and its stored
/// length: a plain encoding is itself, a zstd frame declares its size in
/// its header. Not checked: for bounding what reading it will hold, before
/// reading it (the server's read-ahead, BUG-1087).
pub fn declared_len(prefix: &[u8], stored_len: u64) -> Option<u64> {
    match *prefix.first()? {
        PLAIN => Some(stored_len),
        ZSTD => header_content_size(&prefix[1..]),
        _ => None,
    }
}

#[cfg(feature = "zstd")]
fn header_content_size(header: &[u8]) -> Option<u64> {
    zstd::zstd_safe::get_frame_content_size(header).ok()?
}

#[cfg(not(feature = "zstd"))]
fn header_content_size(header: &[u8]) -> Option<u64> {
    crate::pack::frame_content_size(header)
}

/// The size `enc` says it decodes to (a zstd frame's declared size), not
/// checked: for sizing a buffer, never as a limit.
pub fn decoded_len(enc: &[u8]) -> Option<u64> {
    match *enc.first()? {
        PLAIN => Some(enc.len() as u64),
        ZSTD => crate::pack::frame_content_size(&enc[1..]),
        _ => None,
    }
}

/// The canonical encoding of object `id` from its encoding `enc`, at most
/// `limit` bytes (the object size limit): checked against `id`. A zstd frame
/// that declares more than `limit`, declares no size or a window past
/// [`MAX_WINDOW`], is not exactly one frame, or decodes to anything else is
/// refused before more than its declared size is produced.
pub fn decode<'a>(id: &ObjectId, enc: &'a [u8], limit: u64) -> Result<Cow<'a, [u8]>> {
    let bad = |m: &str| VeilError::Corrupt(id.hex(), m.to_string());
    let raw: Cow<'a, [u8]> = match enc.first() {
        Some(&PLAIN) => {
            if enc.len() as u64 > limit {
                return Err(bad("object larger than the limit"));
            }
            Cow::Borrowed(enc)
        }
        Some(&ZSTD) => {
            let frame = &enc[1..];
            let size = crate::pack::frame_content_size(frame).ok_or_else(|| bad("not one zstd frame that declares its size"))?;
            if size > limit {
                return Err(bad("compressed object expands past the limit"));
            }
            // Every decoder reads it, or none: libzstd's one-shot decoder
            // would accept any window (BUG-1008).
            if frame_window(frame).is_none_or(|w| w > MAX_WINDOW) {
                return Err(bad("compressed object declares a window past 2^27 bytes"));
            }
            Cow::Owned(crate::pack::decompress(frame, size, None, id).map_err(|e| bad(&e))?)
        }
        _ => return Err(bad("unknown object encoding")),
    };
    if ObjectId::hash(&raw) != *id {
        return Err(bad("object does not match its id"));
    }
    Ok(raw)
}

/// Split a body of encoded frames into ids and encodings, checking only
/// the framing (each encoding at most [`super::wire::MAX_FRAME_OBJECT`]).
pub fn split_frames(mut body: &[u8]) -> Result<Vec<(ObjectId, &[u8])>> {
    let bad = |m: &str| VeilError::Corrupt("frames".into(), m.to_string());
    let mut out = Vec::new();
    while !body.is_empty() {
        if body.len() < 36 {
            return Err(bad("truncated frame header"));
        }
        let id = ObjectId(body[..32].try_into().unwrap());
        let len = u32::from_be_bytes(body[32..36].try_into().unwrap()) as usize;
        if len > super::wire::MAX_FRAME_OBJECT || body.len() - 36 < len {
            return Err(bad("truncated or oversized object"));
        }
        out.push((id, &body[36..36 + len]));
        body = &body[36 + len..];
    }
    Ok(out)
}

/// Split and [`decode`] a body of encoded (or plain) frames: each object at
/// most [`super::wire::MAX_FRAME_OBJECT`] bytes, all of them together at
/// most `total` bytes decoded.
pub fn read_frames(body: &[u8], total: u64) -> Result<Vec<(ObjectId, Cow<'_, [u8]>)>> {
    let mut left = total;
    let mut out = Vec::new();
    for (id, enc) in split_frames(body)? {
        let raw = decode(&id, enc, left.min(super::wire::MAX_FRAME_OBJECT as u64))?;
        left -= raw.len() as u64;
        out.push((id, raw));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::{super::wire::put_frame, *};

    fn blob(body: &[u8]) -> Vec<u8> {
        let mut raw = b"veil:blob\n".to_vec();
        raw.extend_from_slice(body);
        raw
    }

    #[cfg(feature = "zstd")]
    fn zframe(data: &[u8]) -> Vec<u8> {
        let mut z = vec![ZSTD];
        z.extend(zstd::bulk::compress(data, LEVEL).unwrap());
        z
    }

    #[test]
    fn encodings_round_trip_and_keep_the_smaller() {
        let text = blob(&b"fn main() { println!(\"hello\"); }\n".repeat(200));
        let enc = encode(&text);
        #[cfg(feature = "zstd")]
        assert!(is_compressed(&enc) && enc.len() < text.len() / 10);
        assert_eq!(&*decode(&ObjectId::hash(&text), &enc, 1 << 20).unwrap(), &text[..]);
        assert_eq!(decoded_len(&enc), Some(text.len() as u64));
        assert_eq!(decoded_len(b"\x01"), None);
        // Ciphertext-like bytes don't shrink: kept as they are.
        let noise = blob(&crate::crypto::random_bytes::<4096>());
        assert!(matches!(encode(&noise), Cow::Borrowed(_)));
        // Tiny objects too.
        assert!(matches!(encode(b"veil:blob\n"), Cow::Borrowed(_)));
        // A plain encoding is its own encoding.
        assert_eq!(&*decode(&ObjectId::hash(&noise), &noise, 1 << 20).unwrap(), &noise[..]);
    }

    #[test]
    fn decoding_refuses_wrong_ids_and_unknown_markers() {
        let raw = blob(&b"abc".repeat(100));
        let id = ObjectId::hash(&raw);
        let other = ObjectId::hash(b"veil:blob\nother");
        assert!(decode(&other, &raw, 1 << 20).is_err());
        assert!(decode(&other, &encode(&raw), 1 << 20).is_err());
        for first in [0u8, 1, b'x', 0x28, 0xff] {
            let mut e = encode(&raw).into_owned();
            e[0] = first;
            assert!(decode(&id, &e, 1 << 20).is_err());
        }
        assert!(decode(&id, b"", 1 << 20).is_err());
        assert!(decode(&id, b"z", 1 << 20).is_err());
        // A plain object over the limit.
        assert!(decode(&id, &raw, 10).is_err());
    }

    /// A zip bomb: a small frame declaring (and holding) far more than the
    /// limit is refused from its header, before anything is decoded.
    #[cfg(feature = "zstd")]
    #[test]
    fn a_zip_bomb_is_refused_before_it_expands() {
        let big = blob(&vec![0u8; 64 << 20]);
        let enc = zframe(&big);
        assert!(enc.len() < 64 << 10, "{} bytes", enc.len());
        let id = ObjectId::hash(&big);
        let e = decode(&id, &enc, 1 << 20).unwrap_err().to_string();
        assert!(e.contains("expands past the limit"), "{e}");
        // At the limit it decodes.
        assert_eq!(decode(&id, &enc, big.len() as u64).unwrap().len(), big.len());
        // The total of a body counts every object's decoded bytes.
        let mut body = Vec::new();
        put_frame(&mut body, &id, &enc);
        put_frame(&mut body, &id, &enc);
        assert!(read_frames(&body, big.len() as u64 + 10).is_err());
        assert_eq!(read_frames(&body, 2 * big.len() as u64).unwrap().len(), 2);
    }

    /// Frames that don't declare their size, lie about it, or carry bytes
    /// after the frame are refused.
    #[cfg(feature = "zstd")]
    #[test]
    fn malformed_frames_are_refused() {
        use std::io::Write;
        let raw = blob(&b"hello world ".repeat(50));
        let id = ObjectId::hash(&raw);
        // No declared size (a streamed frame).
        let mut e = zstd::stream::write::Encoder::new(Vec::new(), 3).unwrap();
        e.include_contentsize(false).unwrap();
        e.write_all(&raw).unwrap();
        let mut undeclared = vec![ZSTD];
        undeclared.extend(e.finish().unwrap());
        assert!(decode(&id, &undeclared, 1 << 20).is_err());
        // Trailing bytes, or a second frame.
        let good = zframe(&raw);
        assert!(decode(&id, &good, 1 << 20).is_ok());
        for tail in [&b"x"[..], &zstd::bulk::compress(b"", 3).unwrap(), &[0x50, 0x2a, 0x4d, 0x18, 0, 0, 0, 0]] {
            let mut t = good.clone();
            t.extend_from_slice(tail);
            assert!(decode(&id, &t, 1 << 20).is_err());
        }
        // A frame of other content (its own size declared truly).
        assert!(decode(&id, &zframe(&blob(b"other")), 1 << 20).is_err());
        // Truncated.
        assert!(decode(&id, &good[..good.len() - 1], 1 << 20).is_err());
        // Flipped bits anywhere: refused, never wrong content.
        for i in 1..good.len() {
            let mut f = good.clone();
            f[i] ^= 0x10;
            if let Ok(r) = decode(&id, &f, 1 << 20) {
                assert_eq!(&*r, &raw[..]);
            }
        }
    }

    /// BUG-1008 (S27 adversarial pass). A frame whose header declares a
    /// window far past its content (2^31 here: allowed by the format, never
    /// written by `encode`) decodes with libzstd's one-shot decoder, which
    /// the server and native `vl` use for objects up to 64 MiB and which
    /// does not check the window. The pure decoder of the WASM web client
    /// refuses any window above 2^27 (`pack::pure::MAX_WINDOW`). The server
    /// stores a participant's encoded upload as sent, under an id the
    /// project may already hold in folders the participant can't write,
    /// and serves it as stored: `decode` must refuse what the slowest
    /// reader refuses, so every reader decodes what the server accepts.
    #[test]
    fn bug_1008_a_frame_every_decoder_reads_or_none() {
        let raw = blob(b"a file any participant knows: a licence, a vendored library");
        let id = ObjectId::hash(&raw);
        // Magic; descriptor: 4-byte content size, not single-segment, no
        // checksum, no dictionary; window descriptor: 2^(10 + exponent);
        // the size; one last raw block holding `raw`.
        let frame = |exponent: u8| {
            let mut enc = vec![ZSTD, 0x28, 0xb5, 0x2f, 0xfd, 0x80, exponent << 3];
            enc.extend_from_slice(&(raw.len() as u32).to_le_bytes());
            enc.extend_from_slice(&(((raw.len() as u32) << 3) | 1).to_le_bytes()[..3]);
            enc.extend_from_slice(&raw);
            enc
        };
        // A 128 MiB window: both decoders read it.
        assert_eq!(&*decode(&id, &frame(17), 1 << 20).unwrap(), &raw[..]);
        #[cfg(feature = "ruzstd")]
        assert!(crate::pack::pure::decompress(&frame(17)[1..], raw.len() as u64, None).is_ok());
        // A 2 GiB window: the WASM decoder refuses it.
        let enc = frame(21);
        #[cfg(feature = "ruzstd")]
        assert!(crate::pack::pure::decompress(&enc[1..], raw.len() as u64, None).is_err(), "the WASM decoder refuses it");
        assert!(decode(&id, &enc, 1 << 20).is_err(), "decode accepted a frame the WASM decoder refuses");
    }

    /// BUG-1009: what a client sends expands at most 64 times (above
    /// 64 KiB); an object that compresses better is sent plain. What a
    /// server stores ([`encode`]) is as small as it gets.
    #[cfg(feature = "zstd")]
    #[test]
    fn what_is_sent_expands_at_most_the_ratio() {
        let zeros = blob(&vec![0u8; 8 << 20]);
        let stored = encode(&zeros);
        assert!(is_compressed(&stored) && !within_ratio(&stored));
        assert!(matches!(encode_to_send(&zeros), Cow::Borrowed(_)));
        // Ordinary text compresses well within it, and is sent compressed.
        let text = blob(&(0..20_000u32).flat_map(|i| format!("    let v{i} = compute({}, \"{:x}\"); // line {i}\n", i * 7 % 13, i.wrapping_mul(2654435761)).into_bytes()).collect::<Vec<u8>>());
        let sent = encode_to_send(&text);
        assert!(is_compressed(&sent) && within_ratio(&sent), "{} bytes for {}", sent.len(), text.len());
        // Below the floor, any ratio.
        let small = blob(&vec![0u8; 60 << 10]);
        assert!(is_compressed(&encode_to_send(&small)));
        assert!(within_ratio(&small) && within_ratio(b"veil:blob\n"));
        // A frame that declares no size is not within it.
        assert!(!within_ratio(&[ZSTD, 0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x00]));
    }

    #[test]
    fn plain_frames_are_encoded_frames() {
        let objs = [blob(b"one"), blob(&b"two ".repeat(400)), b"veil:blob\n".to_vec()];
        let mut plain = Vec::new();
        let mut encoded = Vec::new();
        for raw in &objs {
            let id = ObjectId::hash(raw);
            put_frame(&mut plain, &id, raw);
            put_frame(&mut encoded, &id, &encode(raw));
        }
        for body in [&plain, &encoded] {
            let got = read_frames(body, 1 << 20).unwrap();
            assert_eq!(got.len(), 3);
            for ((_, r), raw) in got.iter().zip(&objs) {
                assert_eq!(&**r, &raw[..]);
            }
        }
        assert!(split_frames(&encoded[..encoded.len() - 1]).is_err());
        assert!(read_frames(&encoded[..35], 1 << 20).is_err());
    }

    #[test]
    fn a_prefix_declares_what_an_encoding_decodes_to() {
        let raw = [&b"veil:blob\n"[..], &b"abc ".repeat(4096)].concat();
        let enc = encode(&raw);
        assert!(is_compressed(&enc));
        assert_eq!(declared_len(&enc[..HEADER.min(enc.len())], enc.len() as u64), Some(raw.len() as u64));
        assert_eq!(declared_len(&raw[..HEADER], raw.len() as u64), Some(raw.len() as u64));
        assert_eq!(declared_len(b"\x01xyz", 4), None);
    }
}