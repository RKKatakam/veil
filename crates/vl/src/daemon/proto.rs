//! The daemon's local protocol (its socket, `docs/HUB.md` §13.29).
//!
//! Messages are `kind (1 byte) ‖ length (u32, big-endian) ‖ payload`.
//! A client sends one request ([`Q`], JSON) per connection; the daemon
//! answers object frames ([`O`]: the id, then the object's bytes), then
//! [`E`] once the answer is whole (JSON, a [`Head`]). Anything else (an
//! error, a closed connection, a timeout) leaves the answer unfinished: the
//! client keeps the objects that arrived (each checked against its id) and
//! asks the server itself for the rest. An object the daemon leaves out is
//! never an answer: only the server's refusal is.

use std::io::{Read, Write};

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use veil_core::{hub::grant::BatchRequest, ObjectId};

/// A request (JSON).
pub const Q: u8 = b'Q';
/// One object: its id (32 bytes), then its bytes.
pub const O: u8 = b'O';
/// The end of a whole answer (JSON: [`Head`]).
pub const E: u8 = b'E';

/// Largest request a daemon reads (about 20,000 wants two folders deep).
pub const MAX_REQUEST: usize = 4 << 20;
/// Largest object the daemon holds, keeps or sends: a larger one is left
/// out, and its reader asks the server.
pub const MAX_OBJECT: usize = 16 << 20;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    /// Objects under a grant, as `POST /v1/objects/{project}:batch` takes
    /// them, for the server at `upstream` (`host[:port]`). The request is the
    /// client's, signed by its device: the daemon checks it and forwards it
    /// as it is.
    Batch { upstream: String, project: String, batch: BatchRequest },
    /// Keep in the store what working copy `key` (a hash of its path)
    /// checks out: the trees `roots` and everything below them that the
    /// store holds. Replaces that key's earlier roots; no roots removes it.
    Pin { upstream: String, project: String, key: String, roots: Vec<ObjectId> },
    /// The projects followed (for `vl daemon follow`).
    Follows,
    Status,
    Stop,
}

/// What ends an answer.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Head {
    /// What the server answered, when the daemon passed the request on and
    /// it refused (401, 404, …); `None` otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    /// `Status`: the daemon's counters; `Follows`: the projects.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<serde_json::Value>,
}

pub fn write_msg(w: &mut impl Write, kind: u8, payload: &[u8]) -> std::io::Result<()> {
    let mut head = [0u8; 5];
    head[0] = kind;
    head[1..].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    w.write_all(&head)?;
    w.write_all(payload)
}

/// An object message: the id, then the bytes (written without copying them).
pub fn write_object(w: &mut impl Write, id: &ObjectId, raw: &[u8]) -> std::io::Result<()> {
    let mut head = [0u8; 37];
    head[0] = O;
    head[1..5].copy_from_slice(&((raw.len() + 32) as u32).to_be_bytes());
    head[5..].copy_from_slice(&id.0);
    w.write_all(&head)?;
    w.write_all(raw)
}

/// The next message's kind and length (at most `max`).
pub fn read_head(r: &mut impl Read, max: usize) -> Result<(u8, usize)> {
    let mut head = [0u8; 5];
    r.read_exact(&mut head)?;
    let len = u32::from_be_bytes(head[1..].try_into().expect("4 bytes")) as usize;
    if len > max {
        bail!("a message of {len} bytes (at most {max})");
    }
    Ok((head[0], len))
}

pub fn read_payload(r: &mut impl Read, len: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

/// Split an object message's payload into its id and bytes.
pub fn object_of(mut payload: Vec<u8>) -> Result<(ObjectId, Vec<u8>)> {
    if payload.len() < 32 {
        bail!("a short object message");
    }
    let id = ObjectId(payload[..32].try_into().expect("32 bytes"));
    payload.drain(..32);
    Ok((id, payload))
}
