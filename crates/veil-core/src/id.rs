use std::fmt;

use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{Result, VeilError};

/// BLAKE3 hash of an encoded object; the address of every node in the CAS.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObjectId(pub [u8; 32]);

impl ObjectId {
    pub fn hash(data: &[u8]) -> Self {
        ObjectId(*blake3::hash(data).as_bytes())
    }

    pub fn hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn short(&self) -> String {
        self.hex()[..8].to_string()
    }

    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s).map_err(|_| VeilError::Revset(format!("invalid object id '{s}'")))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| VeilError::Revset(format!("object id '{s}' has the wrong length")))?;
        Ok(ObjectId(arr))
    }
}

impl fmt::Display for ObjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.hex())
    }
}

impl fmt::Debug for ObjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ObjectId({})", self.short())
    }
}

impl Serialize for ObjectId {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.hex())
    }
}

impl<'de> Deserialize<'de> for ObjectId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        ObjectId::from_hex(&s).map_err(D::Error::custom)
    }
}

/// Stable identity of a logical line of work. Survives rewrites (describe,
/// rebase, amend) while the snapshot's [`ObjectId`] changes.
///
/// Displayed in "reverse hex" (`z`..`k` instead of `0`..`f`, as in Jujutsu)
/// so change ids and snapshot ids can never be confused on the command line.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChangeId(pub [u8; 16]);

impl ChangeId {
    pub const ROOT: ChangeId = ChangeId([0; 16]);

    pub fn random() -> Self {
        ChangeId(crate::crypto::random_bytes())
    }

    pub fn display(&self) -> String {
        hex::encode(self.0)
            .bytes()
            .map(|c| {
                let v = (c as char).to_digit(16).unwrap() as u8;
                (b'z' - v) as char
            })
            .collect()
    }

    pub fn short(&self) -> String {
        self.display()[..8].to_string()
    }

    /// Convert a reverse-hex string (or prefix) to normal hex.
    pub fn reverse_hex_to_hex(s: &str) -> Option<String> {
        s.bytes()
            .map(|c| {
                if (b'k'..=b'z').contains(&c) {
                    std::char::from_digit((b'z' - c) as u32, 16)
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn parse(s: &str) -> Result<Self> {
        let hex_str = Self::reverse_hex_to_hex(s)
            .ok_or_else(|| VeilError::Revset(format!("invalid change id '{s}'")))?;
        let bytes = hex::decode(hex_str).map_err(|_| VeilError::Revset(format!("invalid change id '{s}'")))?;
        let arr: [u8; 16] = bytes
            .try_into()
            .map_err(|_| VeilError::Revset(format!("change id '{s}' has the wrong length")))?;
        Ok(ChangeId(arr))
    }
}

impl fmt::Display for ChangeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.display())
    }
}

impl fmt::Debug for ChangeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ChangeId({})", self.short())
    }
}

impl Serialize for ChangeId {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.display())
    }
}

impl<'de> Deserialize<'de> for ChangeId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        ChangeId::parse(&s).map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn change_id_roundtrip() {
        let c = ChangeId::random();
        assert!(c.display().bytes().all(|b| (b'k'..=b'z').contains(&b)));
        assert_eq!(ChangeId::parse(&c.display()).unwrap(), c);
        assert_eq!(ChangeId::ROOT.display(), "z".repeat(32));
    }
}
