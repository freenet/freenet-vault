//! The stored entry (protocol 12.2).
//!
//! ```text
//! kind 1 ; eflags 1 ; key_len 2 (1..=256) ; key ;
//! content_len 2 ; content ; ext_len 2 ; ext
//! ```
//!
//! An entry is stored exactly as received or written and never decoded and
//! re-encoded, so unknown kinds, unknown eflags bits and extensions are carried
//! forward byte for byte. This type is for building and inspecting entries;
//! storage keeps the original bytes beside it.

use crate::bounds::{MAX_ENTRY, MAX_KEY};
use crate::codec::{Malformed, Reader, Result, Writer};

/// An ed25519 seed; key = slot, content = 32 bytes.
pub const KIND_KEY: u8 = 0x01;
/// A caller mark; key = `author_vk || app_id`, content = a 100-byte pointer record.
pub const KIND_CALLER_MARK: u8 = 0x02;

/// eflags bit 0: this copy failed its integrity check (protocol 4.3).
pub const EFLAG_CORRUPT: u8 = 0x01;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub kind: u8,
    pub eflags: u8,
    pub key: Vec<u8>,
    pub content: Vec<u8>,
    pub ext: Vec<u8>,
}

/// Content length a known kind requires; `None` for reserved kinds, whose
/// content is carried unread.
pub fn required_content_len(kind: u8) -> Option<usize> {
    match kind {
        KIND_KEY => Some(32),
        KIND_CALLER_MARK => Some(100),
        _ => None,
    }
}

impl Entry {
    pub fn new(kind: u8, key: Vec<u8>, content: Vec<u8>) -> Self {
        Self {
            kind,
            eflags: 0,
            key,
            content,
            ext: Vec::new(),
        }
    }

    pub fn is_flagged_corrupt(&self) -> bool {
        self.eflags & EFLAG_CORRUPT != 0
    }

    /// Flag bits this build does not know (spec 11: stored and copied, never
    /// served).
    pub fn has_unknown_flags(&self) -> bool {
        self.eflags & !EFLAG_CORRUPT != 0
    }

    /// Encodes, checking every bound a decoder checks.
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.check()?;
        let mut w = Writer::new();
        w.u8(self.kind)
            .u8(self.eflags)
            .len_u16(self.key.len(), "key_len")
            .bytes(&self.key)
            .len_u16(self.content.len(), "content_len")
            .bytes(&self.content)
            .ext(&self.ext);
        let out = w.finish()?;
        if out.len() > MAX_ENTRY {
            return Err(Malformed("entry too long"));
        }
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_ENTRY {
            return Err(Malformed("entry too long"));
        }
        let mut r = Reader::new(bytes);
        let kind = r.u8("kind")?;
        let eflags = r.u8("eflags")?;
        let key_len = r.u16("key_len")? as usize;
        let key = r.take(key_len, "key")?.to_vec();
        let content_len = r.u16("content_len")? as usize;
        let content = r.take(content_len, "content")?.to_vec();
        let ext = r.ext()?;
        r.finish()?;
        let e = Self {
            kind,
            eflags,
            key,
            content,
            ext,
        };
        e.check()?;
        Ok(e)
    }

    fn check(&self) -> Result<()> {
        // Kinds 0x01 and 0x02 are defined, 0x03..=0xFF reserved and carried.
        // 0x00 is reserved and read as malformed (decided 2026-11-23 by the
        // design session; DESIGN-NOTES.md, spec update pending).
        if self.kind == 0 {
            return Err(Malformed("kind 0"));
        }
        if self.key.is_empty() || self.key.len() > MAX_KEY {
            return Err(Malformed("key_len"));
        }
        if let Some(n) = required_content_len(self.kind) {
            if self.content.len() != n {
                return Err(Malformed("content_len for kind"));
            }
        }
        if self.content.len() > u16::MAX as usize || self.ext.len() > u16::MAX as usize {
            return Err(Malformed("field too long"));
        }
        Ok(())
    }

    /// The entry's identity (protocol 2): `(kind, key)`.
    pub fn identity(&self) -> (u8, &[u8]) {
        (self.kind, &self.key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_entry() -> Entry {
        Entry::new(KIND_KEY, vec![7u8; 32], vec![9u8; 32])
    }

    /// Positive vector: a River key entry is exactly 72 bytes (protocol 7.7)
    /// with this layout.
    #[test]
    fn river_key_entry_vector() {
        let bytes = key_entry().encode().unwrap();
        assert_eq!(bytes.len(), 72);
        let mut expected = vec![0x01, 0x00, 0x00, 0x20];
        expected.extend_from_slice(&[7u8; 32]);
        expected.extend_from_slice(&[0x00, 0x20]);
        expected.extend_from_slice(&[9u8; 32]);
        expected.extend_from_slice(&[0x00, 0x00]);
        assert_eq!(bytes, expected);
        assert_eq!(Entry::decode(&bytes).unwrap(), key_entry());
    }

    #[test]
    fn unknown_kind_flags_and_ext_round_trip_verbatim() {
        let e = Entry {
            kind: 0x7F,
            eflags: 0b1010_0001,
            key: vec![1, 2, 3],
            content: vec![0xAA; 5000],
            ext: vec![0x55; 300],
        };
        let bytes = e.encode().unwrap();
        let back = Entry::decode(&bytes).unwrap();
        assert_eq!(back, e);
        assert_eq!(back.encode().unwrap(), bytes);
    }

    #[test]
    fn malformed_entries() {
        let good = key_entry().encode().unwrap();
        // Truncated, and one trailing byte.
        assert!(Entry::decode(&good[..good.len() - 1]).is_err());
        let mut long = good.clone();
        long.push(0);
        assert!(Entry::decode(&long).is_err());
        // Kind 0.
        let mut k0 = good.clone();
        k0[0] = 0;
        assert!(Entry::decode(&k0).is_err());
        // A key entry whose content is not 32 bytes.
        let bad = Entry::new(KIND_KEY, vec![1], vec![0; 31]);
        assert!(bad.encode().is_err());
        // A caller mark must carry exactly 100 bytes.
        assert!(Entry::new(KIND_CALLER_MARK, vec![1], vec![0; 99])
            .encode()
            .is_err());
        assert!(Entry::new(KIND_CALLER_MARK, vec![1], vec![0; 100])
            .encode()
            .is_ok());
        // Empty key, and a key over 256 bytes.
        assert!(Entry::new(0x10, vec![], vec![]).encode().is_err());
        assert!(Entry::new(0x10, vec![0; 257], vec![]).encode().is_err());
        assert!(Entry::new(0x10, vec![0; 256], vec![]).encode().is_ok());
    }

    #[test]
    fn entry_size_bound_is_exact() {
        // kind 1 + eflags 1 + key_len 2 + key 1 + content_len 2 + ext_len 2 = 9.
        let at = Entry {
            kind: 0x10,
            eflags: 0,
            key: vec![1],
            content: vec![0; 65_399 - 9],
            ext: vec![],
        };
        assert_eq!(at.encode().unwrap().len(), 65_399);
        let over = Entry {
            content: vec![0; 65_399 - 8],
            ..at
        };
        assert!(over.encode().is_err());
    }
}
