//! The frame envelope (protocol 12.1).
//!
//! ```text
//! 0  4  magic          "FVLT"
//! 4  1  proto_version  0x01
//! 5  1  frame_type
//! 6  4  body_len       u32 big-endian
//! 10 n  body
//! ```

use crate::bounds::MAX_FRAME_BODY;
use crate::codec::{Malformed, Reader};

pub const MAGIC: [u8; 4] = *b"FVLT";
pub const PROTO_VERSION: u8 = 0x01;
pub const HEADER_LEN: usize = 10;

/// Frame types (protocol 12.1).
pub mod types {
    // Vault-to-vault handover frames. Reserved; their layouts are not frozen
    // here because the handover design is still open.
    pub const CHUNK: u8 = 0x01;
    pub const ACK: u8 = 0x02;
    pub const COMPLETE: u8 = 0x03;
    pub const COMPLETE_ACK: u8 = 0x04;
    pub const ABORT: u8 = 0x05;
    pub const RETIRED: u8 = 0x06;
    pub const QUERY: u8 = 0x07;

    pub const POKE: u8 = 0x20;
    pub const SUBMIT_RECORD: u8 = 0x21;

    pub const MOVED: u8 = 0x40;
    pub const NOT_HERE: u8 = 0x41;
    pub const HANDOVER_STATUS: u8 = 0x42;
    pub const ABSENT: u8 = 0x43;
    pub const BUSY: u8 = 0x44;
    pub const UNUSABLE: u8 = 0x45;
    pub const REFUSED: u8 = 0x46;

    pub const GENERATE: u8 = 0x80;
    pub const IMPORT: u8 = 0x81;
    pub const DELETE: u8 = 0x82;
    pub const PUBLIC_KEY: u8 = 0x83;
    pub const LIST: u8 = 0x84;
    pub const BATCH: u8 = 0x85;
    pub const EXPORT: u8 = 0x86;
    // 0x87 is reserved: RetireTo was removed in revision 7. A page sending it
    // gets Refused(10), like any other unknown frame.

    pub const KEY_RESULT: u8 = 0xA0;
    pub const OK: u8 = 0xA1;
    pub const LIST_RESULT: u8 = 0xA2;
    pub const BATCH_RESULT: u8 = 0xA3;
    pub const EXPORT_RESULT: u8 = 0xA4;
}

/// A decoded envelope. The body is not interpreted here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame<'a> {
    pub frame_type: u8,
    pub body: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// The bytes do not start with the magic. Protocol 12.1: they go to the
    /// domain's own decoder if it has one.
    NotVault,
    Malformed(Malformed),
}

impl<'a> Frame<'a> {
    pub fn decode(bytes: &'a [u8]) -> Result<Self, FrameError> {
        if bytes.len() < 4 || bytes[..4] != MAGIC {
            return Err(FrameError::NotVault);
        }
        let mut r = Reader::new(&bytes[4..]);
        let m = FrameError::Malformed;
        let version = r.u8("proto_version").map_err(m)?;
        if version != PROTO_VERSION {
            return Err(m(Malformed("proto_version")));
        }
        let frame_type = r.u8("frame_type").map_err(m)?;
        let body_len = r.u32("body_len").map_err(m)? as usize;
        if body_len > MAX_FRAME_BODY {
            return Err(m(Malformed("body too long")));
        }
        // Total length must be exactly 10 + body_len.
        let body = r.take(body_len, "body").map_err(m)?;
        r.finish().map_err(m)?;
        Ok(Self { frame_type, body })
    }
}

/// Wraps a body in the envelope. A body over 16 MiB is an error.
pub fn encode(frame_type: u8, body: &[u8]) -> Result<Vec<u8>, Malformed> {
    if body.len() > MAX_FRAME_BODY {
        return Err(Malformed("frame body over 16 MiB"));
    }
    let mut out = Vec::with_capacity(HEADER_LEN + body.len());
    out.extend_from_slice(&MAGIC);
    out.push(PROTO_VERSION);
    out.push(frame_type);
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(body);
    Ok(out)
}

/// Wraps a reply body in the envelope, enforcing the 65,536-byte bound on a
/// whole reply frame (protocol 11).
pub fn encode_reply(frame_type: u8, body: &[u8]) -> Result<Vec<u8>, Malformed> {
    let out = encode(frame_type, body)?;
    if out.len() > crate::bounds::MAX_REPLY {
        return Err(Malformed("reply over 65536 bytes"));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_vector() {
        let f = encode(0x83, &[1, 2, 3]).unwrap();
        assert_eq!(f, [0x46, 0x56, 0x4C, 0x54, 0x01, 0x83, 0, 0, 0, 3, 1, 2, 3]);
        let d = Frame::decode(&f).unwrap();
        assert_eq!(d.frame_type, 0x83);
        assert_eq!(d.body, &[1, 2, 3]);
    }

    #[test]
    fn envelope_malformed() {
        let f = encode(0x83, &[1, 2, 3]).unwrap();
        assert_eq!(Frame::decode(b"nope"), Err(FrameError::NotVault));
        assert_eq!(Frame::decode(&[]), Err(FrameError::NotVault));
        // Short and long against body_len.
        assert!(matches!(
            Frame::decode(&f[..f.len() - 1]),
            Err(FrameError::Malformed(_))
        ));
        let mut long = f.clone();
        long.push(0);
        assert!(matches!(
            Frame::decode(&long),
            Err(FrameError::Malformed(_))
        ));
        // Another proto_version.
        let mut v2 = f.clone();
        v2[4] = 2;
        assert!(matches!(Frame::decode(&v2), Err(FrameError::Malformed(_))));
        // Header cut short.
        assert!(matches!(
            Frame::decode(&f[..7]),
            Err(FrameError::Malformed(_))
        ));
        // body_len over 16 MiB is refused before reading the body.
        let mut huge = f[..10].to_vec();
        huge[6..10].copy_from_slice(&((16 * 1024 * 1024 + 1) as u32).to_be_bytes());
        assert!(matches!(
            Frame::decode(&huge),
            Err(FrameError::Malformed(_))
        ));
    }
}
