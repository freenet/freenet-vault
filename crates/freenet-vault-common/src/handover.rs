//! Vault-to-vault handover frames (protocol 12.3).
//!
//! ```text
//! Chunk (0x01)       record 100 ; partition 32 ; entry_count 1 (1..=32) ;
//!                    entry_count x { entry_len 2 ; Entry } ; ext_len 2 ; ext
//! Ack (0x02)         transfer_id 32 ; chunk_digest 32 ; partition 32 ; chunk_status 1 ;
//!                    succ_record 100 ; count 2 ; count x { entry_digest 32 ; outcome 1 } ;
//!                    ext_len 2 ; ext
//! Complete (0x03)    record 100 ; partition 32 ; manifest_digest 32 ; count 2 (0..=4096) ;
//!                    count x entry_digest 32 (ascending) ; ext_len 2 ; ext
//! CompleteAck (0x04) transfer_id 32 ; partition 32 ; manifest_digest 32 ; status 1 ;
//!                    succ_record 100 ; missing_count 2 (0..=1024) ;
//!                    missing_count x entry_digest 32 (ascending) ; ext_len 2 ; ext
//! Abort (0x05)       record 100 ; partition 32 ; manifest_digest 32 ; ext_len 2 ; ext
//! Retired (0x06)     record 100 ; partition 32 ; manifest_digest 32 ; ext_len 2 ; ext
//! Query (0x07)       record 100 ; partition 32 ; manifest_digest 32 ; ext_len 2 ; ext
//! ```
//!
//! These layouts are exactly those of the protocol document's section 12.3;
//! this module adds no field. A zero `succ_record` means "none".
//!
//! Every decoder is strict (exact lengths, bounds, ascending digests, and for
//! Complete a manifest digest that recomputes from the listed digests). A
//! receiver that cannot decode a request still needs the record, partition and
//! manifest digest the request carried, to answer and to echo the digest
//! (7.6): [`RequestHeader::peek`] reads those leading fields on their own.

use crate::bounds::MAX_ENTRY;
use crate::codec::{Malformed, Reader, Result, Writer};
use crate::entry::Entry;
use crate::frame::{self, types};
use crate::hash::{chunk_digest, manifest_digest};

/// Entries per chunk (protocol 11).
pub const MAX_CHUNK_ENTRIES: usize = 32;
/// A chunk body (protocol 11).
pub const MAX_CHUNK_BODY: usize = 65_536;
/// Digests in a manifest (protocol 11).
pub const MAX_MANIFEST: usize = 4096;
/// Digests in a missing list (protocol 11).
pub const MAX_MISSING: usize = 1024;

/// Ack chunk_status (12.3).
pub mod chunk_status {
    pub const PROCESSED: u8 = 0x00;
    pub const MALFORMED: u8 = 0x01;
    pub const RECORD_NOT_MINE: u8 = 0x02;
    pub const STOPPED: u8 = 0x03;
    pub const HIGHER_BUILD: u8 = 0x04;
    pub const ANOTHER_WRITER: u8 = 0x06;
    pub const STAGING_FULL: u8 = 0x07;
}

/// Per-entry outcomes in an Ack (7.2).
pub mod outcome {
    pub const STORED: u8 = 0x01;
    pub const IDENTICAL: u8 = 0x02;
    pub const POLICY_DROPPED: u8 = 0x03;
    pub const STAGING_FULL: u8 = 0x10;
    pub const STORAGE_FAILURE: u8 = 0x13;

    /// Whether the outcome counts as delivered (7.2).
    pub fn delivered(o: u8) -> bool {
        matches!(o, STORED | IDENTICAL | POLICY_DROPPED)
    }
}

/// CompleteAck status (12.3). 0x0C is unassigned in v1.
pub mod cstatus {
    pub const ACCEPTED: u8 = 0x00;
    pub const MISSING: u8 = 0x01;
    pub const ALREADY_WRITER: u8 = 0x02;
    pub const STOPPED: u8 = 0x03;
    pub const HIGHER_BUILD: u8 = 0x04;
    pub const STORAGE_FAILURE: u8 = 0x05;
    pub const ABORTED: u8 = 0x06;
    pub const ANOTHER_WRITER: u8 = 0x07;
    pub const DIFFERENT_MANIFEST: u8 = 0x08;
    pub const MALFORMED: u8 = 0x09;
    pub const NOTED: u8 = 0x0A;
    pub const NO_STATE: u8 = 0x0B;

    /// The answers on which a sealed build may unseal (7.5).
    pub fn unseals(s: u8) -> bool {
        matches!(
            s,
            ABORTED | STOPPED | STORAGE_FAILURE | HIGHER_BUILD | ANOTHER_WRITER | MALFORMED
        )
    }
}

fn opt_record(r: &[u8; 100]) -> Option<[u8; 100]> {
    (r != &[0u8; 100]).then_some(*r)
}

fn digests(r: &mut Reader, n: usize, what: &'static str) -> Result<Vec<[u8; 32]>> {
    let mut v: Vec<[u8; 32]> = Vec::with_capacity(n.min(64));
    for _ in 0..n {
        let d: [u8; 32] = r.array(what)?;
        if let Some(p) = v.last() {
            if p >= &d {
                return Err(Malformed("digests not ascending"));
            }
        }
        v.push(d);
    }
    Ok(v)
}

/// Chunk (0x01). Entries are carried as their stored bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chunk {
    pub record: [u8; 100],
    pub partition: [u8; 32],
    pub entries: Vec<Vec<u8>>,
    pub ext: Vec<u8>,
}

impl Chunk {
    /// The body (for the chunk digest) and the frame.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut w = Writer::new();
        w.require(
            (1..=MAX_CHUNK_ENTRIES).contains(&self.entries.len()),
            "entry_count",
        );
        w.bytes(&self.record)
            .bytes(&self.partition)
            .len_u8(self.entries.len(), "entry_count");
        for e in &self.entries {
            w.require(e.len() <= MAX_ENTRY, "entry_len")
                .len_u16(e.len(), "entry_len")
                .bytes(e);
        }
        w.ext(&self.ext);
        let body = w.finish()?;
        if body.len() > MAX_CHUNK_BODY {
            return Err(Malformed("chunk body"));
        }
        frame::encode(types::CHUNK, &body)
    }

    pub fn decode(body: &[u8]) -> Result<Self> {
        if body.len() > MAX_CHUNK_BODY {
            return Err(Malformed("chunk body"));
        }
        let mut r = Reader::new(body);
        let record = r.array("record")?;
        let partition = r.array("partition")?;
        let n = r.u8("entry_count")? as usize;
        if !(1..=MAX_CHUNK_ENTRIES).contains(&n) {
            return Err(Malformed("entry_count"));
        }
        let mut entries = Vec::with_capacity(n);
        for _ in 0..n {
            let len = r.u16("entry_len")? as usize;
            let e = r.take(len, "entry")?;
            Entry::decode(e)?;
            entries.push(e.to_vec());
        }
        let ext = r.ext()?;
        r.finish()?;
        Ok(Self {
            record,
            partition,
            entries,
            ext,
        })
    }
}

/// Ack (0x02).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ack {
    pub transfer_id: [u8; 32],
    pub chunk_digest: [u8; 32],
    pub partition: [u8; 32],
    pub status: u8,
    pub succ_record: Option<[u8; 100]>,
    pub outcomes: Vec<([u8; 32], u8)>,
    pub ext: Vec<u8>,
}

impl Ack {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut w = Writer::new();
        w.require(self.outcomes.len() <= MAX_CHUNK_ENTRIES, "count")
            .bytes(&self.transfer_id)
            .bytes(&self.chunk_digest)
            .bytes(&self.partition)
            .u8(self.status)
            .bytes(&self.succ_record.unwrap_or([0; 100]))
            .len_u16(self.outcomes.len(), "count");
        for (d, o) in &self.outcomes {
            w.bytes(d).u8(*o);
        }
        w.ext(&self.ext);
        frame::encode_reply(types::ACK, &w.finish()?)
    }

    pub fn decode(body: &[u8]) -> Result<Self> {
        let mut r = Reader::new(body);
        let transfer_id = r.array("transfer_id")?;
        let chunk_digest = r.array("chunk_digest")?;
        let partition = r.array("partition")?;
        let status = r.u8("chunk_status")?;
        let succ: [u8; 100] = r.array("succ_record")?;
        let n = r.u16("count")? as usize;
        if n > MAX_CHUNK_ENTRIES {
            return Err(Malformed("count"));
        }
        let mut outcomes = Vec::with_capacity(n);
        for _ in 0..n {
            let d = r.array("entry_digest")?;
            outcomes.push((d, r.u8("outcome")?));
        }
        let ext = r.ext()?;
        r.finish()?;
        Ok(Self {
            transfer_id,
            chunk_digest,
            partition,
            status,
            succ_record: opt_record(&succ),
            outcomes,
            ext,
        })
    }
}

/// Complete (0x03). Decoding checks the digests ascend without duplicates
/// and that `manifest_digest` recomputes from them (7.4: "mismatch,
/// duplicate digests ... malformed").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Complete {
    pub record: [u8; 100],
    pub partition: [u8; 32],
    pub manifest_digest: [u8; 32],
    pub digests: Vec<[u8; 32]>,
    pub ext: Vec<u8>,
}

impl Complete {
    /// A Complete over `digests` (sorted here) with its manifest digest.
    pub fn new(record: [u8; 100], partition: [u8; 32], mut digests: Vec<[u8; 32]>) -> Self {
        digests.sort_unstable();
        digests.dedup();
        Self {
            record,
            partition,
            manifest_digest: manifest_digest(&digests),
            digests,
            ext: Vec::new(),
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut w = Writer::new();
        w.require(self.digests.len() <= MAX_MANIFEST, "count")
            .require(
                self.digests.windows(2).all(|p| p[0] < p[1]),
                "digests not ascending",
            )
            .bytes(&self.record)
            .bytes(&self.partition)
            .bytes(&self.manifest_digest)
            .len_u16(self.digests.len(), "count");
        for d in &self.digests {
            w.bytes(d);
        }
        w.ext(&self.ext);
        frame::encode(types::COMPLETE, &w.finish()?)
    }

    pub fn decode(body: &[u8]) -> Result<Self> {
        let mut r = Reader::new(body);
        let record = r.array("record")?;
        let partition = r.array("partition")?;
        let m: [u8; 32] = r.array("manifest_digest")?;
        let n = r.u16("count")? as usize;
        if n > MAX_MANIFEST {
            return Err(Malformed("count"));
        }
        let digests = digests(&mut r, n, "entry_digest")?;
        let ext = r.ext()?;
        r.finish()?;
        if manifest_digest(&digests) != m {
            return Err(Malformed("manifest digest does not recompute"));
        }
        Ok(Self {
            record,
            partition,
            manifest_digest: m,
            digests,
            ext,
        })
    }
}

/// Abort (0x05), Retired (0x06) and Query (0x07) share one layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Short {
    pub record: [u8; 100],
    pub partition: [u8; 32],
    pub manifest_digest: [u8; 32],
    pub ext: Vec<u8>,
}

impl Short {
    pub fn encode(&self, frame_type: u8) -> Result<Vec<u8>> {
        let mut w = Writer::new();
        w.bytes(&self.record)
            .bytes(&self.partition)
            .bytes(&self.manifest_digest)
            .ext(&self.ext);
        frame::encode(frame_type, &w.finish()?)
    }

    pub fn decode(body: &[u8]) -> Result<Self> {
        let mut r = Reader::new(body);
        let record = r.array("record")?;
        let partition = r.array("partition")?;
        let manifest_digest = r.array("manifest_digest")?;
        let ext = r.ext()?;
        r.finish()?;
        Ok(Self {
            record,
            partition,
            manifest_digest,
            ext,
        })
    }
}

/// CompleteAck (0x04), the answer to Complete, Abort, Retired and Query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompleteAck {
    pub transfer_id: [u8; 32],
    pub partition: [u8; 32],
    pub manifest_digest: [u8; 32],
    pub status: u8,
    pub succ_record: Option<[u8; 100]>,
    pub missing: Vec<[u8; 32]>,
    pub ext: Vec<u8>,
}

impl CompleteAck {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut w = Writer::new();
        w.require(self.missing.len() <= MAX_MISSING, "missing_count")
            .require(
                self.missing.windows(2).all(|p| p[0] < p[1]),
                "missing not ascending",
            )
            .bytes(&self.transfer_id)
            .bytes(&self.partition)
            .bytes(&self.manifest_digest)
            .u8(self.status)
            .bytes(&self.succ_record.unwrap_or([0; 100]))
            .len_u16(self.missing.len(), "missing_count");
        for d in &self.missing {
            w.bytes(d);
        }
        w.ext(&self.ext);
        frame::encode_reply(types::COMPLETE_ACK, &w.finish()?)
    }

    pub fn decode(body: &[u8]) -> Result<Self> {
        let mut r = Reader::new(body);
        let transfer_id = r.array("transfer_id")?;
        let partition = r.array("partition")?;
        let manifest_digest = r.array("manifest_digest")?;
        let status = r.u8("status")?;
        let succ: [u8; 100] = r.array("succ_record")?;
        let n = r.u16("missing_count")? as usize;
        if n > MAX_MISSING {
            return Err(Malformed("missing_count"));
        }
        let missing = digests(&mut r, n, "missing digest")?;
        let ext = r.ext()?;
        r.finish()?;
        Ok(Self {
            transfer_id,
            partition,
            manifest_digest,
            status,
            succ_record: opt_record(&succ),
            missing,
            ext,
        })
    }
}

/// The leading fields of a request frame (Chunk, Complete, Abort, Retired,
/// Query), read without the rest of the body: what a receiver needs to answer
/// a request it cannot decode (7.6: the answer echoes the manifest digest the
/// request carried; "malformed" otherwise).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestHeader {
    pub record: [u8; 100],
    pub partition: [u8; 32],
    /// `None` for a Chunk, or when the body is too short to hold one.
    pub manifest_digest: Option<[u8; 32]>,
}

impl RequestHeader {
    pub fn peek(frame_type: u8, body: &[u8]) -> Option<Self> {
        if body.len() < 132 {
            return None;
        }
        let record: [u8; 100] = body[..100].try_into().ok()?;
        let partition: [u8; 32] = body[100..132].try_into().ok()?;
        let manifest_digest = match frame_type {
            types::COMPLETE | types::ABORT | types::RETIRED | types::QUERY if body.len() >= 164 => {
                body[132..164].try_into().ok()
            }
            _ => None,
        };
        Some(Self {
            record,
            partition,
            manifest_digest,
        })
    }
}

/// The chunk digest an Ack carries: of the chunk's frame body.
pub fn digest_of_chunk_frame(chunk_frame: &[u8]) -> [u8; 32] {
    chunk_digest(&chunk_frame[frame::HEADER_LEN.min(chunk_frame.len())..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::KIND_KEY;
    use crate::frame::Frame;

    fn rec(b: u8) -> [u8; 100] {
        [b; 100]
    }

    #[test]
    fn frames_round_trip() {
        let e = Entry::new(KIND_KEY, vec![1; 32], vec![2; 32])
            .encode()
            .unwrap();
        let c = Chunk {
            record: rec(1),
            partition: [3; 32],
            entries: vec![e.clone(), e],
            ext: vec![9],
        };
        let f = c.encode().unwrap();
        let d = Frame::decode(&f).unwrap();
        assert_eq!(d.frame_type, types::CHUNK);
        assert_eq!(Chunk::decode(d.body).unwrap(), c);

        let comp = Complete::new(rec(1), [3; 32], vec![[5; 32], [4; 32]]);
        let f = comp.encode().unwrap();
        let d = Frame::decode(&f).unwrap();
        assert_eq!(Complete::decode(d.body).unwrap(), comp);
        let h = RequestHeader::peek(types::COMPLETE, d.body).unwrap();
        assert_eq!(h.manifest_digest, Some(comp.manifest_digest));

        let s = Short {
            record: rec(2),
            partition: [3; 32],
            manifest_digest: [7; 32],
            ext: vec![],
        };
        for t in [types::ABORT, types::RETIRED, types::QUERY] {
            let f = s.encode(t).unwrap();
            let d = Frame::decode(&f).unwrap();
            assert_eq!(d.frame_type, t);
            assert_eq!(Short::decode(d.body).unwrap(), s);
        }

        let a = Ack {
            transfer_id: [1; 32],
            chunk_digest: [2; 32],
            partition: [3; 32],
            status: chunk_status::PROCESSED,
            succ_record: None,
            outcomes: vec![([4; 32], outcome::STORED)],
            ext: vec![],
        };
        let f = a.encode().unwrap();
        assert_eq!(Ack::decode(Frame::decode(&f).unwrap().body).unwrap(), a);

        let ca = CompleteAck {
            transfer_id: [1; 32],
            partition: [3; 32],
            manifest_digest: [9; 32],
            status: cstatus::MISSING,
            succ_record: Some(rec(4)),
            missing: vec![[1; 32], [2; 32]],
            ext: vec![],
        };
        let f = ca.encode().unwrap();
        assert_eq!(
            CompleteAck::decode(Frame::decode(&f).unwrap().body).unwrap(),
            ca
        );
    }

    #[test]
    fn complete_refuses_a_digest_that_does_not_recompute() {
        let mut comp = Complete::new(rec(1), [3; 32], vec![[5; 32]]);
        comp.manifest_digest = [0; 32];
        let f = comp.encode().unwrap();
        assert!(Complete::decode(Frame::decode(&f).unwrap().body).is_err());
        // Duplicates or disorder.
        let mut comp = Complete::new(rec(1), [3; 32], vec![[5; 32], [6; 32]]);
        comp.digests.swap(0, 1);
        assert!(comp.encode().is_err());
    }

    #[test]
    fn chunk_bounds() {
        let c = Chunk {
            record: rec(1),
            partition: [3; 32],
            entries: vec![],
            ext: vec![],
        };
        assert!(c.encode().is_err());
        let e = Entry::new(KIND_KEY, vec![1; 32], vec![2; 32])
            .encode()
            .unwrap();
        let c = Chunk {
            record: rec(1),
            partition: [3; 32],
            entries: vec![e; 33],
            ext: vec![],
        };
        assert!(c.encode().is_err());
    }
}
