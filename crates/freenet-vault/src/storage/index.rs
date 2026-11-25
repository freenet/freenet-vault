//! The partition index, `vault:idx:<P>`: the commit point (protocol 4.2).
//!
//! The index is private to one build: a different build is a different
//! delegate key and so a different secret namespace, and builds exchange
//! entries, never indexes. Its layout is therefore not a frozen format; it is
//! versioned only so this build can refuse bytes it did not write.
//!
//! ```text
//! "FVIX" 4 ; format 1 (= 2) ; state 1 ; flags 1
//! [armed record 100]      if flags bit 0
//! [peer record 100]       if flags bit 2
//! problems 1 ; lost_entries 2
//! handover_len 4 ; handover    (the handover fields, `Handover`; empty = none)
//! count 2 ; count x { kind 1 ; key_len 2 ; key ; parity 1 ; len 2 ; digest 32 }
//! checksum 32     BLAKE3 of every byte above
//! ```
//! flags: bit 0 armed, bit 1 awaiting_retirement, bit 2 peer record present.
//! Entries are sorted by `(kind, key)` with no duplicates. The checksum rejects
//! a copy whose bytes were damaged (a torn write, a flipped bit that still
//! parses); the partition is then read-only (protocol 4.5).

use freenet_vault_common::bounds::{MAX_ENTRY, MAX_KEY, MAX_PARTITION_ENTRIES};
use freenet_vault_common::codec::{Malformed, Reader, Writer};

const MAGIC: &[u8; 4] = b"FVIX";
const FORMAT: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    None = 0,
    Writer = 1,
    Sealed = 2,
    Receiving = 3,
    Retired = 4,
}

impl State {
    fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => Self::None,
            1 => Self::Writer,
            2 => Self::Sealed,
            3 => Self::Receiving,
            4 => Self::Retired,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexEntry {
    pub kind: u8,
    pub key: Vec<u8>,
    pub parity: u8,
    /// Stored length of the entry's bytes, for the byte quota.
    pub len: u16,
    pub digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Index {
    pub state: State,
    /// NONE only: the record this build was armed with (Poke flag bit 1).
    pub armed: Option<[u8; 100]>,
    /// WRITER only: took over and waits for the predecessor's retirement.
    pub awaiting_retirement: bool,
    /// SEALED: the target record; RETIRED: `retired_to`.
    pub peer_record: Option<[u8; 100]>,
    pub problems: u8,
    pub lost_entries: u16,
    /// The handover fields of protocol 5.1 that have no field of their own
    /// above, carried in the reserved `handover` bytes of the layout.
    pub ho: Handover,
    pub entries: Vec<IndexEntry>,
}

impl Index {
    pub fn none() -> Self {
        Self {
            state: State::None,
            armed: None,
            awaiting_retirement: false,
            peer_record: None,
            problems: 0,
            lost_entries: 0,
            ho: Handover::default(),
            entries: Vec::new(),
        }
    }

    pub fn find(&self, kind: u8, key: &[u8]) -> Option<usize> {
        self.entries
            .binary_search_by(|e| (e.kind, e.key.as_slice()).cmp(&(kind, key)))
            .ok()
    }

    /// Inserts or replaces, keeping the order.
    pub fn upsert(&mut self, e: IndexEntry) {
        match self
            .entries
            .binary_search_by(|x| (x.kind, x.key.as_slice()).cmp(&(e.kind, e.key.as_slice())))
        {
            Ok(i) => self.entries[i] = e,
            Err(i) => self.entries.insert(i, e),
        }
    }

    pub fn remove(&mut self, kind: u8, key: &[u8]) -> Option<IndexEntry> {
        self.find(kind, key).map(|i| self.entries.remove(i))
    }

    pub fn count_kind(&self, kind: u8) -> usize {
        self.entries.iter().filter(|e| e.kind == kind).count()
    }

    pub fn total_bytes(&self) -> usize {
        self.entries.iter().map(|e| e.len as usize).sum()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        let flags = (self.armed.is_some() as u8)
            | ((self.awaiting_retirement as u8) << 1)
            | ((self.peer_record.is_some() as u8) << 2);
        w.bytes(MAGIC).u8(FORMAT).u8(self.state as u8).u8(flags);
        if let Some(a) = &self.armed {
            w.bytes(a);
        }
        if let Some(p) = &self.peer_record {
            w.bytes(p);
        }
        let ho = self.ho.encode();
        w.u8(self.problems)
            .u16(self.lost_entries)
            .len_u32(ho.len(), "handover length")
            .bytes(&ho)
            .len_u16(self.entries.len(), "entry count");
        for e in &self.entries {
            w.u8(e.kind)
                .len_u16(e.key.len(), "key length")
                .bytes(&e.key)
                .u8(e.parity)
                .u16(e.len)
                .bytes(&e.digest);
        }
        let mut out = w.into_vec();
        if !out.is_empty() {
            let sum = *blake3::hash(&out).as_bytes();
            out.extend_from_slice(&sum);
        }
        out
    }

    /// `body` with its trailing checksum, so a test or fuzz input can reach the
    /// body parser instead of failing the checksum.
    #[cfg(any(test, feature = "testing"))]
    pub fn seal(body: &[u8]) -> Vec<u8> {
        let mut out = body.to_vec();
        out.extend_from_slice(blake3::hash(body).as_bytes());
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Malformed> {
        if bytes.len() < 32 {
            return Err(Malformed("index too short"));
        }
        let (body, sum) = bytes.split_at(bytes.len() - 32);
        if blake3::hash(body).as_bytes() != sum {
            return Err(Malformed("index checksum"));
        }
        let mut r = Reader::new(body);
        if r.take(4, "index magic")? != MAGIC || r.u8("index format")? != FORMAT {
            return Err(Malformed("index header"));
        }
        let state = State::from_u8(r.u8("state")?).ok_or(Malformed("state"))?;
        let flags = r.u8("flags")?;
        if flags & !0b111 != 0 {
            return Err(Malformed("index flags"));
        }
        let armed = if flags & 1 != 0 {
            Some(r.array("armed")?)
        } else {
            None
        };
        let peer_record = if flags & 4 != 0 {
            Some(r.array("peer")?)
        } else {
            None
        };
        let problems = r.u8("problems")?;
        let lost_entries = r.u16("lost")?;
        let hlen = r.u32("handover_len")? as usize;
        let ho = Handover::decode(r.take(hlen, "handover")?)?;
        let count = r.u16("count")? as usize;
        if count > MAX_PARTITION_ENTRIES {
            return Err(Malformed("entry count"));
        }
        let mut entries: Vec<IndexEntry> = Vec::with_capacity(count.min(64));
        for _ in 0..count {
            let kind = r.u8("kind")?;
            if kind == 0 {
                return Err(Malformed("kind 0"));
            }
            let klen = r.u16("key_len")? as usize;
            if klen == 0 || klen > MAX_KEY {
                return Err(Malformed("key_len"));
            }
            let key = r.take(klen, "key")?.to_vec();
            let parity = r.u8("parity")?;
            if parity > 1 {
                return Err(Malformed("parity"));
            }
            let len = r.u16("len")?;
            if len as usize > MAX_ENTRY {
                return Err(Malformed("entry len"));
            }
            let digest = r.array("digest")?;
            if let Some(prev) = entries.last() {
                if (prev.kind, prev.key.as_slice()) >= (kind, key.as_slice()) {
                    return Err(Malformed("index order"));
                }
            }
            entries.push(IndexEntry {
                kind,
                key,
                parity,
                len,
                digest,
            });
        }
        r.finish()?;
        Ok(Self {
            state,
            armed,
            awaiting_retirement: flags & 2 != 0,
            peer_record,
            problems,
            lost_entries,
            ho,
            entries,
        })
    }
}

/// The handover fields (protocol 5.1) kept in the index's reserved
/// `handover` bytes:
///
/// ```text
/// format 1 (= 1) ; flags 1 (bit 0 taken_over, 1 m, 2 paused, 3 store_failed,
///                           4 own_record)
/// [taken_over_version 4 ; taken_over_m 32]   if bit 0
/// [own_record 100]                           if bit 4 (with taken_over: the
///                                            record naming this build that the
///                                            Complete it took over at carried;
///                                            its Query sends it, 12.3)
/// [m 32]                                     if bit 1 (SEALED: the sealed manifest;
///                                                     RETIRED: the m it retired at)
/// [paused_version 4]                         if bit 2
/// receiving_from 4                           (RECEIVING: the sender's version; else 0)
/// confirmed_count 2 ; confirmed_count x version 4 (ascending; NONE armed, 5.3)
/// ```
///
/// All-default fields encode as zero bytes, so an index written before the
/// handover existed reads as having none of them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Handover {
    /// WRITER, SEALED, RETIRED: took over from (version, m).
    pub taken_over: Option<(u32, [u8; 32])>,
    /// With `taken_over`: the record naming this build (from the Complete).
    pub own_record: Option<[u8; 100]>,
    /// SEALED: the manifest digest sealed at; RETIRED: the m retired at.
    pub m: Option<[u8; 32]>,
    /// WRITER: copying toward this target version is paused (Poke bit 0, or
    /// Ack 0x04/0x06, 7.3, 7.5).
    pub paused: Option<u32>,
    /// RECEIVING: the sender's version.
    pub receiving_from: u32,
    /// RECEIVING: an entry failed to store since the last Complete (7.4).
    pub store_failed: bool,
    /// NONE armed: predecessor versions that confirmed (5.3), ascending.
    pub confirmed: Vec<u32>,
}

impl Handover {
    pub fn encode(&self) -> Vec<u8> {
        if self == &Self::default() {
            return Vec::new();
        }
        let flags = (self.taken_over.is_some() as u8)
            | ((self.m.is_some() as u8) << 1)
            | ((self.paused.is_some() as u8) << 2)
            | ((self.store_failed as u8) << 3)
            | ((self.own_record.is_some() as u8) << 4);
        let mut w = Writer::new();
        w.u8(1).u8(flags);
        if let Some((v, m)) = &self.taken_over {
            w.u32(*v).bytes(m);
        }
        if let Some(r) = &self.own_record {
            w.bytes(r);
        }
        if let Some(m) = &self.m {
            w.bytes(m);
        }
        if let Some(p) = self.paused {
            w.u32(p);
        }
        w.u32(self.receiving_from)
            .len_u16(self.confirmed.len(), "confirmed count");
        for c in &self.confirmed {
            w.u32(*c);
        }
        w.into_vec()
    }

    pub fn decode(b: &[u8]) -> Result<Self, Malformed> {
        if b.is_empty() {
            return Ok(Self::default());
        }
        let mut r = Reader::new(b);
        if r.u8("handover format")? != 1 {
            return Err(Malformed("handover format"));
        }
        let flags = r.u8("handover flags")?;
        if flags & !0b1_1111 != 0 {
            return Err(Malformed("handover flags"));
        }
        let taken_over = if flags & 1 != 0 {
            Some((r.u32("taken_over_version")?, r.array("taken_over_m")?))
        } else {
            None
        };
        let own_record = if flags & 16 != 0 {
            Some(r.array("own_record")?)
        } else {
            None
        };
        let m = if flags & 2 != 0 {
            Some(r.array("m")?)
        } else {
            None
        };
        let paused = if flags & 4 != 0 {
            Some(r.u32("paused")?)
        } else {
            None
        };
        let receiving_from = r.u32("receiving_from")?;
        let n = r.u16("confirmed_count")? as usize;
        let mut confirmed: Vec<u32> = Vec::with_capacity(n.min(64));
        for _ in 0..n {
            let v = r.u32("confirmed")?;
            if confirmed.last().is_some_and(|p| *p >= v) {
                return Err(Malformed("confirmed order"));
            }
            confirmed.push(v);
        }
        r.finish()?;
        let h = Self {
            taken_over,
            own_record,
            m,
            paused,
            receiving_from,
            store_failed: flags & 8 != 0,
            confirmed,
        };
        // Canonical: the all-default value is written as zero bytes.
        if h == Self::default() {
            return Err(Malformed("handover not canonical"));
        }
        Ok(h)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_round_trips() {
        let mut i = Index::none();
        i.state = State::Writer;
        i.armed = Some([1; 100]);
        i.peer_record = Some([2; 100]);
        i.awaiting_retirement = true;
        i.problems = 3;
        i.lost_entries = 4;
        i.ho = Handover {
            taken_over: Some((7, [8; 32])),
            own_record: Some([6; 100]),
            m: Some([9; 32]),
            paused: Some(11),
            receiving_from: 12,
            store_failed: true,
            confirmed: vec![1, 3],
        };
        i.upsert(IndexEntry {
            kind: 2,
            key: vec![1],
            parity: 0,
            len: 10,
            digest: [6; 32],
        });
        i.upsert(IndexEntry {
            kind: 1,
            key: vec![9],
            parity: 1,
            len: 72,
            digest: [7; 32],
        });
        i.upsert(IndexEntry {
            kind: 1,
            key: vec![3],
            parity: 0,
            len: 72,
            digest: [8; 32],
        });
        assert_eq!(
            i.entries
                .iter()
                .map(|e| (e.kind, e.key[0]))
                .collect::<Vec<_>>(),
            [(1, 3), (1, 9), (2, 1)]
        );
        let b = i.encode();
        assert_eq!(Index::decode(&b).unwrap(), i);
        assert!(Index::decode(&b[..b.len() - 1]).is_err());
        let mut t = b.clone();
        t.push(0);
        assert!(Index::decode(&t).is_err());
    }

    #[test]
    fn index_refuses_disorder_and_bad_fields() {
        let mut i = Index::none();
        i.upsert(IndexEntry {
            kind: 1,
            key: vec![1],
            parity: 0,
            len: 1,
            digest: [0; 32],
        });
        i.upsert(IndexEntry {
            kind: 1,
            key: vec![2],
            parity: 0,
            len: 1,
            digest: [0; 32],
        });
        let mut swapped = i.clone();
        swapped.entries.swap(0, 1);
        assert!(Index::decode(&swapped.encode()).is_err());
        let mut dup = i.clone();
        dup.entries[1].key = vec![1];
        assert!(Index::decode(&dup.encode()).is_err());
        let mut b = i.encode();
        b[5] = 9; // state
        assert!(Index::decode(&b).is_err());
    }
}
