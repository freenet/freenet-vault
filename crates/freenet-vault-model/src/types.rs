//! Abstract values of the handover protocol (revision 8).
//!
//! Byte layouts are not modelled: a record is (version, withdrawal), an entry
//! is a small struct, a digest is a 64-bit hash of a value. Two values that
//! the protocol treats as equal (byte-identical) are equal here and hash the
//! same; that is the only property of BLAKE3 the protocol relies on.

use std::collections::BTreeMap;

pub type Ver = u32;
pub type Digest = u64;

/// A signed pointer record (protocol 1, 3). Every record in the model
/// verifies; a version is never signed twice (14.5), so a version identifies
/// a record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Rec {
    pub v: Ver,
    pub withdrawal: bool,
}

impl Rec {
    pub fn build(v: Ver) -> Rec {
        Rec {
            v,
            withdrawal: false,
        }
    }
    pub fn withdrawal(v: Ver) -> Rec {
        Rec {
            v,
            withdrawal: true,
        }
    }
}

pub const KIND_KEY: u8 = 0x01;
pub const KIND_MARK: u8 = 0x02;
/// A kind that only the "unknown kind" build writes (15.1); every other build
/// stores, copies and lists it unread (7.1, 11).
pub const KIND_UNKNOWN: u8 = 0x03;

/// Entry identity (kind, key) (2).
pub type Ident = (u8, u16);

/// One entry, as stored (12.2). `content` stands for the seed (kind 0x01) or
/// the caller's record (kind 0x02). `flagged` is eflags bit 0 (4.3).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Entry {
    pub kind: u8,
    pub key: u16,
    pub flagged: bool,
    pub content: u32,
    pub ext: Vec<u8>,
}

impl Entry {
    pub fn ident(&self) -> Ident {
        (self.kind, self.key)
    }
    pub fn digest(&self) -> Digest {
        let mut h = Hasher::new(b"entry");
        h.u8(self.kind);
        h.u64(self.key as u64);
        h.u8(self.flagged as u8);
        h.u64(self.content as u64);
        h.bytes(&self.ext);
        h.finish()
    }
}

/// manifest_digest over the sorted digests (12.1).
pub fn manifest_digest(sorted: &[Digest]) -> Digest {
    let mut h = Hasher::new(b"manifest");
    for d in sorted {
        h.u64(*d);
    }
    h.finish()
}

/// FNV-1a with a splitmix finalizer. Deterministic across runs and platforms.
pub struct Hasher(u64);

impl Hasher {
    pub fn new(tag: &[u8]) -> Hasher {
        let mut h = Hasher(0xcbf2_9ce4_8422_2325);
        h.bytes(tag);
        h
    }
    pub fn u8(&mut self, b: u8) {
        self.0 ^= b as u64;
        self.0 = self.0.wrapping_mul(0x0000_0100_0000_01b3);
    }
    pub fn u64(&mut self, v: u64) {
        for b in v.to_le_bytes() {
            self.u8(b);
        }
    }
    pub fn bytes(&mut self, bs: &[u8]) {
        self.u64(bs.len() as u64);
        for b in bs {
            self.u8(*b);
        }
    }
    pub fn finish(&self) -> u64 {
        let mut z = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}

// ---------------------------------------------------------------- frames

/// Ack chunk_status (12.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ChunkStatus {
    Processed,
    Malformed,
    NotMine,
    Stopped,
    HigherBuild,
    AnotherWriter,
    StagingFull,
}

/// Per-entry outcome in an Ack (7.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Outcome {
    Stored,
    Identical,
    PolicyDropped,
    StagingFull,
    StorageFailure,
}

impl Outcome {
    pub fn delivered(self) -> bool {
        matches!(
            self,
            Outcome::Stored | Outcome::Identical | Outcome::PolicyDropped
        )
    }
}

/// CompleteAck status (12.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CStatus {
    Accepted,
    Missing,
    AlreadyWriter,
    Stopped,
    HigherBuild,
    StorageFailure,
    Aborted,
    AnotherWriter,
    DifferentManifest,
    Malformed,
    /// 0x0A: "noted" (answer to Retired) or "retired" (answer to Query).
    Noted,
    /// 0x0B: "no state, your record stored" (Query only, 7.6, 5.3).
    NoState,
}

impl CStatus {
    pub const ALL: [CStatus; 12] = [
        CStatus::Accepted,
        CStatus::Missing,
        CStatus::AlreadyWriter,
        CStatus::Stopped,
        CStatus::HigherBuild,
        CStatus::StorageFailure,
        CStatus::Aborted,
        CStatus::AnotherWriter,
        CStatus::DifferentManifest,
        CStatus::Malformed,
        CStatus::Noted,
        CStatus::NoState,
    ];
    /// The answers on which a sealed build may unseal (7.5).
    pub fn unseals(self) -> bool {
        matches!(
            self,
            CStatus::Aborted
                | CStatus::Stopped
                | CStatus::StorageFailure
                | CStatus::HigherBuild
                | CStatus::AnotherWriter
                | CStatus::Malformed
        )
    }
}

/// Vault-to-vault frames (12.3). `malformed` stands for a frame whose
/// manifest digest cannot be parsed or recomputed (a frame damaged in
/// transit; injected only by the "garbled hop" fault).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frame {
    Chunk {
        rec: Rec,
        entries: Vec<Entry>,
        malformed: bool,
    },
    Ack {
        /// transfer_id: (sender version, record of the target) (12.1).
        tid: (Ver, Rec),
        status: ChunkStatus,
        succ: Option<Rec>,
        outcomes: Vec<(Digest, Outcome)>,
    },
    Complete {
        rec: Rec,
        m: Digest,
        digests: Vec<Digest>,
        malformed: bool,
    },
    Abort {
        rec: Rec,
        m: Digest,
        malformed: bool,
    },
    Retired {
        rec: Rec,
        m: Digest,
        malformed: bool,
    },
    Query {
        rec: Rec,
        m: Digest,
    },
    CompleteAck {
        tid: (Ver, Rec),
        m: Digest,
        status: CStatus,
        succ: Option<Rec>,
        missing: Vec<Digest>,
    },
}

impl Frame {
    pub fn name(&self) -> &'static str {
        match self {
            Frame::Chunk { .. } => "Chunk",
            Frame::Ack { .. } => "Ack",
            Frame::Complete { .. } => "Complete",
            Frame::Abort { .. } => "Abort",
            Frame::Retired { .. } => "Retired",
            Frame::Query { .. } => "Query",
            Frame::CompleteAck { .. } => "CompleteAck",
        }
    }
    pub fn garble(&mut self) {
        match self {
            Frame::Chunk { malformed, .. }
            | Frame::Complete { malformed, .. }
            | Frame::Abort { malformed, .. }
            | Frame::Retired { malformed, .. } => *malformed = true,
            _ => {}
        }
    }
    pub fn short(&self) -> String {
        match self {
            Frame::Chunk {
                rec,
                entries,
                malformed,
            } => format!(
                "Chunk(rec {}, {} entries{})",
                rec.v,
                entries.len(),
                if *malformed { ", malformed" } else { "" }
            ),
            Frame::Ack {
                status,
                outcomes,
                succ,
                ..
            } => {
                format!("Ack({status:?}, {outcomes:?}, succ {succ:?})")
            }
            Frame::Complete {
                m,
                digests,
                malformed,
                ..
            } => format!(
                "Complete(m {:04x}, {} digests{})",
                m & 0xffff,
                digests.len(),
                if *malformed { ", malformed" } else { "" }
            ),
            Frame::Abort { m, malformed, .. } => format!(
                "Abort(m {:04x}{})",
                m & 0xffff,
                if *malformed { ", malformed" } else { "" }
            ),
            Frame::Retired { m, malformed, .. } => format!(
                "Retired(m {:04x}{})",
                m & 0xffff,
                if *malformed { ", malformed" } else { "" }
            ),
            Frame::Query { m, .. } => format!("Query(m {:04x})", m & 0xffff),
            Frame::CompleteAck {
                status,
                m,
                missing,
                succ,
                ..
            } => format!(
                "CompleteAck({status:?}, m {:04x}, missing {}, succ {succ:?})",
                m & 0xffff,
                missing.len()
            ),
        }
    }
}

// ---------------------------------------------------------- durable state

/// vault:succ (4.1).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Succ {
    pub current: Option<Rec>,
    pub withdrawal: Option<Rec>,
}

impl Succ {
    /// Stopped while the stored withdrawal's version is above current's, or
    /// there is no current (3). Read as: a withdrawal is stored, and either no
    /// current is stored or the withdrawal is higher.
    pub fn stopped(&self) -> bool {
        match (self.withdrawal, self.current) {
            (Some(w), Some(c)) => w.v > c.v,
            (Some(_), None) => true,
            (None, _) => false,
        }
    }
    /// The non-withdrawn successor record, if any.
    pub fn successor(&self) -> Option<Rec> {
        if self.stopped() {
            None
        } else {
            self.current
        }
    }
    pub fn highest(&self) -> Option<Rec> {
        match (self.current, self.withdrawal) {
            (Some(c), Some(w)) => Some(if w.v > c.v { w } else { c }),
            (a, b) => a.or(b),
        }
    }
}

/// The WRITER fields of 5.1, also carried by SEALED.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WFields {
    pub taken_over: Option<(Ver, Digest)>,
    pub awaiting: bool,
    /// Copying paused toward this target version (Poke bit 0, 7.5), or
    /// stopped by Ack 0x04/0x06 (7.3).
    pub paused: Option<Ver>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PState {
    /// NONE (5.1): the arming record, or none, and the predecessor versions
    /// that confirmed under it (5.3).
    None {
        armed: Option<Rec>,
        confirmed: std::collections::BTreeSet<Ver>,
    },
    Writer(WFields),
    Sealed {
        w: WFields,
        target: Rec,
        m: Digest,
    },
    Receiving {
        from: Ver,
        store_failed: bool,
    },
    Retired {
        to: Rec,
        m: Digest,
        taken_over: Option<(Ver, Digest)>,
    },
}

impl PState {
    pub fn code(&self) -> &'static str {
        match self {
            PState::None { armed: None, .. } => "NONE",
            PState::None { armed: Some(_), .. } => "NONE(armed)",
            PState::Writer(w) if w.awaiting => "WRITER(awaiting)",
            PState::Writer(_) => "WRITER",
            PState::Sealed { .. } => "SEALED",
            PState::Receiving { .. } => "RECEIVING",
            PState::Retired { .. } => "RETIRED",
        }
    }
    pub fn taken_over(&self) -> Option<(Ver, Digest)> {
        match self {
            PState::Writer(w) | PState::Sealed { w, .. } => w.taken_over,
            PState::Retired { taken_over, .. } => *taken_over,
            _ => None,
        }
    }
    pub fn is_none(&self) -> bool {
        matches!(self, PState::None { .. })
    }
    /// NONE, not armed, nothing confirmed.
    pub fn none() -> PState {
        PState::None {
            armed: None,
            confirmed: Default::default(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IdxEnt {
    pub parity: bool,
    pub digest: Digest,
}

/// vault:idx:<P>, the commit point (4.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Index {
    pub state: PState,
    pub entries: BTreeMap<Ident, IdxEnt>,
    /// HandoverStatus problem bits (12.4).
    pub problems: u8,
    pub lost: u16,
}

impl Index {
    pub fn none() -> Index {
        Index {
            state: PState::none(),
            entries: BTreeMap::new(),
            problems: 0,
            lost: 0,
        }
    }
    pub fn manifest(&self) -> Vec<Digest> {
        let mut v: Vec<Digest> = self.entries.values().map(|e| e.digest).collect();
        v.sort_unstable();
        v
    }
    pub fn ident_of(&self, d: Digest) -> Option<Ident> {
        self.entries
            .iter()
            .find(|(_, e)| e.digest == d)
            .map(|(i, _)| *i)
    }
}

pub const PROBLEM_STORAGE: u8 = 1 << 0;
pub const PROBLEM_CORRUPT: u8 = 1 << 1;
pub const PROBLEM_ANOTHER_WRITER: u8 = 1 << 2;
pub const PROBLEM_STAGING_FULL: u8 = 1 << 3;
pub const PROBLEM_PAUSED: u8 = 1 << 4;
pub const PROBLEM_HIGHER_RECEIVER: u8 = 1 << 5;
/// "index lost: read-only" (4.5).
pub const PROBLEM_INDEX_LOST: u8 = 1 << 6;

/// Secret names (4.1). One partition, so the partition id is implicit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SName {
    Succ,
    /// vault:parts (4.1): lists the one partition when present.
    Parts,
    Idx,
    E(Ident, bool),
    X(Ver),
    Rx,
    Gc,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SVal {
    Succ(Succ),
    Idx(Index),
    E(Entry),
    /// Bytes that no longer parse (a damaged single secret): read as
    /// present but malformed.
    Garbled,
    /// Bytes that fail authentication (corruption, or a changed node key):
    /// the host reads them as absent without poisoning the call (4.0, #6323).
    Undecryptable,
    /// vault:parts listing the partition.
    Parts,
    X(BTreeMap<Ident, Digest>),
    Rx(std::collections::BTreeSet<Digest>),
    Gc(std::collections::BTreeSet<SName>),
}
