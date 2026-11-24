//! Durable state of one partition (protocol 4).
//!
//! Write ordering (4.2): the index is the commit point. An entry is written
//! to the parity slot the index does not name, then the index; a crash in
//! between leaves the old value intact. Removals go through `vault:gc`:
//! write the names to remove, then the index without them, then remove the
//! secrets and clear `vault:gc`. After a failed index write the store reads
//! the index back and answers from what is on disk.
//!
//! Garbage collection removes only names under this partition's entry prefix
//! that the current index does not reference, so a `vault:gc` left behind by
//! a failed commit can never delete a live entry. A removal that fails keeps
//! its name listed until it succeeds. Every entry copy is listed in
//! `vault:gc` BEFORE it is written, so a crash between the write and the
//! index commit leaves a name the next call removes.
//!
//! There is ONE index copy, `vault:idx`, the commit point, with a BLAKE3
//! checksum. `open` trusts it only when it reads and verifies:
//!
//! - index verified: normal operation.
//! - index absent, and `vault:parts` reads and does not list the partition (an
//!   absent `vault:parts` is an empty list): a new partition. Creation and
//!   arming write the first index; nothing was read, so nothing is removed
//!   until that index is committed.
//! - anything else (index present but damaged, absent while `vault:parts`
//!   lists the partition, or `vault:parts` unreadable): `open` fails and the
//!   partition is read-only for that call: no write, no gc, no creation, no
//!   arming. The next call checks again.
//!
//! After a commit whose outcome is uncertain the store is read-only for the
//! rest of the call.

pub mod index;
pub mod names;
#[cfg(test)]
mod tests;

use crate::host::Host;
use freenet_vault_common::bounds::{MAX_PARTITION_BYTES, MAX_PARTITION_ENTRIES};
use freenet_vault_common::codec::{Malformed, Reader, Writer};
use freenet_vault_common::entry::{Entry, EFLAG_CORRUPT, KIND_CALLER_MARK, KIND_KEY};
use freenet_vault_common::hash::entry_digest;
use freenet_vault_common::status::problems;
use index::{Index, IndexEntry};

/// A write did not reach the disk (or could not be confirmed there).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StorageFailure;

/// Why the index state is unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexFault {
    /// The index is present but torn, malformed or failing its checksum.
    Damaged,
    /// The index is absent while `vault:parts` lists the partition.
    LostWhileListed,
    /// `vault:parts` is present but malformed.
    PartsUnreadable,
}

/// The index state is unknown: never read as "no partition". The partition is
/// read-only for the call, and HandoverStatus problems bit 6 is set (protocol
/// 4.5). Every fault is an index loss for ResetPartition: a malformed
/// `vault:parts` with the index absent would otherwise be a permanent brick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoredIndexMalformed(pub IndexFault);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PutError {
    Quota,
    Storage,
}

impl From<StorageFailure> for PutError {
    fn from(_: StorageFailure) -> Self {
        PutError::Storage
    }
}

/// Local quotas (the domain's, at or below the library maximums).
#[derive(Debug, Clone, Copy)]
pub struct Quota {
    pub max_key_slots: usize,
    pub max_caller_marks: usize,
}

/// The outcome of reading one entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Read {
    Absent,
    Ok(Entry),
    /// Failed its integrity check, now or earlier (eflags bit 0). The entry is
    /// what the stored bytes parse to, when they parse; informational only.
    Corrupt(Option<Entry>),
    /// The index names the entry but its secret is gone (a wipe or restore of
    /// that one secret). Nothing is changed or deleted and the entry is never
    /// treated as corrupt. Callers answer storage failure.
    Missing,
}

/// Whether the store may write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Reads, writes and gc are allowed.
    Clean,
    /// An index commit was uncertain: nothing more is written or removed in
    /// this call. Reads answer from the index loaded at the start.
    ReadOnly,
}

/// The gc list never holds more names than this, so it cannot outgrow its
/// encoding; a write that would exceed it fails until gc drains it. (A name
/// leaves the list only once its secret reads as absent after a removal
/// attempt, so names whose removal keeps failing accumulate: after this many,
/// writes that need a gc entry fail.)
pub const MAX_GC_NAMES: usize = 4096;

pub struct Store<'a, H: Host> {
    host: &'a mut H,
    partition: [u8; 32],
    pub index: Index,
    /// The index bytes known to be on disk, `None` when there is none yet.
    on_disk: Option<Vec<u8>>,
    /// An index was read (or committed) in this call.
    exists: bool,
    mode: Mode,
    /// No index could be read: entries are located by reading both parity
    /// copies directly (protocol 4.5). Read-only.
    blind: bool,
    /// An index passed its checksum in this call. Without that there is no
    /// positive evidence of what the partition holds, so nothing is removed.
    verified: bool,
}

impl<'a, H: Host> Store<'a, H> {
    /// Loads the partition (module docs). `Err` means the index state is
    /// unknown and the caller must treat the partition as read-only; it is
    /// never read as "no partition".
    pub fn open(host: &'a mut H, partition: [u8; 32]) -> Result<Self, StoredIndexMalformed> {
        if let Some(fault) = Self::fault(&*host, &partition) {
            return Err(fault);
        }
        let first = host.get_secret(&names::index(&partition));
        let (index, on_disk, exists, verified) = match first.as_deref().map(Index::decode) {
            Some(Ok(ix)) => {
                // Keeps `vault:parts` in step (best effort; a failure is
                // retried by the next call).
                let _ = ensure_part_listed(host, &partition);
                (ix, first, true, true)
            }
            // `fault` found no fault: the index is absent and `vault:parts`
            // does not name the partition, so it is new (reads in a completed
            // call are truthful, freenet-core #5857).
            _ => (Index::none(), None, false, false),
        };
        Ok(Self {
            host,
            partition,
            index,
            on_disk,
            exists,
            mode: Mode::Clean,
            blind: false,
            verified,
        })
    }

    /// Classifies the index state without keeping a borrow of the host:
    /// `None` when [`open`](Self::open) would succeed.
    pub fn fault(host: &H, partition: &[u8; 32]) -> Option<StoredIndexMalformed> {
        match host
            .get_secret(&names::index(partition))
            .as_deref()
            .map(Index::decode)
        {
            Some(Ok(_)) => None,
            Some(Err(_)) => Some(StoredIndexMalformed(IndexFault::Damaged)),
            None => match host.get_secret(names::PARTS) {
                Some(l) if l.len() % 32 != 0 => {
                    Some(StoredIndexMalformed(IndexFault::PartsUnreadable))
                }
                Some(l) if l.chunks(32).any(|c| c == partition) => {
                    Some(StoredIndexMalformed(IndexFault::LostWhileListed))
                }
                _ => None,
            },
        }
    }

    /// [`fault`](Self::fault), plus one more unknown state for a request that
    /// names `slot`: no index and no `vault:parts` listing, but a decodable
    /// entry for that slot is on disk. The index and the listing may both be
    /// corrupt (an undecryptable blob reads as absent, core #6323), so the
    /// partition is not taken to be new: the slot can be read by direct read,
    /// and nothing may be created over it.
    pub fn fault_for_slot(
        host: &H,
        partition: &[u8; 32],
        slot: Option<&[u8]>,
    ) -> Option<StoredIndexMalformed> {
        if let Some(f) = Self::fault(host, partition) {
            return Some(f);
        }
        let slot = slot?;
        if host.get_secret(&names::index(partition)).is_none()
            && direct_entry(host, partition, KIND_KEY, slot).is_some()
        {
            return Some(StoredIndexMalformed(IndexFault::LostWhileListed));
        }
        None
    }

    /// A read-only store for a partition whose index state is unknown: reads
    /// find an entry by its two parity copies, and nothing is ever written.
    /// The routing state is taken to be WRITER (this build has no other
    /// reachable state while it holds keys).
    pub fn open_blind(host: &'a mut H, partition: [u8; 32]) -> Self {
        let mut index = Index::none();
        index.state = index::State::Writer;
        Self {
            host,
            partition,
            index,
            on_disk: None,
            exists: false,
            mode: Mode::ReadOnly,
            blind: true,
            verified: false,
        }
    }

    pub fn is_blind(&self) -> bool {
        self.blind
    }

    pub fn is_read_only(&self) -> bool {
        self.mode != Mode::Clean || self.host.writes_refused()
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    fn writable(&self) -> Result<(), StorageFailure> {
        if self.is_read_only() {
            Err(StorageFailure)
        } else {
            Ok(())
        }
    }

    pub fn host(&mut self) -> &mut H {
        self.host
    }

    pub fn has_index(&self) -> bool {
        self.exists
    }

    /// Writes `new` as the index. On a failed write, reads back: the commit
    /// stands if the disk holds exactly `new`. Any other outcome is uncertain
    /// (the write may still land), so the store is read-only for the rest of
    /// the call.
    pub fn commit(&mut self, new: Index) -> Result<(), CommitFailure> {
        if self.is_read_only() {
            return Err(CommitFailure { old_intact: true });
        }
        let name = names::index(&self.partition);
        let bytes = new.encode();
        if !self.host.set_secret(&name, &bytes) {
            let back = self.host.get_secret(&name);
            if back.as_deref() != Some(bytes.as_slice()) {
                self.mode = Mode::ReadOnly;
                // Answer from what is on disk (4.2).
                let old_intact = back == self.on_disk;
                return Err(CommitFailure { old_intact });
            }
        }
        let first = !self.exists;
        self.index = new;
        self.on_disk = Some(bytes);
        self.exists = true;
        // The index just committed is the evidence from here on.
        self.verified = true;
        if first {
            // Listed after the index, so a crash between the two leaves an
            // index with no listing (repaired by the next `open`), never a
            // listing with no index.
            let _ = ensure_part_listed(self.host, &self.partition);
        }
        Ok(())
    }

    /// Applies `f` to a copy of the index and commits it.
    pub fn update(&mut self, f: impl FnOnce(&mut Index)) -> Result<(), StorageFailure> {
        let mut new = self.index.clone();
        f(&mut new);
        self.commit(new).map_err(|_| StorageFailure)
    }

    fn entry_name(&self, kind: u8, key: &[u8], parity: u8) -> Vec<u8> {
        names::entry(&self.partition, kind, key, parity)
    }

    /// The union of both gc list copies. A copy that is absent or does not
    /// parse (a torn write) contributes nothing; `write_gc` writes the copies
    /// one after the other, so at most one can be damaged and the other still
    /// holds every pending name.
    fn read_gc(&self) -> Vec<Vec<u8>> {
        let mut out: Vec<Vec<u8>> = Vec::new();
        for name in [names::gc(&self.partition), names::gc2(&self.partition)] {
            if let Some(list) = self.host.get_secret(&name).and_then(|b| decode_names(&b)) {
                for n in list {
                    if !out.contains(&n) {
                        out.push(n);
                    }
                }
            }
        }
        out
    }

    /// Writes the list to `vault:gc`, then to `vault:gc2`, stopping at the
    /// first failure. A failed write may be torn, and may have landed: with
    /// one copy written at a time the other is intact.
    fn write_gc(&mut self, list: &[Vec<u8>]) -> Result<(), StorageFailure> {
        let bytes = encode_names(list)?;
        for name in [names::gc(&self.partition), names::gc2(&self.partition)] {
            if !crate::host::replace_secret(self.host, &name, &bytes) {
                return Err(StorageFailure);
            }
        }
        Ok(())
    }

    /// Adds names to the gc list. Fails, writing nothing further, when the list
    /// would exceed [`MAX_GC_NAMES`] or a copy cannot be written.
    fn add_gc(&mut self, add: &[Vec<u8>]) -> Result<(), StorageFailure> {
        let mut list = self.read_gc();
        for n in add {
            if !list.contains(n) {
                list.push(n.clone());
            }
        }
        self.write_gc(&list)
    }

    /// Processes a non-empty `vault:gc`: removes every listed entry secret
    /// the index does not reference. A name stays listed while its secret still
    /// reads (retried by the next call); a drained list is stored empty.
    pub fn process_gc(&mut self) {
        // Only on positive evidence of what the index names.
        if self.is_read_only() || !self.verified {
            return;
        }
        let list = self.read_gc();
        if list.is_empty() {
            return;
        }
        let prefix = names::entry_prefix(&self.partition);
        let referenced: Vec<Vec<u8>> = self
            .index
            .entries
            .iter()
            .map(|e| self.entry_name(e.kind, &e.key, e.parity))
            .collect();
        let mut keep: Vec<Vec<u8>> = Vec::new();
        for name in list {
            if !name.starts_with(&prefix) || referenced.contains(&name) {
                continue;
            }
            // The result is not trusted (a failed removal may have landed); the
            // read back is.
            let _ = self.host.remove_secret(&name);
            if self.host.get_secret(&name).is_some() {
                keep.push(name);
            }
        }
        // If this write fails the old, longer list stays: also fine.
        let _ = self.write_gc(&keep);
    }

    /// Writes `bytes` as the entry `(kind, key)` into the parity slot the
    /// index does not name, then commits the index with `meta` applied too.
    fn write_entry(
        &mut self,
        kind: u8,
        key: &[u8],
        bytes: &[u8],
        meta: impl FnOnce(&mut Index),
    ) -> Result<(), StorageFailure> {
        self.writable()?;
        let existing = self
            .index
            .find(kind, key)
            .map(|i| self.index.entries[i].clone());
        let parity = existing.as_ref().map(|e| 1 - e.parity).unwrap_or(0);
        let new_name = self.entry_name(kind, key, parity);
        // Listed before it is written: a crash after the write and before the
        // index commit leaves a name gc removes, never an untracked secret.
        // The old copy is listed now too; gc skips it while the index still
        // references it.
        // Both parity names are listed (gc skips the referenced one), so a stale
        // copy at the other parity is always collected, including one left by
        // a Reset.
        let listed = vec![self.entry_name(kind, key, 0), self.entry_name(kind, key, 1)];
        self.add_gc(&listed)?;
        if !crate::host::replace_secret(self.host, &new_name, bytes) {
            // Nothing references it. If it landed anyway gc removes it; the
            // name stays listed until its secret reads as absent.
            self.process_gc();
            return Err(StorageFailure);
        }
        let mut new = self.index.clone();
        new.upsert(IndexEntry {
            kind,
            key: key.to_vec(),
            parity,
            len: bytes.len() as u16,
            digest: entry_digest(bytes),
        });
        meta(&mut new);
        match self.commit(new) {
            Ok(()) => {
                self.process_gc();
                Ok(())
            }
            // The commit was uncertain: the store is read-only for the rest of
            // the call, so the new copy is left to the next call's gc (it may
            // be the committed one).
            Err(_) => Err(StorageFailure),
        }
    }

    /// Stores `entry`, enforcing the quotas when it adds an identity.
    pub fn put(
        &mut self,
        entry: &Entry,
        quota: &Quota,
        meta: impl FnOnce(&mut Index),
    ) -> Result<(), PutError> {
        let bytes = entry.encode().map_err(|_| PutError::Storage)?;
        let existing = self
            .index
            .find(entry.kind, &entry.key)
            .map(|i| self.index.entries[i].len as usize);
        if existing.is_none() {
            let full = match entry.kind {
                KIND_KEY => self.index.count_kind(KIND_KEY) >= quota.max_key_slots,
                KIND_CALLER_MARK => {
                    self.index.count_kind(KIND_CALLER_MARK) >= quota.max_caller_marks
                }
                _ => false,
            };
            if full || self.index.entries.len() >= MAX_PARTITION_ENTRIES {
                return Err(PutError::Quota);
            }
        }
        if self.index.total_bytes() - existing.unwrap_or(0) + bytes.len() > MAX_PARTITION_BYTES {
            return Err(PutError::Quota);
        }
        self.write_entry(entry.kind, &entry.key, &bytes, meta)?;
        Ok(())
    }

    /// Removes `(kind, key)`: gc list, index without it, removal.
    pub fn delete(&mut self, kind: u8, key: &[u8]) -> Result<(), StorageFailure> {
        self.writable()?;
        if self.index.find(kind, key).is_none() {
            return Ok(());
        }
        let both = [self.entry_name(kind, key, 0), self.entry_name(kind, key, 1)];
        self.add_gc(&both)?;
        let mut new = self.index.clone();
        new.remove(kind, key);
        self.commit(new).map_err(|_| StorageFailure)?;
        self.process_gc();
        Ok(())
    }

    /// Reads `(kind, key)`, checking its digest against the index (4.3).
    ///
    /// On a mismatch while not `sealed`: bytes that still parse as this
    /// entry are rewritten with eflags bit 0 set and become its
    /// representation; bytes that do not are dropped from the index and
    /// counted. While sealed nothing is rewritten or removed.
    pub fn read(&mut self, kind: u8, key: &[u8], sealed: bool) -> Read {
        if self.blind {
            return match direct_entry(self.host, &self.partition, kind, key) {
                Some(e) if e.is_flagged_corrupt() => Read::Corrupt(Some(e)),
                Some(e) => Read::Ok(e),
                None => Read::Missing,
            };
        }
        // A read-only store changes nothing, like a sealed one.
        let sealed = sealed || self.mode == Mode::ReadOnly;
        let Some(i) = self.index.find(kind, key) else {
            return Read::Absent;
        };
        let ie = self.index.entries[i].clone();
        let got = self.host.get_secret(&self.entry_name(kind, key, ie.parity));
        // An absent secret is absent, never corrupt: there are no bytes to
        // judge, and dropping the entry would destroy what a restore could
        // bring back.
        if got.is_none() {
            return Read::Missing;
        }
        if let Some(b) = &got {
            if entry_digest(b) == ie.digest {
                // The bytes are exactly what was written. If this build cannot
                // decode them (a newer format), that is not damage: never
                // dropped or rewritten, and not usable either.
                return match Entry::decode(b) {
                    // Unknown flag bits: stored and copied, never served (spec 11).
                    Ok(e) if e.has_unknown_flags() => Read::Corrupt(None),
                    Ok(e) if e.is_flagged_corrupt() => Read::Corrupt(Some(e)),
                    Ok(e) => Read::Ok(e),
                    Err(_) => Read::Corrupt(None),
                };
            }
        }
        let parsed = got.as_ref().and_then(|b| {
            Entry::decode(b)
                .ok()
                .filter(|e| e.kind == kind && e.key == key)
                .map(|e| (e, b.clone()))
        });
        if sealed {
            return Read::Corrupt(parsed.map(|(e, _)| e));
        }
        match parsed {
            Some((mut e, mut raw)) => {
                // Flag in place: every other byte stays as it was.
                raw[1] |= EFLAG_CORRUPT;
                e.eflags |= EFLAG_CORRUPT;
                let _ = self.write_entry(kind, key, &raw, |idx| {
                    idx.problems |= problems::CORRUPT_OR_LOST
                });
                Read::Corrupt(Some(e))
            }
            None => {
                let both = [self.entry_name(kind, key, 0), self.entry_name(kind, key, 1)];
                if self.add_gc(&both).is_ok() {
                    let mut new = self.index.clone();
                    new.remove(kind, key);
                    new.lost_entries = new.lost_entries.saturating_add(1);
                    new.problems |= problems::CORRUPT_OR_LOST;
                    if self.commit(new).is_ok() {
                        self.process_gc();
                    }
                }
                // Unreadable either way: the slot answers as absent.
                Read::Absent
            }
        }
    }
}

/// An index write that did not land.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitFailure {
    /// The disk provably still holds the previous index.
    pub old_intact: bool,
}

/// `"FVGC" 4 ; count 2 ; count x { len 2 ; name }`. Fails above
/// [`MAX_GC_NAMES`] names, so the count always fits and a full list is
/// refused rather than truncated.
fn encode_names(names: &[Vec<u8>]) -> Result<Vec<u8>, StorageFailure> {
    if names.len() > MAX_GC_NAMES {
        return Err(StorageFailure);
    }
    let mut w = Writer::new();
    w.bytes(b"FVGC").len_u16(names.len(), "gc list length");
    for n in names {
        w.len_u16(n.len(), "gc name length").bytes(n);
    }
    w.finish().map_err(|_| StorageFailure)
}

/// `None` when the bytes are not a gc list this build wrote.
fn decode_names(bytes: &[u8]) -> Option<Vec<Vec<u8>>> {
    let parse = || -> Result<Vec<Vec<u8>>, Malformed> {
        let mut r = Reader::new(bytes);
        if r.take(4, "gc magic")? != b"FVGC" {
            return Err(Malformed("gc magic"));
        }
        let count = r.u16("count")? as usize;
        if count > MAX_GC_NAMES {
            return Err(Malformed("gc count"));
        }
        let mut out = Vec::with_capacity(count.min(64));
        for _ in 0..count {
            let len = r.u16("len")? as usize;
            out.push(r.take(len, "name")?.to_vec());
        }
        r.finish()?;
        Ok(out)
    };
    parse().ok()
}

/// The names pending in the gc list (either copy), for tests.
#[cfg(any(test, feature = "testing"))]
pub fn pending_gc_names<H: Host>(host: &H, partition: &[u8; 32]) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = Vec::new();
    for n in [names::gc(partition), names::gc2(partition)] {
        if let Some(l) = host.get_secret(&n).and_then(|b| decode_names(&b)) {
            for g in l {
                if !out.contains(&g) {
                    out.push(g);
                }
            }
        }
    }
    out
}

/// An encoded gc list naming `names`, for tests.
#[cfg(any(test, feature = "testing"))]
pub fn encode_gc_for_test(names: &[Vec<u8>]) -> Vec<u8> {
    encode_names(names).expect("short list")
}

/// Finds the entry `(kind, key)` with no index: reads both parity copies and
/// uses the entry only when exactly one distinct value decodes as a valid
/// entry for that slot (two identical copies are one value). None when neither
/// decodes or the two differ (an interrupted replace).
fn direct_entry<H: Host>(host: &H, partition: &[u8; 32], kind: u8, key: &[u8]) -> Option<Entry> {
    let mut found: Vec<Entry> = Vec::new();
    for parity in 0..2u8 {
        let Some(bytes) = host.get_secret(&names::entry(partition, kind, key, parity)) else {
            continue;
        };
        if let Ok(e) = Entry::decode(&bytes) {
            if e.kind == kind && e.key == key && !e.has_unknown_flags() && !found.contains(&e) {
                found.push(e);
            }
        }
    }
    match found.len() {
        1 => found.pop(),
        _ => None,
    }
}

/// Export while the index state is unknown: the seed of the slot's entry found
/// by [`direct_entry`] (a flagged-corrupt entry is exportable, protocol 4.3).
pub fn rescue_export_seed<H: Host>(
    host: &H,
    partition: &[u8; 32],
    slot: &[u8],
) -> Option<[u8; 32]> {
    let e = direct_entry(host, partition, KIND_KEY, slot)?;
    <[u8; 32]>::try_from(e.content.as_slice()).ok()
}

/// ResetPartition (protocol 4.5): writes a fresh, empty, checksummed WRITER
/// index over a lost one and keeps `vault:parts` listing the partition. Old
/// entry copies stay on disk; the gc lists are emptied so that nothing named
/// in them (possibly a live copy, since no index says which) is removed.
/// The caller has checked that the index is lost.
pub fn reset_partition<H: Host>(host: &mut H, partition: &[u8; 32]) -> Result<(), StorageFailure> {
    // Under the host's rule for undecryptable blobs a `set_secret` over one is
    // refused while `remove_secret` is allowed, so each secret that is rewritten
    // here is removed first (`replace_secret` for the lists, an explicit
    // removal for the index).
    //
    // 1. The gc lists go first, and both must take: once the empty index is
    //    published, gc would remove every name still listed, and a listed name
    //    may be the only copy of a key. A crash or a failure after this point
    //    leaves empty lists, which is harmless.
    let empty = encode_names(&[])?;
    for name in [names::gc(partition), names::gc2(partition)] {
        let _ = host.remove_secret(&name);
        if !host.set_secret(&name, &empty) {
            return Err(StorageFailure);
        }
    }
    // 2. `vault:parts` lists the partition before the index is replaced, so a
    //    crash between the removal and the write of the index leaves the index
    //    absent while listed (read-only, Reset can run again), never "new". A
    //    list that parses is kept; one that is malformed or reads as absent
    //    (maybe undecryptable) is replaced by this partition alone (this build
    //    has one partition).
    let parts = host.get_secret(names::PARTS);
    let parts_ok = parts
        .as_ref()
        .is_some_and(|l| l.len() % 32 == 0 && l.chunks(32).any(|c| c == partition));
    if !parts_ok {
        let mut list = match parts {
            Some(l) if l.len() % 32 == 0 => l,
            _ => Vec::new(),
        };
        list.extend_from_slice(partition);
        let _ = host.remove_secret(names::PARTS);
        if !host.set_secret(names::PARTS, &list) {
            return Err(StorageFailure);
        }
    }
    // 3. The index: remove the damaged one, then write the fresh one.
    let mut fresh = Index::none();
    fresh.state = index::State::Writer;
    let bytes = fresh.encode();
    let name = names::index(partition);
    let _ = host.remove_secret(&name);
    if !host.set_secret(&name, &bytes)
        && host.get_secret(&name).as_deref() != Some(bytes.as_slice())
    {
        return Err(StorageFailure);
    }
    Ok(())
}

/// `vault:parts`: the partition ids this build holds state for.
pub fn ensure_part_listed<H: Host>(
    host: &mut H,
    partition: &[u8; 32],
) -> Result<(), StorageFailure> {
    // A list that reads but does not parse is never replaced: it may hold
    // other partitions, and writing only this one would erase them. An absent
    // list is a first listing.
    let existing = host.get_secret(names::PARTS).unwrap_or_default();
    if !existing.len().is_multiple_of(32) {
        return Err(StorageFailure);
    }
    if existing.chunks(32).any(|c| c == partition) {
        return Ok(());
    }
    let mut list = existing;
    list.extend_from_slice(partition);
    if crate::host::replace_secret(host, names::PARTS, &list)
        || host.get_secret(names::PARTS).as_deref() == Some(list.as_slice())
    {
        Ok(())
    } else {
        Err(StorageFailure)
    }
}
