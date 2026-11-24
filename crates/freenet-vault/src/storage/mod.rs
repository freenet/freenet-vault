//! Durable state of one partition (protocol 4).
//!
//! Write ordering (4.2, revision 10.x): the index is the commit point. A change
//! to a WRITER has four steps: clear both parity names of an identity the index
//! does not name; write the parity the index does not name; commit the index;
//! write the same bytes to the other parity (the mirror). A change never uses
//! `vault:gc`. A Delete lists both names in `vault:gc`, removes the mirror and
//! reads it back as absent, commits, and gc removes the other copy. gc works by
//! identity: it never removes a name whose identity the committed index names.
//! After a failed index write the store reads the index back and answers from
//! what is on disk. Direct read (no index) serves a slot only when both parity
//! copies authenticate and are byte-identical.
//!
//! There is ONE index copy, `vault:idx`, the commit point, with a BLAKE3
//! checksum. `open` trusts it only when it reads and verifies:
//!
//! - index verified: normal operation.
//! - index absent (or malformed) and `vault:parts` a valid list that does not
//!   name the partition (an absent `vault:parts` is an empty list): the build is
//!   NONE for it. Creation and arming write the first index; nothing was read,
//!   so nothing is removed until that index is committed.
//! - anything else (see `Store::fault`: index absent while `vault:parts` lists
//!   the partition or is malformed, or malformed while it lists the partition
//!   or is malformed): `open` fails and the partition is read-only for that
//!   call: no write, no gc, no creation, no arming, no record storage. The next
//!   call checks again.
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
    /// `vault:parts` is present but malformed, and the index is absent.
    PartsUnreadable,
    /// The index is malformed and `vault:parts` is present but malformed.
    DamagedPartsMalformed,
}

impl IndexFault {
    /// `vault:parts` is present but not a valid list (spec 4.5, rev 10.1 G2
    /// and G2b: a build whose `vault:succ` holds a newer record answers Moved
    /// and never direct-reads).
    pub fn parts_malformed(&self) -> bool {
        matches!(self, Self::PartsUnreadable | Self::DamagedPartsMalformed)
    }
}

/// The index state is unknown: never read as "no partition". The partition is
/// read-only for the call, and HandoverStatus problems bit 6 is set (protocol
/// 4.5).
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
    /// `vault:parts` lists the partition. Only a WRITER or SEALED index is
    /// listed (spec 4.2); the index of an unlisted partition is written with
    /// remove before write.
    listed: bool,
    /// A read or the sweep in this call found an entry the index names whose
    /// secret reads as absent (revision 10.2: reported as problems bit 1; not
    /// counted in `lost_entries`, which counts dropped entries only).
    saw_missing: bool,
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
        let listed = host
            .get_secret(names::PARTS)
            .is_some_and(|l| l.len() % 32 == 0 && l.chunks(32).any(|c| c == partition));
        let (index, on_disk, exists, verified) = match first.as_deref().map(Index::decode) {
            Some(Ok(ix)) => (ix, first, true, true),
            // `fault` found no fault: the index is absent or malformed and
            // `vault:parts` is a valid list that does not name the partition, so
            // the build is NONE for it (reads in a completed call are truthful,
            // freenet-core #5857; spec 4.5, G1).
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
            listed,
            saw_missing: false,
            verified,
        })
    }

    /// Classifies the index state without keeping a borrow of the host:
    /// `None` when [`open`](Self::open) would succeed (spec 4.5).
    ///
    /// An absent `vault:parts` is a valid empty list (rev 10.1 G1). A valid
    /// index is never a fault, whatever the list says. An absent index is a
    /// loss when the list names the partition or is malformed. A malformed
    /// index is a loss only while the list names the partition or is
    /// malformed; with a valid list that does not name it, the build is NONE
    /// for the partition, exactly as for an absent index.
    pub fn fault(host: &H, partition: &[u8; 32]) -> Option<StoredIndexMalformed> {
        let index = host
            .get_secret(&names::index(partition))
            .as_deref()
            .map(Index::decode);
        if matches!(index, Some(Ok(_))) {
            return None;
        }
        let (listed, malformed) = match host.get_secret(names::PARTS) {
            None => (false, false),
            Some(l) if l.len() % 32 != 0 => (false, true),
            Some(l) => (l.chunks(32).any(|c| c == partition), false),
        };
        match index {
            None if malformed => Some(StoredIndexMalformed(IndexFault::PartsUnreadable)),
            None if listed => Some(StoredIndexMalformed(IndexFault::LostWhileListed)),
            Some(_) if listed => Some(StoredIndexMalformed(IndexFault::Damaged)),
            Some(_) if malformed => Some(StoredIndexMalformed(IndexFault::DamagedPartsMalformed)),
            _ => None,
        }
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
            listed: false,
            saw_missing: false,
            verified: false,
        }
    }

    /// A named entry read as absent in this call (see the field).
    pub fn saw_missing(&self) -> bool {
        self.saw_missing
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
        // The index of a listed partition is never written while it reads as
        // absent (read-only mode). The index of an unlisted one is written with
        // remove before write (it may hold an undecryptable blob, spec 4.2).
        let wrote = if self.listed {
            self.host.set_secret(&name, &bytes)
        } else {
            crate::host::replace_secret(self.host, &name, &bytes)
        };
        if !wrote {
            let back = self.host.get_secret(&name);
            if back.as_deref() != Some(bytes.as_slice()) {
                self.mode = Mode::ReadOnly;
                // Answer from what is on disk (4.2).
                let old_intact = back == self.on_disk;
                return Err(CommitFailure { old_intact });
            }
        }
        let listable = |st: index::State| matches!(st, index::State::Writer | index::State::Sealed);
        // Only the commit that makes the index WRITER (or SEALED) lists it; an
        // index that already was needs nothing here (the catch-all lists it
        // when it is not listed, overwriting a malformed list, revision 10.2).
        let lists = listable(new.state) && !listable(self.index.state);
        self.index = new;
        self.on_disk = Some(bytes.clone());
        self.exists = true;
        // The index just committed is the evidence from here on.
        self.verified = true;
        if lists && !self.listed {
            // A WRITER or SEALED index is listed only after it reads back, and
            // no answer that depends on it leaves the call before the listing
            // reads back (spec 4.2, F16): if either fails the change answers
            // storage failure, and the next call's catch-all lists it.
            let read_back = self.host.get_secret(&name).as_deref() == Some(bytes.as_slice());
            if read_back && ensure_part_listed(self.host, &self.partition).is_ok() {
                self.listed = true;
            } else {
                self.mode = Mode::ReadOnly;
                return Err(CommitFailure { old_intact: false });
            }
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
        // By identity (spec 4.2): both parity names of an identity the committed
        // index names are in use, one as the copy and one as its mirror.
        let referenced: Vec<Vec<u8>> = self
            .index
            .entries
            .iter()
            .flat_map(|e| {
                [
                    self.entry_name(e.kind, &e.key, 0),
                    self.entry_name(e.kind, &e.key, 1),
                ]
            })
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
        // The index after this change, built up front: the creation shape needs
        // to know whether it makes the index WRITER.
        let parity = existing.as_ref().map(|e| 1 - e.parity).unwrap_or(0);
        let mut staged = self.index.clone();
        staged.upsert(IndexEntry {
            kind,
            key: key.to_vec(),
            parity,
            len: bytes.len() as u16,
            digest: entry_digest(bytes),
        });
        meta(&mut staged);
        // Creation (the index is not WRITER or SEALED and this change makes it
        // WRITER): the first commit is an EMPTY WRITER index, which is listed and
        // read back (inside `commit`). Only then is the first entry written and
        // committed, so a refused listing never leaves a committed key.
        let listable = |st: index::State| matches!(st, index::State::Writer | index::State::Sealed);
        if listable(staged.state) && !listable(self.index.state) {
            let mut empty = staged.clone();
            empty.entries = self.index.entries.clone();
            self.commit(empty).map_err(|_| StorageFailure)?;
        }
        // Step 1 (spec 4.2): an identity the index does not name (a new slot,
        // or one deleted earlier) starts with both parity names removed and
        // read back as absent, so a leftover copy of a failed write or an
        // unfinished Delete cannot pair with this one. A name that reads as
        // present and will not clear refuses the change. (A name that reads as
        // absent may hold an undecryptable blob; the write below removes it.)
        if existing.is_none() {
            for parity in 0..2u8 {
                let name = self.entry_name(kind, key, parity);
                if self.host.get_secret(&name).is_some() {
                    let _ = self.host.remove_secret(&name);
                    if self.host.get_secret(&name).is_some() {
                        return Err(StorageFailure);
                    }
                }
            }
        }
        // Step 2: the parity the index does not name. For a named identity that
        // held the mirror of the old value, so from here until step 4 the two
        // copies disagree.
        let new_name = self.entry_name(kind, key, parity);
        if !crate::host::replace_secret(self.host, &new_name, bytes) {
            return Err(StorageFailure);
        }
        // Step 3: the index naming it. The answer depends on this step.
        self.commit(staged).map_err(|_| StorageFailure)?;
        // Step 4: the same bytes to the other parity (the mirror), for a listed
        // build (WRITER). A failed write here is not an error: the slot is
        // served from the index while it is intact, and unavailable to direct
        // read until the mirror sweep or the slot's next change repairs it. The
        // failed write leaves the call read-only.
        if self.index.state == index::State::Writer {
            let mirror = self.entry_name(kind, key, 1 - parity);
            let _ = crate::host::replace_secret(self.host, &mirror, bytes);
        }
        self.process_gc();
        Ok(())
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
        self.drop_identity(kind, key, |_| {})
    }

    /// Removes an identity from the index (spec 4.2, Delete): list both parity
    /// names in `vault:gc`; remove the mirror (the copy the index does not
    /// name) and read it back as absent, refusing if it is still there; commit
    /// the index without the slot; gc removes the other copy. Only after step 2
    /// does the slot have a single copy, so a Delete whose commit failed can
    /// never leave a pair that direct read would serve.
    fn drop_identity(
        &mut self,
        kind: u8,
        key: &[u8],
        meta: impl FnOnce(&mut Index),
    ) -> Result<(), StorageFailure> {
        self.writable()?;
        let Some(i) = self.index.find(kind, key) else {
            return Ok(());
        };
        let parity = self.index.entries[i].parity;
        let named = self.entry_name(kind, key, parity);
        let mirror = self.entry_name(kind, key, 1 - parity);
        self.add_gc(&[named, mirror.clone()])?;
        let _ = self.host.remove_secret(&mirror);
        if self.host.get_secret(&mirror).is_some() {
            return Err(StorageFailure);
        }
        let mut new = self.index.clone();
        new.remove(kind, key);
        meta(&mut new);
        self.commit(new).map_err(|_| StorageFailure)?;
        self.process_gc();
        Ok(())
    }

    /// The mirror sweep (spec 7.7): for a listed WRITER build, writes the
    /// mirror of every entry the index names whose mirror is missing or
    /// differs, from the named copy, after checking that copy against the
    /// index digest. A sealed build does not sweep. Progress is not kept (it is
    /// volatile in the spec), so nothing is ever marked finished; the sweep
    /// stops at the first failed write, which leaves the call read-only.
    pub fn mirror_sweep(&mut self) {
        if self.is_read_only() || !self.verified || self.index.state != index::State::Writer {
            return;
        }
        for ie in self.index.entries.clone() {
            let named = self.entry_name(ie.kind, &ie.key, ie.parity);
            let mirror = self.entry_name(ie.kind, &ie.key, 1 - ie.parity);
            let Some(bytes) = self.host.get_secret(&named) else {
                self.saw_missing = true;
                continue;
            };
            if entry_digest(&bytes) != ie.digest {
                continue;
            }
            if self.host.get_secret(&mirror).as_deref() != Some(bytes.as_slice())
                && !crate::host::replace_secret(self.host, &mirror, &bytes)
            {
                return;
            }
        }
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
                Some(e) => Read::Ok(e),
                // A missing copy, a copy that does not authenticate or two
                // copies that differ: storage failure. Never Absent.
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
            self.saw_missing = true;
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
        // Unknown flag bits are never served, whichever path found the entry
        // (spec 11): not flagged, not rewritten, not dropped, not exportable.
        if parsed.as_ref().is_some_and(|(e, _)| e.has_unknown_flags()) {
            return Read::Corrupt(None);
        }
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
                // Bytes that do not parse: the entry leaves the index and is
                // counted (4.3), by the steps of a Delete.
                let _ = self.drop_identity(kind, key, |ix| {
                    ix.lost_entries = ix.lost_entries.saturating_add(1);
                    ix.problems |= problems::CORRUPT_OR_LOST;
                });
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

/// Direct read (spec 4.5, rev 10): with no index, a slot is served only when
/// BOTH parity copies authenticate and are byte-identical. A copy
/// authenticates when it reads as present, parses as an entry exactly, and has
/// the expected kind, eflags 0 (no integrity flag, no reserved bit), the key
/// asked for, and content of the kind's length (32 for a key, 100 for a caller
/// mark). Anything else, including one copy, two copies that differ and no
/// copy, is unavailable (`None`): nothing chooses between copies, and
/// `vault:gc` is never consulted.
fn direct_entry<H: Host>(host: &H, partition: &[u8; 32], kind: u8, key: &[u8]) -> Option<Entry> {
    let c0 = host.get_secret(&names::entry(partition, kind, key, 0))?;
    let c1 = host.get_secret(&names::entry(partition, kind, key, 1))?;
    if c0 != c1 {
        return None;
    }
    let e = Entry::decode(&c0).ok()?;
    let want_len = match kind {
        KIND_KEY => 32,
        KIND_CALLER_MARK => 100,
        _ => return None,
    };
    if e.kind != kind || e.eflags != 0 || e.key != key || e.content.len() != want_len {
        return None;
    }
    Some(e)
}

/// Export while the index state is unknown: the seed of the slot's entry found
/// by [`direct_entry`]. A slot that is unavailable cannot be exported in v1.
pub fn rescue_export_seed<H: Host>(
    host: &H,
    partition: &[u8; 32],
    slot: &[u8],
) -> Option<[u8; 32]> {
    let e = direct_entry(host, partition, KIND_KEY, slot)?;
    <[u8; 32]>::try_from(e.content.as_slice()).ok()
}

/// `vault:parts`: the partition ids this build holds state for.
pub fn ensure_part_listed<H: Host>(
    host: &mut H,
    partition: &[u8; 32],
) -> Result<(), StorageFailure> {
    // An absent list is a valid empty list (rev 10.1, G1). A malformed list is
    // overwritten by a list naming this partition (revision 10.2): the index
    // being listed is valid, and other partitions' valid indexes are listed
    // again by their own catch-all. A list that reads is written over directly;
    // one that reads as absent is removed first (replace_secret).
    let mut list = match host.get_secret(names::PARTS) {
        Some(l) if l.len() % 32 == 0 => l,
        _ => Vec::new(),
    };
    if list.chunks(32).any(|c| c == partition) {
        return Ok(());
    }
    list.extend_from_slice(partition);
    // A write that REPORTS failure is a failure even if it landed (G3, the
    // model's rule): the call answers nothing and the next one lists it. The
    // listing also counts only once it reads back.
    if !crate::host::replace_secret(host, names::PARTS, &list) {
        return Err(StorageFailure);
    }
    if host.get_secret(names::PARTS).as_deref() == Some(list.as_slice()) {
        Ok(())
    } else {
        Err(StorageFailure)
    }
}

/// The catch-all (spec 4.2, rev 10.1 G3): a valid WRITER or SEALED index for a
/// partition `vault:parts` does not list is listed before the call does
/// anything else. `Err` means the write reported failure or its read-back
/// failed: the call answers nothing. A malformed `vault:parts` is overwritten
/// by a list naming the partition (revision 10.2).
pub fn ensure_listed<H: Host>(host: &mut H, partition: &[u8; 32]) -> Result<(), StorageFailure> {
    let Some(Ok(ix)) = host
        .get_secret(&names::index(partition))
        .as_deref()
        .map(Index::decode)
    else {
        return Ok(());
    };
    if !matches!(ix.state, index::State::Writer | index::State::Sealed) {
        return Ok(());
    }
    ensure_part_listed(host, partition)
}
