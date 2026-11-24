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

/// The stored index does not parse. Never read as "no partition".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoredIndexMalformed;

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
    /// The index names the entry but the host returned no secret for it. That
    /// can be a transient read failure, so nothing is changed or deleted and
    /// the entry is never treated as corrupt. Callers answer storage failure.
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

/// A name in the gc list and how many times its removal was left uncertain
/// (not removed, yet not read back either).
#[derive(Debug, Clone, PartialEq, Eq)]
struct GcName {
    name: Vec<u8>,
    uncertain: u8,
}

/// A name is dropped from the gc list only after a confirmed removal. The
/// list never holds more names than this, so it cannot outgrow its encoding; a
/// write that would exceed it fails until gc drains it (no name is ever
/// dropped to make room).
/// A name whose removal reports failure while it also reads as absent is
/// dropped after this many passes: freenet-stdlib's `remove_secret` returns
/// false for a secret that was never there.
pub const GC_UNCERTAIN_LIMIT: u8 = 3;
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
    /// An index passed its checksum in this call. Without that there is no
    /// positive evidence of what the partition holds, so nothing is removed.
    verified: bool,
}

impl<'a, H: Host> Store<'a, H> {
    /// Loads the partition (module docs). `Err` means the index state is
    /// unknown and the caller must treat the partition as read-only; it is
    /// never read as "no partition".
    pub fn open(host: &'a mut H, partition: [u8; 32]) -> Result<Self, StoredIndexMalformed> {
        let first = host.get_secret(&names::index(&partition));
        let (index, on_disk, exists, verified) = match first.as_deref().map(Index::decode) {
            Some(Ok(ix)) => {
                // Keeps `vault:parts` in step (best effort; a failure is
                // retried by the next call).
                let _ = ensure_part_listed(host, &partition);
                (ix, first, true, true)
            }
            Some(Err(_)) => return Err(StoredIndexMalformed),
            None => {
                // Absent. A new partition only when `vault:parts` reads and
                // does not name it.
                match host.get_secret(names::PARTS) {
                    Some(l) if l.len() % 32 != 0 || l.chunks(32).any(|c| c == partition) => {
                        return Err(StoredIndexMalformed)
                    }
                    _ => (Index::none(), None, false, false),
                }
            }
        };
        Ok(Self {
            host,
            partition,
            index,
            on_disk,
            exists,
            mode: Mode::Clean,
            verified,
        })
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    fn writable(&self) -> Result<(), StorageFailure> {
        if self.mode != Mode::Clean {
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
        if self.mode != Mode::Clean {
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

    /// The union of both gc list copies, and whether the list can be trusted.
    /// A list is always present once any entry was written (an emptied list is
    /// stored as an empty list, never removed), so BOTH copies reading as
    /// nothing while the index names entries means the reads failed: the list
    /// is not trusted and nothing is rewritten or run from it. A copy that is
    /// absent or does not parse contributes nothing.
    fn read_gc(&self) -> (Vec<GcName>, bool) {
        let mut out: Vec<GcName> = Vec::new();
        let mut any = false;
        for name in [names::gc(&self.partition), names::gc2(&self.partition)] {
            if let Some(list) = self.host.get_secret(&name).and_then(|b| decode_names(&b)) {
                any = true;
                for g in list {
                    match out.iter_mut().find(|x| x.name == g.name) {
                        Some(x) => x.uncertain = x.uncertain.min(g.uncertain),
                        None => out.push(g),
                    }
                }
            }
        }
        let trusted = any || self.index.entries.is_empty();
        (out, trusted)
    }

    /// Writes both gc list copies. With `both`, a copy that does not take is
    /// an error: names are being ADDED, and a list held by one copy only can
    /// be erased by a later write after that copy misses a read. Without it
    /// (shrinking), one copy taking is enough, since a stale second copy only
    /// lists names already removed.
    fn write_gc(&mut self, list: &[GcName], both: bool) -> Result<(), StorageFailure> {
        let bytes = encode_names(list)?;
        let a = self.host.set_secret(&names::gc(&self.partition), &bytes);
        let b = self.host.set_secret(&names::gc2(&self.partition), &bytes);
        if (a && b) || (!both && (a || b)) {
            Ok(())
        } else {
            Err(StorageFailure)
        }
    }

    /// Adds names to the gc list. Fails, writing nothing, when the list is not
    /// trusted (both copies unreadable), when it would exceed [`MAX_GC_NAMES`]
    /// (no name is dropped to make room), or when either copy cannot be
    /// written.
    fn add_gc(&mut self, add: &[Vec<u8>]) -> Result<(), StorageFailure> {
        let (mut list, trusted) = self.read_gc();
        if !trusted {
            return Err(StorageFailure);
        }
        for n in add {
            if !list.iter().any(|g| &g.name == n) {
                list.push(GcName {
                    name: n.clone(),
                    uncertain: 0,
                });
            }
        }
        self.write_gc(&list, true)
    }

    /// Processes a non-empty `vault:gc`: removes every listed entry secret
    /// the index does not reference. Names whose removal did not take stay
    /// listed (and are retried by the next call). A drained list is stored
    /// empty, not removed.
    pub fn process_gc(&mut self) {
        // Only on positive evidence of what the index names, and with a list
        // that can be trusted.
        if self.mode != Mode::Clean || !self.verified {
            return;
        }
        let (list, trusted) = self.read_gc();
        if list.is_empty() || !trusted {
            return;
        }
        let prefix = names::entry_prefix(&self.partition);
        let referenced: Vec<Vec<u8>> = self
            .index
            .entries
            .iter()
            .map(|e| self.entry_name(e.kind, &e.key, e.parity))
            .collect();
        let mut keep: Vec<GcName> = Vec::new();
        for g in list {
            if !g.name.starts_with(&prefix) || referenced.contains(&g.name) {
                continue;
            }
            // `removed` is true when the secret is gone. freenet-stdlib answers
            // false for a secret that was not there, so a name that neither
            // removes nor reads is counted, and dropped after
            // [`GC_UNCERTAIN_LIMIT`] such passes (otherwise every candidate
            // that never landed would stay listed for ever and fill the list).
            let removed = self.host.remove_secret(&g.name);
            if self.host.get_secret(&g.name).is_some() {
                keep.push(g);
            } else if !removed {
                let uncertain = g.uncertain.saturating_add(1);
                if uncertain < GC_UNCERTAIN_LIMIT {
                    keep.push(GcName { uncertain, ..g });
                }
            }
        }
        // If this write fails the old, longer list stays: also fine.
        let _ = self.write_gc(&keep, false);
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
        let mut listed = vec![new_name.clone()];
        if let Some(old) = &existing {
            listed.push(self.entry_name(kind, key, old.parity));
        }
        self.add_gc(&listed)?;
        if !self.host.set_secret(&new_name, bytes) {
            // Nothing references it. If it landed anyway gc removes it; the
            // name stays listed whatever a read now says, since a miss here
            // does not show that nothing was written.
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
        // A read-only store changes nothing, like a sealed one.
        let sealed = sealed || self.mode == Mode::ReadOnly;
        let Some(i) = self.index.find(kind, key) else {
            return Read::Absent;
        };
        let ie = self.index.entries[i].clone();
        let got = self.host.get_secret(&self.entry_name(kind, key, ie.parity));
        // An absent secret is absent, never corrupt: the read may have failed
        // transiently, and deleting on that evidence would destroy a key.
        if got.is_none() {
            return Read::Missing;
        }
        if let Some(b) = &got {
            if entry_digest(b) == ie.digest {
                // The bytes are exactly what was written. If this build cannot
                // decode them (a newer format), that is not damage: never
                // dropped or rewritten, and not usable either.
                return match Entry::decode(b) {
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

/// `"FVGC" 4 ; count 2 ; count x { len 2 ; name ; uncertain 1 }`. Fails above
/// [`MAX_GC_NAMES`] names, so the count always fits and a full list is
/// refused rather than truncated.
fn encode_names(names: &[GcName]) -> Result<Vec<u8>, StorageFailure> {
    if names.len() > MAX_GC_NAMES {
        return Err(StorageFailure);
    }
    let mut w = Writer::new();
    w.bytes(b"FVGC").len_u16(names.len(), "gc list length");
    for n in names {
        w.len_u16(n.name.len(), "gc name length")
            .bytes(&n.name)
            .u8(n.uncertain);
    }
    w.finish().map_err(|_| StorageFailure)
}

/// `None` when the bytes are not a gc list this build wrote.
fn decode_names(bytes: &[u8]) -> Option<Vec<GcName>> {
    let parse = || -> Result<Vec<GcName>, Malformed> {
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
            let name = r.take(len, "name")?.to_vec();
            let uncertain = r.u8("uncertain")?;
            out.push(GcName { name, uncertain });
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
                if !out.contains(&g.name) {
                    out.push(g.name);
                }
            }
        }
    }
    out
}

/// An encoded gc list naming `names`, for tests.
#[cfg(any(test, feature = "testing"))]
pub fn encode_gc_for_test(names: &[Vec<u8>]) -> Vec<u8> {
    let list: Vec<GcName> = names
        .iter()
        .map(|n| GcName {
            name: n.clone(),
            uncertain: 0,
        })
        .collect();
    encode_names(&list).expect("short list")
}

/// Export while the index state is unknown: reads both parity copies of the
/// slot directly and returns a seed only when exactly one of them decodes as a
/// key entry for that slot with a 32-byte seed.
pub fn rescue_export_seed<H: Host>(
    host: &H,
    partition: &[u8; 32],
    slot: &[u8],
) -> Option<[u8; 32]> {
    let mut found: Vec<[u8; 32]> = Vec::new();
    for parity in 0..2u8 {
        let name = names::entry(partition, KIND_KEY, slot, parity);
        let Some(bytes) = host.get_secret(&name) else {
            continue;
        };
        if let Ok(e) = Entry::decode(&bytes) {
            if e.kind == KIND_KEY && e.key == slot {
                if let Ok(seed) = <[u8; 32]>::try_from(e.content.as_slice()) {
                    found.push(seed);
                }
            }
        }
    }
    match found.as_slice() {
        [one] => Some(*one),
        _ => None,
    }
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
    if host.set_secret(names::PARTS, &list)
        || host.get_secret(names::PARTS).as_deref() == Some(list.as_slice())
    {
        Ok(())
    } else {
        Err(StorageFailure)
    }
}
