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
//! The index is written twice, `vault:idx` then `vault:idx2`, each with a
//! checksum. `open` reconciles the two before anything else happens:
//!
//! - first valid: it is the commit point and wins; a second that is absent,
//!   invalid or different is rewritten from it.
//! - first present but invalid, second valid: the first is restored from the
//!   second (the second is at worst one commit behind, and its entry copies
//!   still exist, because gc never runs while the copies differ).
//! - first ABSENT, second valid: ambiguous (a lost secret or a transient
//!   read), so the store is read-only: no write, no gc, no repair of an entry.
//! - both absent: a new partition, unless `vault:parts` lists it, which is an
//!   error (never NONE).
//!
//! gc runs only when both copies are verified identical, so it can never
//! remove a copy that either index names. The gc list is kept twice as well
//! (`vault:gc`, `vault:gc2`) and read as a union.

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

/// How far the two index copies can be trusted to agree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Both copies are verified identical: reads, writes and gc are allowed.
    Clean,
    /// The first copy is valid and authoritative but the second could not be
    /// brought in line: writes are allowed, gc is not.
    Unsynced,
    /// Only the second copy could be used (the first is absent): nothing is
    /// written, rewritten or removed.
    ReadOnly,
}

/// A name in the gc list and how many times its removal was left uncertain
/// (not removed, yet not read back either).
#[derive(Debug, Clone, PartialEq, Eq)]
struct GcName {
    name: Vec<u8>,
    uncertain: u8,
}

/// A name is dropped from the gc list only after a confirmed removal. An
/// uncertain pass (not removed, not readable) keeps it, and counts. Only when
/// the list is full are the most-uncertain names made room from.
/// The gc list never holds more names than this, so it cannot outgrow its
/// encoding; a write that would exceed it fails until gc drains it.
pub const MAX_GC_NAMES: usize = 4096;

pub struct Store<'a, H: Host> {
    host: &'a mut H,
    partition: [u8; 32],
    pub index: Index,
    /// The first index copy's bytes known to be on disk, `None` when absent.
    on_disk: Option<Vec<u8>>,
    /// An index was found, in either copy.
    exists: bool,
    mode: Mode,
    /// At least one index copy was read and passed its checksum in `open`.
    /// Without that there is no positive evidence of what the partition holds
    /// (every read may have missed), so nothing destructive runs.
    verified: bool,
}

/// A write that took, by its own report or by reading it back.
fn write_verified<H: Host>(host: &mut H, name: &[u8], bytes: &[u8]) -> bool {
    host.set_secret(name, bytes) || host.get_secret(name).as_deref() == Some(bytes)
}

impl<'a, H: Host> Store<'a, H> {
    /// Loads the partition and reconciles the two index copies (module
    /// docs). A malformed index is an error the caller must not treat as
    /// NONE, and neither is an absent one for a partition `vault:parts` lists.
    pub fn open(host: &'a mut H, partition: [u8; 32]) -> Result<Self, StoredIndexMalformed> {
        let n1 = names::index(&partition);
        let n2 = names::index2(&partition);
        let first = host.get_secret(&n1);
        let second = host.get_secret(&n2);
        let d1 = first.as_deref().map(Index::decode);
        let d2 = second.as_deref().map(Index::decode);
        let (index, on_disk, mode, exists, verified) = match (d1, d2) {
            (Some(Ok(i1)), _) => {
                let b1 = first.expect("decoded");
                // The second copy is brought in line with the first (the
                // first is the commit point, so it wins) before anything else.
                let in_line =
                    second.as_deref() == Some(b1.as_slice()) || write_verified(host, &n2, &b1);
                let mode = if in_line { Mode::Clean } else { Mode::Unsynced };
                (i1, Some(b1), mode, true, true)
            }
            // The first copy is there but damaged: restore it from the second.
            (Some(Err(_)), Some(Ok(i2))) => {
                let b2 = second.expect("decoded");
                if write_verified(host, &n1, &b2) {
                    (i2, Some(b2), Mode::Clean, true, true)
                } else {
                    (i2, first, Mode::ReadOnly, true, true)
                }
            }
            // Absent first, valid second: ambiguous, so read-only.
            (None, Some(Ok(i2))) => (i2, None, Mode::ReadOnly, true, true),
            (None, None) => {
                let listed = host
                    .get_secret(names::PARTS)
                    .is_some_and(|l| l.len() % 32 == 0 && l.chunks(32).any(|c| c == partition));
                if listed {
                    return Err(StoredIndexMalformed);
                }
                // No index was read: a new partition, or every read missed. Entries
                // may be written (a new partition must start), but nothing is
                // removed in this call (`verified` stays false).
                (Index::none(), None, Mode::Clean, false, false)
            }
            _ => return Err(StoredIndexMalformed),
        };
        Ok(Self {
            host,
            partition,
            index,
            on_disk,
            exists,
            mode,
            verified,
        })
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// Writes need both index copies in line: while the backup is stale it
    /// still names entry copies, and a write could overwrite one of them.
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
    /// stands if the disk holds exactly `new`.
    pub fn commit(&mut self, new: Index) -> Result<(), CommitFailure> {
        if self.mode != Mode::Clean {
            return Err(CommitFailure { old_intact: true });
        }
        let name = names::index(&self.partition);
        let bytes = new.encode();
        let ok = self.host.set_secret(&name, &bytes) || {
            let back = self.host.get_secret(&name);
            if back.as_deref() == Some(bytes.as_slice()) {
                true
            } else {
                // Answer from what is on disk (4.2).
                let old_intact = back == self.on_disk;
                return Err(CommitFailure { old_intact });
            }
        };
        debug_assert!(ok);
        // The second copy goes after the first. The first is the commit point,
        // so a failure here is not an error, but until the second is written
        // gc must not run (it could remove a copy the second still names);
        // the next `open` or commit writes it again.
        self.mode = if write_verified(self.host, &names::index2(&self.partition), &bytes) {
            Mode::Clean
        } else {
            Mode::Unsynced
        };
        self.index = new;
        self.on_disk = Some(bytes);
        self.exists = true;
        // The index just committed is the evidence from here on (a partition
        // that began blind is a new one once it holds an index of its own).
        self.verified = true;
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
    /// parse contributes nothing (a lost list costs quota, never a key: gc
    /// removes only unreferenced names).
    fn read_gc(&self) -> Vec<GcName> {
        let mut out: Vec<GcName> = Vec::new();
        for name in [names::gc(&self.partition), names::gc2(&self.partition)] {
            if let Some(list) = self.host.get_secret(&name).and_then(|b| decode_names(&b)) {
                for g in list {
                    match out.iter_mut().find(|x| x.name == g.name) {
                        Some(x) => x.uncertain = x.uncertain.min(g.uncertain),
                        None => out.push(g),
                    }
                }
            }
        }
        out
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

    /// Adds names to the gc list. Fails, writing nothing, when the list would
    /// exceed [`MAX_GC_NAMES`] even after dropping the names whose removal has
    /// stayed uncertain, most uncertain first; and when either copy cannot be
    /// written.
    fn add_gc(&mut self, add: &[Vec<u8>]) -> Result<(), StorageFailure> {
        let mut list = self.read_gc();
        for n in add {
            if !list.iter().any(|g| &g.name == n) {
                list.push(GcName {
                    name: n.clone(),
                    uncertain: 0,
                });
            }
        }
        while list.len() > MAX_GC_NAMES {
            let worst = list
                .iter()
                .enumerate()
                .filter(|(_, g)| g.uncertain > 0 && !add.contains(&g.name))
                .max_by_key(|(_, g)| g.uncertain)
                .map(|(i, _)| i);
            match worst {
                Some(i) => {
                    list.remove(i);
                }
                None => return Err(StorageFailure),
            }
        }
        self.write_gc(&list, true)
    }

    /// Processes a non-empty `vault:gc`: removes every listed entry secret
    /// the index does not reference. Names whose removal did not take stay
    /// listed (and are retried by the next call); the list is cleared only
    /// when every removal is confirmed.
    pub fn process_gc(&mut self) {
        // Only when both index copies are verified identical: otherwise a name
        // that one of them references could be removed.
        if self.mode != Mode::Clean || !self.verified {
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
        let mut keep: Vec<GcName> = Vec::new();
        for g in list {
            if !g.name.starts_with(&prefix) || referenced.contains(&g.name) {
                continue;
            }
            let removed = self.host.remove_secret(&g.name);
            if self.host.get_secret(&g.name).is_some() {
                // Still there: retry, whatever the removal reported.
                keep.push(g);
            } else if !removed {
                // Neither removed nor readable: it may never have existed, or
                // the read may have failed. Keep it: only a confirmed removal
                // drops a name.
                let uncertain = g.uncertain.saturating_add(1);
                keep.push(GcName { uncertain, ..g });
            }
        }
        if keep.is_empty() {
            self.host.remove_secret(&names::gc(&self.partition));
            self.host.remove_secret(&names::gc2(&self.partition));
        } else {
            // If this write fails the old, longer list stays: also fine.
            let _ = self.write_gc(&keep, false);
        }
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
            Err(f) => {
                // Remove the new copy only when the disk provably still holds
                // the old index; otherwise it may be the committed one.
                if f.old_intact {
                    self.process_gc();
                }
                Err(StorageFailure)
            }
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

/// `vault:parts`: the partition ids this build holds state for.
pub fn ensure_part_listed<H: Host>(
    host: &mut H,
    partition: &[u8; 32],
) -> Result<(), StorageFailure> {
    let existing = host.get_secret(names::PARTS).unwrap_or_default();
    if existing.len().is_multiple_of(32) && existing.chunks(32).any(|c| c == partition) {
        return Ok(());
    }
    let mut list = if existing.len().is_multiple_of(32) {
        existing
    } else {
        Vec::new()
    };
    list.extend_from_slice(partition);
    if host.set_secret(names::PARTS, &list)
        || host.get_secret(names::PARTS).as_deref() == Some(list.as_slice())
    {
        Ok(())
    } else {
        Err(StorageFailure)
    }
}
