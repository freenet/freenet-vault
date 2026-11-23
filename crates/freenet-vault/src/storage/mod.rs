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
//! a failed commit can never delete a live entry.

pub mod index;
pub mod names;

use crate::host::Host;
use freenet_vault_common::bounds::{MAX_PARTITION_BYTES, MAX_PARTITION_ENTRIES};
use freenet_vault_common::codec::{Reader, Writer};
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
}

pub struct Store<'a, H: Host> {
    host: &'a mut H,
    partition: [u8; 32],
    pub index: Index,
    /// The index bytes known to be on disk, `None` when there is no index.
    on_disk: Option<Vec<u8>>,
}

impl<'a, H: Host> Store<'a, H> {
    /// Loads the partition. A missing index is NONE; a malformed one is an
    /// error the caller must not treat as NONE.
    pub fn open(host: &'a mut H, partition: [u8; 32]) -> Result<Self, StoredIndexMalformed> {
        let on_disk = host.get_secret(&names::index(&partition));
        let index = match &on_disk {
            None => Index::none(),
            Some(b) => Index::decode(b).map_err(|_| StoredIndexMalformed)?,
        };
        Ok(Self {
            host,
            partition,
            index,
            on_disk,
        })
    }

    pub fn host(&mut self) -> &mut H {
        self.host
    }

    pub fn has_index(&self) -> bool {
        self.on_disk.is_some()
    }

    /// Writes `new` as the index. On a failed write, reads back: the commit
    /// stands if the disk holds exactly `new`.
    pub fn commit(&mut self, new: Index) -> Result<(), CommitFailure> {
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
        self.index = new;
        self.on_disk = Some(bytes);
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

    /// Adds names to `vault:gc`.
    fn add_gc(&mut self, add: &[Vec<u8>]) -> Result<(), StorageFailure> {
        let name = names::gc(&self.partition);
        let mut list = self
            .host
            .get_secret(&name)
            .map(|b| decode_names(&b))
            .unwrap_or_default();
        list.extend(add.iter().cloned());
        if self.host.set_secret(&name, &encode_names(&list)) {
            Ok(())
        } else {
            Err(StorageFailure)
        }
    }

    /// Processes a non-empty `vault:gc`: removes every listed entry secret
    /// the index does not reference, then clears the list.
    pub fn process_gc(&mut self) {
        let name = names::gc(&self.partition);
        let Some(bytes) = self.host.get_secret(&name) else {
            return;
        };
        let prefix = names::entry_prefix(&self.partition);
        let referenced: Vec<Vec<u8>> = self
            .index
            .entries
            .iter()
            .map(|e| self.entry_name(e.kind, &e.key, e.parity))
            .collect();
        for n in decode_names(&bytes) {
            if n.starts_with(&prefix) && !referenced.contains(&n) {
                self.host.remove_secret(&n);
            }
        }
        self.host.remove_secret(&name);
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
        let existing = self
            .index
            .find(kind, key)
            .map(|i| self.index.entries[i].clone());
        let parity = existing.as_ref().map(|e| 1 - e.parity).unwrap_or(0);
        let new_name = self.entry_name(kind, key, parity);
        if !self.host.set_secret(&new_name, bytes) {
            // Nothing references it; remove whatever may have landed.
            self.host.remove_secret(&new_name);
            return Err(StorageFailure);
        }
        if let Some(old) = &existing {
            let old_name = self.entry_name(kind, key, old.parity);
            if self.add_gc(&[old_name]).is_err() {
                self.host.remove_secret(&new_name);
                return Err(StorageFailure);
            }
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
                    self.host.remove_secret(&new_name);
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
        let Some(i) = self.index.find(kind, key) else {
            return Read::Absent;
        };
        let ie = self.index.entries[i].clone();
        let got = self.host.get_secret(&self.entry_name(kind, key, ie.parity));
        if let Some(b) = &got {
            if entry_digest(b) == ie.digest {
                if let Ok(e) = Entry::decode(b) {
                    return if e.is_flagged_corrupt() {
                        Read::Corrupt(Some(e))
                    } else {
                        Read::Ok(e)
                    };
                }
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

fn encode_names(names: &[Vec<u8>]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u16(names.len() as u16);
    for n in names {
        w.u16(n.len() as u16).bytes(n);
    }
    w.into_vec()
}

fn decode_names(bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut r = Reader::new(bytes);
    let Ok(count) = r.u16("count") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for _ in 0..count {
        let Ok(len) = r.u16("len") else { break };
        let Ok(n) = r.take(len as usize, "name") else {
            break;
        };
        out.push(n.to_vec());
    }
    out
}

/// `vault:parts`: the partition ids this build holds state for.
pub fn ensure_part_listed<H: Host>(
    host: &mut H,
    partition: &[u8; 32],
) -> Result<(), StorageFailure> {
    let existing = host.get_secret(names::PARTS).unwrap_or_default();
    if existing.len() % 32 == 0 && existing.chunks(32).any(|c| c == partition) {
        return Ok(());
    }
    let mut list = if existing.len() % 32 == 0 {
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
