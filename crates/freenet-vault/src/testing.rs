//! An in-memory [`Host`] with fault injection, for tests.
//!
//! The fault model is the real host's (freenet-core #5857): a secret read that
//! fails with an I/O error POISONS THE CALL (`read_fault`): every later
//! `set_secret` and `remove_secret` is refused, and the caller must discard the
//! call's result. So in a call that completes, a `None` read means the secret
//! is really absent. A write or removal that reports failure may or may not
//! have landed (`WriteFault`, `remove_fault`); that is the uncertainty the
//! vault defends against, along with crashes between host calls (`crash_after`)
//! and bytes that are present but corrupt. A blob that cannot be decrypted
//! (corrupt bytes on disk, freenet-core #6323, still open) reads as ABSENT
//! WITHOUT poisoning the call (`undecryptable`): so "absent" can also mean
//! corrupt, and the vault never destroys anything on the absence of a secret
//! that a sibling record says should exist.

use crate::host::Host;
use std::collections::{BTreeMap, BTreeSet};

/// What a `set_secret` call does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteFault {
    /// Writes and reports success.
    None,
    /// Writes nothing and reports failure.
    Fail,
    /// Writes the value but reports failure: a first-time secret whose index
    /// update failed after the value became durable (protocol 1).
    DurableButFail,
    /// Stores garbage under the name and reports failure: a write that was
    /// torn, so a read-back matches neither the old value nor the new one.
    GarbageButFail,
}

type FaultFn = Box<dyn FnMut(&[u8]) -> WriteFault>;

pub struct MemHost {
    pub secrets: BTreeMap<Vec<u8>, Vec<u8>>,
    pub context: Vec<u8>,
    rng_counter: u64,
    /// When set, random bytes are all zero (the host RNG can return zeroes).
    pub zero_rng: bool,
    fault: Option<FaultFn>,
    pub writes: usize,
    /// Secret names whose read fails with an I/O error: the read answers
    /// `None` and poisons the call (see the module docs).
    pub read_fault: BTreeSet<Vec<u8>>,
    poisoned: std::cell::Cell<bool>,
    /// Secret names whose stored bytes cannot be decrypted: the secret is on
    /// disk (and a write replaces it) but a read answers `None`, and the call
    /// is NOT poisoned (core #6323).
    pub undecryptable: BTreeSet<Vec<u8>>,
    /// Secret names `remove_secret` reports failure for without removing.
    pub undeletable: BTreeSet<Vec<u8>>,
    /// Secret names `remove_secret` removes but reports failure for.
    pub remove_lands_but_fails: BTreeSet<Vec<u8>>,
    /// Counts every `set_secret` and `remove_secret`, applied or not.
    pub mutations: usize,
    crash_after: Option<usize>,
}

impl Default for MemHost {
    fn default() -> Self {
        Self::new()
    }
}

impl MemHost {
    pub fn new() -> Self {
        Self {
            secrets: BTreeMap::new(),
            context: Vec::new(),
            rng_counter: 0,
            zero_rng: false,
            fault: None,
            writes: 0,
            read_fault: BTreeSet::new(),
            poisoned: std::cell::Cell::new(false),
            undecryptable: BTreeSet::new(),
            undeletable: BTreeSet::new(),
            remove_lands_but_fails: BTreeSet::new(),
            mutations: 0,
            crash_after: None,
        }
    }

    /// Simulates the process dying after `n` more mutations (`set_secret` or
    /// `remove_secret` calls): the first `n` apply, every later one does
    /// nothing and reports failure, as if the delegate had stopped there.
    pub fn crash_after(&mut self, n: usize) {
        self.crash_after = Some(self.mutations + n);
    }

    /// The disk a restarted process would find: the secrets only.
    pub fn restart(&self) -> Self {
        let mut h = Self::new();
        h.secrets = self.secrets.clone();
        // Corrupt bytes on disk stay corrupt across a restart.
        h.undecryptable = self.undecryptable.clone();
        h
    }

    /// Stores `value` under an entry name AND under its parity twin (`...:0` and
    /// `...:1`): damage that hits both copies of an entry, so that no intact
    /// mirror is left. (The heal of a damaged named copy from a digest-matching
    /// mirror is on hold and not implemented: branch `hold/item7-mirror-heal`.)
    pub fn set_pair(&mut self, name: &[u8], value: Vec<u8>) {
        let mut twin = name.to_vec();
        let last = twin.len() - 1;
        twin[last] = if twin[last] == b'0' { b'1' } else { b'0' };
        self.secrets.insert(twin, value.clone());
        self.secrets.insert(name.to_vec(), value);
    }

    /// A read failed in this call: writes are refused and the result must be
    /// discarded.
    pub fn poisoned(&self) -> bool {
        self.poisoned.get()
    }

    fn crashed(&self) -> bool {
        self.crash_after
            .is_some_and(|limit| self.mutations >= limit)
    }

    /// Decides the outcome of every following write by secret name.
    pub fn set_fault(&mut self, f: impl FnMut(&[u8]) -> WriteFault + 'static) {
        self.fault = Some(Box::new(f));
    }

    pub fn clear_fault(&mut self) {
        self.fault = None;
    }

    /// Secret names starting with `prefix`.
    pub fn names_with_prefix(&self, prefix: &[u8]) -> Vec<Vec<u8>> {
        self.secrets
            .keys()
            .filter(|k| k.starts_with(prefix))
            .cloned()
            .collect()
    }
}

impl Host for MemHost {
    fn get_secret(&self, key: &[u8]) -> Option<Vec<u8>> {
        if self.read_fault.contains(key) {
            self.poisoned.set(true);
            return None;
        }
        if self.undecryptable.contains(key) {
            return None;
        }
        self.secrets.get(key).cloned()
    }

    fn set_secret(&mut self, key: &[u8], value: &[u8]) -> bool {
        // The agreed core rule (#6323): a write over a blob that cannot be
        // decrypted is refused; removing it is always allowed.
        if self.crashed() || self.poisoned.get() || self.undecryptable.contains(key) {
            self.mutations += 1;
            return false;
        }
        self.mutations += 1;
        self.writes += 1;
        let outcome = match &mut self.fault {
            Some(f) => f(key),
            None => WriteFault::None,
        };
        match outcome {
            WriteFault::None => {
                self.secrets.insert(key.to_vec(), value.to_vec());
                true
            }
            WriteFault::Fail => false,
            WriteFault::DurableButFail => {
                self.secrets.insert(key.to_vec(), value.to_vec());
                false
            }
            WriteFault::GarbageButFail => {
                self.secrets.insert(key.to_vec(), b"torn write".to_vec());
                false
            }
        }
    }

    fn remove_secret(&mut self, key: &[u8]) -> bool {
        if self.crashed() || self.poisoned.get() {
            self.mutations += 1;
            return false;
        }
        self.mutations += 1;
        if self.undeletable.contains(key) {
            return false;
        }
        // freenet-stdlib: true if the secret was removed, false if it was not
        // there. Removing an undecryptable blob is allowed and clears it.
        self.undecryptable.remove(key);
        let was = self.secrets.remove(key).is_some();
        was && !self.remove_lands_but_fails.contains(key)
    }

    fn read_context(&self) -> Vec<u8> {
        self.context.clone()
    }

    fn write_context(&mut self, data: &[u8]) -> bool {
        self.context = data.to_vec();
        true
    }

    fn random_bytes(&mut self, out: &mut [u8]) {
        if self.zero_rng {
            out.fill(0);
            return;
        }
        self.rng_counter += 1;
        let mut h = blake3::Hasher::new();
        h.update(b"memhost rng");
        h.update(&self.rng_counter.to_be_bytes());
        h.finalize_xof().fill(out);
    }
}
