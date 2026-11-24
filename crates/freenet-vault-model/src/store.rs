//! The fake host's secret store (15.2), exactly the host of protocol 4.0
//! (revision 8): per-secret atomic writes; a failed write or removal reports
//! failure and either landed or did not; "durable but error returned" for
//! first-time secrets; a quota; a read fault poisons the call (later writes,
//! removals and creation refused, the call's outputs discarded and the
//! request retried); undecryptable bytes read as absent without poisoning;
//! crash points between any two writes. It never returns "absent" for a
//! present, readable secret in a call that completes.

use std::cell::Cell;
use std::collections::BTreeMap;

use crate::types::*;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Store {
    pub secrets: BTreeMap<SName, SVal>,
}

impl Store {
    pub fn idx(&self) -> Option<&Index> {
        match self.secrets.get(&SName::Idx) {
            Some(SVal::Idx(i)) => Some(i),
            _ => None,
        }
    }
    /// 4.5 read-only triggers that persist: the index absent (or
    /// undecryptable, which reads as absent) while vault:parts lists the
    /// partition; the index malformed; vault:parts malformed.
    pub fn index_lost(&self) -> bool {
        let parts = self.secrets.get(&SName::Parts);
        let idx = self.secrets.get(&SName::Idx);
        let listed = matches!(parts, Some(SVal::Parts));
        let parts_malformed = matches!(parts, Some(SVal::Garbled));
        let idx_absent = matches!(idx, None | Some(SVal::Undecryptable));
        let idx_malformed =
            matches!(idx, Some(v) if !matches!(v, SVal::Idx(_) | SVal::Undecryptable));
        parts_malformed || idx_malformed || (idx_absent && listed)
    }
    /// vault:succ is present and malformed (3: never read as "no record").
    pub fn succ_malformed(&self) -> bool {
        matches!(self.secrets.get(&SName::Succ), Some(v) if !matches!(v, SVal::Succ(_) | SVal::Undecryptable))
    }
    /// The committed index as the protocol reads it: absent means NONE.
    pub fn idx_or_none(&self) -> Index {
        self.idx().cloned().unwrap_or_else(Index::none)
    }
    pub fn succ(&self) -> Succ {
        match self.secrets.get(&SName::Succ) {
            Some(SVal::Succ(s)) => s.clone(),
            _ => Succ::default(),
        }
    }
    /// True when this store holds partition state (I5: "state for it"). A
    /// lost index (4.5) holds state: the build may hold keys.
    pub fn has_state(&self) -> bool {
        if self.index_lost() {
            // ground truth for the checker: the build listed the partition
            // or holds entry copies (a damaged index of a build that only
            // held an arming record holds no keys)
            return matches!(
                self.secrets.get(&SName::Parts),
                Some(SVal::Parts) | Some(SVal::Garbled) | Some(SVal::Undecryptable)
            ) || self.secrets.keys().any(|n| matches!(n, SName::E(..)));
        }
        match self.idx() {
            None => false,
            Some(i) => !(i.state.is_none() && i.entries.is_empty()),
        }
    }
}

/// One injected write fault, applied to the n-th durable write from now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteFault {
    /// The node crashes before this write is applied.
    CrashBefore,
    /// The node crashes after this write is applied, before anything else.
    CrashAfter,
    /// Storage failure: nothing written, error returned.
    Fail,
    /// For a first-time secret: durable and readable, error returned (1).
    /// For an overwrite this is a plain failure.
    DurableButError,
    /// Any write or removal: it landed, and an error is returned (4.0).
    LandedButError,
}

#[derive(Clone, Debug, Default)]
pub struct FaultPlan {
    /// (writes to skip before the fault, fault)
    pub armed: Option<(u32, WriteFault)>,
    /// Maximum number of secrets per build store; None is unlimited.
    pub quota: Option<usize>,
    pub fired: Vec<WriteFault>,
    pub quota_hits: u64,
    /// The n-th secret read from now fails with an I/O error (4.0).
    pub read_armed: Option<u32>,
    pub read_fired: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Crash;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WErr {
    Crash,
    Fail,
}

impl From<Crash> for WErr {
    fn from(_: Crash) -> WErr {
        WErr::Crash
    }
}

/// A recorded durable event, used by the invariant checker (I6).
#[derive(Clone, Debug)]
pub enum Event {
    Delete {
        build: Ver,
        name: SName,
        /// Whether the committed index named it at deletion time.
        named_by_committed: bool,
    },
}

pub struct Host<'a> {
    pub build: Ver,
    pub store: &'a mut Store,
    pub faults: &'a mut FaultPlan,
    pub events: &'a mut Vec<Event>,
    pub writes: u32,
    pub crashed: bool,
    /// Reads left before the armed read fault fires.
    pub read_left: Cell<Option<u32>>,
    /// A read failed in this call: later writes, removals and creation are
    /// refused and the call's outputs are discarded (4.0).
    pub poisoned: Cell<bool>,
    /// Writes and removals refused because the call was poisoned.
    pub refused_poisoned: u32,
}

impl<'a> Host<'a> {
    pub fn new(
        build: Ver,
        store: &'a mut Store,
        faults: &'a mut FaultPlan,
        events: &'a mut Vec<Event>,
    ) -> Host<'a> {
        let read_left = Cell::new(faults.read_armed);
        Host {
            build,
            store,
            faults,
            events,
            writes: 0,
            crashed: false,
            read_left,
            poisoned: Cell::new(false),
            refused_poisoned: 0,
        }
    }

    /// Write the read-fault countdown back to the plan at the end of a call.
    pub fn finish(&mut self) {
        self.faults.read_armed = self.read_left.get();
    }

    /// A secret read as the host returns it: undecryptable bytes read as
    /// absent; an armed read fault fires (the value returned is then
    /// meaningless: nothing the call does afterwards leaves it).
    pub fn read(&self, n: &SName) -> Option<SVal> {
        if let Some(k) = self.read_left.get() {
            if k == 0 {
                self.read_left.set(None);
                self.poisoned.set(true);
                return None;
            }
            self.read_left.set(Some(k - 1));
        }
        match self.store.secrets.get(n) {
            Some(SVal::Undecryptable) | None => None,
            Some(v) => Some(v.clone()),
        }
    }

    fn fault_now(&mut self) -> Option<WriteFault> {
        match self.faults.armed {
            Some((0, f)) => {
                self.faults.armed = None;
                self.faults.fired.push(f);
                Some(f)
            }
            Some((n, f)) => {
                self.faults.armed = Some((n - 1, f));
                None
            }
            None => None,
        }
    }

    pub fn set(&mut self, n: SName, v: SVal) -> Result<(), WErr> {
        if self.crashed {
            return Err(WErr::Crash);
        }
        if self.poisoned.get() {
            self.refused_poisoned += 1;
            return Err(WErr::Fail);
        }
        self.writes += 1;
        let first_time = !self.store.secrets.contains_key(&n);
        if first_time {
            if let Some(q) = self.faults.quota {
                if self.store.secrets.len() >= q {
                    self.faults.quota_hits += 1;
                    return Err(WErr::Fail);
                }
            }
        }
        match self.fault_now() {
            Some(WriteFault::CrashBefore) => {
                self.crashed = true;
                Err(WErr::Crash)
            }
            Some(WriteFault::CrashAfter) => {
                self.store.secrets.insert(n, v);
                self.crashed = true;
                Err(WErr::Crash)
            }
            Some(WriteFault::Fail) => Err(WErr::Fail),
            Some(WriteFault::DurableButError) => {
                if first_time {
                    self.store.secrets.insert(n, v);
                }
                Err(WErr::Fail)
            }
            Some(WriteFault::LandedButError) => {
                self.store.secrets.insert(n, v);
                Err(WErr::Fail)
            }
            None => {
                self.store.secrets.insert(n, v);
                Ok(())
            }
        }
    }

    pub fn del(&mut self, n: SName) -> Result<(), WErr> {
        if self.crashed {
            return Err(WErr::Crash);
        }
        if self.poisoned.get() {
            self.refused_poisoned += 1;
            return Err(WErr::Fail);
        }
        if !self.store.secrets.contains_key(&n) {
            return Ok(());
        }
        self.writes += 1;
        let mut landed_error = false;
        match self.fault_now() {
            Some(WriteFault::CrashBefore) => {
                self.crashed = true;
                return Err(WErr::Crash);
            }
            Some(WriteFault::Fail) | Some(WriteFault::DurableButError) => return Err(WErr::Fail),
            Some(WriteFault::LandedButError) => landed_error = true,
            Some(WriteFault::CrashAfter) => {
                self.crashed = true;
            }
            None => {}
        }
        let named = match (&n, self.store.idx()) {
            (SName::E(id, p), Some(i)) => i.entries.get(id).map(|e| e.parity) == Some(*p),
            _ => false,
        };
        self.events.push(Event::Delete {
            build: self.build,
            name: n,
            named_by_committed: named,
        });
        self.store.secrets.remove(&n);
        if self.crashed {
            Err(WErr::Crash)
        } else if landed_error {
            Err(WErr::Fail)
        } else {
            Ok(())
        }
    }
}
