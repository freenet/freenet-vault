//! The fake host's secret store (15.2): per-secret atomic writes, storage
//! failure on any write, "durable but error returned" for first-time secrets,
//! a quota, and crash points between any two writes.

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
    /// True when this store holds partition state (I5: "state for it").
    pub fn has_state(&self) -> bool {
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
}

#[derive(Clone, Debug, Default)]
pub struct FaultPlan {
    /// (writes to skip before the fault, fault)
    pub armed: Option<(u32, WriteFault)>,
    /// Maximum number of secrets per build store; None is unlimited.
    pub quota: Option<usize>,
    pub fired: Vec<WriteFault>,
    pub quota_hits: u64,
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
}

impl<'a> Host<'a> {
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

    pub fn get(&self, n: &SName) -> Option<&SVal> {
        self.store.secrets.get(n)
    }

    pub fn set(&mut self, n: SName, v: SVal) -> Result<(), WErr> {
        if self.crashed {
            return Err(WErr::Crash);
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
        if !self.store.secrets.contains_key(&n) {
            return Ok(());
        }
        self.writes += 1;
        match self.fault_now() {
            Some(WriteFault::CrashBefore) => {
                self.crashed = true;
                return Err(WErr::Crash);
            }
            Some(WriteFault::Fail) | Some(WriteFault::DurableButError) => return Err(WErr::Fail),
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
        } else {
            Ok(())
        }
    }
}
