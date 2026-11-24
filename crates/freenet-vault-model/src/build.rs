//! One vault build as a pure state machine over its durable store
//! (sections 3 to 9 of the handover protocol, revision 9).
//!
//! Every call starts from the committed store; the only volatile state is
//! the in-flight set of 7.1, which a crash clears. Every durable write and
//! every read goes through [`Host`], so a crash can cut between any two
//! writes and a read fault can poison any call (4.0).

use std::collections::{BTreeMap, BTreeSet};

use crate::cov::Cov;
use crate::store::{Crash, Event, FaultPlan, Host, Store, WErr};
use crate::types::*;

/// Model-scaled constants. The real values (4096 entries, 32 entries per
/// chunk, windows 32 and 8, 1024 missing) are scaled down so that staging
/// full, multi-chunk copies, window limits and hop caps are reached by short
/// schedules. None of the protocol rules depends on the absolute sizes.
#[derive(Clone, Debug)]
pub struct Params {
    pub max_entries: usize,
    pub chunk_max: usize,
    pub window_poke: usize,
    pub window_wakeup: usize,
    pub missing_max: usize,
    /// Builds at or above this version no longer accept marks whose caller
    /// (content) is odd: such marks are "dropped by policy" (0x03).
    pub reject_odd_marks_from: Ver,
    /// Deliberately broken variant (15.5 mutation check), or None.
    pub mutant: Option<Mutant>,
    /// Maximum names the host's list_secrets returns per scope (15.2;
    /// real 4096 against up to 2 x 4096 entry copies, scaled with
    /// max_entries).
    pub list_cap: usize,
    /// Reading of 4.2 for a replace (labelled, revision 9): the old parity
    /// copy is written to vault:gc BEFORE the index write that stops naming
    /// it (true, the "Removing entries" rule: names to vault:gc, then the
    /// index), or after it (false).
    pub gc_old_before_index: bool,
    /// Reading of 4.2 (labelled, revision 9): "any call that reads a valid
    /// index for an unlisted partition adds the listing" applies to NONE
    /// indexes too (an armed NONE build has an index). true is the literal
    /// reading.
    pub list_none_indexes: bool,
}

impl Default for Params {
    fn default() -> Params {
        Params {
            max_entries: 6,
            chunk_max: 2,
            window_poke: 3,
            window_wakeup: 2,
            missing_max: 3,
            reject_odd_marks_from: 40,
            mutant: None,
            list_cap: 8,
            gc_old_before_index: true,
            list_none_indexes: true,
        }
    }
}

/// The mutants of the 15.5 mutation check that revision 9 adds, plus the
/// designer's checklist (designer3-REPORT, "What the model must re-check").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mutant {
    /// Leave REPAIRING with one predecessor unconfirmed.
    RepairOneUnconfirmed,
    /// Leave REPAIRING while the creation bar applies.
    RepairIgnoresBar,
    /// Probe predecessors in any order (all at once), not lowest first.
    RepairAnyOrder,
    /// A RETIRED predecessor answers 0x0C whatever its retired_to.
    Accept0x0CAbove,
    /// A creation counts 0x0C as confirmed.
    CreationAccepts0x0C,
    /// Send Retired (or answer "retired") before unlisting; unlist at the
    /// next call.
    RetiredBeforeUnlist,
    /// Never unlist on retire.
    NeverUnlist,
    /// Re-list a RETIRED index (the catch-all lists it too).
    RelistRetired,
    /// List vault:parts before the first index write.
    PartsBeforeIndex,
    /// Direct read and Reindex ignore vault:gc.
    DirectReadIgnoresGc,
    /// Drop names from vault:gc before they read as absent (the new list is
    /// written first, then the removals).
    GcDropBeforeAbsent,
    /// Arm and create while the domain is stopped.
    CreateWhileStopped,
    /// A NONE predecessor answers 0x0B to a creation probe without storing
    /// the record.
    NoState0x0BWithoutStoring,
}

impl Mutant {
    pub const ALL: [Mutant; 13] = [
        Mutant::RepairOneUnconfirmed,
        Mutant::RepairIgnoresBar,
        Mutant::RepairAnyOrder,
        Mutant::Accept0x0CAbove,
        Mutant::CreationAccepts0x0C,
        Mutant::RetiredBeforeUnlist,
        Mutant::NeverUnlist,
        Mutant::RelistRetired,
        Mutant::PartsBeforeIndex,
        Mutant::DirectReadIgnoresGc,
        Mutant::GcDropBeforeAbsent,
        Mutant::CreateWhileStopped,
        Mutant::NoState0x0BWithoutStoring,
    ];
    pub fn name(self) -> String {
        format!("{self:?}")
    }
    pub fn parse(s: &str) -> Option<Mutant> {
        Mutant::ALL.iter().copied().find(|m| m.name() == s)
    }
}

/// Compile-time constants of one build (2).
#[derive(Clone, Debug)]
pub struct BuildDef {
    pub v: Ver,
    /// Every signed non-withdrawal version below v, published or reserved.
    pub preds: Vec<Ver>,
    /// Whether this build's code writes entries of KIND_UNKNOWN (15.1).
    pub writes_unknown_kind: bool,
    /// For reporting: the build whose code this one runs (rollback build).
    pub code_of: Ver,
}

#[derive(Clone, Debug, Default)]
pub struct Volatile {
    pub in_flight: BTreeSet<Ident>,
    pub complete_in_flight: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Op {
    Generate {
        slot: u16,
        seed: u32,
    },
    Import {
        slot: u16,
        seed: u32,
        replace: bool,
    },
    Delete {
        slot: u16,
    },
    PublicKey {
        slot: u16,
    },
    Batch {
        slot: u16,
        expected: u32,
    },
    /// Writes a KIND_UNKNOWN entry with a non-empty extension (only builds
    /// whose code knows the kind; others answer Refused(10)).
    PutExt {
        key: u16,
        content: u32,
    },
    /// A chat-delegate request whose caller proof raises its mark (9).
    RaiseMark {
        caller: u16,
        rec: u32,
    },
    /// Export (0x86): the seed, allowed on a corrupt slot; in read-only mode
    /// by the direct-read rule (4.5).
    Export {
        slot: u16,
    },
    /// Reindex (0x88, revision 9, 4.6): domain pages only; every slot the
    /// page knows with the public key it expects.
    Reindex {
        slots: Vec<(u16, u32)>,
    },
    /// UI marker (not a vault operation): poke the REPAIRING build while it
    /// reports state 8, at most 8 times (4.6 "Verify").
    RepairPokes,
}

impl Op {
    pub fn is_change(&self) -> bool {
        !matches!(
            self,
            Op::PublicKey { .. } | Op::Batch { .. } | Op::Export { .. } | Op::RepairPokes
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OpRes {
    Key(u32),
    Ok,
    Moved(Rec),
    NotHere,
    Busy,
    Absent,
    Unusable,
    Refused(u8),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Status {
    pub state: PState,
    /// partition_state 7, "unknown: index lost" (4.5, 12.4).
    pub index_lost: bool,
    /// record_state 3, "stored record malformed" (3).
    pub record_malformed: bool,
    pub problems: u8,
    pub succ: Succ,
    /// 0 none, 2 accepted, 3 not newer, 4 equivocation (12.4 step_result).
    pub record_result: u8,
    pub sent: bool,
}

#[derive(Clone, Debug)]
pub enum Input {
    Poke { flags: u8, rec: Option<Rec> },
    Wakeup,
    Hop { from: Ver, frame: Frame },
    Op(Op),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reply {
    None,
    Status(Status),
    Op(OpRes),
    Frame(Frame),
}

/// Transitions the invariant checker needs to see.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Note {
    Unsealed {
        target: Ver,
        m: Digest,
        cause: Option<CStatus>,
    },
    Created,
    TookOver {
        from: Ver,
        m: Digest,
    },
    Retired {
        to: Ver,
        m: Digest,
    },
    AwaitingCleared,
    SealedCorruptSent,
    /// Pushed before the unseal write, so a crash right after it is seen.
    UnsealIntent {
        target: Ver,
        m: Digest,
    },
    /// Reindex is about to write its REPAIRING index (pushed before the
    /// write, so a crash right after it is seen). `unrecovered` lists the
    /// page's slots it could not recover and why; `listed` the idents the
    /// host's key listing returned; `listing_incomplete` when the listing
    /// was corrupt or cut by the cap.
    Reindex {
        unrecovered: Vec<(u16, Unrecovered)>,
        listed: BTreeSet<Ident>,
        listing_incomplete: bool,
    },
    /// Reindex write k (1: remove the undecryptable old index, 2: the
    /// REPAIRING index, 3: vault:parts) is about to happen.
    ReindexWrite(u8),
    /// The REPAIRING build wrote WRITER (4.6 step 5).
    RepairDone,
}

/// Why Reindex left out one of the page's slots (4.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unrecovered {
    /// Two different copies that neither the expected key nor vault:gc can
    /// tell apart (stated in 4.6).
    Ambiguous,
    /// No usable copy (stated in 4.6, reported).
    NoCopy,
    /// The direct-read rule picked a copy whose key differs from the
    /// expected one (NOT stated as a residual).
    Mismatch,
    /// Both parity names listed in vault:gc: a deleted slot.
    Deleted,
}

pub struct Output {
    pub reply: Reply,
    pub hops: Vec<(Ver, Frame)>,
    pub writes: u32,
    /// A read failed in this call (4.0): the host fails the call, its
    /// outputs are not delivered and the request is retried.
    pub poisoned: bool,
}

pub const POKE_PAUSE: u8 = 1 << 0;
pub const POKE_ARM: u8 = 1 << 1;
/// Bit 4 was "discard an abandoned partial copy" until revision 8; it is
/// reserved (F6) and a build ignores it.
pub const POKE_RESERVED_4: u8 = 1 << 4;

/// Run one vault call against `store`. Err(Crash) means the node crashed
/// inside the call: the writes made so far stand, outputs are lost.
/// Transitions are appended to `notes` as they are committed, so they are
/// visible even when the call crashes afterwards.
#[allow(clippy::too_many_arguments)]
pub fn call(
    def: &BuildDef,
    p: &Params,
    store: &mut Store,
    vol: &mut Volatile,
    faults: &mut FaultPlan,
    events: &mut Vec<Event>,
    cov: &mut Cov,
    notes: &mut Vec<Note>,
    input: Input,
) -> Result<Output, Crash> {
    let mut host = Host::new(def.v, store, faults, events);
    host.list_cap = p.list_cap;
    let mut cx = Cx {
        def,
        p,
        host,
        vol,
        cov,
        out: Vec::new(),
        notes,
        ro: false,
    };
    let res = cx.dispatch(input);
    cx.host.finish();
    for n in std::mem::take(&mut cx.host.refused_undecryptable) {
        cx.cov.hit(&format!(
            "6323/set-refused-over-undecryptable/{}",
            sname_kind(&n)
        ));
    }
    let mut reply = res?;
    let poisoned = cx.host.poisoned.get();
    if poisoned {
        cx.hit("4.0/call-poisoned");
        if cx.host.refused_poisoned > 0 {
            cx.hit("4.0/write-refused-after-failed-read");
        }
    }
    if let Reply::Frame(f) = &reply {
        if is_ignored(f) {
            reply = Reply::None;
        } else if let Frame::CompleteAck { status, .. } = f {
            cx.cov.hit(&format!("sent/CompleteAck/{status:?}"));
        } else if let Frame::Ack { status, .. } = f {
            cx.cov.hit(&format!("sent/Ack/{status:?}"));
        }
    }
    Ok(Output {
        reply,
        hops: cx.out,
        writes: cx.host.writes,
        poisoned,
    })
}

struct Cx<'a> {
    def: &'a BuildDef,
    p: &'a Params,
    host: Host<'a>,
    vol: &'a mut Volatile,
    cov: &'a mut Cov,
    out: Vec<(Ver, Frame)>,
    notes: &'a mut Vec<Note>,
    /// An earlier write in this call reported failure: read-only for the
    /// rest of the call (4.2 "no further write", 4.5 condition 4).
    ro: bool,
}

type R<T> = Result<T, Crash>;

impl<'a> Cx<'a> {
    fn own(&self) -> Ver {
        self.def.v
    }
    /// The committed index as read in this call. Only called when the
    /// index is not lost (4.5 is checked at the start of the call).
    fn idx(&self) -> Index {
        match self.host.read(&SName::Idx) {
            Some(SVal::Idx(i)) => i,
            _ => Index::none(),
        }
    }
    /// vault:succ; a malformed one is checked separately (3).
    fn succ(&self) -> Succ {
        match self.host.read(&SName::Succ) {
            Some(SVal::Succ(s)) => s,
            _ => Succ::default(),
        }
    }
    fn succ_malformed(&self) -> bool {
        matches!(self.host.read(&SName::Succ), Some(v) if !matches!(v, SVal::Succ(_)))
    }
    /// 4.5: the index is absent while vault:parts lists the partition, the
    /// index is malformed, or vault:parts is malformed and the index absent
    /// (revision 9: a malformed list with a verified index is writable).
    fn index_lost(&self) -> bool {
        let parts = self.host.read(&SName::Parts);
        let idx = self.host.read(&SName::Idx);
        match (parts, idx) {
            (_, Some(SVal::Idx(_))) => false,
            (Some(SVal::Parts) | Some(SVal::Garbled), None) => true,
            (None, None) => false,
            _ => true,
        }
    }
    fn parts_listed(&self) -> bool {
        matches!(self.host.read(&SName::Parts), Some(SVal::Parts))
    }
    /// Mutant PartsBeforeIndex: vault:parts before the first index write
    /// that gives this build state (the revision 8 default ordering).
    fn ensure_parts(&mut self) -> R<bool> {
        if self.p.mutant != Some(Mutant::PartsBeforeIndex) || self.parts_listed() {
            return Ok(true);
        }
        self.hit("mutant/parts-written-before-index");
        self.put(SName::Parts, SVal::Parts)
    }
    /// 4.2 (revision 9, F8): after a first index write, read the index
    /// back and only then list the partition (and read that back).
    fn list_after_index(&mut self, new: &Index) -> R<bool> {
        if self.parts_listed() || matches!(new.state, PState::Retired { .. }) {
            return Ok(true);
        }
        if self.idx_raw() != Some(new.clone()) {
            self.hit("4.2/first-index-read-back-failed-not-listed");
            return Ok(false);
        }
        self.hit("4.2/listed-after-first-index");
        if !self.put(SName::Parts, SVal::Parts)? {
            self.hit("4.2/listing-write-failed");
            return Ok(false);
        }
        Ok(self.parts_listed())
    }
    /// The index as stored, if it decodes.
    fn idx_raw(&self) -> Option<Index> {
        match self.host.read(&SName::Idx) {
            Some(SVal::Idx(i)) => Some(i),
            _ => None,
        }
    }
    /// 4.2 (revision 9, F7): remove the partition from vault:parts and read
    /// that back. Ok(true) once the list no longer names it.
    fn unlist(&mut self) -> R<bool> {
        if !self.parts_listed() {
            return Ok(true);
        }
        if !self.del(SName::Parts)? {
            self.hit("4.2/unlist-failed");
            return Ok(false);
        }
        let gone = !self.parts_listed();
        if gone {
            self.hit("4.2/unlisted-on-retire");
        }
        Ok(gone)
    }
    /// Creation bar (3): a non-withdrawal record above OWN_VERSION.
    fn creation_bar(&self) -> bool {
        self.succ().current.is_some_and(|c| c.v > self.own())
    }
    fn hit(&mut self, k: &str) {
        self.cov.hit(k);
    }

    /// A durable write. Ok(false) is a storage failure. After any failed
    /// write the call makes no further write (4.2, 4.5).
    fn put(&mut self, n: SName, v: SVal) -> R<bool> {
        if self.ro {
            self.hit("4.5/write-refused-after-failed-write");
            return Ok(false);
        }
        match self.host.set(n, v) {
            Ok(()) => Ok(true),
            Err(WErr::Fail) => {
                self.hit("fault/storage-failure-seen");
                self.ro = true;
                Ok(false)
            }
            Err(WErr::Crash) => Err(Crash),
        }
    }
    fn del(&mut self, n: SName) -> R<bool> {
        if self.ro {
            self.hit("4.5/write-refused-after-failed-write");
            return Ok(false);
        }
        match self.host.del(n) {
            Ok(()) => Ok(true),
            Err(WErr::Fail) => {
                self.ro = true;
                Ok(false)
            }
            Err(WErr::Crash) => Err(Crash),
        }
    }

    /// Commit an index (4.2). On failure, read the index back (a disk read:
    /// the host's cache is cleared by the write, 4.0) and report whether
    /// the disk holds what was intended.
    fn commit(&mut self, new: &Index) -> R<bool> {
        if self.put(SName::Idx, SVal::Idx(new.clone()))? {
            let state = !(new.state.is_none() && new.entries.is_empty());
            if state && self.p.mutant != Some(Mutant::PartsBeforeIndex) {
                self.list_after_index(new)?;
            }
            return Ok(true);
        }
        self.hit("4.2/commit-failed-read-back");
        let landed = self.idx() == *new;
        if landed {
            self.hit("4.2/commit-failed-but-landed");
        }
        Ok(landed)
    }

    fn gc_set(&self) -> BTreeSet<SName> {
        match self.host.read(&SName::Gc) {
            Some(SVal::Gc(s)) => s.clone(),
            _ => BTreeSet::new(),
        }
    }
    fn gc_add(&mut self, names: &[SName]) -> R<bool> {
        if names.is_empty() {
            return Ok(true);
        }
        let mut s = self.gc_set();
        s.extend(names.iter().copied());
        self.put(SName::Gc, SVal::Gc(s))
    }

    /// 4.2: a name is deleted only if the committed index, read at deletion
    /// time, does not name it. Revision 9 (F11): a name leaves vault:gc
    /// only when its secret reads as absent after the removal, or when the
    /// committed index names it.
    fn process_gc(&mut self) -> R<()> {
        let gc = self.gc_set();
        if gc.is_empty() {
            return Ok(());
        }
        self.hit("4.2/gc-processed");
        if self.p.mutant == Some(Mutant::GcDropBeforeAbsent) {
            // mutant: the list is rewritten first, then the removals
            let idx = self.idx();
            let mut remaining = BTreeSet::new();
            for n in &gc {
                if let SName::E(id, par) = n {
                    if idx.entries.get(id).map(|e| e.parity) == Some(*par) {
                        continue;
                    }
                }
                remaining.insert(*n);
            }
            if !self.put(SName::Gc, SVal::Gc(BTreeSet::new()))? {
                return Ok(());
            }
            for n in remaining {
                self.del(n)?;
            }
            return Ok(());
        }
        let mut remaining = BTreeSet::new();
        for n in gc {
            let idx = self.idx();
            let named = match n {
                SName::E(id, par) => idx.entries.get(&id).map(|e| e.parity) == Some(par),
                _ => false,
            };
            if named {
                self.hit("4.2/gc-kept-named");
                continue;
            }
            if !self.del(n)? || self.host.read(&n).is_some() {
                self.hit("4.2/gc-name-kept-not-absent");
                remaining.insert(n);
            }
        }
        self.put(SName::Gc, SVal::Gc(remaining))?;
        Ok(())
    }

    /// 4.2 (revision 9, F11): before an entry is written to a name that
    /// vault:gc lists, that name is processed first (removed, read back as
    /// absent, dropped from the list). Ok(false): storage failure.
    fn clear_gc_name(&mut self, n: SName) -> R<bool> {
        let mut gc = self.gc_set();
        if !gc.contains(&n) {
            return Ok(true);
        }
        self.hit("4.2/gc-listed-name-processed-before-write");
        if !self.del(n)? || self.host.read(&n).is_some() {
            return Ok(false);
        }
        gc.remove(&n);
        self.put(SName::Gc, SVal::Gc(gc))
    }

    /// The old parity copy of a replaced entry goes to vault:gc (4.2
    /// "unused parity copies"); before or after the index write per the
    /// labelled reading `gc_old_before_index`.
    fn gc_old_copy(&mut self, old: Option<SName>, before_index: bool) -> R<bool> {
        match old {
            Some(n) if before_index == self.p.gc_old_before_index => self.gc_add(&[n]),
            _ => Ok(true),
        }
    }

    fn rx(&self) -> BTreeSet<Digest> {
        match self.host.read(&SName::Rx) {
            Some(SVal::Rx(s)) => s.clone(),
            _ => BTreeSet::new(),
        }
    }
    fn prog(&self, t: Ver) -> BTreeMap<Ident, Digest> {
        match self.host.read(&SName::X(t)) {
            Some(SVal::X(s)) => s.clone(),
            _ => BTreeMap::new(),
        }
    }

    fn send(&mut self, to: Ver, f: Frame) {
        self.out.push((to, f));
    }

    fn rejects_mark(&self, e: &Entry) -> bool {
        e.kind == KIND_MARK && self.own() >= self.p.reject_odd_marks_from && e.content % 2 == 1
    }

    // ------------------------------------------------------------ dispatch

    fn dispatch(&mut self, input: Input) -> R<Reply> {
        if self.index_lost() {
            return self.lost(input);
        }
        if !self.fix_listing()? {
            // a RETIRED build still listed answers nothing in a call where
            // unlisting fails (4.2)
            self.hit("4.2/retired-unlist-failed-answers-nothing");
            return Ok(Reply::None);
        }
        let record_bad = self.succ_malformed();
        self.process_gc()?;
        if record_bad {
            return self.record_malformed(input);
        }
        if matches!(self.idx().state, PState::Repairing { .. }) {
            return self.repairing(input);
        }
        match input {
            Input::Poke { flags, rec } => {
                self.hit("6/poke");
                self.poke(flags, rec).map(Reply::Status)
            }
            Input::Wakeup => {
                self.hit("6/wakeup");
                if self.has_work() {
                    let w = self.p.window_wakeup;
                    self.step(w)?;
                }
                Ok(Reply::None)
            }
            Input::Op(op) => self.op(op).map(Reply::Op),
            Input::Hop { from, frame } => Ok(self
                .hop(from, frame)?
                .map(Reply::Frame)
                .unwrap_or(Reply::None)),
        }
    }

    /// 4.2 (revision 9): a RETIRED build still listed (a crash between the
    /// two writes) unlists before answering anything; any call that reads
    /// a valid index for an unlisted partition adds the listing before
    /// doing anything else, except for a RETIRED index. Ok(false): the
    /// RETIRED build could not unlist, so the call answers nothing.
    fn fix_listing(&mut self) -> R<bool> {
        let Some(i) = self.idx_raw() else {
            return Ok(true);
        };
        let parts = self.host.read(&SName::Parts);
        let retired = matches!(i.state, PState::Retired { .. });
        let m = self.p.mutant;
        match parts {
            Some(SVal::Parts)
                if retired
                    && m != Some(Mutant::NeverUnlist)
                    && m != Some(Mutant::RelistRetired) =>
            {
                self.hit("4.2/retired-still-listed-unlists-first");
                self.unlist()
            }
            None if !retired || m == Some(Mutant::RelistRetired) => {
                let has_state = !(i.state.is_none() && i.entries.is_empty());
                if !has_state && !self.p.list_none_indexes {
                    return Ok(true);
                }
                self.hit(if retired {
                    "mutant/retired-index-relisted"
                } else if has_state {
                    "4.2/valid-index-unlisted-listed-first"
                } else {
                    "4.2/none-index-unlisted-listed-first"
                });
                // a failure leaves the rest of the call read-only (4.5)
                self.put(SName::Parts, SVal::Parts)?;
                Ok(true)
            }
            _ => Ok(true),
        }
    }

    fn status(&self, record_result: u8, sent: bool) -> Status {
        let idx = self.idx();
        Status {
            state: idx.state,
            index_lost: false,
            record_malformed: self.succ_malformed(),
            problems: idx.problems,
            succ: self.succ(),
            record_result,
            sent,
        }
    }

    // ------------------------------------------------------------ 4.5 index lost

    /// A call whose index is lost (4.5): read-only mode. No writes, no gc,
    /// no creation, no arming; no handover frame sent or answered; Poke
    /// flags ignored; status reports partition_state 7 and problems bit 6.
    fn lost(&mut self, input: Input) -> R<Reply> {
        self.hit("4.5/index-lost-call");
        match input {
            Input::Poke { .. } => {
                self.hit("4.5/lost/poke-reports-state-7");
                Ok(Reply::Status(Status {
                    state: PState::none(),
                    index_lost: true,
                    record_malformed: self.succ_malformed(),
                    problems: PROBLEM_INDEX_LOST,
                    succ: self.succ(),
                    record_result: 0,
                    sent: false,
                }))
            }
            Input::Wakeup => Ok(Reply::None),
            Input::Hop { frame, .. } => {
                self.hit("4.5/lost/hop-not-answered");
                if let Frame::Query { m, .. } = frame {
                    self.hit("7.6q/index-lost");
                    if m == 0 {
                        self.hit("5.3/probe-to-index-lost-build");
                    }
                }
                Ok(Reply::None)
            }
            Input::Op(op) => self.lost_op(op).map(Reply::Op),
        }
    }

    /// 4.5 direct-read rule (revision 9): read vault:gc; a slot whose two
    /// parity names are both listed is deleted (Ok(None)). Read both
    /// copies; use one only if exactly one decodes as a valid entry for
    /// that slot (or both decode to the same value); of two different
    /// copies, if exactly one is listed in vault:gc use the other; Reindex
    /// also resolves two different unlisted copies by the expected key.
    /// Returns the parity of the copy used.
    fn direct_read_id(
        &mut self,
        id: Ident,
        expected: Option<u32>,
    ) -> Result<Option<(bool, Entry)>, Unrecovered> {
        let gc = if self.p.mutant == Some(Mutant::DirectReadIgnoresGc) {
            BTreeSet::new()
        } else {
            match self.host.read(&SName::Gc) {
                Some(SVal::Gc(g)) => g,
                _ => BTreeSet::new(),
            }
        };
        let (n0, n1) = (SName::E(id, false), SName::E(id, true));
        if gc.contains(&n0) && gc.contains(&n1) {
            self.hit("4.5/direct-read-deleted-by-gc");
            return Ok(None);
        }
        let vals: Vec<(bool, Entry)> = [false, true]
            .iter()
            .filter_map(|par| match self.host.read(&SName::E(id, *par)) {
                Some(SVal::E(e)) if e.ident() == id => Some((*par, e)),
                _ => None,
            })
            .collect();
        match vals.as_slice() {
            [] => Err(Unrecovered::NoCopy),
            [e] => Ok(Some(e.clone())),
            [a, b] if a.1 == b.1 => Ok(Some(a.clone())),
            [a, b] => {
                let la = gc.contains(&SName::E(id, a.0));
                let lb = gc.contains(&SName::E(id, b.0));
                match (la, lb) {
                    (true, false) => {
                        self.hit("4.5/direct-read-gc-listed-copy-ignored");
                        Ok(Some(b.clone()))
                    }
                    (false, true) => {
                        self.hit("4.5/direct-read-gc-listed-copy-ignored");
                        Ok(Some(a.clone()))
                    }
                    _ => {
                        if let Some(x) = expected {
                            let m: Vec<&(bool, Entry)> =
                                [a, b].into_iter().filter(|e| e.1.content == x).collect();
                            if let [e] = m.as_slice() {
                                self.hit("4.6/reindex-two-copies-resolved-by-expected-key");
                                return Ok(Some((*e).clone()));
                            }
                        }
                        self.hit("4.5/direct-read-two-values");
                        Err(Unrecovered::Ambiguous)
                    }
                }
            }
            _ => Err(Unrecovered::Ambiguous),
        }
    }

    /// Direct read of a key slot for an operation: Ok(None) is Absent.
    fn direct_read(&mut self, slot: u16) -> Result<Option<Entry>, ()> {
        match self.direct_read_id((KIND_KEY, slot), None) {
            Ok(o) => Ok(o.map(|(_, e)| e)),
            Err(Unrecovered::NoCopy) => Ok(None),
            Err(_) => Err(()),
        }
    }

    fn lost_op(&mut self, op: Op) -> R<OpRes> {
        match op {
            Op::PublicKey { slot } => {
                self.hit("4.5/lost/read");
                Ok(match self.direct_read(slot) {
                    Ok(None) => OpRes::Absent,
                    Ok(Some(e)) if e.flagged => OpRes::Unusable,
                    Ok(Some(e)) => OpRes::Key(e.content),
                    Err(()) => OpRes::Refused(12),
                })
            }
            Op::Batch { slot, expected } => {
                self.hit("4.5/lost/read");
                Ok(match self.direct_read(slot) {
                    Ok(None) => OpRes::Absent,
                    Ok(Some(e)) if e.flagged => OpRes::Unusable,
                    Ok(Some(e)) if e.content != expected => OpRes::Refused(14),
                    Ok(Some(e)) => OpRes::Key(e.content),
                    Err(()) => OpRes::Refused(12),
                })
            }
            Op::Export { slot } => {
                self.hit("4.5/lost/export");
                Ok(match self.direct_read(slot) {
                    Ok(None) => OpRes::Absent,
                    Ok(Some(e)) => OpRes::Key(e.content),
                    Err(()) => OpRes::Refused(12),
                })
            }
            Op::Reindex { slots } => self.reindex(slots, true),
            _ => {
                self.hit("4.5/lost/change-refused");
                Ok(OpRes::Refused(12))
            }
        }
    }

    /// Reindex (0x88, revision 9, 4.6), in the call that carries the
    /// consent. `lost`: the index is lost (else the partition is
    /// REPAIRING and this rebuilds again).
    fn reindex(&mut self, slots: Vec<(u16, u32)>, lost: bool) -> R<OpRes> {
        self.hit(if lost {
            "4.6/reindex-on-lost-index"
        } else {
            "4.6/reindex-while-repairing"
        });
        if self.succ_malformed() {
            self.hit("4.6/reindex-refused-record-malformed");
            return Ok(OpRes::Refused(7));
        }
        if self.creation_bar() {
            self.hit("4.6/reindex-refused-creation-bar");
            return Ok(OpRes::Refused(8));
        }
        let mut found: BTreeMap<Ident, (bool, Entry)> = BTreeMap::new();
        let mut unrecovered = vec![];
        let page: BTreeSet<Ident> = slots.iter().map(|(s, _)| (KIND_KEY, *s)).collect();
        for (slot, exp) in &slots {
            let id = (KIND_KEY, *slot);
            match self.direct_read_id(id, Some(*exp)) {
                Ok(Some((par, e))) if e.content == *exp => {
                    self.hit("4.6/reindex-slot-recovered");
                    found.insert(id, (par, e));
                }
                Ok(Some(_)) => {
                    self.hit("4.6/reindex-slot-key-mismatch");
                    unrecovered.push((*slot, Unrecovered::Mismatch));
                }
                Ok(None) => {
                    self.hit("4.6/reindex-slot-deleted");
                    unrecovered.push((*slot, Unrecovered::Deleted));
                }
                Err(r) => {
                    self.hit("4.6/reindex-slot-unrecovered");
                    unrecovered.push((*slot, r));
                }
            }
        }
        // caller marks, by the names computed for each accepted caller
        for caller in 0..NCALLERS {
            let id = (KIND_MARK, caller);
            let mut best: Option<(bool, Entry)> = None;
            for par in [false, true] {
                if let Some(SVal::E(e)) = self.host.read(&SName::E(id, par)) {
                    let better = match &best {
                        None => true,
                        Some(b) => e.content > b.1.content,
                    };
                    if e.ident() == id && better {
                        best = Some((par, e));
                    }
                }
            }
            if let Some(b) = best {
                self.hit("4.6/reindex-mark-carried");
                found.insert(id, b);
            }
        }
        // every other entry, through the host's advisory key listing
        let (names, incomplete) = self.host.list_entries();
        if incomplete {
            self.hit("4.6/reindex-listing-incomplete");
        }
        let mut listed = BTreeSet::new();
        for n in names {
            let SName::E(id, _) = n else { continue };
            listed.insert(id);
            if found.contains_key(&id) || page.contains(&id) || id.0 == KIND_MARK {
                continue;
            }
            if let Ok(Some((par, e))) = self.direct_read_id(id, None) {
                self.hit(if id.0 == KIND_KEY {
                    "4.6/reindex-unlisted-slot-found-by-listing"
                } else {
                    "4.6/reindex-unknown-kind-carried"
                });
                found.insert(id, (par, e));
            }
        }
        let mut n = Index::none();
        n.state = PState::Repairing {
            confirmed: BTreeSet::new(),
        };
        for (id, (par, e)) in &found {
            n.entries.insert(
                *id,
                IdxEnt {
                    parity: *par,
                    digest: e.digest(),
                },
            );
        }
        self.notes.push(Note::Reindex {
            unrecovered,
            listed,
            listing_incomplete: incomplete,
        });
        if self.host.read(&SName::Idx).is_none()
            && self.host.store.secrets.contains_key(&SName::Idx)
        {
            // the old index reads as absent: remove it first (#6323)
            self.notes.push(Note::ReindexWrite(1));
            if !self.del(SName::Idx)? {
                return Ok(OpRes::Refused(12));
            }
            self.hit("4.6/reindex-removed-undecryptable-index");
        }
        self.notes.push(Note::ReindexWrite(2));
        if !self.put(SName::Idx, SVal::Idx(n.clone()))? {
            self.hit("4.6/reindex-write-failed-read-back");
            if self.idx_raw() != Some(n.clone()) {
                return Ok(OpRes::Refused(12));
            }
            self.hit("4.6/reindex-write-failed-but-landed");
            return Ok(OpRes::Ok);
        }
        self.hit("4.6/reindex-written");
        if self.idx_raw() == Some(n.clone()) && !self.parts_listed() {
            self.notes.push(Note::ReindexWrite(3));
            if self.put(SName::Parts, SVal::Parts)? {
                self.hit("4.6/reindex-parts-rewritten");
            }
        }
        Ok(OpRes::Ok)
    }

    // ------------------------------------------------------------ 4.6 REPAIRING

    /// A REPAIRING call (4.6): reads from the rebuilt index, every change
    /// Refused(12), no vault-to-vault frame answered, records stored,
    /// partition_state 8; a poke from a domain page sends the next probe.
    fn repairing(&mut self, input: Input) -> R<Reply> {
        self.hit("4.6/repairing-call");
        match input {
            Input::Poke { rec, .. } => {
                let mut rr = 0;
                if let Some(r) = rec {
                    rr = self.accept_record(r)?;
                }
                let out_before = self.out.len();
                self.hit("4.6/repairing-poke");
                self.repair_advance()?;
                let sent = self.out.len() > out_before;
                Ok(Reply::Status(self.status(rr, sent)))
            }
            Input::Wakeup => Ok(Reply::None),
            Input::Hop { from, frame } => {
                match frame {
                    Frame::CompleteAck { m: 0, status, .. } if self.def.preds.contains(&from) => {
                        self.hit("6/repair-answer");
                        self.on_repair_answer(from, status)?;
                    }
                    Frame::Query { m, .. } => {
                        self.hit("4.6/repairing-hop-not-answered");
                        self.hit("7.6q/repairing");
                        if m == 0 {
                            self.hit("5.3/probe-to-repairing-build");
                        }
                    }
                    _ => self.hit("4.6/repairing-hop-not-answered"),
                }
                Ok(Reply::None)
            }
            Input::Op(op) => match op {
                Op::PublicKey { .. } | Op::Batch { .. } | Op::Export { .. } => {
                    self.hit("4.6/repairing-read");
                    self.serve(op).map(Reply::Op)
                }
                Op::Reindex { slots } => self.reindex(slots, false).map(Reply::Op),
                _ => {
                    self.hit("4.6/repairing-change-refused");
                    Ok(Reply::Op(OpRes::Refused(12)))
                }
            },
        }
    }

    fn repair_unconfirmed(&self, confirmed: &BTreeSet<Ver>) -> Vec<Ver> {
        let mut v: Vec<Ver> = self
            .def
            .preds
            .iter()
            .filter(|p| !confirmed.contains(p))
            .copied()
            .collect();
        v.sort_unstable();
        v
    }

    /// Whether the guard lets the REPAIRING build become WRITER.
    fn repair_may_finish(&self, confirmed: &BTreeSet<Ver>) -> bool {
        let left = self.repair_unconfirmed(confirmed).len();
        let all = match self.p.mutant {
            Some(Mutant::RepairOneUnconfirmed) => left <= 1,
            _ => left == 0,
        };
        let bar = self.creation_bar() && self.p.mutant != Some(Mutant::RepairIgnoresBar);
        all && !bar
    }

    /// A poke to a REPAIRING build: send the next probe (lowest
    /// unconfirmed predecessor), or, with every predecessor confirmed and
    /// no creation bar, write WRITER.
    fn repair_advance(&mut self) -> R<()> {
        let idx = self.idx();
        let PState::Repairing { confirmed } = &idx.state else {
            return Ok(());
        };
        if self.repair_may_finish(confirmed) {
            return self.repair_finish(&idx);
        }
        let un = self.repair_unconfirmed(confirmed);
        if self.creation_bar() {
            self.hit("4.6/repair-blocked-by-creation-bar");
        }
        let targets: Vec<Ver> = if self.p.mutant == Some(Mutant::RepairAnyOrder) {
            un
        } else {
            un.into_iter().take(1).collect()
        };
        for pv in targets {
            self.hit("4.6/repair-probe-sent");
            self.send(
                pv,
                Frame::Query {
                    rec: Rec::build(self.own()),
                    m: 0,
                },
            );
        }
        Ok(())
    }

    fn repair_finish(&mut self, idx: &Index) -> R<()> {
        let mut n = idx.clone();
        n.state = PState::Writer(WFields::default());
        self.notes.push(Note::RepairDone);
        if self.commit(&n)? {
            self.hit("4.6/repair-finished-writer");
            if self.def.preds.is_empty() {
                self.hit("4.6/repair-finished-no-predecessors");
            }
        }
        Ok(())
    }

    /// Section 6 row (revision 9): the answer to the REPAIRING build's own
    /// probe, from the predecessor it last probed.
    fn on_repair_answer(&mut self, p: Ver, status: CStatus) -> R<()> {
        let idx = self.idx();
        let PState::Repairing { confirmed } = &idx.state else {
            return Ok(());
        };
        let un = self.repair_unconfirmed(confirmed);
        let expected = if self.p.mutant == Some(Mutant::RepairAnyOrder) {
            un.contains(&p)
        } else {
            un.first() == Some(&p)
        };
        if !expected {
            self.hit("4.6/repair-answer-not-from-probed-predecessor");
            return Ok(());
        }
        self.hit(&format!("4.6/repair-answer/{status:?}"));
        match status {
            CStatus::NoState | CStatus::RetiredNotAhead => {
                let mut n = idx.clone();
                let mut c = confirmed.clone();
                c.insert(p);
                if self.repair_may_finish(&c) {
                    n.state = PState::Writer(WFields::default());
                    self.notes.push(Note::RepairDone);
                    if self.commit(&n)? {
                        self.hit("4.6/repair-finished-writer");
                    }
                    return Ok(());
                }
                n.state = PState::Repairing { confirmed: c };
                if self.commit(&n)? {
                    self.hit("4.6/repair-confirmed");
                    if self.p.mutant != Some(Mutant::RepairAnyOrder) {
                        self.repair_advance()?;
                    }
                }
            }
            CStatus::AnotherWriter => {
                let mut n = idx.clone();
                n.problems |= PROBLEM_ANOTHER_WRITER;
                if n != idx {
                    self.commit(&n)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// vault:succ is malformed (3): the build refuses handover activity,
    /// reports it, and keeps serving as whatever it was.
    fn record_malformed(&mut self, input: Input) -> R<Reply> {
        self.hit("3/record-malformed-call");
        match input {
            Input::Poke { .. } => Ok(Reply::Status(self.status(3, false))),
            Input::Wakeup => Ok(Reply::None),
            Input::Hop { .. } => {
                self.hit("3/record-malformed-refuses-handover");
                Ok(Reply::None)
            }
            Input::Op(op) => self.op(op).map(Reply::Op),
        }
    }

    // ------------------------------------------------------------ records

    /// Section 3. Returns 0 (retry / not stored), 2 accepted, 3 not newer,
    /// 4 equivocation.
    fn accept_record(&mut self, rec: Rec) -> R<u8> {
        let s = self.succ();
        let floor = [
            Some(self.own()),
            s.current.map(|r| r.v),
            s.withdrawal.map(|r| r.v),
        ]
        .into_iter()
        .flatten()
        .max()
        .unwrap();
        if rec.v < floor || rec.v == self.own() {
            self.hit("3/not-newer");
            return Ok(3);
        }
        if rec.v == floor {
            if s.current == Some(rec) || s.withdrawal == Some(rec) {
                self.hit("3/retry");
                return Ok(0);
            }
            self.hit("3/equivocation");
            return Ok(4);
        }
        let mut n = s.clone();
        if rec.withdrawal {
            n.withdrawal = Some(rec);
            self.hit("3/withdrawal-stored");
        } else {
            n.current = Some(rec);
            self.hit("3/record-stored");
        }
        if !self.put(SName::Succ, SVal::Succ(n.clone()))? {
            // Read vault:succ back and report the floor actually held (3).
            self.hit("3/record-write-failed-read-back");
            if self.succ() != n {
                return Ok(0);
            }
            self.hit("3/record-write-failed-but-landed");
        }
        // "in the same write clear any creation arming and creation
        // confirmations": they live in the index, a different secret, so
        // this is a second write.
        let mut idx = self.idx();
        match &mut idx.state {
            PState::None { armed, confirmed } if armed.is_some() || !confirmed.is_empty() => {
                *armed = None;
                confirmed.clear();
                self.hit("5.1/arming-cleared-by-record");
                self.commit(&idx)?;
            }
            PState::Repairing { confirmed } => {
                // "storing a record above its own version stops the repair
                // for good, exactly as it stops a creation" (4.6)
                self.hit("4.6/record-stored-while-repairing");
                if !confirmed.is_empty() {
                    confirmed.clear();
                    self.hit("4.6/repair-confirmations-cleared-by-record");
                    self.commit(&idx)?;
                }
            }
            _ => {}
        }
        Ok(2)
    }

    fn abort_trigger(&self, target: Rec) -> bool {
        let s = self.succ();
        s.stopped() || s.successor().is_some_and(|c| c.v > target.v)
    }

    fn copy_target(&self, idx: &Index) -> Option<Rec> {
        match &idx.state {
            PState::Writer(w) if !w.awaiting => {
                let t = self.succ().successor()?;
                if w.paused == Some(t.v) {
                    None
                } else {
                    Some(t)
                }
            }
            _ => None,
        }
    }

    fn has_work(&self) -> bool {
        let idx = self.idx();
        !self.gc_set().is_empty()
            || matches!(idx.state, PState::Sealed { .. })
            || matches!(&idx.state, PState::Writer(w) if w.awaiting)
            || self.copy_target(&idx).is_some()
    }

    // ------------------------------------------------------------ poke

    fn poke(&mut self, flags: u8, rec: Option<Rec>) -> R<Status> {
        let out_before = self.out.len();
        let mut rr = 0;
        if let Some(r) = rec {
            rr = self.accept_record(r)?;
        }
        // Flags (the model's pokes all come from the domain's own pages).
        let mut idx = self.idx();
        let succ = self.succ();
        if flags & POKE_PAUSE != 0 {
            if let (PState::Writer(w), Some(t)) = (&mut idx.state, succ.successor()) {
                if w.paused != Some(t.v) {
                    w.paused = Some(t.v);
                    idx.problems |= PROBLEM_PAUSED;
                    self.hit("7.5/pause-set");
                    self.commit(&idx)?;
                }
            }
        } else if let PState::Writer(w) = &mut idx.state {
            if w.paused.is_some() {
                w.paused = None;
                idx.problems &= !PROBLEM_PAUSED;
                self.hit("7.5/pause-cleared-by-poke");
                self.commit(&idx)?;
            }
        }
        if flags & POKE_RESERVED_4 != 0 {
            self.hit("12.4/poke-bit-4-ignored");
        }
        if flags & POKE_ARM != 0 {
            let idx = self.idx();
            if let (PState::None { armed, .. }, Some(r)) = (&idx.state, rec) {
                if armed.is_some() {
                    self.hit("13.1/arm-already-armed");
                } else if r.v == self.own() && !r.withdrawal {
                    if self.creation_bar() {
                        self.hit("3/creation-bar-refused-arm");
                    } else if self.succ().stopped()
                        && self.p.mutant != Some(Mutant::CreateWhileStopped)
                    {
                        self.hit("3/arm-refused-stopped");
                    } else {
                        // 5.3 step 1: the arming record with an empty
                        // confirmed set.
                        let mut n = idx.clone();
                        n.state = PState::None {
                            armed: Some(r),
                            confirmed: BTreeSet::new(),
                        };
                        if self.commit(&n)? {
                            self.hit("13.1/armed");
                            if self.succ().stopped() {
                                self.hit("13.1/armed-while-stopped");
                            }
                        }
                    }
                } else {
                    self.hit("13.1/arm-refused");
                }
            }
        }
        // 5.3: a poke to an armed build sends creation probes (Query with a
        // zero manifest digest) to its unconfirmed predecessors.
        let idx = self.idx();
        if let PState::None {
            armed: Some(ar),
            confirmed,
        } = &idx.state
        {
            let unconfirmed: Vec<Ver> = self
                .def
                .preds
                .iter()
                .filter(|p| !confirmed.contains(p))
                .copied()
                .collect();
            if unconfirmed.is_empty() {
                self.hit("5.3/armed-all-confirmed");
            }
            for pv in unconfirmed {
                self.hit("5.3/probe-sent");
                self.send(pv, Frame::Query { rec: *ar, m: 0 });
            }
        }
        let w = self.p.window_poke;
        self.step(w)?;
        let sent = self.out.len() > out_before;
        Ok(self.status(rr, sent))
    }

    // ------------------------------------------------------------ step (7.7)

    fn step(&mut self, window: usize) -> R<bool> {
        self.vol.in_flight.clear();
        self.vol.complete_in_flight = false;
        let before = self.out.len();
        let idx = self.idx();
        match idx.state.clone() {
            PState::Writer(w) if w.awaiting => {
                let (pv, m) = w.taken_over.expect("awaiting without taken_over");
                self.hit("7.7/step-query");
                self.send(
                    pv,
                    Frame::Query {
                        rec: Rec::build(self.own()),
                        m,
                    },
                );
            }
            PState::Sealed { target, m, .. } => {
                if self.abort_trigger(target) {
                    self.hit("7.5/step-abort");
                    self.send(
                        target.v,
                        Frame::Abort {
                            rec: target,
                            m,
                            malformed: false,
                        },
                    );
                } else {
                    let sent = self.send_pending(target, window.saturating_sub(1))?;
                    if self.pending(target).is_empty() {
                        self.hit("7.5/step-resend-complete");
                        self.send_complete(target, m);
                    } else if sent == 0 {
                        self.send_complete(target, m);
                    }
                }
            }
            PState::Writer(_) => {
                if let Some(t) = self.copy_target(&idx) {
                    if self.pending(t).is_empty() {
                        self.seal(t)?;
                    } else {
                        self.hit("7.7/step-copy");
                        self.send_pending(t, window)?;
                    }
                }
            }
            _ => {}
        }
        Ok(self.out.len() > before)
    }

    /// Entries not acknowledged at their current digest and not in flight.
    fn pending(&self, t: Rec) -> Vec<Ident> {
        let idx = self.idx();
        let prog = self.prog(t.v);
        let mut v: Vec<Ident> = idx
            .entries
            .iter()
            .filter(|(id, e)| prog.get(id) != Some(&e.digest) && !self.vol.in_flight.contains(id))
            .map(|(id, _)| *id)
            .collect();
        // marks first, then key order
        v.sort_by_key(|id| (id.0 != KIND_MARK, *id));
        v
    }

    fn send_pending(&mut self, t: Rec, max_msgs: usize) -> R<usize> {
        let mut sent = 0;
        while sent < max_msgs {
            let pend = self.pending(t);
            if pend.is_empty() {
                break;
            }
            let mut entries = Vec::new();
            for id in pend.into_iter().take(self.p.chunk_max) {
                self.vol.in_flight.insert(id);
                if let Some(e) = self.read_entry(id)? {
                    entries.push(e);
                }
            }
            if entries.is_empty() {
                continue;
            }
            self.send(
                t.v,
                Frame::Chunk {
                    rec: t,
                    entries,
                    malformed: false,
                },
            );
            sent += 1;
        }
        Ok(sent)
    }

    fn send_complete(&mut self, t: Rec, m: Digest) {
        let digests = self.idx().manifest();
        self.vol.complete_in_flight = true;
        self.send(
            t.v,
            Frame::Complete {
                rec: t,
                m,
                digests,
                malformed: false,
            },
        );
    }

    /// 7.4: one index write to SEALED(target, m), then Complete.
    fn seal(&mut self, t: Rec) -> R<()> {
        let idx = self.idx();
        let PState::Writer(w) = idx.state.clone() else {
            return Ok(());
        };
        let m = manifest_digest(&idx.manifest());
        let mut n = idx.clone();
        n.state = PState::Sealed { w, target: t, m };
        if self.commit(&n)? {
            self.hit("7.4/sealed");
            self.send_complete(t, m);
        }
        Ok(())
    }

    /// 4.3 read with digest check.
    fn read_entry(&mut self, id: Ident) -> R<Option<Entry>> {
        let idx = self.idx();
        let Some(ie) = idx.entries.get(&id).copied() else {
            return Ok(None);
        };
        // Undecryptable bytes read as absent (4.0) and are handled as bytes
        // that do not parse (4.3).
        let val = self.host.read(&SName::E(id, ie.parity));
        if let Some(SVal::E(e)) = &val {
            if e.digest() == ie.digest {
                return Ok(Some(e.clone()));
            }
        }
        let sealed = matches!(idx.state, PState::Sealed { .. });
        if sealed {
            // Nothing is rewritten or removed while sealed (4.3). The model
            // copies the bytes as they are on disk.
            self.hit("4.3/corrupt-while-sealed");
            return Ok(match val {
                Some(SVal::E(e)) => {
                    self.notes.push(Note::SealedCorruptSent);
                    Some(e)
                }
                _ => None,
            });
        }
        let mut n = idx.clone();
        match val {
            Some(SVal::E(e)) => {
                self.hit("4.3/corrupt-rewritten-flagged");
                let f = Entry { flagged: true, ..e };
                let par = !ie.parity;
                if !self.clear_gc_name(SName::E(id, par))? {
                    return Ok(None);
                }
                if !self.gc_add(&[SName::E(id, ie.parity)])? {
                    return Ok(None);
                }
                if !self.put(SName::E(id, par), SVal::E(f.clone()))? {
                    return Ok(None);
                }
                n.entries.insert(
                    id,
                    IdxEnt {
                        parity: par,
                        digest: f.digest(),
                    },
                );
                n.problems |= PROBLEM_CORRUPT;
                if self.commit(&n)? {
                    Ok(Some(f))
                } else {
                    Ok(None)
                }
            }
            _ => {
                self.hit("4.3/corrupt-unparseable-removed");
                self.gc_add(&[SName::E(id, ie.parity)])?;
                n.entries.remove(&id);
                n.lost = n.lost.saturating_add(1);
                n.problems |= PROBLEM_CORRUPT;
                self.commit(&n)?;
                Ok(None)
            }
        }
    }

    // ------------------------------------------------------------ hops (6)

    fn hop(&mut self, from: Ver, frame: Frame) -> R<Option<Frame>> {
        let idx = self.idx();
        let s = self.succ();
        let sealed_target = match &idx.state {
            PState::Sealed { target, .. } => Some(target.v),
            _ => None,
        };
        let from_successor = s.current.map(|r| r.v) == Some(from) || sealed_target == Some(from);
        match &frame {
            Frame::Chunk { .. }
            | Frame::Complete { .. }
            | Frame::Abort { .. }
            | Frame::Retired { .. }
                if self.def.preds.contains(&from) =>
            {
                self.hit("6/receiver-role");
                self.receiver(from, frame).map(Some)
            }
            Frame::Ack { .. } | Frame::CompleteAck { .. } if from_successor => {
                self.hit("6/ack-from-successor");
                match frame {
                    Frame::Ack {
                        tid,
                        status,
                        succ,
                        outcomes,
                    } => self.on_ack(from, tid, status, succ, outcomes)?,
                    Frame::CompleteAck {
                        tid,
                        m,
                        status,
                        succ,
                        missing,
                    } => self.on_cack(from, tid, m, status, succ, missing)?,
                    _ => unreachable!(),
                }
                Ok(None)
            }
            Frame::Query { rec, m } if rec.v == from && !rec.withdrawal && from > self.own() => {
                self.hit("6/predecessor-role");
                self.on_query(from, *rec, *m).map(Some)
            }
            // Section 6 row (revision 8, F1): a CompleteAck from P in
            // PREDECESSORS answering this build's own Query.
            Frame::CompleteAck { m, status, .. } if self.def.preds.contains(&from) => {
                let (m, status) = (*m, *status);
                match &idx.state {
                    PState::Writer(w) if w.awaiting && w.taken_over == Some((from, m)) => {
                        self.hit("6/query-answer/awaiting");
                        self.on_query_answer(status)?;
                    }
                    PState::None { armed: Some(_), .. } if m == 0 => {
                        self.hit("6/query-answer/armed");
                        self.on_probe_answer(from, status)?;
                    }
                    _ => {
                        self.hit("6/ignored");
                        self.hit("6/ignored/answer-from-predecessor");
                    }
                }
                Ok(None)
            }
            _ => {
                self.hit("6/ignored");
                Ok(None)
            }
        }
    }

    // ------------------------------------------------------------ receiver role (7.6)

    fn receiver(&mut self, from: Ver, frame: Frame) -> R<Frame> {
        let idx = self.idx();
        let s = self.succ();
        let (rec, malformed) = match &frame {
            Frame::Chunk { rec, malformed, .. }
            | Frame::Complete { rec, malformed, .. }
            | Frame::Abort { rec, malformed, .. }
            | Frame::Retired { rec, malformed, .. } => (*rec, *malformed),
            _ => unreachable!(),
        };
        let fname = frame.name();
        let tid = (from, rec);
        let echo = match &frame {
            Frame::Complete { m, .. } | Frame::Abort { m, .. } | Frame::Retired { m, .. } => *m,
            _ => 0,
        };
        let ack = |status, outcomes: Vec<(Digest, Outcome)>, succ: Option<Rec>| Frame::Ack {
            tid,
            status,
            succ,
            outcomes,
        };
        let cack = |status, missing: Vec<Digest>, succ: Option<Rec>| Frame::CompleteAck {
            tid,
            m: echo,
            status,
            succ,
            missing,
        };
        let hs = s.highest();

        // Rows "taken over from P at m'" take precedence over every other row.
        if let Some((pv, m2)) = idx.state.taken_over() {
            if pv == from {
                self.hit(&format!("7.6/taken-over-from-P/{fname}"));
                return Ok(match frame {
                    Frame::Chunk { .. } => ack(ChunkStatus::AnotherWriter, vec![], hs),
                    Frame::Complete { m, malformed, .. } | Frame::Abort { m, malformed, .. } => {
                        if !malformed && m == m2 {
                            cack(CStatus::AlreadyWriter, vec![], hs)
                        } else {
                            cack(CStatus::DifferentManifest, vec![], hs)
                        }
                    }
                    Frame::Retired { m, malformed, .. } => {
                        if !malformed && m == m2 {
                            if let PState::Writer(w) = &idx.state {
                                if w.awaiting {
                                    let mut n = idx.clone();
                                    if let PState::Writer(w) = &mut n.state {
                                        w.awaiting = false;
                                    }
                                    if self.commit(&n)? {
                                        self.hit("7.4/awaiting-cleared-by-retired");
                                        self.notes.push(Note::AwaitingCleared);
                                    }
                                }
                            }
                            cack(CStatus::Noted, vec![], hs)
                        } else {
                            self.hit("7.6/taken-over-from-P/Retired-other-m-ignored");
                            // "ignored": the model sends no reply.
                            ignored()
                        }
                    }
                    _ => unreachable!(),
                });
            }
        }

        if malformed {
            self.hit(&format!("7.6/malformed/{fname}"));
            return Ok(match frame {
                Frame::Chunk { .. } => ack(ChunkStatus::Malformed, vec![], hs),
                _ => cack(CStatus::Malformed, vec![], hs),
            });
        }
        if rec.v != self.own() || rec.withdrawal {
            self.hit(&format!("12.3/record-not-mine/{fname}"));
            return Ok(match frame {
                Frame::Chunk { .. } => ack(ChunkStatus::NotMine, vec![], hs),
                _ => cack(CStatus::Malformed, vec![], hs),
            });
        }

        match idx.state.clone() {
            PState::Writer(_) | PState::Sealed { .. } | PState::Retired { .. } => {
                self.hit(&format!("7.6/other-writer-or-not-from-P/{fname}"));
                Ok(match frame {
                    Frame::Chunk { .. } => ack(ChunkStatus::AnotherWriter, vec![], hs),
                    Frame::Complete { .. } => cack(CStatus::AnotherWriter, vec![], hs),
                    Frame::Abort { .. } => cack(CStatus::Aborted, vec![], hs),
                    _ => ignored(),
                })
            }
            PState::None { .. } | PState::Receiving { .. } if s.stopped() => {
                self.hit(&format!("7.6/stopped/{fname}"));
                Ok(match frame {
                    Frame::Chunk { .. } => ack(ChunkStatus::Stopped, vec![], s.withdrawal),
                    Frame::Complete { .. } => cack(CStatus::Stopped, vec![], s.withdrawal),
                    Frame::Abort { .. } => cack(CStatus::Aborted, vec![], hs),
                    _ => ignored(),
                })
            }
            PState::None { .. } => {
                self.hit(&format!("7.6/NONE/{fname}"));
                match frame {
                    Frame::Chunk { entries, .. } => {
                        let mut n = idx.clone();
                        n.state = PState::Receiving {
                            from,
                            store_failed: false,
                        };
                        self.ensure_parts()?;
                        self.put(SName::Rx, SVal::Rx(BTreeSet::new()))?;
                        if !self.commit(&n)? {
                            // Still NONE on disk: nothing stored.
                            let outs = entries
                                .iter()
                                .map(|e| (e.digest(), Outcome::StorageFailure))
                                .collect();
                            return Ok(ack(ChunkStatus::Processed, outs, hs));
                        }
                        self.process_chunk(from, tid, entries)
                    }
                    Frame::Complete { m, digests, .. } => {
                        if digests.is_empty() {
                            let mut n = idx.clone();
                            n.state = PState::Receiving {
                                from,
                                store_failed: false,
                            };
                            self.ensure_parts()?;
                            if !self.commit(&n)? {
                                return Ok(cack(CStatus::StorageFailure, vec![], hs));
                            }
                            self.take_over(from, tid, m, digests)
                        } else {
                            let missing = digests.into_iter().take(self.p.missing_max).collect();
                            Ok(cack(CStatus::Missing, missing, hs))
                        }
                    }
                    Frame::Abort { .. } => Ok(cack(CStatus::Aborted, vec![], hs)),
                    _ => Ok(ignored()),
                }
            }
            PState::Receiving { from: q, .. } if q == from => {
                self.hit(&format!("7.6/RECEIVING(P)/{fname}"));
                match frame {
                    Frame::Chunk { entries, .. } => self.process_chunk(from, tid, entries),
                    Frame::Complete { m, digests, .. } => self.take_over(from, tid, m, digests),
                    Frame::Abort { .. } => Ok(cack(CStatus::Aborted, vec![], hs)),
                    _ => Ok(ignored()),
                }
            }
            PState::Receiving { from: q, .. } if q < from => {
                self.hit(&format!("7.6/RECEIVING(lower)/{fname}"));
                match frame {
                    Frame::Chunk { entries, .. } => {
                        let st = PState::Receiving {
                            from,
                            store_failed: false,
                        };
                        if !self.discard_to(&idx, st)? {
                            let outs = entries
                                .iter()
                                .map(|e| (e.digest(), Outcome::StorageFailure))
                                .collect();
                            return Ok(ack(ChunkStatus::Processed, outs, hs));
                        }
                        self.process_chunk(from, tid, entries)
                    }
                    Frame::Complete { digests, .. } => {
                        let st = PState::Receiving {
                            from,
                            store_failed: false,
                        };
                        self.discard_to(&idx, st)?;
                        let missing = digests.into_iter().take(self.p.missing_max).collect();
                        Ok(cack(CStatus::Missing, missing, hs))
                    }
                    Frame::Abort { .. } => Ok(cack(CStatus::Aborted, vec![], hs)),
                    _ => Ok(ignored()),
                }
            }
            PState::Repairing { .. } => {
                unreachable!("REPAIRING calls are dispatched to repairing()")
            }
            PState::Receiving { .. } => {
                self.hit(&format!("7.6/RECEIVING(higher)/{fname}"));
                Ok(match frame {
                    Frame::Chunk { .. } => ack(ChunkStatus::HigherBuild, vec![], hs),
                    Frame::Complete { .. } => cack(CStatus::HigherBuild, vec![], hs),
                    Frame::Abort { .. } => cack(CStatus::Aborted, vec![], hs),
                    _ => ignored(),
                })
            }
        }
    }

    /// Drop every entry (through vault:gc) and write `state`.
    fn discard_to(&mut self, idx: &Index, state: PState) -> R<bool> {
        let names: Vec<SName> = idx
            .entries
            .iter()
            .map(|(id, e)| SName::E(*id, e.parity))
            .collect();
        if !self.gc_add(&names)? {
            return Ok(false);
        }
        self.put(SName::Rx, SVal::Rx(BTreeSet::new()))?;
        let mut n = idx.clone();
        n.entries.clear();
        n.state = state;
        self.commit(&n)
    }

    fn process_chunk(&mut self, from: Ver, tid: (Ver, Rec), entries: Vec<Entry>) -> R<Frame> {
        let mut idx = self.idx();
        let s = self.succ();
        let mut rx = self.rx();
        let rx0 = rx.clone();
        let mut outcomes: Vec<(Digest, Outcome)> = Vec::new();
        let mut plan: Vec<(usize, Entry, bool)> = Vec::new();
        let mut new_count = 0usize;
        for e in &entries {
            let d = e.digest();
            let id = e.ident();
            if self.rejects_mark(e) {
                self.hit("7.2/outcome-policy-dropped");
                rx.insert(d);
                outcomes.push((d, Outcome::PolicyDropped));
                continue;
            }
            if idx.entries.get(&id).map(|x| x.digest) == Some(d) {
                self.hit("7.2/outcome-identical");
                outcomes.push((d, Outcome::Identical));
                continue;
            }
            if !idx.entries.contains_key(&id) {
                if idx.entries.len() + new_count >= self.p.max_entries {
                    self.hit("7.2/outcome-staging-full");
                    outcomes.push((d, Outcome::StagingFull));
                    continue;
                }
                new_count += 1;
            }
            let par = idx.entries.get(&id).map(|x| !x.parity).unwrap_or(false);
            plan.push((outcomes.len(), e.clone(), par));
            outcomes.push((d, Outcome::Stored));
        }
        let mut failed = false;
        let mut gc_ok = true;
        for (_, e, par) in &plan {
            if !self.clear_gc_name(SName::E(e.ident(), *par))? {
                gc_ok = false;
            }
        }
        let olds: Vec<SName> = plan
            .iter()
            .filter_map(|(_, e, _)| {
                idx.entries
                    .get(&e.ident())
                    .map(|x| SName::E(e.ident(), x.parity))
            })
            .collect();
        if gc_ok && self.p.gc_old_before_index {
            gc_ok = self.gc_add(&olds)?;
        }
        for (i, e, par) in &plan {
            if gc_ok && self.put(SName::E(e.ident(), *par), SVal::E(e.clone()))? {
                idx.entries.insert(
                    e.ident(),
                    IdxEnt {
                        parity: *par,
                        digest: e.digest(),
                    },
                );
                self.hit("7.2/outcome-stored");
            } else {
                outcomes[*i].1 = Outcome::StorageFailure;
                self.hit("7.2/outcome-storage-failure");
                failed = true;
            }
        }
        if rx != rx0 && !self.put(SName::Rx, SVal::Rx(rx))? {
            for o in outcomes.iter_mut() {
                if o.1 == Outcome::PolicyDropped {
                    o.1 = Outcome::StorageFailure;
                }
            }
            failed = true;
        }
        let prev_failed = matches!(
            idx.state,
            PState::Receiving {
                store_failed: true,
                ..
            }
        );
        idx.state = PState::Receiving {
            from,
            store_failed: prev_failed || failed,
        };
        if !self.commit(&idx)? {
            let disk = self.idx();
            for o in outcomes.iter_mut() {
                if o.1 == Outcome::Stored && !disk.entries.values().any(|x| x.digest == o.0) {
                    o.1 = Outcome::StorageFailure;
                }
            }
        } else if !self.p.gc_old_before_index {
            self.gc_add(&olds)?;
        }
        Ok(Frame::Ack {
            tid,
            status: ChunkStatus::Processed,
            succ: s.highest(),
            outcomes,
        })
    }

    /// 7.4 step 2.
    fn take_over(
        &mut self,
        from: Ver,
        tid: (Ver, Rec),
        m: Digest,
        digests: Vec<Digest>,
    ) -> R<Frame> {
        let idx = self.idx();
        let hs = self.succ().highest();
        let cack = |status, missing: Vec<Digest>| Frame::CompleteAck {
            tid,
            m,
            status,
            succ: hs,
            missing,
        };
        if let PState::Receiving {
            store_failed: true, ..
        } = idx.state
        {
            self.hit("7.4/complete-storage-failure-flag");
            let mut n = idx.clone();
            n.state = PState::Receiving {
                from,
                store_failed: false,
            };
            self.commit(&n)?;
            return Ok(cack(CStatus::StorageFailure, vec![]));
        }
        let listed: BTreeSet<Digest> = digests.iter().copied().collect();
        let rx = self.rx();
        let drop: Vec<(Ident, IdxEnt)> = idx
            .entries
            .iter()
            .filter(|(_, e)| !listed.contains(&e.digest))
            .map(|(i, e)| (*i, *e))
            .collect();
        let mut n = idx.clone();
        if !drop.is_empty() {
            self.hit("7.4/unlisted-dropped");
            let names: Vec<SName> = drop.iter().map(|(i, e)| SName::E(*i, e.parity)).collect();
            if !self.gc_add(&names)? {
                return Ok(cack(CStatus::StorageFailure, vec![]));
            }
            for (i, _) in &drop {
                n.entries.remove(i);
            }
        }
        let held: BTreeSet<Digest> = n
            .entries
            .values()
            .map(|e| e.digest)
            .chain(rx.iter().copied())
            .collect();
        let missing: Vec<Digest> = listed.difference(&held).copied().collect();
        if missing.is_empty() {
            n.state = PState::Writer(WFields {
                taken_over: Some((from, m)),
                awaiting: true,
                paused: None,
            });
            if self.commit(&n)? {
                self.hit("7.4/took-over");
                self.notes.push(Note::TookOver { from, m });
                Ok(cack(CStatus::Accepted, vec![]))
            } else {
                Ok(cack(CStatus::StorageFailure, vec![]))
            }
        } else {
            if !drop.is_empty() {
                self.commit(&n)?;
            }
            self.hit("7.4/missing");
            Ok(cack(
                CStatus::Missing,
                missing.into_iter().take(self.p.missing_max).collect(),
            ))
        }
    }

    // ------------------------------------------------------------ sender role (7.3 to 7.5)

    fn on_ack(
        &mut self,
        from: Ver,
        tid: (Ver, Rec),
        status: ChunkStatus,
        succ_rec: Option<Rec>,
        outcomes: Vec<(Digest, Outcome)>,
    ) -> R<()> {
        let idx = self.idx();
        let target = match &idx.state {
            PState::Sealed { target, .. } => Some(*target),
            PState::Writer(_) => self.succ().successor(),
            _ => None,
        };
        let Some(t) = target else {
            self.hit("7.3/ack-ignored-no-target");
            return Ok(());
        };
        if from != t.v || tid != (self.own(), t) {
            self.hit("7.3/ack-ignored-transfer-mismatch");
            return Ok(());
        }
        self.hit(&format!("7.3/ack/{status:?}"));
        let mut prog = self.prog(t.v);
        let prog0 = prog.clone();
        let mut seal_now = false;
        let mut n = idx.clone();
        match status {
            ChunkStatus::Processed => {
                for (d, o) in &outcomes {
                    if let Some(id) = idx.ident_of(*d) {
                        self.vol.in_flight.remove(&id);
                        if o.delivered() {
                            prog.insert(id, *d);
                        }
                    }
                    // A digest that is no longer current (changed meanwhile)
                    // records nothing: its entry stays pending.
                    if *o == Outcome::StagingFull {
                        seal_now = true;
                    }
                }
                // Outcomes for digests no longer current still clear in-flight.
                let ids: Vec<Ident> = self.vol.in_flight.iter().copied().collect();
                for id in ids {
                    if !idx.entries.contains_key(&id) {
                        self.vol.in_flight.remove(&id);
                    }
                }
                if let PState::Writer(w) = &mut n.state {
                    if w.paused == Some(t.v) && n.problems & PROBLEM_PAUSED != 0 {
                        w.paused = None;
                        n.problems &= !PROBLEM_PAUSED;
                        self.hit("7.5/pause-cleared-by-ack");
                    }
                }
            }
            ChunkStatus::Stopped => {
                if let Some(r) = succ_rec.filter(|r| r.withdrawal) {
                    self.accept_record(r)?;
                }
                n = self.idx();
            }
            ChunkStatus::HigherBuild | ChunkStatus::AnotherWriter => {
                if let PState::Writer(w) = &mut n.state {
                    w.paused = Some(t.v);
                }
                n.problems |= if status == ChunkStatus::HigherBuild {
                    PROBLEM_HIGHER_RECEIVER
                } else {
                    PROBLEM_ANOTHER_WRITER
                };
            }
            ChunkStatus::StagingFull => seal_now = true,
            ChunkStatus::NotMine | ChunkStatus::Malformed => {}
        }
        if seal_now {
            n.problems |= PROBLEM_STAGING_FULL;
        }
        if n != idx {
            self.commit(&n)?;
        }
        if prog != prog0 {
            self.put(SName::X(t.v), SVal::X(prog))?;
        }
        if let Some(r) = succ_rec.filter(|r| !r.withdrawal) {
            self.accept_record(r)?;
        }
        self.next_message(seal_now)
    }

    /// "Send at most one further message."
    fn next_message(&mut self, seal_now: bool) -> R<()> {
        let idx = self.idx();
        match idx.state.clone() {
            PState::Writer(_) => {
                let Some(t) = self.copy_target(&idx) else {
                    return Ok(());
                };
                if seal_now {
                    self.hit("7.3/seal-now-staging-full");
                    return self.seal(t);
                }
                if !self.pending(t).is_empty() {
                    self.send_pending(t, 1)?;
                } else if self.vol.in_flight.is_empty() {
                    self.seal(t)?;
                }
            }
            PState::Sealed { target, m, .. } => {
                if self.abort_trigger(target) {
                    return Ok(());
                }
                if !self.pending(target).is_empty() {
                    self.send_pending(target, 1)?;
                } else if self.vol.in_flight.is_empty() && !self.vol.complete_in_flight {
                    self.send_complete(target, m);
                }
            }
            _ => {}
        }
        Ok(())
    }

    #[allow(clippy::collapsible_match)]
    fn on_cack(
        &mut self,
        from: Ver,
        tid: (Ver, Rec),
        m: Digest,
        status: CStatus,
        succ_rec: Option<Rec>,
        missing: Vec<Digest>,
    ) -> R<()> {
        let idx = self.idx();
        let PState::Sealed { w, target, m: sm } = idx.state.clone() else {
            self.hit("7.5/completeack-ignored-not-sealed");
            return Ok(());
        };
        if from != target.v || tid != (self.own(), target) || m != sm {
            self.hit("7.5/completeack-ignored-mismatch");
            return Ok(());
        }
        self.hit(&format!("7.5/completeack/{status:?}"));
        if status == CStatus::Stopped {
            if let Some(r) = succ_rec.filter(|r| r.withdrawal) {
                self.accept_record(r)?;
            }
        }
        if let Some(r) = succ_rec.filter(|r| !r.withdrawal) {
            self.accept_record(r)?;
        }
        let idx = self.idx();
        match status {
            CStatus::Accepted | CStatus::AlreadyWriter => {
                if self.retire(&idx, target, m, w.taken_over)? {
                    self.send(
                        target.v,
                        Frame::Retired {
                            rec: target,
                            m,
                            malformed: false,
                        },
                    );
                }
            }
            CStatus::Missing => {
                self.vol.complete_in_flight = false;
                let mut prog = self.prog(target.v);
                for d in &missing {
                    if let Some(id) = idx.ident_of(*d) {
                        prog.remove(&id);
                        self.vol.in_flight.remove(&id);
                    }
                }
                self.put(SName::X(target.v), SVal::X(prog))?;
                self.next_message(false)?;
            }
            CStatus::DifferentManifest => {
                let mut n = idx.clone();
                n.problems |= PROBLEM_ANOTHER_WRITER;
                if n != idx {
                    self.commit(&n)?;
                }
            }
            s if s.unseals() => {
                let mut n = idx.clone();
                n.state = PState::Writer(w);
                self.notes.push(Note::UnsealIntent {
                    target: target.v,
                    m,
                });
                if self.commit(&n)? {
                    self.hit("7.5/unsealed");
                    self.notes.push(Note::Unsealed {
                        target: target.v,
                        m,
                        cause: Some(s),
                    });
                    self.vol.in_flight.clear();
                    self.next_message(false)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Write RETIRED(to target, m), then delete progress toward it.
    fn retire(
        &mut self,
        idx: &Index,
        target: Rec,
        m: Digest,
        taken_over: Option<(Ver, Digest)>,
    ) -> R<bool> {
        let mut n = idx.clone();
        n.state = PState::Retired {
            to: target,
            m,
            taken_over,
        };
        if !self.commit(&n)? {
            return Ok(false);
        }
        self.hit("7.4/retired");
        self.notes.push(Note::Retired { to: target.v, m });
        // revision 9, F7: unlist and read back; Retired (or "retired") only
        // once the list no longer names the partition
        match self.p.mutant {
            Some(Mutant::NeverUnlist) | Some(Mutant::RelistRetired) => {}
            Some(Mutant::RetiredBeforeUnlist) => {
                self.hit("mutant/retired-sent-before-unlist");
            }
            _ => {
                if !self.unlist()? {
                    return Ok(false);
                }
            }
        }
        self.del(SName::X(target.v))?;
        Ok(true)
    }

    // ------------------------------------------------------------ predecessor role (Query)

    /// 7.6 Query table (revision 9). `m` zero is a creation probe (5.3),
    /// also sent by a REPAIRING build (4.6).
    fn on_query(&mut self, _from: Ver, rec: Rec, m: Digest) -> R<Frame> {
        let idx = self.idx();
        let probe = m == 0;
        if probe {
            self.hit("5.3/probe-received");
        }
        let cack = |status, succ| Frame::CompleteAck {
            tid: (self.def.v, rec),
            m,
            status,
            succ,
            missing: vec![],
        };
        match idx.state.clone() {
            PState::Retired { to, m: rm, .. } if to == rec && rm == m && !probe => {
                // "once unlisted": a still-listed RETIRED build unlisted at
                // the start of this call, or answered nothing (4.2)
                self.hit("7.6q/RETIRED-to-querier-same-m");
                Ok(cack(CStatus::Noted, self.succ().highest()))
            }
            PState::Retired { to, .. }
                if probe && (to.v <= rec.v || self.p.mutant == Some(Mutant::Accept0x0CAbove)) =>
            {
                self.hit("7.6q/RETIRED/probe-retired-not-ahead-0x0C");
                if to.v > rec.v {
                    self.hit("mutant/0x0C-for-retired-to-above-querier");
                }
                Ok(cack(CStatus::RetiredNotAhead, self.succ().highest()))
            }
            PState::Sealed { target, m: sm, w } if target == rec && sm == m && !probe => {
                self.hit("7.6q/SEALED-toward-querier-same-m");
                if self.retire(&idx, target, m, w.taken_over)? {
                    Ok(cack(CStatus::Noted, self.succ().highest()))
                } else if matches!(self.idx().state, PState::Retired { .. }) {
                    // retired, but the list still names the partition:
                    // answer nothing in this call (4.2)
                    self.hit("4.2/retired-not-unlisted-no-answer");
                    Ok(ignored())
                } else {
                    Ok(cack(CStatus::StorageFailure, self.succ().highest()))
                }
            }
            PState::None { .. } if probe => self.none_probe(rec),
            PState::None { .. } => {
                self.hit("7.6q/NONE/query");
                self.accept_record(rec)?;
                // "answers 0x0B only if the record is there": a stored
                // non-withdrawal record at or above the querier's version,
                // which is what raises this build's creation bar against it.
                let s = self.succ();
                if s.current.is_some_and(|c| c.v >= rec.v) {
                    self.hit("7.6q/NONE-record-stored");
                    Ok(cack(CStatus::NoState, s.highest()))
                } else {
                    self.hit("7.6q/NONE-storage-failure");
                    Ok(cack(CStatus::StorageFailure, s.highest()))
                }
            }
            st => {
                self.hit("7.6q/anything-else");
                if matches!(st, PState::Retired { .. }) {
                    self.hit("7.6q/anything-else/RETIRED-elsewhere-or-other-m");
                    if probe {
                        self.hit("7.6q/RETIRED/probe-retired-above-0x07");
                    }
                }
                if matches!(st, PState::Sealed { .. }) && probe {
                    self.hit("7.6q/SEALED/probe-0x07");
                }
                if probe {
                    self.hit("5.3/probe-answered-state");
                }
                Ok(cack(CStatus::AnotherWriter, self.succ().highest()))
            }
        }
    }

    /// 7.6, creation-probe column, NONE (revision 9, F10): 0x0B only if it
    /// stores, or already holds as current, the querier's record; with a
    /// floor already at or above the querier's version, 0x03 when the floor
    /// comes from a withdrawal, else 0x07.
    fn none_probe(&mut self, rec: Rec) -> R<Frame> {
        self.hit("7.6q/NONE/probe");
        if self.p.mutant == Some(Mutant::NoState0x0BWithoutStoring) {
            self.hit("mutant/0x0B-without-storing");
            return Ok(self.qack(rec, CStatus::NoState));
        }
        let s = self.succ();
        if s.current == Some(rec) {
            // Labelled reading: "or already holds as current" (5.3) is
            // applied before the floor test of 7.6, so a NONE build that
            // holds the querier's record as current answers 0x0B even when
            // a later withdrawal is above it.
            self.hit("7.6q/NONE/probe-already-current-0x0B");
            if s.withdrawal.is_some_and(|w| w.v > rec.v) {
                self.hit("reading/0x0B-current-below-withdrawal");
            }
            return Ok(self.qack(rec, CStatus::NoState));
        }
        let cur = s.current.map(|r| r.v).unwrap_or(0);
        let wd = s.withdrawal.map(|r| r.v).unwrap_or(0);
        let floor = self.own().max(cur).max(wd);
        if floor >= rec.v {
            if wd >= cur && wd >= rec.v {
                self.hit("7.6q/NONE/probe-stopped-0x03");
                return Ok(self.qack(rec, CStatus::Stopped));
            }
            self.hit("7.6q/NONE/probe-higher-record-0x07");
            return Ok(self.qack(rec, CStatus::AnotherWriter));
        }
        self.accept_record(rec)?;
        let s = self.succ();
        if s.current == Some(rec) {
            self.hit("7.6q/NONE-record-stored");
            Ok(self.qack(rec, CStatus::NoState))
        } else {
            self.hit("7.6q/NONE-storage-failure");
            Ok(self.qack(rec, CStatus::StorageFailure))
        }
    }

    fn qack(&self, rec: Rec, status: CStatus) -> Frame {
        Frame::CompleteAck {
            tid: (self.def.v, rec),
            m: 0,
            status,
            succ: self.succ().highest(),
            missing: vec![],
        }
    }

    /// Section 6 row, awaiting: the answer to this build's Query from the
    /// build it took over from, at the m it took over at.
    fn on_query_answer(&mut self, status: CStatus) -> R<()> {
        let idx = self.idx();
        let PState::Writer(_) = &idx.state else {
            return Ok(());
        };
        let mut n = idx.clone();
        match status {
            CStatus::Noted | CStatus::NoState => {
                if let PState::Writer(w) = &mut n.state {
                    w.awaiting = false;
                }
                if self.commit(&n)? {
                    self.hit(&format!("6/query-answer/awaiting-cleared/{status:?}"));
                    self.notes.push(Note::AwaitingCleared);
                }
            }
            CStatus::AnotherWriter => {
                self.hit("6/query-answer/awaiting/AnotherWriter");
                n.problems |= PROBLEM_ANOTHER_WRITER;
                if n != idx {
                    self.commit(&n)?;
                }
            }
            s => self.hit(&format!("6/query-answer/awaiting/other/{s:?}")),
        }
        Ok(())
    }

    /// 5.3 step 3: the answer to a creation probe, applied in the call that
    /// delivers it.
    fn on_probe_answer(&mut self, p: Ver, status: CStatus) -> R<()> {
        let idx = self.idx();
        let PState::None {
            armed: Some(_),
            confirmed,
        } = &idx.state
        else {
            return Ok(());
        };
        match status {
            CStatus::NoState => {
                if confirmed.contains(&p) {
                    self.hit("5.3/confirmed-again");
                    return Ok(());
                }
                let mut n = idx.clone();
                if let PState::None { confirmed, .. } = &mut n.state {
                    confirmed.insert(p);
                }
                if self.commit(&n)? {
                    self.hit("5.3/confirmed");
                }
            }
            CStatus::RetiredNotAhead if self.p.mutant == Some(Mutant::CreationAccepts0x0C) => {
                self.hit("mutant/creation-accepted-0x0C");
                let mut n = idx.clone();
                if let PState::None { confirmed, .. } = &mut n.state {
                    confirmed.insert(p);
                }
                self.commit(&n)?;
            }
            CStatus::AnotherWriter | CStatus::RetiredNotAhead => {
                // The predecessor holds state: clear the arming. A creation
                // treats 0x0C like any answer showing state (5.3).
                if status == CStatus::RetiredNotAhead {
                    self.hit("5.3/creation-treats-0x0C-as-state");
                }
                let mut n = idx.clone();
                n.state = PState::none();
                if self.commit(&n)? {
                    self.hit("5.3/arming-cleared-by-state-answer");
                }
            }
            s => self.hit(&format!("5.3/probe-answer-other/{s:?}")),
        }
        Ok(())
    }

    // ------------------------------------------------------------ operations

    fn op(&mut self, op: Op) -> R<OpRes> {
        if let (Op::Reindex { slots }, PState::Repairing { .. }) = (&op, &self.idx().state) {
            return self.reindex(slots.clone(), false);
        }
        if let Op::Reindex { .. } = op {
            // only while problems bit 6 is set or REPAIRING (4.6)
            self.hit("4.6/reindex-refused-index-not-lost");
            return Ok(OpRes::Refused(8));
        }
        if op == Op::RepairPokes {
            return Ok(OpRes::Refused(5));
        }
        let idx = self.idx();
        let s = self.succ();
        let change = op.is_change();
        let mark = matches!(op, Op::RaiseMark { .. });
        let kind = if mark {
            "mark"
        } else if change {
            "change"
        } else {
            "read"
        };
        match &idx.state {
            PState::None { armed, confirmed } => {
                self.hit(&format!("5.1/NONE/{kind}"));
                if change && armed.is_some() {
                    let all = self.def.preds.iter().all(|p| confirmed.contains(p));
                    if self.creation_bar() {
                        self.hit("3/creation-bar-refused-create");
                    } else if !all {
                        self.hit("5.3/create-refused-unconfirmed");
                    } else if self.succ_malformed() {
                        self.hit("3/record-malformed-refused-create");
                    } else if self.succ().stopped()
                        && self.p.mutant != Some(Mutant::CreateWhileStopped)
                    {
                        self.hit("3/create-refused-stopped");
                    } else {
                        if !self.ensure_parts()? {
                            return Ok(OpRes::Refused(12));
                        }
                        let mut n = idx.clone();
                        n.state = PState::Writer(WFields::default());
                        if !self.commit(&n)? {
                            return Ok(OpRes::Refused(12));
                        }
                        self.hit("5.1/created");
                        if self.succ().stopped() {
                            self.hit("5.3/created-while-stopped");
                        }
                        if !self.def.preds.is_empty() {
                            self.hit("5.3/created-after-every-predecessor-confirmed");
                        }
                        self.notes.push(Note::Created);
                        return self.serve(op);
                    }
                }
                Ok(match s.successor() {
                    Some(c) => OpRes::Moved(c),
                    None => OpRes::NotHere,
                })
            }
            PState::Writer(w) => {
                self.hit(&format!(
                    "5.1/WRITER{}/{kind}",
                    if w.awaiting { "(awaiting)" } else { "" }
                ));
                if change && w.awaiting {
                    return Ok(OpRes::Busy);
                }
                self.serve(op)
            }
            PState::Sealed { .. } => {
                self.hit(&format!("5.1/SEALED/{kind}"));
                if change {
                    return Ok(OpRes::Busy);
                }
                self.serve(op)
            }
            PState::Receiving { .. } => {
                self.hit(&format!("5.1/RECEIVING/{kind}"));
                Ok(OpRes::NotHere)
            }
            PState::Retired { to, .. } => {
                self.hit(&format!("5.1/RETIRED/{kind}"));
                Ok(OpRes::Moved(*to))
            }
            PState::Repairing { .. } => {
                // reached with a malformed vault:succ (3): reads served,
                // changes refused (4.6)
                self.hit(&format!("5.1/REPAIRING/{kind}"));
                if change {
                    return Ok(OpRes::Refused(12));
                }
                self.serve(op)
            }
        }
    }

    fn serve(&mut self, op: Op) -> R<OpRes> {
        match op {
            Op::Export { slot } => Ok(match self.read_key(slot)? {
                None => OpRes::Absent,
                Some(e) => OpRes::Key(e.content),
            }),
            Op::Reindex { .. } | Op::RepairPokes => Ok(OpRes::Refused(5)),
            Op::PublicKey { slot } => Ok(match self.read_key(slot)? {
                None => OpRes::Absent,
                Some(e) if e.flagged => OpRes::Unusable,
                Some(e) => OpRes::Key(e.content),
            }),
            Op::Batch { slot, expected } => Ok(match self.read_key(slot)? {
                None => OpRes::Absent,
                Some(e) if e.flagged => OpRes::Unusable,
                Some(e) if e.content != expected => OpRes::Refused(14),
                Some(e) => OpRes::Key(e.content),
            }),
            Op::Generate { slot, seed } => {
                if self.read_key(slot)?.is_some() {
                    return Ok(OpRes::Refused(4));
                }
                self.write_key(slot, seed)
            }
            Op::Import {
                slot,
                seed,
                replace,
            } => match self.read_key(slot)? {
                Some(e) if e.content == seed && !e.flagged => Ok(OpRes::Key(seed)),
                Some(e) if e.content != seed && !replace => Ok(OpRes::Refused(4)),
                _ => self.write_key(slot, seed),
            },
            Op::Delete { slot } => {
                let idx = self.idx();
                let id = (KIND_KEY, slot);
                let Some(ie) = idx.entries.get(&id).copied() else {
                    return Ok(OpRes::Absent);
                };
                // revision 9, F11: both parity names, whether or not each
                // copy exists, in the first write
                let _ = ie;
                if !self.gc_add(&[SName::E(id, false), SName::E(id, true)])? {
                    return Ok(OpRes::Refused(12));
                }
                let mut n = idx.clone();
                n.entries.remove(&id);
                if self.commit(&n)? {
                    self.hit("ops/delete");
                    Ok(OpRes::Ok)
                } else {
                    Ok(OpRes::Refused(12))
                }
            }
            Op::PutExt { key, content } => {
                if !self.def.writes_unknown_kind {
                    self.hit("ops/unknown-op-refused");
                    return Ok(OpRes::Refused(10));
                }
                let e = Entry {
                    kind: KIND_UNKNOWN,
                    key,
                    flagged: false,
                    content,
                    ext: vec![0xE0, key as u8, content as u8],
                };
                if self.write_entry(e)? {
                    self.hit("ops/unknown-kind-written");
                    Ok(OpRes::Ok)
                } else {
                    Ok(OpRes::Refused(12))
                }
            }
            Op::RaiseMark { caller, rec } => {
                let id = (KIND_MARK, caller);
                let idx = self.idx();
                let cur = idx.entries.get(&id).copied();
                if let Some(ie) = cur {
                    if let Some(SVal::E(e)) = self.host.read(&SName::E(id, ie.parity)) {
                        if e.content >= rec {
                            return Ok(OpRes::Ok);
                        }
                    }
                }
                let e = Entry {
                    kind: KIND_MARK,
                    key: caller,
                    flagged: false,
                    content: rec,
                    ext: vec![],
                };
                if self.write_entry(e)? {
                    self.hit("9/mark-raised");
                    Ok(OpRes::Ok)
                } else {
                    Ok(OpRes::Refused(12))
                }
            }
        }
    }

    fn read_key(&mut self, slot: u16) -> R<Option<Entry>> {
        self.read_entry((KIND_KEY, slot))
    }

    fn write_key(&mut self, slot: u16, seed: u32) -> R<OpRes> {
        let e = Entry {
            kind: KIND_KEY,
            key: slot,
            flagged: false,
            content: seed,
            ext: vec![],
        };
        if self.write_entry(e)? {
            self.hit("ops/key-written");
            Ok(OpRes::Key(seed))
        } else {
            Ok(OpRes::Refused(12))
        }
    }

    /// Entry to the parity slot the index does not name, then the index.
    fn write_entry(&mut self, e: Entry) -> R<bool> {
        let idx = self.idx();
        let id = e.ident();
        if !idx.entries.contains_key(&id) && idx.entries.len() >= self.p.max_entries {
            self.hit("8/quota-refused");
            return Ok(false);
        }
        let par = idx.entries.get(&id).map(|x| !x.parity).unwrap_or(false);
        let old = idx.entries.get(&id).map(|x| SName::E(id, x.parity));
        // revision 9 (F11): a name vault:gc lists is processed before it is
        // written; the old parity copy goes to vault:gc (4.2)
        if !self.clear_gc_name(SName::E(id, par))? {
            self.hit("4.2/write-refused-gc-name-not-cleared");
            return Ok(false);
        }
        if !self.gc_old_copy(old, true)? {
            return Ok(false);
        }
        if !self.put(SName::E(id, par), SVal::E(e.clone()))? {
            return Ok(false);
        }
        let mut n = idx.clone();
        n.entries.insert(
            id,
            IdxEnt {
                parity: par,
                digest: e.digest(),
            },
        );
        if !self.commit(&n)? {
            return Ok(false);
        }
        self.gc_old_copy(old, false)?;
        Ok(true)
    }
}

/// Caller apps the domain accepts (caller marks, 9); Reindex computes their
/// mark names (4.6).
pub const NCALLERS: u16 = 3;

pub fn sname_kind(n: &SName) -> &'static str {
    match n {
        SName::Succ => "succ",
        SName::Parts => "parts",
        SName::Idx => "index",
        SName::E(..) => "entry",
        SName::X(_) => "progress",
        SName::Rx => "rx",
        SName::Gc => "gc",
    }
}

fn ignored() -> Frame {
    unreachable_reply()
}

/// Marker frame for "ignored: no reply". The world drops it. Kept as a frame
/// so the receiver role has a single return type.
fn unreachable_reply() -> Frame {
    Frame::Query {
        rec: Rec::build(0),
        m: 0,
    }
}

/// Whether a receiver reply is the "ignored" marker.
pub fn is_ignored(f: &Frame) -> bool {
    matches!(f, Frame::Query { rec, m: 0 } if rec.v == 0)
}
