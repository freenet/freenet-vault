//! One vault build as a pure state machine over its durable store
//! (sections 3 to 9 of the handover protocol, revision 10: the v1 base;
//! section 4.6 is v1.1 and not modelled).
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
    /// Labelled reading of 4.2 (revision 10): when the catch-all listing
    /// write ("any call that reads a valid WRITER or SEALED index for an
    /// unlisted partition adds the listing before doing anything else")
    /// fails, the call continues read-only (4.5 condition 4) and may still
    /// answer (true, the literal reading and the one most likely to fail),
    /// or answers nothing (false, as for an unlist that fails).
    pub catchall_fail_continues: bool,
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
            catchall_fail_continues: false,
        }
    }
}

/// The mutants of the 15.5 mutation check (revision 10 final text, the
/// mirror rule, plus the base mutants carried from revision 9; no repair
/// mutants, 4.6 is v1.1). The revision 9 mutant "direct read ignoring
/// vault:gc" is not carried: in revision 10 direct read never reads
/// vault:gc, so that variant is the correct behaviour.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mutant {
    // ---- carried base mutants (revision 9)
    /// Send Retired (or answer "retired") before unlisting; unlist at the
    /// next call.
    RetiredBeforeUnlist,
    /// Never unlist on retire.
    NeverUnlist,
    /// Re-list a RETIRED index (the catch-all lists it too).
    RelistRetired,
    /// List vault:parts before the first WRITER index write.
    PartsBeforeIndex,
    /// Drop names from vault:gc before they read as absent (the new list is
    /// written first, then the removals).
    GcDropBeforeAbsent,
    /// Arm and create while the domain is stopped.
    CreateWhileStopped,
    /// A NONE predecessor answers 0x0B to a creation probe without storing
    /// the record.
    NoState0x0BWithoutStoring,
    // ---- revision 10 (15.5, the mirror)
    /// Write the mirror (step 4) before the index commits (step 3).
    MirrorBeforeCommit,
    /// Write a new identity without first clearing both parity names.
    NoStep1,
    /// A Delete commits before its mirror reads back as absent (step 2 is
    /// skipped; gc removes both copies after the commit).
    DeleteCommitBeforeMirrorAbsent,
    /// gc deletes the mirror of a named identity (the revision 9 parity
    /// rule instead of the identity rule).
    GcDeletesNamedMirror,
    /// A receiver writes a mirror after its index commits.
    ReceiverMirrors,
    /// The sweep mirrors a named copy without checking the index digest.
    SweepUncheckedDigest,
    /// A sealed build runs the mirror sweep.
    SweepWhileSealed,
    /// Direct read serves a slot with one authenticating copy and the other
    /// missing.
    DirectReadSingleCopy,
    /// Direct read chooses between two disagreeing authenticating copies
    /// (the copy at parity 0).
    DirectReadChooses,
    /// Direct read ignores eflags and the key check (a flagged copy is
    /// served as a usable key).
    DirectReadIgnoresEflagsOrKey,
    /// Direct read answers Absent when no copy is present.
    DirectReadAbsent,
    /// List a NONE (with an index) or RECEIVING index.
    ListNoneOrReceiving,
    /// Answer a creating change, or "accepted", before the listing reads
    /// back (a failed listing is ignored).
    AnswerBeforeListing,
    /// Treat a malformed index as NONE while the partition is listed.
    MalformedListedIsNone,
    /// Treat a malformed index as index lost while the partition is
    /// unlisted (the revision 9 rule).
    MalformedUnlistedIsLost,
    /// Write over a secret that reads as absent without removing it first.
    WriteWithoutRemove,
    /// Revision 10.1 (G2): direct-read in 4.5 condition 3 although
    /// vault:succ holds a non-withdrawal record above OWN_VERSION.
    DirectReadDespiteSuccessor,
}

impl Mutant {
    /// The revision 10.1 15.5 list (M1 removed GcDropBeforeAbsent,
    /// GcDeletesNamedMirror and ReceiverMirrors; SweepWhileSealed was
    /// never in 15.5) plus the G2 mutant. The removed ones stay in
    /// EQUIVALENT for information.
    pub const EQUIVALENT: [Mutant; 4] = [
        Mutant::GcDropBeforeAbsent,
        Mutant::GcDeletesNamedMirror,
        Mutant::ReceiverMirrors,
        Mutant::SweepWhileSealed,
    ];
    pub const ALL: [Mutant; 20] = [
        Mutant::RetiredBeforeUnlist,
        Mutant::NeverUnlist,
        Mutant::RelistRetired,
        Mutant::PartsBeforeIndex,
        Mutant::CreateWhileStopped,
        Mutant::NoState0x0BWithoutStoring,
        Mutant::MirrorBeforeCommit,
        Mutant::NoStep1,
        Mutant::DeleteCommitBeforeMirrorAbsent,
        Mutant::SweepUncheckedDigest,
        Mutant::DirectReadSingleCopy,
        Mutant::DirectReadChooses,
        Mutant::DirectReadIgnoresEflagsOrKey,
        Mutant::DirectReadAbsent,
        Mutant::ListNoneOrReceiving,
        Mutant::AnswerBeforeListing,
        Mutant::MalformedListedIsNone,
        Mutant::MalformedUnlistedIsLost,
        Mutant::WriteWithoutRemove,
        Mutant::DirectReadDespiteSuccessor,
    ];
    pub fn name(self) -> String {
        format!("{self:?}")
    }
    pub fn parse(s: &str) -> Option<Mutant> {
        Mutant::ALL
            .iter()
            .chain(Mutant::EQUIVALENT.iter())
            .copied()
            .find(|m| m.name() == s)
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
    /// The mirror sweep (7.7) has finished since this build started or
    /// took over. Volatile: a restart sweeps again.
    pub swept: bool,
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
}

impl Op {
    pub fn is_change(&self) -> bool {
        !matches!(
            self,
            Op::PublicKey { .. } | Op::Batch { .. } | Op::Export { .. }
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
    /// 4.3 (decided 2026-11-24): an entry the index names that reads as
    /// absent answers Missing and stays in the index.
    Missing,
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
    /// Revision 10, 4.2: step k of an entry write of this identity is about
    /// to happen (1 clear both parity names, 2 the entry, 3 the index, 4 the
    /// mirror). Receivers: 1, 2 and 3 only.
    EntryStep(u8, Ident),
    /// Step 4 of an entry write landed: both copies hold the new bytes.
    Mirrored(Ident),
    /// Revision 10: step k of a Delete of this identity is about to happen
    /// (1 vault:gc, 2 remove the mirror, 3 the index, 4 gc processing).
    DeleteStep(u8, Ident),
    /// The mirror sweep (7.7) finished in this call.
    SweepDone,
    /// The partition was listed in vault:parts in this call (4.2).
    Listed,
    /// An injected write fault fired on this write or removal (coverage of
    /// the step it hit).
    Faulted,
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
    /// 4.5 (revision 10), as this build reads it: the index absent while
    /// vault:parts lists the partition; the index malformed while
    /// vault:parts lists the partition or does not read as a valid list;
    /// vault:parts malformed and the index absent. A malformed index while
    /// vault:parts reads as a valid list without the partition is NONE.
    fn index_lost(&self) -> bool {
        let parts = self.host.read(&SName::Parts);
        let idx = self.host.read(&SName::Idx);
        let listed = matches!(parts, Some(SVal::Parts));
        match idx {
            Some(SVal::Idx(_)) => false,
            None => listed || matches!(parts, Some(SVal::Garbled)),
            Some(_) => {
                let m = self.p.mutant;
                if m == Some(Mutant::MalformedUnlistedIsLost) {
                    return true;
                }
                if listed && m == Some(Mutant::MalformedListedIsNone) {
                    return false;
                }
                listed || !crate::store::parts_valid_list(parts.as_ref())
            }
        }
    }
    fn parts_listed(&self) -> bool {
        matches!(self.host.read(&SName::Parts), Some(SVal::Parts))
    }
    /// Mutant PartsBeforeIndex: vault:parts before the first WRITER index
    /// write (the revision 8 default ordering).
    fn ensure_parts(&mut self) -> R<bool> {
        if self.p.mutant != Some(Mutant::PartsBeforeIndex) || self.parts_listed() {
            return Ok(true);
        }
        self.hit("mutant/parts-written-before-index");
        self.put(SName::Parts, SVal::Parts)
    }
    /// Which index states are listed (revision 10, A1): WRITER and SEALED
    /// only. Mutant ListNoneOrReceiving also lists a NONE index that exists
    /// and a RECEIVING index.
    fn listable(&self, st: &PState) -> bool {
        match st {
            PState::Writer(_) | PState::Sealed { .. } => true,
            PState::None { .. } | PState::Receiving { .. } => {
                self.p.mutant == Some(Mutant::ListNoneOrReceiving)
            }
            PState::Retired { .. } => false,
        }
    }
    /// 4.2 (revision 10): after an index write that makes the partition
    /// WRITER or SEALED, read the index back and only then list the
    /// partition, and read that back. Ok(true) once listed.
    fn list_after_index(&mut self, new: &Index) -> R<bool> {
        if self.parts_listed() {
            return Ok(true);
        }
        if !self.listable(&new.state) {
            return Ok(false);
        }
        if !matches!(new.state, PState::Writer(_) | PState::Sealed { .. }) {
            self.hit("mutant/none-or-receiving-index-listed");
        }
        if self.idx_raw() != Some(new.clone()) {
            self.hit("4.2/first-index-read-back-failed-not-listed");
            return Ok(false);
        }
        self.notes.push(Note::Listed);
        if !self.put(SName::Parts, SVal::Parts)? {
            self.hit("4.2/listing-write-failed");
            return Ok(false);
        }
        let ok = self.parts_listed();
        if ok {
            self.hit("4.2/listed-after-first-writer-index");
        }
        Ok(ok)
    }
    /// The index as stored, if it decodes.
    fn idx_raw(&self) -> Option<Index> {
        match self.host.read(&SName::Idx) {
            Some(SVal::Idx(i)) => Some(i),
            _ => None,
        }
    }
    /// 4.2 (revision 9, F7; revision 10: the list is never removed):
    /// rewrite vault:parts without the partition and read that back.
    /// Ok(true) once the list no longer names it.
    fn unlist(&mut self) -> R<bool> {
        match self.host.read(&SName::Parts) {
            Some(SVal::Parts) => {}
            None => {
                // reads as absent (never written, or undecryptable): it does
                // not name the partition; nothing is written
                self.hit("4.2/unlist-parts-absent-no-write");
                return Ok(true);
            }
            _ => return Ok(true),
        }
        if !self.put(SName::Parts, SVal::PartsEmpty)? {
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
    /// write the call makes no further write (4.2, 4.5). Revision 10 (F17):
    /// a secret that reads as absent is removed first (core #6323 refuses a
    /// write over an undecryptable blob and allows a removal).
    fn put(&mut self, n: SName, v: SVal) -> R<bool> {
        if self.ro {
            self.hit("4.5/write-refused-after-failed-write");
            return Ok(false);
        }
        if self.host.read(&n).is_none() {
            let undecryptable =
                matches!(self.host.store.secrets.get(&n), Some(SVal::Undecryptable));
            if n == SName::Idx && self.parts_listed() {
                // never reached: a listed partition whose index reads as
                // absent is index-lost and makes no write (4.5)
                self.hit("4.2/BUG-index-of-listed-partition-written-while-absent");
            }
            if self.p.mutant == Some(Mutant::WriteWithoutRemove) {
                if undecryptable {
                    self.hit("mutant/write-without-remove");
                }
            } else {
                if undecryptable {
                    self.hit(&format!("4.2/remove-before-write/{}", sname_kind(&n)));
                }
                if !self.del(n)? {
                    return Ok(false);
                }
            }
        }
        let fired = self.host.faults.fired.len();
        let r = self.host.set(n, v);
        if self.host.faults.fired.len() > fired {
            self.notes.push(Note::Faulted);
        }
        match r {
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
        let fired = self.host.faults.fired.len();
        let r = self.host.del(n);
        if self.host.faults.fired.len() > fired {
            self.notes.push(Note::Faulted);
        }
        match r {
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
    /// the disk holds what was intended. After a successful write that
    /// makes the partition WRITER or SEALED, list it (revision 10); the
    /// caller checks `parts_listed` before any answer that depends on it.
    fn commit(&mut self, new: &Index) -> R<bool> {
        if self.put(SName::Idx, SVal::Idx(new.clone()))? {
            if self.p.mutant != Some(Mutant::PartsBeforeIndex) {
                self.list_after_index(new)?;
            }
            return Ok(true);
        }
        self.hit("4.2/commit-failed-read-back");
        let landed = self.idx_raw().as_ref() == Some(new);
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

    /// Whether the committed index keeps this name (revision 10, 4.2: gc
    /// deletes by identity; both parity names of a named identity are in
    /// use, one as the copy and one as the mirror). Mutant
    /// GcDeletesNamedMirror keeps only the named parity.
    fn gc_keeps(&mut self, idx: &Index, n: &SName) -> bool {
        match n {
            SName::E(id, par) => match idx.entries.get(id) {
                None => false,
                Some(e) if e.parity == *par => true,
                Some(_) => {
                    if self.p.mutant == Some(Mutant::GcDeletesNamedMirror) {
                        self.hit("mutant/gc-deletes-named-mirror");
                        false
                    } else {
                        true
                    }
                }
            },
            _ => false,
        }
    }

    /// 4.2 (revision 10): a name in vault:gc is deleted only if the
    /// committed index, read at deletion time, does not name its identity;
    /// a name the committed index still uses is dropped from vault:gc and
    /// kept. A name leaves vault:gc otherwise only once its secret reads as
    /// absent after removal.
    fn process_gc(&mut self) -> R<()> {
        let gc = self.gc_set();
        if gc.is_empty() {
            return Ok(());
        }
        self.hit("4.2/gc-processed");
        if self.p.mutant == Some(Mutant::GcDropBeforeAbsent) {
            self.hit("mutant/gc-list-rewritten-before-removals");
            let idx = self.idx();
            let mut remaining = BTreeSet::new();
            for n in &gc {
                if self.gc_keeps(&idx, n) {
                    continue;
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
            if self.gc_keeps(&idx, &n) {
                self.hit("4.2/gc-dropped-named-by-commit");
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
        // rule (c) of the mutation check needs to see the mutated branch
        if matches!(self.host.read(&SName::Idx), Some(v) if !matches!(v, SVal::Idx(_))) {
            let parts = self.host.read(&SName::Parts);
            let listed = matches!(parts, Some(SVal::Parts));
            let valid = crate::store::parts_valid_list(parts.as_ref());
            match self.p.mutant {
                Some(Mutant::MalformedListedIsNone) if listed => {
                    self.hit("mutant/malformed-listed-index-read-as-none");
                }
                Some(Mutant::MalformedUnlistedIsLost) if !listed && valid => {
                    self.hit("mutant/malformed-unlisted-index-read-as-lost");
                }
                _ => {}
            }
        }
        if self.index_lost() {
            return self.lost(input);
        }
        if matches!(self.host.read(&SName::Idx), Some(v) if !matches!(v, SVal::Idx(_))) {
            // revision 10, F14: a malformed index of an unlisted partition
            // is NONE
            self.hit("4.5/malformed-index-unlisted-reads-none");
        }
        if !self.fix_listing()? {
            self.hit("4.2/listing-fix-failed-answers-nothing");
            return Ok(Reply::None);
        }
        let record_bad = self.succ_malformed();
        self.process_gc()?;
        if record_bad {
            return self.record_malformed(input);
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

    /// 4.2: a RETIRED build still listed (a crash between the two writes)
    /// unlists before answering anything, and answers nothing in a call
    /// where that write fails; any call that reads a valid WRITER or
    /// SEALED index for an unlisted partition adds the listing before doing
    /// anything else (revision 10: only those states). Ok(false): answer
    /// nothing in this call.
    fn fix_listing(&mut self) -> R<bool> {
        let Some(i) = self.idx_raw() else {
            return Ok(true);
        };
        let listed = self.parts_listed();
        let retired = matches!(i.state, PState::Retired { .. });
        let m = self.p.mutant;
        if retired {
            if listed && m != Some(Mutant::NeverUnlist) && m != Some(Mutant::RelistRetired) {
                self.hit("4.2/retired-still-listed-unlists-first");
                return self.unlist();
            }
            if !listed && m == Some(Mutant::RelistRetired) {
                self.hit("mutant/retired-index-relisted");
                self.put(SName::Parts, SVal::Parts)?;
            }
            return Ok(true);
        }
        if listed || !self.listable(&i.state) {
            return Ok(true);
        }
        if matches!(i.state, PState::None { .. } | PState::Receiving { .. }) {
            self.hit("mutant/none-or-receiving-index-listed");
        } else {
            self.hit("4.2/valid-index-unlisted-listed-first");
        }
        self.notes.push(Note::Listed);
        if self.put(SName::Parts, SVal::Parts)? && self.parts_listed() {
            return Ok(true);
        }
        self.hit("4.2/catch-all-listing-failed");
        // a failure leaves the rest of the call read-only (4.5 condition 4)
        if self.p.catchall_fail_continues {
            self.hit("reading/catch-all-listing-failed-call-continues");
            Ok(true)
        } else {
            Ok(false)
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
        match self.host.read(&SName::Idx) {
            None => self.hit("4.5/index-absent-while-listed"),
            Some(_) if self.parts_listed() => self.hit("4.5/malformed-index-listed-lost"),
            Some(_) => self.hit("4.5/malformed-index-parts-not-valid-list-lost"),
        }
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
            Input::Op(op) => {
                // revision 10.1 (G2): 4.5 condition 3 with a higher
                // successor record answers Moved and never direct-reads
                if let Some(r) = crate::store::g2_moved(self.host.store, self.own()) {
                    if self.p.mutant == Some(Mutant::DirectReadDespiteSuccessor) {
                        if !op.is_change() {
                            self.hit("mutant/direct-read-despite-successor");
                        }
                    } else {
                        self.hit(if self.host.read(&SName::Idx).is_some() {
                            "4.5/g2b-condition-2-successor-moved"
                        } else {
                            "4.5/g2-condition-3-successor-moved"
                        });
                        return Ok(Reply::Op(OpRes::Moved(r)));
                    }
                }
                self.lost_op(op).map(Reply::Op)
            }
        }
    }

    /// 4.5 direct-read rule (revision 10 final, the mirror): read both
    /// parity copies; a copy authenticates if it reads as present and
    /// parses exactly as a 12.2 entry of kind 0x01, eflags 0, key equal to
    /// the slot, content_len 32 and an ext_len that fits. Served only when
    /// both authenticate and their bytes are identical; otherwise storage
    /// failure (Err). Never Absent (Ok(None) only under mutant
    /// DirectReadAbsent). vault:gc is never read.
    fn direct_read(&mut self, slot: u16) -> Result<Option<Entry>, ()> {
        let id = (KIND_KEY, slot);
        let m = self.p.mutant;
        let ign = m == Some(Mutant::DirectReadIgnoresEflagsOrKey);
        let c0 = self.host.read(&SName::E(id, false));
        let c1 = self.host.read(&SName::E(id, true));
        let auth = |v: &Option<SVal>| -> Option<Entry> {
            match v {
                Some(SVal::E(e))
                    if e.kind == KIND_KEY && (ign || (!e.flagged && e.key == slot)) =>
                {
                    Some(e.clone())
                }
                _ => None,
            }
        };
        let (a0, a1) = (auth(&c0), auth(&c1));
        if ign {
            let strict = |v: &Option<SVal>| matches!(v, Some(SVal::E(e)) if e.kind == KIND_KEY && !e.flagged && e.key == slot);
            if a0.is_some() && a1.is_some() && (!strict(&c0) || !strict(&c1)) {
                self.hit("mutant/direct-read-ignored-eflags-or-key");
            }
        }
        match (&a0, &a1) {
            (Some(x), Some(y)) if x == y => {
                self.hit("4.5/direct-read-served");
                let mut e = x.clone();
                if ign {
                    e.flagged = false;
                }
                return Ok(Some(e));
            }
            (Some(x), Some(_)) => {
                if m == Some(Mutant::DirectReadChooses) {
                    self.hit("mutant/direct-read-chose-between-copies");
                    return Ok(Some(x.clone()));
                }
                self.hit("4.5/direct-read-unavailable/disagreement");
            }
            (Some(x), None) | (None, Some(x)) => {
                let other = if a0.is_some() { &c1 } else { &c0 };
                if m == Some(Mutant::DirectReadSingleCopy) && other.is_none() {
                    self.hit("mutant/direct-read-served-single-copy");
                    return Ok(Some(x.clone()));
                }
                self.hit(if other.is_none() {
                    "4.5/direct-read-unavailable/missing-copy"
                } else {
                    "4.5/direct-read-unavailable/authentication-failure"
                });
            }
            (None, None) => {
                if c0.is_none() && c1.is_none() {
                    if m == Some(Mutant::DirectReadAbsent) {
                        self.hit("mutant/direct-read-answered-absent");
                        return Ok(None);
                    }
                    self.hit("4.5/direct-read-unavailable/missing-copy");
                    self.hit("4.5/direct-read-unavailable/no-copy");
                } else {
                    self.hit("4.5/direct-read-unavailable/authentication-failure");
                }
            }
        }
        self.hit("4.5/direct-read-storage-failure");
        Err(())
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
            _ => {
                self.hit("4.5/lost/change-refused");
                Ok(OpRes::Refused(12))
            }
        }
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
        let sweep_due = !self.vol.swept
            && self.parts_listed()
            && (matches!(idx.state, PState::Writer(_))
                || (self.p.mutant == Some(Mutant::SweepWhileSealed)
                    && matches!(idx.state, PState::Sealed { .. })));
        !self.gc_set().is_empty()
            || sweep_due
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
                        if self.succ().stopped() {
                            self.hit("mutant/armed-while-stopped");
                        }
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
        // revision 10, 7.7: the mirror sweep, until it has finished since
        // this build started or took over (not while sealed)
        self.sweep()?;
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
                if let Ok(Some(e)) = self.read_entry(id)? {
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

    /// 4.3 read with digest check. Ok(Err(())) is Missing: an entry the
    /// index names that reads as absent (it may be an undecryptable blob,
    /// core #6323) answers Missing and is NOT dropped from the index
    /// (decided 2026-11-24 after review round 6).
    fn read_entry(&mut self, id: Ident) -> R<Result<Option<Entry>, ()>> {
        let idx = self.idx();
        let Some(ie) = idx.entries.get(&id).copied() else {
            return Ok(Ok(None));
        };
        let val = self.host.read(&SName::E(id, ie.parity));
        if let Some(SVal::E(e)) = &val {
            if e.digest() == ie.digest {
                return Ok(Ok(Some(e.clone())));
            }
        }
        if val.is_none() {
            self.hit("4.3/entry-absent-answers-missing-kept");
            return Ok(Err(()));
        }
        let sealed = matches!(idx.state, PState::Sealed { .. });
        if sealed {
            // Nothing is rewritten or removed while sealed (4.3). The model
            // copies the bytes as they are on disk.
            self.hit("4.3/corrupt-while-sealed");
            return Ok(match val {
                Some(SVal::E(e)) => {
                    self.notes.push(Note::SealedCorruptSent);
                    Ok(Some(e))
                }
                _ => Err(()),
            });
        }
        let mut n = idx.clone();
        match val {
            Some(SVal::E(e)) => {
                self.hit("4.3/corrupt-rewritten-flagged");
                let f = Entry { flagged: true, ..e };
                // revision 10: the same four steps as every entry write
                if self.write_entry_steps(f.clone(), &mut n)? {
                    Ok(Ok(Some(f)))
                } else {
                    Ok(Err(()))
                }
            }
            _ => {
                self.hit("4.3/corrupt-unparseable-removed");
                self.gc_add(&[SName::E(id, ie.parity)])?;
                n.entries.remove(&id);
                n.lost = n.lost.saturating_add(1);
                n.problems |= PROBLEM_CORRUPT;
                if self.commit(&n)? {
                    self.process_gc()?;
                }
                Ok(Ok(None))
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
        if !self.commit(&n)? {
            return Ok(false);
        }
        self.process_gc()?;
        Ok(true)
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
        // revision 10, 4.2: a receiver writes one copy per entry, to the
        // parity its index does not name, applying step 1 to identities its
        // index does not name (0x13 if a parity name will not clear); it
        // never mirrors
        let mut written: Vec<Entry> = vec![];
        for (i, e, par) in &plan {
            let id = e.ident();
            let ok = (idx.entries.contains_key(&id) || self.clear_both(id)?) && {
                self.notes.push(Note::EntryStep(2, id));
                self.put(SName::E(id, *par), SVal::E(e.clone()))?
            };
            if ok {
                idx.entries.insert(
                    id,
                    IdxEnt {
                        parity: *par,
                        digest: e.digest(),
                    },
                );
                written.push(e.clone());
                self.hit("7.2/outcome-stored");
                self.hit("4.2/receiver/single-copy-written");
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
        if let Some(e) = written.first() {
            self.notes.push(Note::EntryStep(3, e.ident()));
        }
        if !self.commit(&idx)? {
            let disk = self.idx();
            for o in outcomes.iter_mut() {
                if o.1 == Outcome::Stored && !disk.entries.values().any(|x| x.digest == o.0) {
                    o.1 = Outcome::StorageFailure;
                }
            }
        } else {
            if self.p.mutant == Some(Mutant::ReceiverMirrors) {
                for e in &written {
                    let id = e.ident();
                    let par = idx.entries[&id].parity;
                    self.hit("mutant/receiver-wrote-mirror");
                    if !self.put(SName::E(id, !par), SVal::E(e.clone()))? {
                        break;
                    }
                }
            }
            self.process_gc()?;
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
            self.ensure_parts()?;
            if self.commit(&n)? {
                self.hit("7.4/took-over");
                // the new writer mirrors what it took over (7.7)
                self.vol.swept = false;
                self.notes.push(Note::TookOver { from, m });
                // revision 10, F16: "accepted" leaves only after the
                // partition is listed and the listing reads back; otherwise
                // no answer (the sender resends Complete)
                if !self.parts_listed() {
                    if self.p.mutant == Some(Mutant::AnswerBeforeListing) {
                        self.hit("mutant/accepted-before-listing");
                    } else {
                        self.hit("4.2/take-over-not-listed-no-answer");
                        return Ok(ignored());
                    }
                }
                self.process_gc()?;
                Ok(cack(CStatus::Accepted, vec![]))
            } else {
                Ok(cack(CStatus::StorageFailure, vec![]))
            }
        } else {
            if !drop.is_empty() && self.commit(&n)? {
                self.process_gc()?;
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
            Some(Mutant::NeverUnlist) | Some(Mutant::RelistRetired) => {
                if self.parts_listed() {
                    self.hit("mutant/retired-left-listed");
                }
            }
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
                        // revision 10, v1: every creation probe
                        self.hit("7.6q/RETIRED/probe-0x07");
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
            CStatus::AnotherWriter => {
                // The predecessor holds state: clear the arming.
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
                        if self.succ().stopped() {
                            self.hit("mutant/created-while-stopped");
                        }
                        if !self.ensure_parts()? {
                            return Ok(OpRes::Refused(12));
                        }
                        let mut n = idx.clone();
                        n.state = PState::Writer(WFields::default());
                        if !self.commit(&n)? {
                            return Ok(OpRes::Refused(12));
                        }
                        self.hit("5.1/created");
                        self.notes.push(Note::Created);
                        // revision 10: a creating change answers
                        // Refused(12) if the listing fails
                        if !self.parts_listed() {
                            if self.p.mutant == Some(Mutant::AnswerBeforeListing) {
                                self.hit("mutant/creating-change-before-listing");
                            } else {
                                self.hit("4.2/creation-not-listed-refused-12");
                                return Ok(OpRes::Refused(12));
                            }
                        }
                        if self.succ().stopped() {
                            self.hit("5.3/created-while-stopped");
                        }
                        if !self.def.preds.is_empty() {
                            self.hit("5.3/created-after-every-predecessor-confirmed");
                        }
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
        }
    }

    fn serve(&mut self, op: Op) -> R<OpRes> {
        match op {
            Op::Export { slot } => Ok(match self.read_key(slot)? {
                Err(()) => OpRes::Missing,
                Ok(None) => OpRes::Absent,
                Ok(Some(e)) => OpRes::Key(e.content),
            }),
            Op::PublicKey { slot } => Ok(match self.read_key(slot)? {
                Err(()) => OpRes::Missing,
                Ok(None) => OpRes::Absent,
                Ok(Some(e)) if e.flagged || self.corrupt_named(&e) => OpRes::Unusable,
                Ok(Some(e)) => OpRes::Key(e.content),
            }),
            Op::Batch { slot, expected } => Ok(match self.read_key(slot)? {
                Err(()) => OpRes::Missing,
                Ok(None) => OpRes::Absent,
                Ok(Some(e)) if e.flagged || self.corrupt_named(&e) => OpRes::Unusable,
                Ok(Some(e)) if e.content != expected => OpRes::Refused(14),
                Ok(Some(e)) => OpRes::Key(e.content),
            }),
            Op::Generate { slot, seed } => match self.read_key(slot)? {
                Err(()) => Ok(OpRes::Missing),
                Ok(Some(_)) => Ok(OpRes::Refused(4)),
                Ok(None) => self.write_key(slot, seed),
            },
            Op::Import {
                slot,
                seed,
                replace,
            } => match self.read_key(slot)? {
                Ok(Some(e)) if e.content == seed && !e.flagged => Ok(OpRes::Key(seed)),
                Ok(Some(e)) if e.content != seed && !replace => Ok(OpRes::Refused(4)),
                _ => self.write_key(slot, seed),
            },
            Op::Delete { slot } => {
                let idx = self.idx();
                let id = (KIND_KEY, slot);
                if !idx.entries.contains_key(&id) {
                    return Ok(OpRes::Absent);
                }
                // 4.2 (revision 10, F15): (1) one vault:gc write listing both
                // parity names; (2) remove the mirror and read it back as
                // absent; (3) commit; (4) gc removes the other copy
                let named = idx.entries[&id].parity;
                self.notes.push(Note::DeleteStep(1, id));
                if !self.gc_add(&[SName::E(id, false), SName::E(id, true)])? {
                    return Ok(OpRes::Refused(12));
                }
                if self.p.mutant == Some(Mutant::DeleteCommitBeforeMirrorAbsent) {
                    if self.host.read(&SName::E(id, !named)).is_some() {
                        self.hit("mutant/delete-committed-before-mirror-absent");
                    }
                } else {
                    self.notes.push(Note::DeleteStep(2, id));
                    let mn = SName::E(id, !named);
                    if !self.del(mn)? || self.host.read(&mn).is_some() {
                        self.hit("4.2/delete/step-2-refused");
                        return Ok(OpRes::Refused(12));
                    }
                }
                let mut n = idx.clone();
                n.entries.remove(&id);
                self.notes.push(Note::DeleteStep(3, id));
                if self.commit(&n)? {
                    self.hit("ops/delete");
                    self.notes.push(Note::DeleteStep(4, id));
                    self.process_gc()?;
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

    /// 4.3: while sealed a corrupt slot is not rewritten and answers
    /// Unusable(corrupt); read_entry hands back the bytes on disk for
    /// copying, so a digest that differs from the index marks it.
    fn corrupt_named(&mut self, e: &Entry) -> bool {
        let bad = self.idx().entries.get(&e.ident()).map(|x| x.digest) != Some(e.digest());
        if bad {
            self.hit("4.3/sealed-corrupt-slot-answers-unusable");
        }
        bad
    }

    fn read_key(&mut self, slot: u16) -> R<Result<Option<Entry>, ()>> {
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

    /// A change or mark raise (4.2).
    fn write_entry(&mut self, e: Entry) -> R<bool> {
        let mut n = self.idx();
        let id = e.ident();
        if !n.entries.contains_key(&id) && n.entries.len() >= self.p.max_entries {
            self.hit("8/quota-refused");
            return Ok(false);
        }
        self.write_entry_steps(e, &mut n)
    }

    /// Revision 10, 4.2 step 1: before writing an identity the index does
    /// not name, remove both of its parity names and read each back as
    /// absent. Ok(false): a name still reads as present, or a removal
    /// failed (the change is refused with storage failure).
    fn clear_both(&mut self, id: Ident) -> R<bool> {
        if self.p.mutant == Some(Mutant::NoStep1) {
            if [false, true]
                .iter()
                .any(|p| self.host.store.secrets.contains_key(&SName::E(id, *p)))
            {
                self.hit("mutant/no-step-1-leftover-kept");
            }
            return Ok(true);
        }
        self.notes.push(Note::EntryStep(1, id));
        for par in [false, true] {
            let n = SName::E(id, par);
            if self.host.store.secrets.contains_key(&n) {
                self.hit("4.2/step-1/leftover-found");
            }
            if !self.del(n)? {
                self.hit("4.2/step-1/removal-failed-refused");
                return Ok(false);
            }
            if self.host.read(&n).is_some() {
                self.hit("4.2/step-1/still-present-refused");
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Revision 10, 4.2: an entry write by a listed build takes four steps:
    /// (1) if the index does not name the identity, clear both parity names
    /// with read-back; (2) the entry, to the parity the index does not name;
    /// (3) the index, read back; (4) the same bytes to the other parity (the
    /// mirror). The answer depends on step 3 only: a failed step 4 leaves
    /// the slot served from the index. `n` is the index to commit (its
    /// other fields already set by the caller).
    fn write_entry_steps(&mut self, e: Entry, n: &mut Index) -> R<bool> {
        let id = e.ident();
        let named = n.entries.get(&id).map(|x| x.parity);
        let par = named.map(|p| !p).unwrap_or(false);
        let new = SName::E(id, par);
        let mirror = SName::E(id, !par);
        let m = self.p.mutant;
        if named.is_none() && !self.clear_both(id)? {
            return Ok(false);
        }
        self.notes.push(Note::EntryStep(2, id));
        if !self.put(new, SVal::E(e.clone()))? {
            return Ok(false);
        }
        n.entries.insert(
            id,
            IdxEnt {
                parity: par,
                digest: e.digest(),
            },
        );
        if e.flagged {
            n.problems |= PROBLEM_CORRUPT;
        }
        if m == Some(Mutant::MirrorBeforeCommit) {
            self.hit("mutant/mirror-before-commit");
            self.notes.push(Note::EntryStep(4, id));
            if !self.put(mirror, SVal::E(e.clone()))? {
                return Ok(false);
            }
        }
        self.notes.push(Note::EntryStep(3, id));
        if !self.commit(n)? {
            return Ok(false);
        }
        if m != Some(Mutant::MirrorBeforeCommit) {
            self.notes.push(Note::EntryStep(4, id));
            if self.put(mirror, SVal::E(e.clone()))? {
                self.hit("4.2/entry-write/step-4");
                self.notes.push(Note::Mirrored(id));
            } else {
                self.hit("4.2/entry-write/mirror-failed-committed");
            }
        } else {
            self.notes.push(Note::Mirrored(id));
        }
        Ok(true)
    }

    /// 7.7 (revision 10): the mirror sweep of a listed, unsealed build. For
    /// each identity the index names, read both copies; where the mirror is
    /// missing or differs, write it from the named copy after checking that
    /// copy against the index digest. Progress is volatile.
    fn sweep(&mut self) -> R<()> {
        if self.vol.swept || !self.parts_listed() {
            return Ok(());
        }
        let idx = self.idx();
        match idx.state {
            PState::Writer(_) => {}
            PState::Sealed { .. } if self.p.mutant == Some(Mutant::SweepWhileSealed) => {
                self.hit("mutant/sweep-while-sealed");
            }
            _ => return Ok(()),
        }
        for (id, ie) in &idx.entries {
            let named = self.host.read(&SName::E(*id, ie.parity));
            let mirror = SName::E(*id, !ie.parity);
            let mv = self.host.read(&mirror);
            if mv.is_some() && mv == named {
                continue;
            }
            let ok = match &named {
                Some(SVal::E(e)) => {
                    if e.digest() == ie.digest {
                        true
                    } else if self.p.mutant == Some(Mutant::SweepUncheckedDigest) {
                        self.hit("mutant/sweep-mirrored-unchecked-copy");
                        true
                    } else {
                        false
                    }
                }
                _ => false,
            };
            if !ok {
                self.hit("7.7/sweep-skipped-named-copy-fails-digest");
                continue;
            }
            if !self.put(mirror, named.clone().unwrap())? {
                self.hit("7.7/sweep-write-failed");
                return Ok(());
            }
            self.hit("7.7/sweep-repair");
        }
        if self.host.poisoned.get() {
            // a failed read poisons the call (4.0): its reads may have
            // returned nothing, so the sweep has not finished
            return Ok(());
        }
        self.vol.swept = true;
        self.notes.push(Note::SweepDone);
        self.hit("7.7/sweep-finished");
        Ok(())
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
