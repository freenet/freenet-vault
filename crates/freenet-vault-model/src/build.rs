//! One vault build as a pure state machine over its durable store
//! (sections 3 to 9 of the handover protocol, revision 7).
//!
//! Every call starts from the committed store; the only volatile state is
//! the in-flight set of 7.1, which a crash clears. Every durable write goes
//! through [`Host`], so a crash can cut between any two writes.

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
    pub spec: SpecReading,
}

/// Places where the document, read literally, leaves a gap. The default is
/// the literal reading; each switch exists only so that a finding can be
/// confirmed by flipping it, and is reported with the finding. Gate runs use
/// the default.
#[derive(Clone, Debug, Default)]
pub struct SpecReading {
    /// Section 6 accepts Ack/CompleteAck only from S(current) or S(sealed
    /// target). The answer to Query comes from the predecessor, which is
    /// neither, so read literally it is ignored. `true` applies it (7.4).
    pub accept_query_answer: bool,
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
            spec: SpecReading::default(),
        }
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
}

impl Op {
    pub fn is_change(&self) -> bool {
        !matches!(self, Op::PublicKey { .. } | Op::Batch { .. })
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
}

pub struct Output {
    pub reply: Reply,
    pub hops: Vec<(Ver, Frame)>,
    pub notes: Vec<Note>,
    pub writes: u32,
}

pub const POKE_PAUSE: u8 = 1 << 0;
pub const POKE_ARM: u8 = 1 << 1;
pub const POKE_DISCARD: u8 = 1 << 4;

/// Run one vault call against `store`. Err(Crash) means the node crashed
/// inside the call: the writes made so far stand, outputs are lost.
#[allow(clippy::too_many_arguments)]
pub fn call(
    def: &BuildDef,
    p: &Params,
    store: &mut Store,
    vol: &mut Volatile,
    faults: &mut FaultPlan,
    events: &mut Vec<Event>,
    cov: &mut Cov,
    input: Input,
) -> Result<Output, Crash> {
    let host = Host {
        build: def.v,
        store,
        faults,
        events,
        writes: 0,
        crashed: false,
    };
    let mut cx = Cx {
        def,
        p,
        host,
        vol,
        cov,
        out: Vec::new(),
        notes: Vec::new(),
    };
    let mut reply = cx.dispatch(input)?;
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
        notes: cx.notes,
        writes: cx.host.writes,
    })
}

struct Cx<'a> {
    def: &'a BuildDef,
    p: &'a Params,
    host: Host<'a>,
    vol: &'a mut Volatile,
    cov: &'a mut Cov,
    out: Vec<(Ver, Frame)>,
    notes: Vec<Note>,
}

type R<T> = Result<T, Crash>;

impl<'a> Cx<'a> {
    fn own(&self) -> Ver {
        self.def.v
    }
    fn idx(&self) -> Index {
        self.host.store.idx_or_none()
    }
    fn succ(&self) -> Succ {
        self.host.store.succ()
    }
    fn hit(&mut self, k: &str) {
        self.cov.hit(k);
    }

    /// A durable write. Ok(false) is a storage failure.
    fn put(&mut self, n: SName, v: SVal) -> R<bool> {
        match self.host.set(n, v) {
            Ok(()) => Ok(true),
            Err(WErr::Fail) => {
                self.hit("fault/storage-failure-seen");
                Ok(false)
            }
            Err(WErr::Crash) => Err(Crash),
        }
    }
    fn del(&mut self, n: SName) -> R<bool> {
        match self.host.del(n) {
            Ok(()) => Ok(true),
            Err(WErr::Fail) => Ok(false),
            Err(WErr::Crash) => Err(Crash),
        }
    }

    /// Commit an index (4.2). On failure, read the index back and report
    /// whether the disk holds what was intended.
    fn commit(&mut self, new: &Index) -> R<bool> {
        if self.put(SName::Idx, SVal::Idx(new.clone()))? {
            return Ok(true);
        }
        self.hit("4.2/commit-failed-read-back");
        Ok(self.idx() == *new)
    }

    fn gc_set(&self) -> BTreeSet<SName> {
        match self.host.get(&SName::Gc) {
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
    /// time, does not name it.
    fn process_gc(&mut self) -> R<()> {
        let gc = self.gc_set();
        if gc.is_empty() {
            return Ok(());
        }
        self.hit("4.2/gc-processed");
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
            if !self.del(n)? {
                remaining.insert(n);
            }
        }
        self.put(SName::Gc, SVal::Gc(remaining))?;
        Ok(())
    }

    fn rx(&self) -> BTreeSet<Digest> {
        match self.host.get(&SName::Rx) {
            Some(SVal::Rx(s)) => s.clone(),
            _ => BTreeSet::new(),
        }
    }
    fn prog(&self, t: Ver) -> BTreeMap<Ident, Digest> {
        match self.host.get(&SName::X(t)) {
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
        self.process_gc()?;
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

    fn status(&self, record_result: u8, sent: bool) -> Status {
        let idx = self.idx();
        Status {
            state: idx.state,
            problems: idx.problems,
            succ: self.succ(),
            record_result,
            sent,
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
        if !self.put(SName::Succ, SVal::Succ(n.clone()))? && self.succ() != n {
            return Ok(0);
        }
        // "in the same write clear any creation arming": the arming lives
        // in the index, a different secret, so this is a second write.
        let mut idx = self.idx();
        if let PState::None { armed: Some(_) } = idx.state {
            idx.state = PState::None { armed: None };
            self.hit("5.1/arming-cleared-by-record");
            self.commit(&idx)?;
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
        if flags & POKE_ARM != 0 {
            let idx = self.idx();
            if let (PState::None { armed: None }, Some(r)) = (&idx.state, rec) {
                if r.v == self.own() && !r.withdrawal && self.succ().successor().is_none() {
                    let mut n = idx.clone();
                    n.state = PState::None { armed: Some(r) };
                    self.hit("13.1/armed");
                    self.commit(&n)?;
                } else {
                    self.hit("13.1/arm-refused");
                }
            }
        }
        if flags & POKE_DISCARD != 0 {
            let idx = self.idx();
            if let PState::Receiving { .. } = idx.state {
                self.hit("8/discard-partial-copy");
                self.discard_to(&idx, PState::None { armed: None })?;
            }
        }
        let w = self.p.window_poke;
        let sent = self.step(w)?;
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
        let val = self.host.get(&SName::E(id, ie.parity)).cloned();
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
                if !self.gc_add(&[SName::E(id, par), SName::E(id, ie.parity)])? {
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
            Frame::CompleteAck { m, status, .. }
                if self.p.spec.accept_query_answer
                    && matches!(&idx.state, PState::Writer(w) if w.awaiting && w.taken_over.map(|t| t.0) == Some(from)) =>
            {
                self.hit("6/query-answer-applied(reading)");
                let (m, status) = (*m, *status);
                self.on_query_answer(m, status)?;
                Ok(None)
            }
            _ => {
                self.hit("6/ignored");
                if matches!(frame, Frame::CompleteAck { .. })
                    && matches!(&idx.state, PState::Writer(w) if w.awaiting && w.taken_over.map(|t| t.0) == Some(from))
                {
                    self.hit("6/query-answer-ignored");
                }
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
        let names: Vec<SName> = plan
            .iter()
            .flat_map(|(_, e, par)| [SName::E(e.ident(), *par), SName::E(e.ident(), !*par)])
            .collect();
        let gc_ok = self.gc_add(&names)?;
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
        self.del(SName::X(target.v))?;
        Ok(true)
    }

    // ------------------------------------------------------------ predecessor role (Query)

    fn on_query(&mut self, from: Ver, rec: Rec, m: Digest) -> R<Frame> {
        let idx = self.idx();
        let cack = |status, succ| Frame::CompleteAck {
            tid: (self.def.v, rec),
            m,
            status,
            succ,
            missing: vec![],
        };
        match idx.state.clone() {
            PState::Retired { .. } => {
                self.hit("7.6q/RETIRED");
                Ok(cack(CStatus::Noted, self.succ().highest()))
            }
            PState::None { .. } => {
                self.hit("7.6q/NONE");
                self.accept_record(rec)?;
                let s = self.succ();
                let known = s.current.is_some_and(|c| c.v >= rec.v)
                    || s.withdrawal.is_some_and(|w| w.v >= rec.v);
                if known {
                    Ok(cack(CStatus::Noted, s.highest()))
                } else {
                    Ok(cack(CStatus::StorageFailure, s.highest()))
                }
            }
            PState::Sealed { target, m: sm, w } if target.v == from && sm == m => {
                self.hit("7.6q/SEALED-toward-querier-same-m");
                if self.retire(&idx, target, m, w.taken_over)? {
                    Ok(cack(CStatus::Noted, self.succ().highest()))
                } else {
                    Ok(cack(CStatus::StorageFailure, self.succ().highest()))
                }
            }
            _ => {
                self.hit("7.6q/anything-else");
                Ok(cack(CStatus::AnotherWriter, self.succ().highest()))
            }
        }
    }

    fn on_query_answer(&mut self, m: Digest, status: CStatus) -> R<()> {
        let idx = self.idx();
        let PState::Writer(w) = &idx.state else {
            return Ok(());
        };
        if w.taken_over.map(|t| t.1) != Some(m) {
            return Ok(());
        }
        let mut n = idx.clone();
        if status == CStatus::Noted {
            if let PState::Writer(w) = &mut n.state {
                w.awaiting = false;
            }
            if self.commit(&n)? {
                self.hit("7.4/awaiting-cleared-by-query");
                self.notes.push(Note::AwaitingCleared);
            }
        } else {
            n.problems |= PROBLEM_ANOTHER_WRITER;
            if n != idx {
                self.commit(&n)?;
            }
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
            PState::None { armed } => {
                self.hit(&format!("5.1/NONE/{kind}"));
                if change && armed.is_some() && s.successor().is_none() {
                    let mut n = idx.clone();
                    n.state = PState::Writer(WFields::default());
                    if !self.commit(&n)? {
                        return Ok(OpRes::Refused(12));
                    }
                    self.hit("5.1/created");
                    self.notes.push(Note::Created);
                    return self.serve(op);
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
                if !self.gc_add(&[SName::E(id, ie.parity)])? {
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
                    if let Some(SVal::E(e)) = self.host.get(&SName::E(id, ie.parity)) {
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
        if !self.gc_add(&[SName::E(id, par), SName::E(id, !par)])? {
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
        self.commit(&n)
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
