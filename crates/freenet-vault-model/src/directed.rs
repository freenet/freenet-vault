//! Directed scenarios: action lists built by driving a `World` toward a
//! row that random schedules do not reach, recorded as they are applied so
//! that they replay exactly. Each is run with the seeded schedules (15.5,
//! every row at least once per run); a test fails if one stops reaching its
//! row.

use crate::build::Op;
use crate::store::WriteFault;
use crate::types::*;
use crate::world::*;

struct Rec_ {
    w: World,
    actions: Vec<Action>,
}

impl Rec_ {
    fn new(cfg: &Cfg, ledger: Vec<Rec>) -> Rec_ {
        Rec_ {
            w: World::new(cfg.clone(), ledger),
            actions: vec![],
        }
    }
    fn act(&mut self, a: Action) {
        self.w.apply(&a);
        self.actions.push(a);
    }
    fn step(&mut self) {
        self.act(Action::Step {
            pick: 0,
            fate: Fate::Deliver,
        });
    }
    fn drain(&mut self) {
        for _ in 0..500 {
            if self.w.idle() || self.w.violation.is_some() {
                return;
            }
            self.step();
        }
    }
    fn load(&mut self, ops: Vec<Op>) {
        self.act(Action::Load {
            client: 0,
            fetch: Fetch::Newest,
            ops,
        });
        self.drain();
    }
    fn state(&self, v: Ver) -> PState {
        self.w.stores[bi(v)].idx_or_none().state
    }
    /// Load until build `v` is a writer that is not awaiting.
    fn load_until_writer(&mut self, v: Ver) {
        for _ in 0..6 {
            if matches!(self.state(v), PState::Writer(ref w) if !w.awaiting) {
                return;
            }
            self.load(vec![]);
        }
    }
    fn snapshot_where(&self, v: Ver, f: impl Fn(&PState) -> bool) -> Option<u16> {
        self.w
            .snapshot_states(bi(v))
            .iter()
            .position(f)
            .map(|i| i as u16)
    }
    fn done(self) -> Scenario {
        Scenario {
            ledger: self.w.ledger.clone(),
            actions: self.actions,
        }
    }
}

/// 7.6, "taken over from another build" x Retired(m) from P: the sealed
/// predecessor P retires on T's "accepted" and sends Retired(m) in the same
/// run, but T's store is restored, between the two calls, to an earlier
/// snapshot in which T had taken over from a different build Q.
///
/// 10 hands over to 20, 20 to 30 (30 took over from 20). 30 is wiped and 10
/// is restored to its first WRITER snapshot (from before it knew 20), so 10
/// copies straight to 30 and 30 takes over from 10. When 10 has retired, 30
/// is restored to its "taken over from 20" snapshot; then 10's Retired(m)
/// reaches it.
fn other_writer_retired(cfg: &Cfg) -> Option<Scenario> {
    let mut r = Rec_::new(cfg, vec![Rec::build(10), Rec::build(20), Rec::build(30)]);
    r.act(Action::Publish);
    r.load(vec![Op::Generate { slot: 0, seed: 500 }]);
    r.act(Action::Publish);
    r.load_until_writer(20);
    r.act(Action::Publish);
    r.load_until_writer(30);
    let from_20 = r.snapshot_where(
        30,
        |s| matches!(s, PState::Writer(w) if w.taken_over.map(|t| t.0) == Some(20)),
    )?;
    let first_writer = r.snapshot_where(10, |s| matches!(s, PState::Writer(_)))?;
    r.act(Action::Wipe { b: bi(30) as u8 });
    r.act(Action::Restore {
        b: bi(10) as u8,
        snap: first_writer,
        secret: None,
    });
    r.act(Action::Load {
        client: 0,
        fetch: Fetch::Newest,
        ops: vec![],
    });
    for _ in 0..200 {
        if r.w.idle() || r.w.violation.is_some() {
            return None;
        }
        r.step();
        if matches!(r.state(10), PState::Retired { .. }) {
            break;
        }
    }
    // 10 has retired to 30 and its Retired(m) is the next hop of its run
    r.act(Action::Restore {
        b: bi(30) as u8,
        snap: from_20,
        secret: None,
    });
    r.step();
    Some(r.done())
}

/// 3 and 5.3 (revision 8): a fresh install while the domain is stopped.
/// Ledger 10, 20, withdrawal 25, all published before the first load. The
/// courier arms 20 (the newest non-withdrawal record below the
/// withdrawal); 20 probes 10, which already stored the withdrawal 25 from
/// the courier's pokes, so 20's record is "not newer" there, is never
/// stored, and 10 never answers 0x0B: 20 never creates.
pub fn fresh_install_while_stopped(cfg: &Cfg) -> Scenario {
    let mut r = Rec_::new(
        cfg,
        vec![Rec::build(10), Rec::build(20), Rec::withdrawal(25)],
    );
    r.act(Action::Publish);
    r.act(Action::Publish);
    r.act(Action::Publish);
    for _ in 0..4 {
        r.load(vec![Op::Generate { slot: 0, seed: 77 }]);
    }
    r.done()
}

/// Decision 1 (2026-11-24) condition: the older build crashes between
/// storing the newer build's record and answering its creation probe. 20
/// is armed; the node crashes right after 10's write of vault:succ, so 20
/// gets no answer. Later loads re-probe 10, which answers 0x0B from the
/// record already stored; 20 then creates, and 10 can never create.
pub fn probe_crash_after_record_stored(cfg: &Cfg) -> Option<Scenario> {
    let mut r = Rec_::new(cfg, vec![Rec::build(10), Rec::build(20)]);
    r.act(Action::Publish);
    r.act(Action::Publish);
    // 10's write of record 20 from the courier's poke fails, so the probe
    // is what stores it
    r.act(Action::ArmWriteFault {
        after: 0,
        fault: WriteFault::Fail,
    });
    r.act(Action::Load {
        client: 0,
        fetch: Fetch::Newest,
        ops: vec![Op::Generate { slot: 0, seed: 5 }],
    });
    let armed = |r: &Rec_| matches!(r.state(20), PState::None { armed: Some(_), .. });
    for _ in 0..200 {
        if armed(&r) || r.w.idle() {
            break;
        }
        r.step();
    }
    if !armed(&r) {
        return None;
    }
    // the next call is 10 answering the probe: its first write is vault:succ
    r.act(Action::ArmWriteFault {
        after: 0,
        fault: WriteFault::CrashAfter,
    });
    r.drain();
    for _ in 0..4 {
        r.load(vec![Op::Generate { slot: 0, seed: 5 }]);
    }
    r.act(Action::Load {
        client: 2,
        fetch: Fetch::Newest,
        ops: vec![Op::Generate { slot: 1, seed: 6 }],
    });
    r.drain();
    Some(r.done())
}

/// Decision 1 (2026-11-24), awaiting path: 10 hands over to 20; the
/// "accepted" answer is lost, so 20 is awaiting and 10 still sealed. 10's
/// store is then wiped (a predecessor reads NONE only after a wipe or a
/// restore: 4.4). 20's Query reaches NONE 10, which stores 20's record and
/// crashes before answering. Later steps re-query; 10 answers 0x0B from the
/// record already stored and 20 stops awaiting.
pub fn query_crash_after_record_stored(cfg: &Cfg) -> Option<Scenario> {
    let mut r = Rec_::new(cfg, vec![Rec::build(10), Rec::build(20)]);
    r.act(Action::Publish);
    r.load(vec![Op::Generate { slot: 0, seed: 5 }]);
    r.act(Action::Publish);
    r.act(Action::Load {
        client: 0,
        fetch: Fetch::Newest,
        ops: vec![],
    });
    let awaiting = |r: &Rec_| matches!(r.state(20), PState::Writer(ref w) if w.awaiting);
    for _ in 0..200 {
        if awaiting(&r) || r.w.idle() {
            break;
        }
        r.step();
    }
    if !awaiting(&r) {
        return None;
    }
    // lose the "accepted" answer
    r.act(Action::Step {
        pick: 0,
        fate: Fate::Drop,
    });
    r.act(Action::Wipe { b: bi(10) as u8 });
    // revision 10: 20's step first writes the mirror of its one entry
    // (the sweep after take-over); the next write is 10's record
    r.act(Action::ArmWriteFault {
        after: 1,
        fault: WriteFault::CrashAfter,
    });
    r.act(Action::Wakeup { b: bi(20) as u8 });
    r.drain();
    for _ in 0..3 {
        r.act(Action::Wakeup { b: bi(20) as u8 });
        r.drain();
        r.load(vec![]);
    }
    Some(r.done())
}

// ---------------------------------------------------------------- revision 9

impl Rec_ {
    fn steps_until(&mut self, f: impl Fn(&Rec_) -> bool) -> bool {
        for _ in 0..400 {
            if f(self) {
                return true;
            }
            if self.w.idle() || self.w.violation.is_some() {
                return f(self);
            }
            self.step();
        }
        f(self)
    }
    /// One step that advances session `sid` if it is idle, else the active
    /// run (or queued work). False when nothing can move.
    fn step_session(&mut self, sid: usize) -> bool {
        let c = self.w.candidates();
        let pick = c
            .iter()
            .position(|x| x.0 == 1 && x.1 == sid)
            .or_else(|| c.iter().position(|x| x.0 != 1));
        match pick {
            Some(p) => {
                self.act(Action::Step {
                    pick: p as u16,
                    fate: Fate::Deliver,
                });
                true
            }
            None => false,
        }
    }
}

/// 10 creates with keys in slots 0 and 1, then deletes slot 1; 10 hands
/// over to 20 (10 RETIRED to 20, unlisted).
fn handed_over_10_to_20(cfg: &Cfg, ledger: Vec<Rec>) -> Rec_ {
    let mut r = Rec_::new(cfg, ledger);
    r.act(Action::Publish);
    r.load(vec![
        Op::Generate { slot: 0, seed: 500 },
        Op::Generate { slot: 1, seed: 501 },
    ]);
    r.load(vec![Op::Delete { slot: 1 }]);
    r.act(Action::Publish);
    r.load_until_writer(20);
    r
}

/// 3 and 5.3 (revision 9, F10): a fresh install while the domain is
/// stopped is refused (the courier never arms: "paused"), and the vault is
/// created after a fix-forward record ends the stop.
pub fn stopped_then_fix_forward(cfg: &Cfg) -> Scenario {
    let mut r = Rec_::new(
        cfg,
        vec![
            Rec::build(10),
            Rec::build(20),
            Rec::withdrawal(25),
            Rec::build(30),
        ],
    );
    r.act(Action::Publish);
    r.act(Action::Publish);
    r.act(Action::Publish);
    for _ in 0..3 {
        r.load(vec![Op::Generate { slot: 0, seed: 77 }]);
    }
    r.act(Action::Publish);
    for _ in 0..4 {
        r.load(vec![Op::Generate { slot: 0, seed: 78 }]);
    }
    r.done()
}

/// 4.5 (v1 base) end to end: 20 took over from 10. 20's index becomes
/// undecryptable; the courier selects 20 (state 7), the UI exports the room
/// keys with consent and reads every slot; a deleted slot answers storage
/// failure, never a key. Then 30 is published (no handover from a lost
/// index in v1).
pub fn read_only_end_to_end(cfg: &Cfg) -> Scenario {
    let mut r = handed_over_10_to_20(cfg, vec![Rec::build(10), Rec::build(20), Rec::build(30)]);
    r.act(Action::GarbleIndex {
        b: bi(20) as u8,
        undecryptable: true,
    });
    for _ in 0..3 {
        r.load(vec![Op::PublicKey { slot: 1 }]);
    }
    r.act(Action::Publish);
    for _ in 0..3 {
        r.load(vec![Op::Generate { slot: 2, seed: 9 }]);
    }
    r.done()
}

/// Revision 10 (checklist item 7): a crash or a failed write (landed or
/// not) at write `j` of a key change at writer 10, followed by the loss of
/// 10's index (undecryptable or malformed), then reads of every slot by
/// direct read, by the courier and by a cached caller. `replace`: an Import
/// over slot 0, which the index names (writes: 0 the entry, step 2; 1 the
/// index, step 3; 2 the mirror, step 4); else a Generate into the new slot
/// 1, whose step 1 finds nothing to remove (same three writes).
pub fn entry_write_fault_then_index_lost(
    cfg: &Cfg,
    replace: bool,
    j: u8,
    fault: WriteFault,
    malformed: bool,
) -> Scenario {
    let mut r = Rec_::new(cfg, vec![Rec::build(10)]);
    r.act(Action::Publish);
    r.load(vec![Op::Generate { slot: 0, seed: 500 }]);
    r.act(Action::ArmWriteFault { after: j, fault });
    let op = if replace {
        Op::Import {
            slot: 0,
            seed: 7,
            replace: true,
        }
    } else {
        Op::Generate { slot: 1, seed: 8 }
    };
    r.act(Action::Cached { op, b: Some(0) });
    r.act(Action::GarbleIndex {
        b: 0,
        undecryptable: !malformed,
    });
    for slot in 0..2 {
        r.act(Action::Cached {
            op: Op::PublicKey { slot },
            b: Some(0),
        });
        r.act(Action::Cached {
            op: Op::Export { slot },
            b: Some(0),
        });
    }
    r.load(vec![]);
    r.done()
}

/// Revision 10 (checklist item 7): a crash or a failed write at write `j`
/// of a Delete of slot 1 at writer 10 (writes: 0 vault:gc listing both
/// names, step 1; 1 the mirror's removal, step 2; 2 the index, step 3; 3
/// the other copy's removal and 4 vault:gc, step 4), then the
/// loss of 10's index; reads of slot 1 must answer storage failure or the
/// acknowledged key, never Absent and never a deleted key.
pub fn delete_fault_then_index_lost(
    cfg: &Cfg,
    j: u8,
    fault: WriteFault,
    malformed: bool,
) -> Scenario {
    let mut r = Rec_::new(cfg, vec![Rec::build(10)]);
    r.act(Action::Publish);
    r.load(vec![
        Op::Generate { slot: 0, seed: 500 },
        Op::Generate { slot: 1, seed: 501 },
    ]);
    r.act(Action::ArmWriteFault { after: j, fault });
    r.act(Action::Cached {
        op: Op::Delete { slot: 1 },
        b: Some(0),
    });
    r.act(Action::GarbleIndex {
        b: 0,
        undecryptable: !malformed,
    });
    for _ in 0..2 {
        r.act(Action::Cached {
            op: Op::PublicKey { slot: 1 },
            b: Some(0),
        });
        r.act(Action::Cached {
            op: Op::Export { slot: 1 },
            b: Some(0),
        });
    }
    r.load(vec![]);
    r.done()
}

/// Revision 10, F16 liveness (checklist item 6): 10 copies to 20 and 20's
/// index is lost (undecryptable or malformed) after its first chunk. 20 is
/// unlisted, so it reads as NONE, answers "missing", is copied to again,
/// and the handover completes (I7 is checked at quiescence).
pub fn receiver_index_lost_mid_copy(cfg: &Cfg, malformed: bool) -> Option<Scenario> {
    let mut r = Rec_::new(cfg, vec![Rec::build(10), Rec::build(20)]);
    r.act(Action::Publish);
    r.load(vec![
        Op::Generate { slot: 0, seed: 500 },
        Op::Generate { slot: 1, seed: 501 },
        Op::Generate { slot: 2, seed: 502 },
    ]);
    r.act(Action::Publish);
    r.act(Action::Load {
        client: 0,
        fetch: Fetch::Newest,
        ops: vec![],
    });
    if !r.steps_until(|r| matches!(r.state(20), PState::Receiving { .. })) {
        return None;
    }
    r.act(Action::GarbleIndex {
        b: bi(20) as u8,
        undecryptable: !malformed,
    });
    r.drain();
    for _ in 0..4 {
        r.load(vec![Op::PublicKey { slot: 0 }]);
    }
    Some(r.done())
}

/// 4.4 (revision 9, F7; revision 10, F14): a RETIRED build whose index
/// becomes undecryptable, or malformed, is unlisted, so it reads as NONE,
/// answers Moved and reports no state 7.
pub fn retired_index_lost(cfg: &Cfg, malformed: bool) -> Scenario {
    let mut r = handed_over_10_to_20(cfg, vec![Rec::build(10), Rec::build(20)]);
    r.act(Action::GarbleIndex {
        b: bi(10) as u8,
        undecryptable: !malformed,
    });
    r.act(Action::Cached {
        op: Op::PublicKey { slot: 0 },
        b: Some(bi(10) as u8),
    });
    r.load(vec![Op::PublicKey { slot: 0 }]);
    r.act(Action::Load {
        client: 2,
        fetch: Fetch::Newest,
        ops: vec![Op::PublicKey { slot: 0 }],
    });
    r.drain();
    r.done()
}

/// Revision 9 finding F16 (directed): 10 copies to 20, 20's index is lost
/// after its first chunk and the Ack is lost; 30 is published and 10 hands
/// over to 30; 30 changes slot 0; an old-lineage client (10, 20, 30) and a
/// cached caller of 20 read slot 0.
pub fn damaged_partial_receiver_behind_retired(cfg: &Cfg) -> Option<Scenario> {
    let mut r = Rec_::new(cfg, vec![Rec::build(10), Rec::build(20), Rec::build(30)]);
    r.act(Action::Publish);
    r.load(vec![Op::Generate { slot: 0, seed: 500 }]);
    r.act(Action::Publish);
    r.act(Action::Load {
        client: 0,
        fetch: Fetch::Newest,
        ops: vec![],
    });
    if !r.steps_until(|r| matches!(r.state(20), PState::Receiving { .. })) {
        return None;
    }
    r.act(Action::GarbleIndex {
        b: bi(20) as u8,
        undecryptable: true,
    });
    r.act(Action::Step {
        pick: 0,
        fate: Fate::Drop,
    });
    r.drain();
    r.act(Action::Publish);
    r.load_until_writer(30);
    r.load(vec![Op::Import {
        slot: 0,
        seed: 2,
        replace: true,
    }]);
    r.act(Action::Load {
        client: 2,
        fetch: Fetch::Newest,
        ops: vec![Op::PublicKey { slot: 0 }],
    });
    r.drain();
    r.act(Action::Cached {
        op: Op::PublicKey { slot: 0 },
        b: Some(bi(20) as u8),
    });
    Some(r.done())
}

/// Revision 10 (checklist item 7): a take-over whose listing write fails
/// (write `j` of 20's take-over call: 0 the WRITER index, 1 vault:parts),
/// landed or not. 20 must send no answer until the listing reads back; 10
/// resends Complete and the next call lists first and answers "already
/// writer". Then 20's index is damaged.
pub fn take_over_listing_fails(cfg: &Cfg, fault: WriteFault, malformed: bool) -> Option<Scenario> {
    let mut r = Rec_::new(cfg, vec![Rec::build(10), Rec::build(20)]);
    r.act(Action::Publish);
    r.load(vec![Op::Generate { slot: 0, seed: 500 }]);
    r.act(Action::Publish);
    r.act(Action::Load {
        client: 0,
        fetch: Fetch::Newest,
        ops: vec![],
    });
    if !r.steps_until(|r| matches!(r.state(10), PState::Sealed { .. })) {
        return None;
    }
    r.act(Action::ArmWriteFault { after: 1, fault });
    r.drain();
    r.act(Action::GarbleIndex {
        b: bi(20) as u8,
        undecryptable: !malformed,
    });
    for _ in 0..3 {
        r.load(vec![Op::PublicKey { slot: 0 }]);
    }
    Some(r.done())
}

/// Revision 10 (checklist item 7): a creation whose listing write fails
/// (write 1 of the creating call: 0 the WRITER index, 1 vault:parts). The
/// creating change answers Refused(12); then the index is damaged; later
/// loads find the build NONE or listed, never a lost acknowledged key.
pub fn creation_listing_fails(cfg: &Cfg, fault: WriteFault, malformed: bool) -> Scenario {
    let mut r = Rec_::new(cfg, vec![Rec::build(10)]);
    r.act(Action::Publish);
    r.act(Action::Load {
        client: 0,
        fetch: Fetch::Newest,
        ops: vec![],
    });
    r.drain();
    r.act(Action::ArmWriteFault { after: 1, fault });
    r.act(Action::Cached {
        op: Op::Generate { slot: 0, seed: 500 },
        b: Some(0),
    });
    r.act(Action::GarbleIndex {
        b: 0,
        undecryptable: !malformed,
    });
    for _ in 0..3 {
        r.load(vec![
            Op::Generate { slot: 0, seed: 501 },
            Op::PublicKey { slot: 0 },
        ]);
    }
    r.done()
}

/// Revision 10 stated residual I3-retired-still-listed: 10 hands over to
/// 40; the node crashes right after 10's RETIRED write (before the unlist),
/// 10's index is damaged before its next call, 40 changes slot 0, and an
/// old-lineage client (10, 20, 30) reads slot 0.
pub fn retired_still_listed_window(cfg: &Cfg, malformed: bool) -> Option<Scenario> {
    let mut r = Rec_::new(cfg, vec![Rec::build(10), Rec::build(40)]);
    r.act(Action::Publish);
    r.load(vec![Op::Generate { slot: 0, seed: 500 }]);
    r.act(Action::Publish);
    r.act(Action::Load {
        client: 0,
        fetch: Fetch::Newest,
        ops: vec![],
    });
    if !r.steps_until(|r| matches!(r.state(40), PState::Writer(_))) {
        return None;
    }
    // 40 has taken over; 10's next write is its RETIRED index (on
    // "accepted")
    r.act(Action::ArmWriteFault {
        after: 0,
        fault: WriteFault::CrashAfter,
    });
    if !r.steps_until(|r| matches!(r.state(10), PState::Retired { .. })) {
        return None;
    }
    r.act(Action::GarbleIndex {
        b: 0,
        undecryptable: !malformed,
    });
    r.load(vec![Op::Import {
        slot: 0,
        seed: 2,
        replace: true,
    }]);
    r.act(Action::Load {
        client: 2,
        fetch: Fetch::Newest,
        ops: vec![Op::PublicKey { slot: 0 }],
    });
    r.drain();
    Some(r.done())
}

/// Revision 10 observation G4 (one fault): 40 has taken over from 10 and
/// is awaiting 10's retirement; 10 is SEALED and still listed when its
/// index becomes undecryptable. 10 is then in read-only mode and answers
/// no Query (4.5), so 40 stays awaiting for good: reads work, every change
/// answers Busy.
pub fn awaiting_predecessor_index_lost(cfg: &Cfg, malformed: bool) -> Option<Scenario> {
    let mut r = Rec_::new(cfg, vec![Rec::build(10), Rec::build(40)]);
    r.act(Action::Publish);
    r.load(vec![Op::Generate { slot: 0, seed: 500 }]);
    r.act(Action::Publish);
    r.act(Action::Load {
        client: 0,
        fetch: Fetch::Newest,
        ops: vec![],
    });
    if !r.steps_until(|r| matches!(r.state(40), PState::Writer(_))) {
        return None;
    }
    r.act(Action::GarbleIndex {
        b: 0,
        undecryptable: !malformed,
    });
    r.drain();
    for _ in 0..4 {
        r.load(vec![Op::Generate { slot: 1, seed: 9 }]);
    }
    Some(r.done())
}

/// Revision 10, F17 (checklist item 5): an undecryptable vault:parts,
/// vault:gc or vault:succ (`which` 0, 1, 2) on writer 10 whose index is
/// valid; 10 keeps changing, deleting and handing over to 40. An
/// old-lineage client (10, 20, 30) first gives 10 the record of 40 with
/// copying paused, so that 10 holds a vault:succ to damage.
pub fn control_secret_undecryptable(cfg: &Cfg, which: u8) -> Scenario {
    let mut r = Rec_::new(cfg, vec![Rec::build(10), Rec::build(40)]);
    r.act(Action::Publish);
    r.load(vec![
        Op::Generate { slot: 0, seed: 500 },
        Op::Generate { slot: 1, seed: 501 },
        Op::Delete { slot: 1 },
    ]);
    r.act(Action::Publish);
    r.act(Action::Load {
        client: 2,
        fetch: Fetch::Newest,
        ops: vec![],
    });
    r.drain();
    r.act(Action::GarbleNamed {
        b: 0,
        which,
        undecryptable: true,
    });
    r.act(Action::Load {
        client: 2,
        fetch: Fetch::Newest,
        ops: vec![
            Op::Generate { slot: 2, seed: 502 },
            Op::Delete { slot: 0 },
            Op::Import {
                slot: 2,
                seed: 503,
                replace: true,
            },
        ],
    });
    r.drain();
    for _ in 0..4 {
        r.load(vec![Op::PublicKey { slot: 2 }]);
    }
    r.done()
}

/// Mutant "drop a name from vault:gc before it reads as absent": slot 1 is
/// deleted; the node crashes inside the next vault:gc processing; the
/// writer's index is then lost and a cached caller reads slot 1 by direct
/// read. The deletion must stay visible.
pub fn gc_crash_then_index_lost(cfg: &Cfg) -> Scenario {
    let mut r = Rec_::new(cfg, vec![Rec::build(10)]);
    r.act(Action::Publish);
    r.load(vec![
        Op::Generate { slot: 0, seed: 500 },
        Op::Generate { slot: 1, seed: 501 },
        Op::Delete { slot: 1 },
    ]);
    r.act(Action::ArmWriteFault {
        after: 1,
        fault: WriteFault::CrashBefore,
    });
    r.act(Action::Wakeup { b: 0 });
    r.drain();
    r.act(Action::GarbleIndex {
        b: 0,
        undecryptable: true,
    });
    r.act(Action::Cached {
        op: Op::PublicKey { slot: 1 },
        b: Some(0),
    });
    r.done()
}

/// Mutant "a NONE predecessor answers 0x0B to a creation probe whose record
/// it did not store": page B fetched 10 when only 10 was published; then 20
/// is published and page A's courier arms 20, whose probe reaches 10. 10's
/// write of record 20 from A's poke failed, so only the probe can store it.
/// If 10 answers 0x0B without storing, B's courier can still arm 10.
pub fn probe_answer_without_storing(cfg: &Cfg) -> Scenario {
    let mut r = Rec_::new(cfg, vec![Rec::build(10), Rec::build(20)]);
    r.act(Action::Publish);
    // page B (session 0) fetched 10; its first poke runs now
    r.act(Action::Load {
        client: 2,
        fetch: Fetch::Newest,
        ops: vec![Op::Generate { slot: 1, seed: 6 }],
    });
    r.act(Action::Publish);
    r.act(Action::ArmWriteFault {
        after: 0,
        fault: WriteFault::Fail,
    });
    // page A (session 1) fetched 20; its poke of 10 fails to store 20
    r.act(Action::Load {
        client: 0,
        fetch: Fetch::Newest,
        ops: vec![Op::Generate { slot: 0, seed: 5 }],
    });
    // run A until 10 has answered 20's creation probe
    let probed = |r: &Rec_| {
        matches!(r.state(20), PState::None { armed: Some(_), ref confirmed } if confirmed.contains(&10))
            || !r.state(20).is_none()
    };
    for _ in 0..200 {
        if probed(&r) || !r.step_session(1) {
            break;
        }
    }
    // then B: its remaining pokes, its decision, arming and its change
    for _ in 0..200 {
        if !r.w.idle() && r.step_session(0) {
            continue;
        }
        break;
    }
    r.drain();
    r.load(vec![]);
    r.done()
}

/// Mutants on unlisting: 10 hands over straight to 40 (versions 20 and 30
/// are not published), 10's index becomes undecryptable before any later
/// call to it, 40 changes slot 0, and an old-lineage client (bundle 10, 20,
/// 30) reads slot 0. Unlisted, 10 reads as NONE and the old client finds no
/// vault; still listed, 10 reports state 7 and serves its stale key.
pub fn retired_listed_stale_read(cfg: &Cfg) -> Scenario {
    let mut r = Rec_::new(cfg, vec![Rec::build(10), Rec::build(40)]);
    r.act(Action::Publish);
    r.load(vec![Op::Generate { slot: 0, seed: 500 }]);
    r.act(Action::Publish);
    r.act(Action::Load {
        client: 0,
        fetch: Fetch::Newest,
        ops: vec![],
    });
    // damage 10's index in the step right after it retires, before any
    // later call to it
    r.steps_until(|r| matches!(r.state(10), PState::Retired { .. }));
    r.act(Action::GarbleIndex {
        b: 0,
        undecryptable: true,
    });
    r.load(vec![Op::Import {
        slot: 0,
        seed: 2,
        replace: true,
    }]);
    r.act(Action::Load {
        client: 2,
        fetch: Fetch::Newest,
        ops: vec![Op::PublicKey { slot: 0 }],
    });
    r.drain();
    r.done()
}

/// Finding (revision 9): the same as `retired_listed_stale_read`, but the
/// retired build's index is MALFORMED (bytes present that fail the
/// checksum) rather than undecryptable. 4.5 condition 2 makes it index-lost
/// whether or not it is listed, so unlisting does not apply.
pub fn retired_malformed_index_stale_read(cfg: &Cfg) -> Scenario {
    let mut r = Rec_::new(cfg, vec![Rec::build(10), Rec::build(40)]);
    r.act(Action::Publish);
    r.load(vec![Op::Generate { slot: 0, seed: 500 }]);
    r.act(Action::Publish);
    r.load_until_writer(40);
    r.act(Action::GarbleIndex {
        b: 0,
        undecryptable: false,
    });
    r.load(vec![Op::Import {
        slot: 0,
        seed: 2,
        replace: true,
    }]);
    r.act(Action::Load {
        client: 2,
        fetch: Fetch::Newest,
        ops: vec![Op::PublicKey { slot: 0 }],
    });
    r.drain();
    r.done()
}

/// Finding (revision 9): an Import into a new slot whose index write fails
/// after the entry copy landed leaves an entry copy that no record names
/// (not the index, not vault:gc). After an index loss, direct read serves
/// that never-acknowledged key (`repair: false`), and Reindex indexes it
/// through list_secrets (`repair: true`).
pub fn orphan_copy_of_failed_write(cfg: &Cfg) -> Scenario {
    let mut r = Rec_::new(cfg, vec![Rec::build(10)]);
    r.act(Action::Publish);
    r.load(vec![Op::Generate { slot: 0, seed: 500 }]);
    // the Import's writes (revision 10): vault:gc (write 0), entry copy
    // (write 1), index (write 2, fails)
    r.act(Action::ArmWriteFault {
        after: 2,
        fault: WriteFault::Fail,
    });
    r.act(Action::Cached {
        op: Op::Import {
            slot: 1,
            seed: 3,
            replace: false,
        },
        b: Some(0),
    });
    r.act(Action::GarbleIndex {
        b: 0,
        undecryptable: true,
    });
    r.act(Action::Cached {
        op: Op::PublicKey { slot: 1 },
        b: Some(0),
    });
    r.done()
}

/// Revision 10 (checklist item 8): slot 1 holds 501 at parity 1 (Generate
/// 777, then Import 501 over it). A Delete of slot 1 commits, but gc's
/// removal of the named copy fails, leaving 501 at parity 1 on disk, and
/// vault:gc is then lost (undecryptable), so nothing removes it. Slot 1
/// is then generated again with the same seed 501, with a fault `fault` at
/// write `j` of that change (0 step 1's removal of the leftover, 1 the
/// entry, 2 the index), and 10's index is lost. Direct read must never
/// serve the deleted 501 unless the new change was acknowledged.
pub fn delete_then_recreate_same_seed(cfg: &Cfg, j: u8, fault: WriteFault) -> Scenario {
    let mut r = Rec_::new(cfg, vec![Rec::build(10)]);
    r.act(Action::Publish);
    r.load(vec![
        Op::Generate { slot: 0, seed: 500 },
        Op::Generate { slot: 1, seed: 777 },
        Op::Import {
            slot: 1,
            seed: 501,
            replace: true,
        },
    ]);
    // Delete writes: 0 vault:gc, 1 mirror removal, 2 index, 3 removal of
    // the named copy (fails, not landed)
    r.act(Action::ArmWriteFault {
        after: 3,
        fault: WriteFault::Fail,
    });
    r.act(Action::Cached {
        op: Op::Delete { slot: 1 },
        b: Some(0),
    });
    // vault:gc, which still lists the leftover, is lost (4.4: the copies it
    // listed stay on disk until the slot is next written or deleted)
    r.act(Action::GarbleNamed {
        b: 0,
        which: 1,
        undecryptable: true,
    });
    r.act(Action::ArmWriteFault { after: j, fault });
    r.act(Action::Cached {
        op: Op::Generate { slot: 1, seed: 501 },
        b: Some(0),
    });
    r.act(Action::GarbleIndex {
        b: 0,
        undecryptable: true,
    });
    for _ in 0..2 {
        r.act(Action::Cached {
            op: Op::PublicKey { slot: 1 },
            b: Some(0),
        });
        r.act(Action::Cached {
            op: Op::Export { slot: 1 },
            b: Some(0),
        });
    }
    r.load(vec![]);
    r.done()
}

/// Revision 10 (checklist item 8): 10 hands over to 40 and 40's index is
/// lost right after the take-over, before its mirror sweep ran. 40's keys
/// are single copies, so every slot answers storage failure (accepted by
/// the coordinator); never Absent and never a wrong key.
pub fn index_lost_after_take_over_before_sweep(cfg: &Cfg, malformed: bool) -> Option<Scenario> {
    let mut r = Rec_::new(cfg, vec![Rec::build(10), Rec::build(40)]);
    r.act(Action::Publish);
    r.load(vec![
        Op::Generate { slot: 0, seed: 500 },
        Op::Generate { slot: 1, seed: 501 },
    ]);
    r.act(Action::Publish);
    r.act(Action::Load {
        client: 0,
        fetch: Fetch::Newest,
        ops: vec![],
    });
    if !r.steps_until(|r| matches!(r.state(40), PState::Writer(_))) {
        return None;
    }
    r.act(Action::GarbleIndex {
        b: 3,
        undecryptable: !malformed,
    });
    r.drain();
    for slot in 0..2 {
        r.act(Action::Cached {
            op: Op::PublicKey { slot },
            b: Some(3),
        });
    }
    r.load(vec![Op::PublicKey { slot: 0 }, Op::Export { slot: 1 }]);
    Some(r.done())
}

/// Revision 10 (checklist item 7, liveness): writer 10's mirror writes
/// fail for a while (the third write of each change: the mirror), then
/// faults stop, the node restarts and the sweep repairs every mirror; the
/// index is then lost and every slot must sign.
pub fn mirror_writes_failing_then_restart(cfg: &Cfg) -> Scenario {
    let mut r = Rec_::new(cfg, vec![Rec::build(10)]);
    r.act(Action::Publish);
    r.load(vec![Op::Generate { slot: 0, seed: 500 }]);
    for (slot, seed) in [(1u16, 501u32), (2, 502), (0, 600)] {
        r.act(Action::ArmWriteFault {
            after: 2,
            fault: WriteFault::Fail,
        });
        let op = if slot == 0 {
            Op::Import {
                slot,
                seed,
                replace: true,
            }
        } else {
            Op::Generate { slot, seed }
        };
        r.act(Action::Cached { op, b: Some(0) });
    }
    r.act(Action::Crash);
    r.drain();
    r.act(Action::Wakeup { b: 0 });
    r.drain();
    r.act(Action::GarbleIndex {
        b: 0,
        undecryptable: true,
    });
    for slot in 0..3 {
        r.act(Action::Cached {
            op: Op::PublicKey { slot },
            b: Some(0),
        });
    }
    r.done()
}

/// Every directed scenario with the row it exists to reach.
pub fn directed(cfg: &Cfg) -> Vec<(&'static str, Scenario)> {
    let mut v = vec![];
    if let Some(sc) = other_writer_retired(cfg) {
        v.push(("7.6/other-writer-or-not-from-P/Retired", sc));
    }
    v.push(("5.2/paused-no-arm", fresh_install_while_stopped(cfg)));
    v.push((
        "5.3/created-after-every-predecessor-confirmed",
        stopped_then_fix_forward(cfg),
    ));
    v.push(("4.5/lost/export", read_only_end_to_end(cfg)));
    let faults = [
        WriteFault::CrashBefore,
        WriteFault::CrashAfter,
        WriteFault::Fail,
        WriteFault::LandedButError,
    ];
    for malformed in [false, true] {
        for f in faults {
            for j in 0..3u8 {
                let row = match j {
                    0 => "4.2/entry-write/fault-at-step-2",
                    1 => "4.2/entry-write/fault-at-step-3",
                    _ => "4.2/entry-write/fault-at-step-4",
                };
                v.push((
                    row,
                    entry_write_fault_then_index_lost(cfg, true, j, f, malformed),
                ));
                v.push((
                    row,
                    entry_write_fault_then_index_lost(cfg, false, j, f, malformed),
                ));
            }
            for j in 0..5u8 {
                v.push((
                    match j {
                        0 => "4.2/delete/fault-at-step-1",
                        1 => "4.2/delete/fault-at-step-2",
                        2 => "4.2/delete/fault-at-step-3",
                        _ => "4.2/delete/fault-at-step-4",
                    },
                    delete_fault_then_index_lost(cfg, j, f, malformed),
                ));
            }
            if !malformed {
                for j in 0..3u8 {
                    v.push((
                        if j == 0 {
                            "4.2/entry-write/fault-at-step-1"
                        } else {
                            "4.2/step-1/leftover-found"
                        },
                        delete_then_recreate_same_seed(cfg, j, f),
                    ));
                }
            }
        }
        if let Some(sc) = index_lost_after_take_over_before_sweep(cfg, malformed) {
            v.push(("4.5/direct-read-unavailable/missing-copy", sc));
        }
        if let Some(sc) = receiver_index_lost_mid_copy(cfg, malformed) {
            // revision 10 finding G1: a malformed RECEIVING index while
            // vault:parts was never written is index loss (4.5 condition 2,
            // literal reading), so the handover never completes
            v.push((
                if malformed {
                    "finding/I7-receiver-index-lost"
                } else {
                    "4.4/receiver-index-lost-reads-none"
                },
                sc,
            ));
        }
        v.push((
            "4.4/retired-index-lost-reads-none",
            retired_index_lost(cfg, malformed),
        ));
        for f in [
            WriteFault::Fail,
            WriteFault::LandedButError,
            WriteFault::CrashAfter,
        ] {
            if let Some(sc) = take_over_listing_fails(cfg, f, malformed) {
                v.push((
                    match f {
                        WriteFault::Fail => "4.2/take-over-not-listed-no-answer",
                        WriteFault::LandedButError => "4.2/listing-write-failed",
                        _ => "fault/crash-after-write",
                    },
                    sc,
                ));
            }
            v.push((
                match f {
                    WriteFault::Fail => "4.2/creation-not-listed-refused-12",
                    WriteFault::LandedButError => "4.2/listing-write-failed",
                    _ => "fault/crash-after-write",
                },
                creation_listing_fails(cfg, f, malformed),
            ));
        }
        if let Some(sc) = retired_still_listed_window(cfg, malformed) {
            v.push(("liveness/awaiting-forever-predecessor-index-lost", sc));
        }
    }
    for malformed in [false, true] {
        if let Some(sc) = awaiting_predecessor_index_lost(cfg, malformed) {
            v.push(("liveness/awaiting-forever-predecessor-index-lost", sc));
        }
    }
    if let Some(sc) = damaged_partial_receiver_behind_retired(cfg) {
        v.push(("4.4/receiver-index-lost-reads-none", sc));
    }
    for which in 0..3u8 {
        v.push((
            match which {
                0 => "4.2/remove-before-write/parts",
                1 => "4.2/remove-before-write/gc",
                _ => "4.2/remove-before-write/succ",
            },
            control_secret_undecryptable(cfg, which),
        ));
    }
    v.push(("4.2/gc-processed", gc_crash_then_index_lost(cfg)));
    v.push(("7.6q/NONE-record-stored", probe_answer_without_storing(cfg)));
    v.push(("client/old-lineage", retired_listed_stale_read(cfg)));
    v.push((
        "4.5/malformed-index-unlisted-reads-none",
        retired_malformed_index_stale_read(cfg),
    ));
    v.push((
        "4.5/direct-read-unavailable/missing-copy",
        orphan_copy_of_failed_write(cfg),
    ));
    v.push(("7.7/sweep-repair", mirror_writes_failing_then_restart(cfg)));
    if let Some(sc) = probe_crash_after_record_stored(cfg) {
        v.push(("5.3/probe-crash-after-record-stored", sc));
    }
    if let Some(sc) = query_crash_after_record_stored(cfg) {
        v.push(("7.4/query-crash-after-record-stored", sc));
    }
    for (name, sc) in crate::replay_rev9::scenarios() {
        v.push((name, sc));
    }
    v
}
