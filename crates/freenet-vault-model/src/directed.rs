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
    r.act(Action::ArmWriteFault {
        after: 0,
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
    fn writer(&self, v: Ver) -> bool {
        matches!(self.state(v), PState::Writer(ref w) if !w.awaiting)
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

/// 4.6 end to end: 20 took over from 10 (10 RETIRED to 20, so its answer
/// to the repair probe is 0x0C). 20's index becomes undecryptable; the
/// courier selects 20, the UI sends Reindex and pokes; 20 becomes WRITER.
/// A deleted slot stays deleted. Then 30 is published and 20 hands over to
/// it (I7 after repair is checked at quiescence).
pub fn repair_end_to_end(cfg: &Cfg) -> Scenario {
    let mut r = handed_over_10_to_20(cfg, vec![Rec::build(10), Rec::build(20), Rec::build(30)]);
    r.act(Action::GarbleIndex {
        b: bi(20) as u8,
        undecryptable: true,
    });
    for _ in 0..3 {
        r.load(vec![Op::PublicKey { slot: 1 }]);
    }
    r.act(Action::Publish);
    for _ in 0..4 {
        r.load(vec![Op::Generate { slot: 2, seed: 9 }]);
    }
    r.done()
}

/// 4.6 crash points: as `repair_end_to_end`, with vault:parts also
/// malformed (so Reindex makes all three writes: remove the undecryptable
/// index, write the REPAIRING index, rewrite vault:parts), and the node
/// crashing before or after write `k`. Later loads repeat the repair.
pub fn reindex_crash(cfg: &Cfg, k: u8, after: bool) -> Option<Scenario> {
    let mut r = handed_over_10_to_20(cfg, vec![Rec::build(10), Rec::build(20)]);
    if !r.writer(20) {
        return None;
    }
    r.act(Action::GarbleIndex {
        b: bi(20) as u8,
        undecryptable: true,
    });
    // vault:parts by its position among the secrets Garble can pick
    let names: Vec<SName> = r.w.stores[bi(20)]
        .secrets
        .iter()
        .filter(|(_, v)| !matches!(v, SVal::Garbled | SVal::Undecryptable))
        .map(|(n, _)| *n)
        .collect();
    let pick = names.iter().position(|n| *n == SName::Parts)? as u16;
    r.act(Action::Garble {
        b: bi(20) as u8,
        pick,
        undecryptable: false,
    });
    r.act(Action::ArmWriteFault {
        after: k - 1,
        fault: if after {
            WriteFault::CrashAfter
        } else {
            WriteFault::CrashBefore
        },
    });
    r.act(Action::ReindexAt {
        b: bi(20) as u8,
        newest: true,
    });
    r.drain();
    for _ in 0..4 {
        r.load(vec![Op::PublicKey { slot: 0 }]);
    }
    Some(r.done())
}

/// Decision 2 (4.6): 10 is SEALED toward 20 and 20's index is lost before
/// it takes over. The courier routes to the sealed build and offers no
/// repair; a Reindex sent to 20 anyway leaves it at state 8, because 10
/// answers its probe 0x07.
pub fn sealed_toward_damaged(cfg: &Cfg) -> Option<Scenario> {
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
    r.act(Action::GarbleIndex {
        b: bi(20) as u8,
        undecryptable: true,
    });
    r.drain();
    r.act(Action::ReindexAt {
        b: bi(20) as u8,
        newest: true,
    });
    r.drain();
    for _ in 0..3 {
        r.load(vec![Op::PublicKey { slot: 0 }]);
    }
    Some(r.done())
}

/// 4.4 (revision 9, F7): a RETIRED build whose index becomes undecryptable
/// is unlisted, so it reads as NONE, answers Moved, reports no state 7 and
/// refuses Reindex.
pub fn retired_index_lost(cfg: &Cfg) -> Scenario {
    let mut r = handed_over_10_to_20(cfg, vec![Rec::build(10), Rec::build(20)]);
    r.act(Action::GarbleIndex {
        b: bi(10) as u8,
        undecryptable: true,
    });
    r.act(Action::Cached {
        op: Op::PublicKey { slot: 0 },
        b: Some(bi(10) as u8),
    });
    r.act(Action::ReindexAt {
        b: bi(10) as u8,
        newest: false,
    });
    r.drain();
    r.load(vec![Op::PublicKey { slot: 0 }]);
    r.done()
}

/// A damaged partial receiver below the head: 10 copies to 20, 20's index
/// is lost after its first chunk (the Ack is lost, so 10 does not seal);
/// 30 is published and 10 hands over to 30 (10 RETIRED to 30). A wrong
/// offer sends Reindex to 20 with no record. 10 must answer 20's probe 0x07
/// (retired to a build above 20), so 20 stays REPAIRING.
pub fn wrong_offer_partial_receiver(cfg: &Cfg) -> Option<Scenario> {
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
    // lose 20's Ack so that 10 does not seal toward it
    r.act(Action::Step {
        pick: 0,
        fate: Fate::Drop,
    });
    r.drain();
    r.act(Action::Publish);
    r.load_until_writer(30);
    if !matches!(r.state(10), PState::Retired { .. }) {
        return None;
    }
    r.act(Action::ReindexAt {
        b: bi(20) as u8,
        newest: false,
    });
    r.drain();
    r.act(Action::Cached {
        op: Op::PublicKey { slot: 0 },
        b: Some(bi(30) as u8),
    });
    Some(r.done())
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
pub fn orphan_copy_of_failed_write(cfg: &Cfg, repair: bool) -> Scenario {
    let mut r = Rec_::new(cfg, vec![Rec::build(10)]);
    r.act(Action::Publish);
    r.load(vec![Op::Generate { slot: 0, seed: 500 }]);
    // the Import's writes: entry copy (write 1), index (write 2, fails)
    r.act(Action::ArmWriteFault {
        after: 1,
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
    if repair {
        for _ in 0..2 {
            r.load(vec![]);
        }
    }
    r.act(Action::Cached {
        op: Op::PublicKey { slot: 1 },
        b: Some(0),
    });
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
    v.push(("4.6/repair-answer/RetiredNotAhead", repair_end_to_end(cfg)));
    for k in 1..=3u8 {
        for after in [false, true] {
            if let Some(sc) = reindex_crash(cfg, k, after) {
                v.push((
                    match k {
                        1 => "4.6/reindex-crash-at-write-1",
                        2 => "4.6/reindex-crash-at-write-2",
                        _ => "4.6/reindex-crash-at-write-3",
                    },
                    sc,
                ));
            }
        }
    }
    if let Some(sc) = sealed_toward_damaged(cfg) {
        v.push(("7.6q/SEALED/probe-0x07", sc));
    }
    v.push(("4.4/retired-index-lost-reads-none", retired_index_lost(cfg)));
    if let Some(sc) = wrong_offer_partial_receiver(cfg) {
        v.push(("7.6q/RETIRED/probe-retired-above-0x07", sc));
    }
    v.push(("4.2/gc-processed", gc_crash_then_index_lost(cfg)));
    v.push(("7.6q/NONE-record-stored", probe_answer_without_storing(cfg)));
    v.push(("client/old-lineage", retired_listed_stale_read(cfg)));
    v.push((
        "finding/I3-retired-malformed-index",
        retired_malformed_index_stale_read(cfg),
    ));
    v.push((
        "finding/I3-orphan-direct-read",
        orphan_copy_of_failed_write(cfg, false),
    ));
    v.push((
        "finding/I3-orphan-reindexed",
        orphan_copy_of_failed_write(cfg, true),
    ));
    if let Some(sc) = probe_crash_after_record_stored(cfg) {
        v.push(("5.3/probe-crash-after-record-stored", sc));
    }
    if let Some(sc) = query_crash_after_record_stored(cfg) {
        v.push(("7.4/query-crash-after-record-stored", sc));
    }
    v
}
