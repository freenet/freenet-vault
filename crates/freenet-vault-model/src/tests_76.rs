//! One test per row of the 7.6 answer tables, plus the sender transitions of
//! 7.3 to 7.5 and the trigger rule of section 6.

use crate::build::*;
use crate::cov::Cov;
use crate::store::{Event, FaultPlan, Store};
use crate::types::*;

struct T {
    def: BuildDef,
    p: Params,
    store: Store,
    vol: Volatile,
    faults: FaultPlan,
    events: Vec<Event>,
    cov: Cov,
}

fn t(v: Ver) -> T {
    T {
        def: BuildDef {
            v,
            preds: (1..v / 10).map(|i| i * 10).collect(),
            writes_unknown_kind: false,
            code_of: v,
        },
        p: Params::default(),
        store: Store::default(),
        vol: Volatile::default(),
        faults: FaultPlan::default(),
        events: vec![],
        cov: Cov::default(),
    }
}

impl T {
    fn call(&mut self, i: Input) -> Output {
        call(
            &self.def,
            &self.p,
            &mut self.store,
            &mut self.vol,
            &mut self.faults,
            &mut self.events,
            &mut self.cov,
            &mut Vec::new(),
            i,
        )
        .expect("no crash")
    }
    fn try_call(&mut self, i: Input) -> Result<Output, crate::store::Crash> {
        call(
            &self.def,
            &self.p,
            &mut self.store,
            &mut self.vol,
            &mut self.faults,
            &mut self.events,
            &mut self.cov,
            &mut Vec::new(),
            i,
        )
    }
    fn hop(&mut self, from: Ver, f: Frame) -> Option<Frame> {
        match self.call(Input::Hop { from, frame: f }).reply {
            Reply::Frame(f) => Some(f),
            Reply::None => None,
            r => panic!("unexpected {r:?}"),
        }
    }
    fn set(&mut self, state: PState, entries: &[Entry]) {
        let mut idx = Index::none();
        idx.state = state;
        for e in entries {
            self.store
                .secrets
                .insert(SName::E(e.ident(), false), SVal::E(e.clone()));
            idx.entries.insert(
                e.ident(),
                IdxEnt {
                    parity: false,
                    digest: e.digest(),
                },
            );
        }
        self.store.secrets.insert(SName::Idx, SVal::Idx(idx));
    }
    fn succ(&mut self, s: Succ) {
        self.store.secrets.insert(SName::Succ, SVal::Succ(s));
    }
    fn state(&self) -> PState {
        self.store.idx_or_none().state
    }
    fn digests(&self) -> Vec<Digest> {
        self.store.idx_or_none().manifest()
    }
}

fn key(slot: u16, c: u32) -> Entry {
    Entry {
        kind: KIND_KEY,
        key: slot,
        flagged: false,
        content: c,
        ext: vec![],
    }
}

fn mf(es: &[Entry]) -> (Digest, Vec<Digest>) {
    let mut d: Vec<Digest> = es.iter().map(|e| e.digest()).collect();
    d.sort_unstable();
    (manifest_digest(&d), d)
}

fn complete(rec: Ver, es: &[Entry]) -> Frame {
    let (m, digests) = mf(es);
    Frame::Complete {
        rec: Rec::build(rec),
        m,
        digests,
        malformed: false,
    }
}

fn chunk(rec: Ver, es: &[Entry]) -> Frame {
    Frame::Chunk {
        rec: Rec::build(rec),
        entries: es.to_vec(),
        malformed: false,
    }
}

fn abort(rec: Ver, m: Digest) -> Frame {
    Frame::Abort {
        rec: Rec::build(rec),
        m,
        malformed: false,
    }
}

fn retired(rec: Ver, m: Digest) -> Frame {
    Frame::Retired {
        rec: Rec::build(rec),
        m,
        malformed: false,
    }
}

fn cstatus(f: &Option<Frame>) -> CStatus {
    match f {
        Some(Frame::CompleteAck { status, .. }) => *status,
        o => panic!("expected CompleteAck, got {o:?}"),
    }
}

fn astatus(f: &Option<Frame>) -> (ChunkStatus, Vec<Outcome>) {
    match f {
        Some(Frame::Ack {
            status, outcomes, ..
        }) => (*status, outcomes.iter().map(|o| o.1).collect()),
        o => panic!("expected Ack, got {o:?}"),
    }
}

fn writer_from(p: Ver, m: Digest, awaiting: bool) -> PState {
    PState::Writer(WFields {
        taken_over: Some((p, m)),
        awaiting,
        paused: None,
    })
}

// ------------------------------------------------------- row: taken over from P

#[test]
fn row_taken_over_chunk_answers_another_writer() {
    let es = [key(1, 7)];
    let (m, _) = mf(&es);
    let mut b = t(30);
    b.set(writer_from(20, m, true), &es);
    let r = b.hop(20, chunk(30, &[key(1, 8)]));
    assert_eq!(astatus(&r).0, ChunkStatus::AnotherWriter);
    assert_eq!(b.digests(), mf(&es).1, "nothing stored");
}

#[test]
fn row_taken_over_complete_same_m_already_writer_else_different_manifest() {
    let es = [key(1, 7)];
    let (m, _) = mf(&es);
    for state in [
        writer_from(20, m, true),
        writer_from(20, m, false),
        PState::Sealed {
            w: WFields {
                taken_over: Some((20, m)),
                ..Default::default()
            },
            target: Rec::build(40),
            m: 99,
        },
        PState::Retired {
            to: Rec::build(40),
            m: 99,
            taken_over: Some((20, m)),
        },
    ] {
        let mut b = t(30);
        b.set(state.clone(), &es);
        assert_eq!(
            cstatus(&b.hop(20, complete(30, &es))),
            CStatus::AlreadyWriter,
            "{state:?}"
        );
        assert_eq!(
            cstatus(&b.hop(20, complete(30, &[key(1, 8)]))),
            CStatus::DifferentManifest,
            "{state:?}"
        );
        assert_eq!(cstatus(&b.hop(20, abort(30, m))), CStatus::AlreadyWriter);
        assert_eq!(
            cstatus(&b.hop(20, abort(30, m ^ 1))),
            CStatus::DifferentManifest
        );
        assert_eq!(b.state(), state, "Complete/Abort change nothing");
    }
}

#[test]
fn row_taken_over_precedes_stopped_and_malformed() {
    let es = [key(1, 7)];
    let (m, _) = mf(&es);
    let mut b = t(30);
    b.set(writer_from(20, m, true), &es);
    b.succ(Succ {
        current: None,
        withdrawal: Some(Rec::withdrawal(35)),
    });
    assert_eq!(
        cstatus(&b.hop(20, complete(30, &es))),
        CStatus::AlreadyWriter
    );
    let mut f = complete(30, &es);
    f.garble();
    assert_eq!(
        cstatus(&b.hop(20, f)),
        CStatus::DifferentManifest,
        "unparseable digest from P: took over from you, different manifest"
    );
    // a record that does not name this build still gets the taken-over answer
    assert_eq!(
        cstatus(&b.hop(20, complete(40, &es))),
        CStatus::AlreadyWriter
    );
}

#[test]
fn row_taken_over_retired_clears_awaiting_only_for_same_m() {
    let es = [key(1, 7)];
    let (m, _) = mf(&es);
    let mut b = t(30);
    b.set(writer_from(20, m, true), &es);
    assert_eq!(b.hop(20, retired(30, m ^ 1)), None, "other m: ignored");
    assert_eq!(b.state(), writer_from(20, m, true));
    assert_eq!(cstatus(&b.hop(20, retired(30, m))), CStatus::Noted);
    assert_eq!(b.state(), writer_from(20, m, false));
}

// ------------------------------------------- row: fresh writer / other build

#[test]
fn row_fresh_writer_or_other_build() {
    let es = [key(1, 7)];
    for state in [
        PState::Writer(WFields::default()),
        writer_from(10, 5, false),
        PState::Sealed {
            w: WFields::default(),
            target: Rec::build(40),
            m: 5,
        },
        PState::Retired {
            to: Rec::build(40),
            m: 5,
            taken_over: None,
        },
    ] {
        let mut b = t(30);
        b.set(state.clone(), &es);
        assert_eq!(
            astatus(&b.hop(20, chunk(30, &es))).0,
            ChunkStatus::AnotherWriter
        );
        assert_eq!(
            cstatus(&b.hop(20, complete(30, &es))),
            CStatus::AnotherWriter
        );
        assert_eq!(cstatus(&b.hop(20, abort(30, 5))), CStatus::Aborted);
        assert_eq!(b.hop(20, retired(30, 5)), None);
        assert_eq!(b.state(), state);
    }
}

// --------------------------------------------------------- row: stopped

#[test]
fn row_stopped_none_or_receiving() {
    for state in [
        PState::none(),
        PState::Receiving {
            from: 20,
            store_failed: false,
        },
    ] {
        let mut b = t(30);
        b.set(state.clone(), &[]);
        let w = Rec::withdrawal(35);
        b.succ(Succ {
            current: None,
            withdrawal: Some(w),
        });
        let r = b.hop(20, chunk(30, &[key(1, 1)]));
        assert_eq!(astatus(&r).0, ChunkStatus::Stopped);
        assert!(
            matches!(r, Some(Frame::Ack { succ: Some(x), .. }) if x == w),
            "withdrawal in reply"
        );
        assert_eq!(cstatus(&b.hop(20, complete(30, &[]))), CStatus::Stopped);
        assert_eq!(cstatus(&b.hop(20, abort(30, 1))), CStatus::Aborted);
        assert_eq!(b.state(), state);
    }
}

// --------------------------------------------------------- row: NONE

#[test]
fn row_none_chunk_writes_receiving_and_stores() {
    let mut b = t(30);
    let r = b.hop(20, chunk(30, &[key(1, 1), key(2, 2)]));
    let (s, o) = astatus(&r);
    assert_eq!(s, ChunkStatus::Processed);
    assert_eq!(o, vec![Outcome::Stored, Outcome::Stored]);
    assert_eq!(
        b.state(),
        PState::Receiving {
            from: 20,
            store_failed: false
        }
    );
}

#[test]
fn row_none_complete_empty_takes_over_else_missing() {
    let mut b = t(30);
    assert_eq!(cstatus(&b.hop(20, complete(30, &[]))), CStatus::Accepted);
    assert_eq!(b.state(), writer_from(20, manifest_digest(&[]), true));

    let mut b = t(30);
    let r = b.hop(20, complete(30, &[key(1, 1)]));
    assert_eq!(cstatus(&r), CStatus::Missing);
    assert!(matches!(&r, Some(Frame::CompleteAck { missing, .. }) if missing.len() == 1));
    assert_eq!(b.state(), PState::none());
}

#[test]
fn row_none_abort_and_retired() {
    let mut b = t(30);
    assert_eq!(cstatus(&b.hop(20, abort(30, 3))), CStatus::Aborted);
    assert_eq!(b.hop(20, retired(30, 3)), None);
    assert_eq!(b.state(), PState::none());
    assert!(b.store.idx().is_none(), "no state change");
}

// --------------------------------------------------------- row: RECEIVING(P)

#[test]
fn row_receiving_p_full_transfer() {
    let es = [key(1, 1), key(2, 2), key(3, 3)];
    let mut b = t(30);
    b.hop(20, chunk(30, &es[..2]));
    // stale entry from an earlier copy that the sender has since deleted
    b.hop(20, chunk(30, &[key(9, 9)]));
    let r = b.hop(20, complete(30, &es));
    assert_eq!(cstatus(&r), CStatus::Missing);
    assert!(
        matches!(&r, Some(Frame::CompleteAck { missing, .. }) if *missing == vec![es[2].digest()])
    );
    assert!(
        !b.store.idx_or_none().entries.contains_key(&(KIND_KEY, 9)),
        "unlisted dropped"
    );
    b.hop(20, chunk(30, &es[2..]));
    assert_eq!(
        cstatus(&b.hop(20, abort(30, 1))),
        CStatus::Aborted,
        "abort changes nothing"
    );
    assert_eq!(cstatus(&b.hop(20, complete(30, &es))), CStatus::Accepted);
    assert_eq!(b.state(), writer_from(20, mf(&es).0, true));
    assert_eq!(b.digests(), mf(&es).1);
}

#[test]
fn row_receiving_p_store_failed_flag_answers_storage_failure_once() {
    let mut b = t(30);
    b.set(
        PState::Receiving {
            from: 20,
            store_failed: true,
        },
        &[key(1, 1)],
    );
    assert_eq!(
        cstatus(&b.hop(20, complete(30, &[key(1, 1)]))),
        CStatus::StorageFailure
    );
    assert_eq!(
        cstatus(&b.hop(20, complete(30, &[key(1, 1)]))),
        CStatus::Accepted
    );
}

#[test]
fn row_receiving_p_policy_dropped_counts_as_held() {
    let mark_odd = Entry {
        kind: KIND_MARK,
        key: 4,
        flagged: false,
        content: 3,
        ext: vec![],
    };
    let mut b = t(40); // rejects odd marks
    let r = b.hop(30, chunk(40, &[mark_odd.clone(), key(1, 1)]));
    assert_eq!(astatus(&r).1, vec![Outcome::PolicyDropped, Outcome::Stored]);
    assert_eq!(
        cstatus(&b.hop(30, complete(40, &[mark_odd, key(1, 1)]))),
        CStatus::Accepted
    );
}

#[test]
fn row_receiving_staging_full() {
    let mut b = t(30);
    let many: Vec<Entry> = (0..7).map(|i| key(i, i as u32)).collect();
    for c in many[..6].chunks(2) {
        b.hop(20, chunk(30, c));
    }
    let r = b.hop(20, chunk(30, &many[6..]));
    assert_eq!(astatus(&r).1, vec![Outcome::StagingFull]);
}

// ------------------------------------------------ rows: RECEIVING(Q != P)

#[test]
fn row_receiving_lower_discards_partial_copy() {
    let mut b = t(30);
    b.set(
        PState::Receiving {
            from: 10,
            store_failed: false,
        },
        &[key(5, 5)],
    );
    let r = b.hop(20, chunk(30, &[key(1, 1)]));
    assert_eq!(astatus(&r).1, vec![Outcome::Stored]);
    assert_eq!(
        b.state(),
        PState::Receiving {
            from: 20,
            store_failed: false
        }
    );
    assert!(!b.store.idx_or_none().entries.contains_key(&(KIND_KEY, 5)));

    let mut b = t(30);
    b.set(
        PState::Receiving {
            from: 10,
            store_failed: false,
        },
        &[key(1, 1)],
    );
    let r = b.hop(20, complete(30, &[key(1, 1)]));
    assert_eq!(cstatus(&r), CStatus::Missing, "discard; missing (all)");
    assert_eq!(cstatus(&b.hop(20, abort(30, 1))), CStatus::Aborted);
}

#[test]
fn row_receiving_higher() {
    let mut b = t(40);
    b.set(
        PState::Receiving {
            from: 30,
            store_failed: false,
        },
        &[key(5, 5)],
    );
    assert_eq!(
        astatus(&b.hop(20, chunk(40, &[key(1, 1)]))).0,
        ChunkStatus::HigherBuild
    );
    assert_eq!(cstatus(&b.hop(20, complete(40, &[]))), CStatus::HigherBuild);
    assert_eq!(cstatus(&b.hop(20, abort(40, 1))), CStatus::Aborted);
    assert_eq!(b.hop(20, retired(40, 1)), None);
}

#[test]
fn malformed_and_not_mine() {
    let mut b = t(30);
    let mut c = chunk(30, &[key(1, 1)]);
    c.garble();
    assert_eq!(astatus(&b.hop(20, c)).0, ChunkStatus::Malformed);
    let mut c = complete(30, &[]);
    c.garble();
    assert_eq!(cstatus(&b.hop(20, c)), CStatus::Malformed);
    assert_eq!(
        astatus(&b.hop(20, chunk(40, &[key(1, 1)]))).0,
        ChunkStatus::NotMine
    );
    assert_eq!(cstatus(&b.hop(20, complete(40, &[]))), CStatus::Malformed);
    assert!(b.store.idx().is_none());
}

// ------------------------------------------------------------ Query table

fn query(from: Ver, m: Digest) -> Frame {
    Frame::Query {
        rec: Rec::build(from),
        m,
    }
}

#[test]
fn query_rows() {
    // revision 8 (F4): "retired" only when RETIRED to the querier's record
    // at the same m
    let mut b = t(20);
    b.set(
        PState::Retired {
            to: Rec::build(30),
            m: 7,
            taken_over: None,
        },
        &[],
    );
    assert_eq!(cstatus(&b.hop(30, query(30, 7))), CStatus::Noted);
    for (to, m) in [(40, 7), (30, 8)] {
        let mut b = t(20);
        b.set(
            PState::Retired {
                to: Rec::build(to),
                m,
                taken_over: None,
            },
            &[],
        );
        assert_eq!(
            cstatus(&b.hop(30, query(30, 7))),
            CStatus::AnotherWriter,
            "retired to {to} at {m}"
        );
    }

    // NONE: stores the querier's record, answers 0x0B
    let mut b = t(20);
    assert_eq!(cstatus(&b.hop(30, query(30, 7))), CStatus::NoState);
    assert_eq!(
        b.store.succ().current,
        Some(Rec::build(30)),
        "stores the querier's record"
    );

    let mut b = t(20);
    b.set(
        PState::Sealed {
            w: WFields::default(),
            target: Rec::build(30),
            m: 7,
        },
        &[],
    );
    assert_eq!(cstatus(&b.hop(30, query(30, 7))), CStatus::Noted);
    assert!(matches!(b.state(), PState::Retired { m: 7, .. }));

    for state in [
        PState::Sealed {
            w: WFields::default(),
            target: Rec::build(30),
            m: 8,
        },
        PState::Writer(WFields::default()),
        PState::Receiving {
            from: 10,
            store_failed: false,
        },
    ] {
        let mut b = t(20);
        b.set(state.clone(), &[]);
        assert_eq!(
            cstatus(&b.hop(30, query(30, 7))),
            CStatus::AnotherWriter,
            "{state:?}"
        );
        assert_eq!(b.state(), state);
    }
}

#[test]
fn query_with_record_not_naming_sender_is_ignored() {
    let mut b = t(20);
    assert_eq!(b.hop(30, query(40, 7)), None);
    assert_eq!(b.hop(10, query(10, 7)), None, "not above own version");
}

fn answer(from: Ver, to: Ver, m: Digest, status: CStatus) -> Frame {
    Frame::CompleteAck {
        tid: (from, Rec::build(to)),
        m,
        status,
        succ: None,
        missing: vec![],
    }
}

/// Section 6 row (revision 8, F1): the answer to this build's own Query is
/// applied; "retired" and "no state" clear awaiting_retirement, only for
/// the m taken over at and only from the build taken over from.
#[test]
fn section6_applies_the_answer_to_query() {
    for st in [CStatus::Noted, CStatus::NoState] {
        let mut b = t(30);
        b.set(writer_from(20, 7, true), &[]);
        assert_eq!(b.hop(20, answer(20, 30, 7, st)), None);
        assert_eq!(b.state(), writer_from(20, 7, false), "{st:?}");
    }
    let mut b = t(30);
    b.set(writer_from(20, 7, true), &[]);
    b.hop(20, answer(20, 30, 8, CStatus::Noted));
    b.hop(10, answer(10, 30, 7, CStatus::Noted));
    assert_eq!(
        b.state(),
        writer_from(20, 7, true),
        "other m or other build"
    );
    b.hop(20, answer(20, 30, 7, CStatus::AnotherWriter));
    assert_eq!(b.store.idx_or_none().problems & PROBLEM_ANOTHER_WRITER, 4);
    assert!(matches!(b.state(), PState::Writer(ref w) if w.awaiting));
}

// ------------------------------------------------------ creation (3, 5.3)

fn arm(b: &mut T) -> Output {
    let v = b.def.v;
    b.call(Input::Poke {
        flags: POKE_ARM,
        rec: Some(Rec::build(v)),
    })
}

fn generate(b: &mut T) -> OpRes {
    match b.call(Input::Op(Op::Generate { slot: 0, seed: 9 })).reply {
        Reply::Op(r) => r,
        r => panic!("{r:?}"),
    }
}

#[test]
fn creation_guard_probes_every_predecessor_and_creates_only_when_all_confirmed() {
    let mut b = t(30);
    let out = arm(&mut b);
    let probes: Vec<Ver> = out
        .hops
        .iter()
        .filter(|(_, f)| matches!(f, Frame::Query { m: 0, .. }))
        .map(|(t, _)| *t)
        .collect();
    assert_eq!(probes, vec![10, 20]);
    assert_eq!(generate(&mut b), OpRes::NotHere, "no confirmation yet");
    b.hop(10, answer(10, 30, 0, CStatus::NoState));
    assert_eq!(generate(&mut b), OpRes::NotHere, "20 unconfirmed");
    // a later poke re-sends only to the unconfirmed predecessor
    let out = b.call(Input::Poke {
        flags: 0,
        rec: None,
    });
    assert_eq!(
        out.hops.iter().map(|(t, _)| *t).collect::<Vec<_>>(),
        vec![20]
    );
    b.hop(20, answer(20, 30, 0, CStatus::StorageFailure));
    assert_eq!(generate(&mut b), OpRes::NotHere);
    b.hop(20, answer(20, 30, 0, CStatus::NoState));
    assert_eq!(generate(&mut b), OpRes::Key(9));
}

#[test]
fn creation_guard_state_answer_clears_arming() {
    let mut b = t(30);
    arm(&mut b);
    b.hop(10, answer(10, 30, 0, CStatus::AnotherWriter));
    assert_eq!(b.state(), PState::none());
}

#[test]
fn creation_bar_refuses_arming_and_a_withdrawal_does_not_lift_it() {
    let mut b = t(20);
    b.succ(Succ {
        current: Some(Rec::build(30)),
        withdrawal: Some(Rec::withdrawal(35)),
    });
    arm(&mut b);
    assert_eq!(b.state(), PState::none());
}

#[test]
fn a_newer_record_clears_arming_and_confirmations() {
    let mut b = t(30);
    arm(&mut b);
    b.hop(10, answer(10, 30, 0, CStatus::NoState));
    b.call(Input::Poke {
        flags: 0,
        rec: Some(Rec::build(40)),
    });
    assert_eq!(b.state(), PState::none());
}

/// Revision 9 (F10): a NONE predecessor whose floor is already at or above
/// the querier's version answers a creation probe "stopped" (0x03) when the
/// floor comes from a withdrawal, else 0x07; it stores nothing.
#[test]
fn probe_below_the_floor_answers_stopped_or_another_writer() {
    let mut b = t(10);
    b.succ(Succ {
        current: None,
        withdrawal: Some(Rec::withdrawal(25)),
    });
    assert_eq!(cstatus(&b.hop(20, query(20, 0))), CStatus::Stopped);
    let mut b = t(10);
    b.succ(Succ {
        current: Some(Rec::build(30)),
        withdrawal: None,
    });
    assert_eq!(cstatus(&b.hop(20, query(20, 0))), CStatus::AnotherWriter);
    assert_eq!(b.store.succ().current, Some(Rec::build(30)));
}

/// Revision 9 (F10): a build that holds a withdrawal above its current
/// record never arms.
#[test]
fn a_stopped_build_refuses_arming() {
    let mut b = t(20);
    b.succ(Succ {
        current: None,
        withdrawal: Some(Rec::withdrawal(25)),
    });
    arm(&mut b);
    assert_eq!(b.state(), PState::none());
}

/// Revision 10 (v1): a RETIRED predecessor answers every creation probe
/// 0x07 (0x0C is unassigned in v1).
#[test]
fn retired_answers_every_creation_probe_0x07_in_v1() {
    for to in [20, 30] {
        let mut b = t(10);
        b.set(
            PState::Retired {
                to: Rec::build(to),
                m: 7,
                taken_over: None,
            },
            &[],
        );
        assert_eq!(cstatus(&b.hop(20, query(20, 0))), CStatus::AnotherWriter);
        assert_eq!(cstatus(&b.hop(30, query(30, 0))), CStatus::AnotherWriter);
    }
}

/// Revision 9 (F7): retiring unlists the partition before Retired is sent.
#[test]
fn retire_unlists_before_sending_retired() {
    let es = [key(0, 5)];
    let (mut s, m) = sealed_sender(30, &es);
    s.store.secrets.insert(SName::Parts, SVal::Parts);
    let out = s.call(Input::Hop {
        from: 30,
        frame: cack(30, m, CStatus::Accepted),
    });
    assert!(matches!(s.state(), PState::Retired { .. }));
    // revision 10: vault:parts is never removed; unlisting writes the
    // shorter list
    assert_eq!(s.store.secrets.get(&SName::Parts), Some(&SVal::PartsEmpty));
    assert!(out
        .hops
        .iter()
        .any(|(t, f)| *t == 30 && matches!(f, Frame::Retired { .. })));
}

// ------------------------------------------------------ host faults (4.0) and index loss (4.5)

#[test]
fn a_poisoned_call_refuses_every_later_write() {
    let mut b = t(20);
    b.faults.read_armed = Some(0);
    let out = b.call(Input::Hop {
        from: 30,
        frame: query(30, 0),
    });
    assert!(out.poisoned);
    assert_eq!(b.store.succ().current, None, "the record write was refused");
}

#[test]
fn undecryptable_index_while_listed_is_index_loss() {
    let mut b = t(20);
    b.set(PState::Writer(WFields::default()), &[key(0, 5)]);
    // revision 10: a listed build keeps the mirror
    b.store
        .secrets
        .insert(SName::E((KIND_KEY, 0), true), SVal::E(key(0, 5)));
    b.store.secrets.insert(SName::Parts, SVal::Parts);
    b.store.secrets.insert(SName::Idx, SVal::Undecryptable);
    assert!(b.store.index_lost());
    // no handover frame is answered
    assert_eq!(b.hop(30, query(30, 7)), None);
    assert_eq!(b.hop(10, complete(20, &[])), None);
    // status reports partition_state 7 and problems bit 6
    match b
        .call(Input::Poke {
            flags: 0,
            rec: None,
        })
        .reply
    {
        Reply::Status(s) => {
            assert!(s.index_lost);
            assert_eq!(s.problems & PROBLEM_INDEX_LOST, PROBLEM_INDEX_LOST);
        }
        r => panic!("{r:?}"),
    }
    // reads work by the direct-read rule; changes are refused
    match b.call(Input::Op(Op::PublicKey { slot: 0 })).reply {
        Reply::Op(r) => assert_eq!(r, OpRes::Key(5)),
        r => panic!("{r:?}"),
    }
    assert_eq!(generate(&mut b), OpRes::Refused(12));
    // revision 10: a slot with no usable copy answers storage failure,
    // never Absent
    match b.call(Input::Op(Op::PublicKey { slot: 3 })).reply {
        Reply::Op(r) => assert_eq!(r, OpRes::Refused(12)),
        r => panic!("{r:?}"),
    }
}

/// Revision 10 final (F13, F15, the mirror): direct read serves a slot
/// only when both parity copies authenticate and are byte-identical; a
/// single copy, two disagreeing copies, a flagged pair or a pair with the
/// wrong key answer storage failure, never Absent; vault:gc is not read.
#[test]
fn direct_read_serves_only_complete_agreeing_authenticating_pairs() {
    let id = (KIND_KEY, 0);
    let read = |b: &mut T, op: Op| match b.call(Input::Op(op)).reply {
        Reply::Op(r) => r,
        r => panic!("{r:?}"),
    };
    let mut b = t(20);
    b.set(PState::Writer(WFields::default()), &[key(0, 5)]);
    b.store.secrets.insert(SName::Parts, SVal::Parts);
    b.store
        .secrets
        .insert(SName::E(id, true), SVal::E(key(0, 5)));
    b.store.secrets.insert(SName::Idx, SVal::Undecryptable);
    assert_eq!(read(&mut b, Op::PublicKey { slot: 0 }), OpRes::Key(5));
    // a malformed vault:gc listing both names changes nothing
    b.store.secrets.insert(SName::Gc, SVal::Garbled);
    assert_eq!(read(&mut b, Op::Export { slot: 0 }), OpRes::Key(5));
    // two copies that disagree
    b.store
        .secrets
        .insert(SName::E(id, true), SVal::E(key(0, 9)));
    assert_eq!(read(&mut b, Op::PublicKey { slot: 0 }), OpRes::Refused(12));
    // a single copy
    b.store.secrets.remove(&SName::E(id, true));
    assert_eq!(read(&mut b, Op::PublicKey { slot: 0 }), OpRes::Refused(12));
    // a copy that does not authenticate (undecryptable, flagged, wrong key)
    b.store
        .secrets
        .insert(SName::E(id, true), SVal::Undecryptable);
    assert_eq!(read(&mut b, Op::Export { slot: 0 }), OpRes::Refused(12));
    let flagged = Entry {
        flagged: true,
        ..key(0, 5)
    };
    b.store
        .secrets
        .insert(SName::E(id, false), SVal::E(flagged.clone()));
    b.store.secrets.insert(SName::E(id, true), SVal::E(flagged));
    assert_eq!(read(&mut b, Op::Export { slot: 0 }), OpRes::Refused(12));
    let wrong = Entry {
        key: 7,
        ..key(0, 5)
    };
    b.store
        .secrets
        .insert(SName::E(id, false), SVal::E(wrong.clone()));
    b.store.secrets.insert(SName::E(id, true), SVal::E(wrong));
    assert_eq!(read(&mut b, Op::PublicKey { slot: 0 }), OpRes::Refused(12));
    // no copy at all: storage failure, never Absent
    b.store.secrets.remove(&SName::E(id, false));
    b.store.secrets.remove(&SName::E(id, true));
    assert_eq!(read(&mut b, Op::PublicKey { slot: 0 }), OpRes::Refused(12));
}

/// Revision 10 final (4.2): a change writes the parity the index does not
/// name, commits, then mirrors; a crash before the mirror leaves two
/// disagreeing copies; a new identity first clears both parity names.
#[test]
fn entry_write_mirrors_after_commit_and_clears_leftovers_first() {
    let id = (KIND_KEY, 0);
    let mut b = t(20);
    b.set(PState::Writer(WFields::default()), &[key(0, 5)]);
    b.store
        .secrets
        .insert(SName::E(id, true), SVal::E(key(0, 5)));
    b.store.secrets.insert(SName::Parts, SVal::Parts);
    // crash right after the entry write (step 2): the pair disagrees
    b.faults.armed = Some((0, crate::store::WriteFault::CrashAfter));
    let _ = b.try_call(Input::Op(Op::Import {
        slot: 0,
        seed: 6,
        replace: true,
    }));
    assert_eq!(
        b.store.secrets.get(&SName::E(id, true)),
        Some(&SVal::E(key(0, 6)))
    );
    assert_eq!(
        b.store.secrets.get(&SName::E(id, false)),
        Some(&SVal::E(key(0, 5)))
    );
    assert_eq!(b.store.direct_value(id), Err(()));
    // a complete write leaves both copies identical
    let mut b = t(20);
    b.set(PState::Writer(WFields::default()), &[key(0, 5)]);
    b.store
        .secrets
        .insert(SName::E(id, true), SVal::E(key(0, 5)));
    b.store.secrets.insert(SName::Parts, SVal::Parts);
    b.call(Input::Op(Op::Import {
        slot: 0,
        seed: 6,
        replace: true,
    }));
    assert_eq!(
        b.store.secrets.get(&SName::E(id, true)),
        Some(&SVal::E(key(0, 6)))
    );
    assert_eq!(
        b.store.secrets.get(&SName::E(id, false)),
        Some(&SVal::E(key(0, 6)))
    );
    // a new identity with a leftover copy: step 1 removes it first
    let id1 = (KIND_KEY, 1);
    b.store
        .secrets
        .insert(SName::E(id1, true), SVal::E(key(1, 8)));
    b.faults.armed = Some((1, crate::store::WriteFault::CrashBefore));
    let _ = b.try_call(Input::Op(Op::Generate { slot: 1, seed: 8 }));
    assert!(!b.store.secrets.contains_key(&SName::E(id1, true)));
    assert_eq!(b.store.direct_value(id1), Err(()));
}

/// Revision 10 (F14): a malformed index is index loss only while
/// vault:parts lists the partition or does not read as a valid list.
#[test]
fn malformed_index_is_none_only_while_parts_is_a_valid_list_without_it() {
    let mut b = t(20);
    b.store.secrets.insert(SName::Idx, SVal::Garbled);
    b.store.secrets.insert(SName::Parts, SVal::PartsEmpty);
    assert!(!b.store.index_lost());
    b.store.secrets.insert(SName::Parts, SVal::Parts);
    assert!(b.store.index_lost());
    b.store.secrets.remove(&SName::Parts);
    assert!(
        !b.store.index_lost(),
        "revision 10.1 (G1): an absent vault:parts is a valid empty list"
    );
    b.store.secrets.insert(SName::Parts, SVal::Garbled);
    assert!(b.store.index_lost(), "present but not a valid list");
}

/// Revision 10 (F17): an undecryptable vault:parts on a writer whose index
/// is valid is removed and written again; changes keep working.
#[test]
fn undecryptable_parts_with_a_valid_index_is_removed_and_relisted() {
    let mut b = t(20);
    b.set(PState::Writer(WFields::default()), &[key(0, 5)]);
    b.store.secrets.insert(SName::Parts, SVal::Undecryptable);
    match b.call(Input::Op(Op::Generate { slot: 1, seed: 9 })).reply {
        Reply::Op(r) => assert_eq!(r, OpRes::Key(9)),
        r => panic!("{r:?}"),
    }
    assert_eq!(b.store.secrets.get(&SName::Parts), Some(&SVal::Parts));
}

#[test]
fn undecryptable_index_without_parts_reads_as_none() {
    let mut b = t(20);
    b.store.secrets.insert(SName::Idx, SVal::Undecryptable);
    assert!(!b.store.index_lost());
    assert_eq!(cstatus(&b.hop(30, query(30, 0))), CStatus::NoState);
}

// ------------------------------------------------------ sender (7.3 to 7.5)

fn sealed_sender(target: Ver, es: &[Entry]) -> (T, Digest) {
    let mut s = t(20);
    let (m, _) = mf(es);
    s.set(
        PState::Sealed {
            w: WFields::default(),
            target: Rec::build(target),
            m,
        },
        es,
    );
    s.succ(Succ {
        current: Some(Rec::build(target)),
        withdrawal: None,
    });
    (s, m)
}

fn cack(target: Ver, m: Digest, status: CStatus) -> Frame {
    Frame::CompleteAck {
        tid: (20, Rec::build(target)),
        m,
        status,
        succ: None,
        missing: vec![],
    }
}

#[test]
fn sender_unseals_only_on_did_not_take_over_answers() {
    let es = [key(1, 1)];
    for st in CStatus::ALL {
        let (mut s, m) = sealed_sender(30, &es);
        let out = s.call(Input::Hop {
            from: 30,
            frame: cack(30, m, st),
        });
        let state = s.state();
        match st {
            CStatus::Accepted | CStatus::AlreadyWriter => {
                assert!(
                    matches!(state, PState::Retired { m: mm, .. } if mm == m),
                    "{st:?}"
                );
                assert!(out
                    .hops
                    .iter()
                    .any(|(to, f)| *to == 30 && matches!(f, Frame::Retired { .. })));
            }
            s2 if s2.unseals() => assert!(matches!(state, PState::Writer(_)), "{st:?}"),
            _ => assert!(
                matches!(state, PState::Sealed { .. }),
                "{st:?} must not unseal"
            ),
        }
        if st == CStatus::DifferentManifest {
            assert_ne!(s.store.idx_or_none().problems & PROBLEM_ANOTHER_WRITER, 0);
        }
    }
}

#[test]
fn sender_ignores_answers_for_another_m_or_from_another_build() {
    let es = [key(1, 1)];
    let (mut s, m) = sealed_sender(30, &es);
    s.call(Input::Hop {
        from: 30,
        frame: cack(30, m ^ 1, CStatus::Aborted),
    });
    s.call(Input::Hop {
        from: 40,
        frame: cack(40, m, CStatus::Aborted),
    });
    assert!(matches!(s.state(), PState::Sealed { .. }));
}

#[test]
fn sender_step_sends_abort_only_with_a_trigger() {
    let es = [key(1, 1)];
    let (mut s, m) = sealed_sender(30, &es);
    let out = s.call(Input::Wakeup);
    // no acknowledged progress: the entries are resent, then Complete(m)
    assert!(matches!(out.hops.last(), Some((30, Frame::Complete { m: mm, .. })) if *mm == m));
    assert!(!out
        .hops
        .iter()
        .any(|(_, f)| matches!(f, Frame::Abort { .. })));
    s.call(Input::Poke {
        flags: 0,
        rec: Some(Rec::build(40)),
    });
    let out = s.call(Input::Wakeup);
    assert!(
        matches!(out.hops.as_slice(), [(30, Frame::Abort { .. })]),
        "{:?}",
        out.hops
    );
    assert!(
        matches!(s.state(), PState::Sealed { .. }),
        "a record never unseals by itself"
    );
}

#[test]
fn awaiting_writer_queries_and_refuses_changes() {
    let mut b = t(30);
    b.set(writer_from(20, 7, true), &[key(1, 1)]);
    let out = b.call(Input::Wakeup);
    assert!(matches!(
        out.hops.as_slice(),
        [(20, Frame::Query { m: 7, .. })]
    ));
    assert_eq!(
        b.call(Input::Op(Op::Delete { slot: 1 })).reply,
        Reply::Op(OpRes::Busy)
    );
    assert_eq!(
        b.call(Input::Op(Op::PublicKey { slot: 1 })).reply,
        Reply::Op(OpRes::Key(1))
    );
}

/// Deliver every hop between two builds until quiet; the basic handover.
#[test]
fn basic_handover_between_two_builds() {
    let mut a = t(20);
    a.set(
        PState::Writer(WFields::default()),
        &[key(1, 1), key(2, 2), key(3, 3)],
    );
    let mut b = t(30);
    a.call(Input::Poke {
        flags: 0,
        rec: Some(Rec::build(30)),
    });
    let mut q: std::collections::VecDeque<(Ver, Ver, Frame)> = Default::default();
    for _ in 0..20 {
        if q.is_empty() {
            let o = a.call(Input::Wakeup);
            q.extend(o.hops.into_iter().map(|(to, f)| (20, to, f)));
            let o = b.call(Input::Wakeup);
            q.extend(o.hops.into_iter().map(|(to, f)| (30, to, f)));
        }
        let Some((from, to, f)) = q.pop_front() else {
            break;
        };
        let (x, y) = if to == 30 {
            (&mut b, &mut a)
        } else {
            (&mut a, &mut b)
        };
        let o = x.call(Input::Hop { from, frame: f });
        q.extend(o.hops.into_iter().map(|(t2, f)| (to, t2, f)));
        if let Reply::Frame(r) = o.reply {
            let o2 = y.call(Input::Hop { from: to, frame: r });
            q.extend(o2.hops.into_iter().map(|(t2, f)| (from, t2, f)));
        }
    }
    assert!(
        matches!(a.state(), PState::Retired { to, .. } if to.v == 30),
        "{:?}",
        a.state()
    );
    assert!(
        matches!(
            b.state(),
            PState::Writer(WFields {
                awaiting: false,
                ..
            })
        ),
        "{:?}",
        b.state()
    );
    assert_eq!(b.digests(), a.digests());
}
