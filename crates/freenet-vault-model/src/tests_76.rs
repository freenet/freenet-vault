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
            i,
        )
        .expect("no crash")
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
        PState::None { armed: None },
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
    assert_eq!(b.state(), PState::None { armed: None });
}

#[test]
fn row_none_abort_and_retired() {
    let mut b = t(30);
    assert_eq!(cstatus(&b.hop(20, abort(30, 3))), CStatus::Aborted);
    assert_eq!(b.hop(20, retired(30, 3)), None);
    assert_eq!(b.state(), PState::None { armed: None });
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
    let mut b = t(20);
    b.set(
        PState::Retired {
            to: Rec::build(40),
            m: 1,
            taken_over: None,
        },
        &[],
    );
    assert_eq!(
        cstatus(&b.hop(30, query(30, 7))),
        CStatus::Noted,
        "retired to any build"
    );

    let mut b = t(20);
    assert_eq!(cstatus(&b.hop(30, query(30, 7))), CStatus::Noted);
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

/// Section 6 read literally: an Ack/CompleteAck is applied only from
/// S(current) or S(sealed target). The answer to Query comes from the
/// predecessor, which is neither, so it is ignored and awaiting_retirement
/// is never cleared by Query. This test pins the literal reading; the gap is
/// reported as a spec finding.
#[test]
fn section6_literal_ignores_the_answer_to_query() {
    let mut b = t(30);
    b.set(writer_from(20, 7, true), &[]);
    let ans = Frame::CompleteAck {
        tid: (20, Rec::build(30)),
        m: 7,
        status: CStatus::Noted,
        succ: None,
        missing: vec![],
    };
    assert_eq!(b.hop(20, ans.clone()), None);
    assert_eq!(b.state(), writer_from(20, 7, true), "still awaiting");

    let mut b = t(30);
    b.p.spec.accept_query_answer = true;
    b.set(writer_from(20, 7, true), &[]);
    b.hop(20, ans);
    assert_eq!(b.state(), writer_from(20, 7, false));
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
