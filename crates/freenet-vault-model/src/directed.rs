//! Directed scenarios: action lists built by driving a `World` toward a
//! row that random schedules do not reach, recorded as they are applied so
//! that they replay exactly. Each is run with the seeded schedules (15.5,
//! every row at least once per run); a test fails if one stops reaching its
//! row.

use crate::build::Op;
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

/// Every directed scenario with the row it exists to reach.
pub fn directed(cfg: &Cfg) -> Vec<(&'static str, Scenario)> {
    let mut v = vec![];
    if let Some(sc) = other_writer_retired(cfg) {
        v.push(("7.6/other-writer-or-not-from-P/Retired", sc));
    }
    v
}
