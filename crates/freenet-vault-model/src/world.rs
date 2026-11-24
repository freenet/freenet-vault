//! The node, the fake runtime, the clients and the operator (15.2), driven
//! by a schedule of actions, with invariants I1 to I8 (15.4) checked after
//! every action.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::build::{self, BuildDef, Input, Note, Op, OpRes, Params, Reply, Status, Volatile};
use crate::cov::Cov;
use crate::store::{Crash, Event, FaultPlan, Store, WriteFault};
use crate::types::*;

pub const NBUILDS: usize = 6;
pub const ROLLBACK: Ver = 50;

pub fn ver(i: usize) -> Ver {
    (i as Ver + 1) * 10
}
pub fn bi(v: Ver) -> usize {
    (v / 10 - 1) as usize
}

/// Builds 10..60. 40 and 60 write the unknown kind; 50 is the reserved
/// rollback build R(5) of release 40, running the code of 30 (14.7).
pub fn build_defs() -> Vec<BuildDef> {
    (0..NBUILDS)
        .map(|i| {
            let v = ver(i);
            BuildDef {
                v,
                preds: (0..i).map(ver).collect(),
                writes_unknown_kind: v == 40 || v == 60,
                code_of: if v == ROLLBACK { 30 } else { v },
            }
        })
        .collect()
}

/// Client bundles (13.1): two full lineages, an old lineage, a mid lineage.
pub const CLIENTS: [&[Ver]; 4] = [
    &[10, 20, 30, 40, 50, 60],
    &[10, 20, 30, 40, 50, 60],
    &[10, 20, 30],
    &[10, 20, 30, 40],
];

/// How hops are delivered.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Delivery {
    /// What freenet-core does (main after #6340, `contract.rs`
    /// `handle_delegate_with_contract_requests`): a hop is executed
    /// synchronously inside the caller's run or dropped, never queued; the one
    /// reply is delivered later in the same run or lost; runs of one delegate
    /// never interleave; a client request's first call may run on the
    /// delegate lane between two calls of a loop run of another delegate.
    /// Gating.
    #[default]
    Core,
    /// Every hop of every run sits in a queue and any eligible hop of any
    /// run may be delivered next, interleaved with everything else. A
    /// superset of core's schedules; with `adversarial` it also violates
    /// assumption D. Not gating.
    Queued,
}

#[derive(Clone, Debug, Default)]
pub struct Cfg {
    pub params: Params,
    pub delivery: Delivery,
    /// Adversarial delivery mode: hops delayed past their run, duplicated
    /// and reordered (violates assumption D; not gating).
    pub adversarial: bool,
    /// The pointer read may return any published record (not in 15.3; not
    /// gating).
    pub stale_pointer: bool,
    /// Assumption D read as "never reorders two hops between the same pair"
    /// across runs too. false: FIFO only within a run (not gating).
    pub d_global_fifo: bool,
    /// Hops damaged in transit (answered "malformed"); beyond 15.3.
    pub garble_hops: bool,
    pub withdrawals: bool,
    pub wakeup_hop_cap: usize,
    pub client_iter_cap: usize,
    pub quiesce_rounds: usize,
    pub trace: bool,
}

impl Cfg {
    pub fn gate() -> Cfg {
        Cfg {
            params: Params::default(),
            delivery: Delivery::Core,
            adversarial: false,
            stale_pointer: false,
            d_global_fifo: true,
            garble_hops: true,
            withdrawals: true,
            wakeup_hop_cap: 6,
            client_iter_cap: 14,
            quiesce_rounds: 12,
            trace: false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fetch {
    Newest,
    Unreachable,
    Stale(u8),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fate {
    Deliver,
    Drop,
    Garble,
    /// adversarial only
    Delay,
    /// adversarial only
    Duplicate,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    Publish,
    Load {
        client: u8,
        fetch: Fetch,
        ops: Vec<Op>,
    },
    Step {
        pick: u16,
        fate: Fate,
    },
    Wakeup {
        b: u8,
    },
    Crash,
    ArmWriteFault {
        after: u8,
        fault: WriteFault,
    },
    Quota {
        limit: Option<u8>,
    },
    Unregister {
        b: u8,
    },
    Restore {
        b: u8,
        snap: u16,
        secret: Option<u16>,
    },
    Wipe {
        b: u8,
    },
    /// Damage one secret of build `b`: bytes that no longer parse, or
    /// (`undecryptable`) bytes that fail authentication and read as absent
    /// (4.0). Any secret, the index and vault:parts included (15.3).
    Garble {
        b: u8,
        pick: u16,
        undecryptable: bool,
    },
    /// The n-th secret read from now fails with an I/O error: the call is
    /// poisoned (4.0).
    ArmReadFault {
        after: u8,
    },
    /// A cached caller: addresses the build it last used (`b: None`), or a
    /// build it used long ago (`b: Some`).
    Cached {
        op: Op,
        b: Option<u8>,
    },
}

#[derive(Clone, Debug)]
pub struct Scenario {
    pub ledger: Vec<Rec>,
    pub actions: Vec<Action>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Violation {
    pub inv: &'static str,
    pub msg: String,
    pub at: usize,
}

#[derive(Clone, Debug)]
struct Hop {
    from: Ver,
    to: Ver,
    frame: Frame,
    reply: bool,
    seq: u64,
}

#[derive(Clone, Debug)]
enum RunKind {
    #[allow(dead_code)]
    Client(usize),
    Unprompted,
}

#[derive(Clone, Debug)]
struct Run {
    kind: RunKind,
    queue: VecDeque<Hop>,
    sent: usize,
    iters: usize,
}

/// Core delivery: one delegate run (`handle_delegate_with_contract_requests`).
#[derive(Clone, Debug)]
struct CRun {
    id: usize,
    b: usize,
    kind: RunKind,
    /// Hops the last call of this run emitted, executed one per step, in
    /// order, before the next call into the run's delegate.
    hops: VecDeque<(Ver, Frame)>,
    /// Hop replies queued for calls of their own (`next_call`), oldest first.
    replies: VecDeque<(Ver, Frame)>,
    /// Calls into the run's delegate so far (MAX_CONTRACT_REQUEST_ITERATIONS).
    iters: usize,
    /// Hops attempted (MAX_UNPROMPTED_HOPS_PER_RUN, unprompted runs only).
    attempted: usize,
    /// A hop whose target's pending unit is running nested on top of this
    /// run; delivered when that unit finishes. The target stays claimed.
    resume: Option<(Ver, Frame)>,
}

/// Core delivery: work waiting for the serial contract loop.
#[derive(Clone, Debug)]
enum LoopItem {
    /// A wake-up or lifecycle run.
    Wakeup(usize),
    /// A client request the lane forwarded because its delegate was busy.
    Req {
        rid: usize,
        sid: usize,
        b: usize,
        input: Input,
    },
    /// A client operation the lane forwarded.
    Op {
        rid: usize,
        sid: Option<usize>,
        b: usize,
        op: Op,
    },
}

/// Core: `MAX_PENDING_UNITS`.
const MAX_PENDING_UNITS: usize = 16;

#[derive(Clone, Debug, PartialEq, Eq)]
enum Phase {
    Poke(usize),
    Decide,
    Ops,
    Done,
}

#[derive(Clone, Debug)]
struct Session {
    client: u8,
    bundle: Vec<Ver>,
    fetched: Option<Rec>,
    /// Newest non-withdrawal record below a withdrawal, from the same fetch.
    fetched_nonwd: Option<Rec>,
    phase: Phase,
    statuses: BTreeMap<Ver, Option<Status>>,
    rounds: u8,
    again: BTreeSet<Ver>,
    ops: VecDeque<Op>,
    target: Option<Ver>,
    run: Option<usize>,
}

/// Possible values of one entry identity (I2, I3, I8): the last
/// acknowledged value plus every unacknowledged attempt since.
#[derive(Clone, Debug, Default)]
struct Possible {
    acked: Option<Entry>,
    maybe: Vec<Option<Entry>>,
}

impl Possible {
    fn allows(&self, v: &Option<Entry>) -> bool {
        let eq = |a: &Option<Entry>| match (a, v) {
            (None, None) => true,
            (Some(x), Some(y)) => x.content == y.content && x.ext == y.ext && x.kind == y.kind,
            _ => false,
        };
        eq(&self.acked) || self.maybe.iter().any(eq)
    }
}

pub struct World {
    pub cfg: Cfg,
    pub defs: Vec<BuildDef>,
    pub stores: Vec<Store>,
    vols: Vec<Volatile>,
    pub registered: Vec<bool>,
    history: Vec<Vec<Store>>,
    pub ledger: Vec<Rec>,
    pub published: usize,
    runs: BTreeMap<usize, Run>,
    next_run: usize,
    next_seq: u64,
    sessions: BTreeMap<usize, Session>,
    next_session: usize,
    limbo: Vec<Hop>,
    /// Core delivery: the loop's run stack (top runs; below it, a run whose
    /// hop target's pending unit is running nested), the loop's queue, and
    /// the lane's handed-off continuations (at most one per delegate).
    stack: Vec<CRun>,
    lq: VecDeque<LoopItem>,
    units: BTreeMap<usize, CRun>,
    faults: FaultPlan,
    events: Vec<Event>,
    pub cov: Cov,
    oracle: BTreeMap<Ident, Possible>,
    tainted: BTreeSet<Ident>,
    pub restored: bool,
    pub garbled: bool,
    held: BTreeSet<Ver>,
    cached_target: Option<Ver>,
    pub trace: Vec<String>,
    pub violation: Option<Violation>,
    step_no: usize,
    pub sealed_corrupt_sent: u64,
    /// Repair flow (4.5): seeds each session exported, and sessions whose
    /// ResetPartition succeeded.
    exports: BTreeMap<usize, BTreeMap<u16, u32>>,
    reset_done: BTreeSet<usize>,
    /// Keys whose repair flow ended after the reset and before their
    /// re-import (labels I2 failures on them).
    repair_interrupted: BTreeSet<Ident>,
    repair_tries: BTreeMap<(usize, u16), u8>,
    /// Per predecessor, the queriers it answered 0x0B (decision 1).
    nostate_to: BTreeMap<Ver, BTreeSet<Ver>>,
}

impl World {
    pub fn new(cfg: Cfg, ledger: Vec<Rec>) -> World {
        World {
            defs: build_defs(),
            stores: vec![Store::default(); NBUILDS],
            vols: vec![Volatile::default(); NBUILDS],
            registered: vec![false; NBUILDS],
            history: vec![vec![Store::default()]; NBUILDS],
            ledger,
            published: 0,
            runs: BTreeMap::new(),
            next_run: 0,
            next_seq: 0,
            sessions: BTreeMap::new(),
            next_session: 0,
            limbo: vec![],
            stack: vec![],
            lq: VecDeque::new(),
            units: BTreeMap::new(),
            faults: FaultPlan::default(),
            events: vec![],
            cov: Cov::default(),
            oracle: BTreeMap::new(),
            tainted: BTreeSet::new(),
            restored: false,
            garbled: false,
            held: BTreeSet::new(),
            cached_target: None,
            trace: vec![],
            violation: None,
            step_no: 0,
            sealed_corrupt_sent: 0,
            exports: BTreeMap::new(),
            reset_done: BTreeSet::new(),
            repair_interrupted: BTreeSet::new(),
            repair_tries: BTreeMap::new(),
            nostate_to: BTreeMap::new(),
            cfg,
        }
    }

    fn log(&mut self, s: impl FnOnce() -> String) {
        if self.cfg.trace {
            let line = s();
            self.trace.push(line);
        }
    }

    fn fail(&mut self, inv: &'static str, msg: String) {
        if self.violation.is_none() {
            self.log(|| format!("!! {inv}: {msg}"));
            self.violation = Some(Violation {
                inv,
                msg,
                at: self.step_no,
            });
        }
    }

    pub fn newest_published(&self) -> Option<Rec> {
        self.ledger[..self.published].last().copied()
    }

    fn newest_nonwd_below(&self, w: Rec) -> Option<Rec> {
        self.ledger[..self.published]
            .iter()
            .rev()
            .find(|r| !r.withdrawal && r.v < w.v)
            .copied()
    }

    // ---------------------------------------------------------- build calls

    /// One vault call. None if the node crashed inside it. A call poisoned
    /// by a read fault (4.0) has its outputs discarded and is retried once
    /// (the read fault is consumed by the first attempt).
    fn call(&mut self, b: usize, input: Input) -> Option<build::Output> {
        let out = self.call_once(b, input.clone())?;
        if !out.poisoned {
            return Some(out);
        }
        self.cov.hit("fault/read-poisoned");
        self.log(|| {
            format!(
                "  {} call poisoned: outputs discarded, request retried",
                ver(b)
            )
        });
        if let Input::Op(op) = &input {
            // the first attempt's writes before the failed read stand
            if let Some((id, v)) = intended_value(op, &self.oracle) {
                self.oracle.entry(id).or_default().maybe.push(v);
            }
        }
        let out = self.call_once(b, input)?;
        if out.poisoned {
            // a second armed read fault: drop the request
            return None;
        }
        Some(out)
    }

    fn call_once(&mut self, b: usize, input: Input) -> Option<build::Output> {
        let before = self.stores[b].idx_or_none();
        let before_lost = self.stores[b].index_lost();
        let before_succ = self.stores[b].succ();
        // A Query (creation probe, m zero; or an awaiting successor's
        // Query, m non-zero) reaching a NONE predecessor.
        let query_to_none = match &input {
            Input::Hop {
                from,
                frame: Frame::Query { m, .. },
            } if before.state.is_none() && !before_lost => Some((*from, *m)),
            _ => None,
        };
        let fired_before = self.faults.fired.len();
        let quota_before = self.faults.quota_hits;
        let desc = if self.cfg.trace {
            format!("{input:?}")
        } else {
            String::new()
        };
        let mut notes = Vec::new();
        let res = build::call(
            &self.defs[b],
            &self.cfg.params,
            &mut self.stores[b],
            &mut self.vols[b],
            &mut self.faults,
            &mut self.events,
            &mut self.cov,
            &mut notes,
            input,
        );
        let fired: Vec<WriteFault> = self.faults.fired[fired_before..].to_vec();
        for f in fired {
            self.cov.hit(match f {
                WriteFault::CrashBefore => "fault/crash-before-write",
                WriteFault::CrashAfter => "fault/crash-after-write",
                WriteFault::Fail => "fault/storage-failure",
                WriteFault::DurableButError => "fault/durable-but-error",
                WriteFault::LandedButError => "fault/landed-but-error",
            });
        }
        if self.faults.quota_hits > quota_before {
            self.cov.hit("fault/quota");
        }
        self.check_events();
        let after = self.stores[b].idx_or_none();
        if after != before {
            let h = &mut self.history[b];
            h.push(self.stores[b].clone());
            if h.len() > 24 {
                h.remove(0);
            }
        }
        if matches!(after.state, PState::Writer(_) | PState::Sealed { .. }) {
            self.held.insert(ver(b));
        }
        match res {
            Err(Crash) => {
                self.log(|| format!("  {} {desc} -> CRASH inside the call", ver(b)));
                if let Some((_, m)) = query_to_none {
                    if self.stores[b].succ() != before_succ {
                        // decision 1 condition: the older build crashes
                        // between storing the record and answering "no state"
                        self.cov.hit(if m == 0 {
                            "5.3/probe-crash-after-record-stored"
                        } else {
                            "7.4/query-crash-after-record-stored"
                        });
                    }
                }
                self.check_transition(b, &before, before_lost, &after, &notes);
                self.crash_node();
                None
            }
            Ok(out) => {
                if let (Some((q, m)), Reply::Frame(f)) = (query_to_none, &out.reply) {
                    if is_nostate(f) {
                        // decision 1 condition: two new builds racing to
                        // query the same predecessor
                        let set = self.nostate_to.entry(ver(b)).or_default();
                        set.insert(q);
                        if set.len() >= 2 {
                            self.cov
                                .hit("dec1/two-queriers-got-nostate-from-same-predecessor");
                            if m != 0 {
                                self.cov
                                    .hit("dec1/two-queriers-same-predecessor-one-awaiting");
                            }
                        }
                        if m != 0 {
                            self.cov.hit("dec1/nostate-answers-awaiting-query");
                        }
                    }
                }
                self.log(|| {
                    format!(
                        "  {} {desc} -> {:?} hops [{}] state {} -> {}",
                        ver(b),
                        short_reply(&out.reply),
                        out.hops
                            .iter()
                            .map(|(t, f)| format!("{}:{}", t, f.short()))
                            .collect::<Vec<_>>()
                            .join(", "),
                        before.state.code(),
                        after.state.code()
                    )
                });
                self.check_transition(b, &before, before_lost, &after, &notes);
                Some(out)
            }
        }
    }

    fn crash_node(&mut self) {
        // A repair flow (4.5) that dies after ResetPartition, before its
        // re-imports, takes the keys it held in memory with it.
        for sid in self.sessions.keys() {
            if self.reset_done.contains(sid) {
                if let Some(e) = self.exports.get(sid) {
                    for slot in e.keys() {
                        self.cov.hit("4.5/repair-flow-interrupted-after-reset");
                        self.repair_interrupted.insert((KIND_KEY, *slot));
                    }
                }
            }
        }
        self.runs.clear();
        self.sessions.clear();
        self.limbo.clear();
        self.stack.clear();
        self.lq.clear();
        self.units.clear();
        for v in self.vols.iter_mut() {
            *v = Volatile::default();
        }
        // lifecycle NodeStarted: a step for each registered build with work
        for b in 0..NBUILDS {
            if self.registered[b] {
                if self.core() {
                    self.lq.push_back(LoopItem::Wakeup(b));
                } else {
                    self.start_unprompted(b, Input::Wakeup);
                }
            }
        }
    }

    fn new_run(&mut self, kind: RunKind) -> usize {
        let id = self.next_run;
        self.next_run += 1;
        self.runs.insert(
            id,
            Run {
                kind,
                queue: VecDeque::new(),
                sent: 0,
                iters: 1,
            },
        );
        id
    }

    fn start_unprompted(&mut self, b: usize, input: Input) {
        let r = self.new_run(RunKind::Unprompted);
        if let Some(out) = self.call(b, input) {
            self.enqueue(r, ver(b), out.hops);
        }
        self.gc_runs();
    }

    fn enqueue(&mut self, r: usize, from: Ver, hops: Vec<(Ver, Frame)>) {
        let cap = self.cfg.wakeup_hop_cap;
        let Some(run) = self.runs.get_mut(&r) else {
            return;
        };
        for (to, frame) in hops {
            if matches!(run.kind, RunKind::Unprompted) && run.sent >= cap {
                self.cov.hit("fault/hop-cap");
                continue;
            }
            run.sent += 1;
            run.queue.push_back(Hop {
                from,
                to,
                frame,
                reply: false,
                seq: {
                    self.next_seq += 1;
                    self.next_seq
                },
            });
        }
    }

    fn gc_runs(&mut self) {
        let done: Vec<usize> = self
            .runs
            .iter()
            .filter(|(_, r)| r.queue.is_empty())
            .map(|(k, _)| *k)
            .collect();
        for k in done {
            self.runs.remove(&k);
            for s in self.sessions.values_mut() {
                if s.run == Some(k) {
                    s.run = None;
                }
            }
        }
    }

    // ---------------------------------------------------------- hops

    fn deliver(&mut self, r: Option<usize>, hop: Hop, fate: Fate) {
        let mut hop = hop;
        match fate {
            Fate::Drop => {
                self.cov.hit(if hop.reply {
                    "fault/reply-lost"
                } else {
                    "fault/hop-lost"
                });
                if is_nostate(&hop.frame) {
                    self.cov.hit(nostate_label(&hop.frame, "lost"));
                }
                self.log(|| format!("  drop {}->{} {}", hop.from, hop.to, hop.frame.short()));
                return;
            }
            Fate::Garble => {
                self.cov.hit("fault/garbled-hop");
                hop.frame.garble();
            }
            Fate::Delay if self.cfg.adversarial => {
                self.cov.hit("adv/delayed");
                self.limbo.push(hop);
                return;
            }
            Fate::Duplicate if self.cfg.adversarial => {
                self.cov.hit("adv/duplicated");
                if is_nostate(&hop.frame) {
                    self.cov.hit(nostate_label(&hop.frame, "duplicated"));
                }
                if let Some(r) = r {
                    if let Some(run) = self.runs.get_mut(&r) {
                        run.queue.push_back(hop.clone());
                    }
                }
            }
            _ => {}
        }
        let to = bi(hop.to);
        if !self.registered[to] {
            self.cov.hit("runtime/hop-to-unregistered");
            return;
        }
        if let Some(r) = r {
            let cap = self.cfg.client_iter_cap;
            if let Some(run) = self.runs.get_mut(&r) {
                run.iters += 1;
                if matches!(run.kind, RunKind::Client(_)) && run.iters > cap {
                    self.cov.hit("fault/hop-cap");
                    run.queue.clear();
                    return;
                }
            }
        }
        let Some(out) = self.call(
            to,
            Input::Hop {
                from: hop.from,
                frame: hop.frame.clone(),
            },
        ) else {
            return;
        };
        let Some(r) = r else {
            // adversarial delivery outside any run: outputs go to limbo
            for (t, f) in out.hops {
                self.limbo.push(Hop {
                    from: hop.to,
                    to: t,
                    frame: f,
                    reply: false,
                    seq: {
                        self.next_seq += 1;
                        self.next_seq
                    },
                });
            }
            if let Reply::Frame(f) = out.reply {
                self.limbo.push(Hop {
                    from: hop.to,
                    to: hop.from,
                    frame: f,
                    reply: true,
                    seq: {
                        self.next_seq += 1;
                        self.next_seq
                    },
                });
            }
            return;
        };
        if !self.runs.contains_key(&r) {
            return;
        }
        if let Reply::Frame(f) = out.reply {
            if let Some(run) = self.runs.get_mut(&r) {
                run.queue.push_back(Hop {
                    from: hop.to,
                    to: hop.from,
                    frame: f,
                    reply: true,
                    seq: {
                        self.next_seq += 1;
                        self.next_seq
                    },
                });
            }
        }
        self.enqueue(r, hop.to, out.hops);
    }

    /// Candidates for a Step: FIFO-eligible hops (assumption D: no
    /// reordering between the same pair), idle sessions, limbo hops.
    fn candidates(&self) -> Vec<(u8, usize, usize)> {
        if self.core() {
            return self.core_candidates();
        }
        let mut c = vec![];
        // oldest pending hop per ordered pair, over every run
        let mut oldest: BTreeMap<(Ver, Ver), u64> = BTreeMap::new();
        for run in self.runs.values() {
            for h in &run.queue {
                let e = oldest.entry((h.from, h.to)).or_insert(h.seq);
                *e = (*e).min(h.seq);
            }
        }
        for (rid, run) in &self.runs {
            let mut seen = BTreeSet::new();
            for (i, h) in run.queue.iter().enumerate() {
                let first_in_run = seen.insert((h.from, h.to));
                let first_global = oldest.get(&(h.from, h.to)) == Some(&h.seq);
                let ok = if self.cfg.adversarial {
                    true
                } else if self.cfg.d_global_fifo {
                    first_global
                } else {
                    first_in_run
                };
                if ok {
                    c.push((0, *rid, i));
                }
            }
        }
        for (sid, s) in &self.sessions {
            if s.run.is_none() {
                c.push((1, *sid, 0));
            }
        }
        for i in 0..self.limbo.len() {
            c.push((2, 0, i));
        }
        c
    }

    // ---------------------------------------------------------- core delivery

    fn core(&self) -> bool {
        self.cfg.delivery == Delivery::Core
    }

    /// Whether the delegate lane may run build `b` now (`DelegateGate`): no
    /// loop run of it or claim on it, no pending unit, no forwarded request
    /// of it still with the loop (one user on a node that is not hosted).
    fn lane_free(&self, b: usize) -> bool {
        !self
            .stack
            .iter()
            .any(|r| r.b == b || r.resume.as_ref().is_some_and(|(t, _)| bi(*t) == b))
            && !self.units.contains_key(&b)
            && !self.lq.iter().any(|i| match i {
                LoopItem::Req { b: x, .. } | LoopItem::Op { b: x, .. } => *x == b,
                LoopItem::Wakeup(_) => false,
            })
            && self.units.len() < MAX_PENDING_UNITS
    }

    fn finish_request(&mut self, rid: usize) {
        for s in self.sessions.values_mut() {
            if s.run == Some(rid) {
                s.run = None;
            }
        }
    }

    /// A client request from session `sid` to build `b`: the lane runs its
    /// first call now if `b` is free, else the loop gets it.
    fn client_request(&mut self, sid: usize, b: usize, input: Input) {
        let rid = self.next_run;
        self.next_run += 1;
        if let Some(s) = self.sessions.get_mut(&sid) {
            s.run = Some(rid);
        }
        if self.lane_free(b) {
            self.cov.hit("core/lane-call");
            self.first_call(rid, b, RunKind::Client(sid), input, true);
        } else {
            self.cov.hit("core/forwarded-to-loop");
            self.lq.push_back(LoopItem::Req { rid, sid, b, input });
        }
    }

    /// A client operation (no hops): the lane runs it if `b` is free, else
    /// the loop does later and the session waits for it.
    fn client_op(&mut self, sid: Option<usize>, b: usize, op: Op) {
        if self.lane_free(b) {
            self.do_op(b, op, sid);
            return;
        }
        self.cov.hit("core/forwarded-to-loop");
        let rid = self.next_run;
        self.next_run += 1;
        if let Some(s) = sid.and_then(|sid| self.sessions.get_mut(&sid)) {
            s.run = Some(rid);
        }
        self.lq.push_back(LoopItem::Op { rid, sid, b, op });
    }

    /// The first call of a run. Its hops make it a run: a pending unit if
    /// the lane made the call, the loop's active run otherwise.
    fn first_call(&mut self, rid: usize, b: usize, kind: RunKind, input: Input, lane: bool) {
        let is_poke = matches!(input, Input::Poke { .. });
        let Some(out) = self.call(b, input) else {
            return;
        };
        if let RunKind::Client(sid) = kind {
            if is_poke {
                let st = match out.reply {
                    Reply::Status(st) => Some(st),
                    _ => None,
                };
                if let Some(sess) = self.sessions.get_mut(&sid) {
                    sess.statuses.insert(ver(b), st);
                }
            }
        }
        if out.hops.is_empty() {
            self.finish_request(rid);
            return;
        }
        let run = CRun {
            id: rid,
            b,
            kind,
            hops: out.hops.into(),
            replies: VecDeque::new(),
            iters: 1,
            attempted: 0,
            resume: None,
        };
        if lane {
            self.cov.hit("core/handed-off-unit");
            self.units.insert(b, run);
        } else {
            self.stack.push(run);
        }
    }

    /// Start loop item `i` (or, if its delegate has a pending unit, that
    /// unit first: `claim_delegate` runs it before anything else).
    fn core_start_item(&mut self, i: usize) {
        let b = match &self.lq[i] {
            LoopItem::Wakeup(b) | LoopItem::Req { b, .. } | LoopItem::Op { b, .. } => *b,
        };
        if let Some(u) = self.units.remove(&b) {
            self.cov.hit("core/claim-runs-unit-first");
            self.stack.push(u);
            return;
        }
        let item = self.lq.remove(i).unwrap();
        match item {
            LoopItem::Wakeup(b) => {
                if self.registered[b] {
                    let rid = self.next_run;
                    self.next_run += 1;
                    self.first_call(rid, b, RunKind::Unprompted, Input::Wakeup, false);
                }
            }
            LoopItem::Req { rid, sid, b, input } => {
                self.first_call(rid, b, RunKind::Client(sid), input, false);
            }
            LoopItem::Op { rid, sid, b, op } => {
                self.do_op(b, op, sid);
                self.finish_request(rid);
            }
        }
    }

    /// One call of the loop's active run: the next hop, or the next reply.
    fn core_advance(&mut self, fate: Fate) {
        let Some(top) = self.stack.len().checked_sub(1) else {
            return;
        };
        let cap_iters = self.cfg.client_iter_cap;
        let cap_hops = self.cfg.wakeup_hop_cap;
        let nested = top > 0;
        let (from, b) = (ver(self.stack[top].b), self.stack[top].b);

        // a hop held while its target's unit ran nested
        let next_hop = match self.stack[top].resume.take() {
            Some(h) => Some((h, true)),
            None => self.stack[top].hops.pop_front().map(|h| (h, false)),
        };
        if let Some(((to, frame), was_held)) = next_hop {
            let t = bi(to);
            if !was_held {
                if t == b {
                    self.cov.hit("core/self-hop-refused");
                    return;
                }
                if matches!(self.stack[top].kind, RunKind::Unprompted)
                    && self.stack[top].attempted >= cap_hops
                {
                    self.cov.hit("fault/hop-cap");
                    return;
                }
                self.stack[top].attempted += 1;
                if self.stack.iter().any(|r| r.b == t) {
                    self.cov.hit("core/hop-dropped-target-mid-round-trip");
                    return;
                }
                if !self.registered[t] {
                    self.cov.hit("runtime/hop-to-unregistered");
                    return;
                }
                if self.units.contains_key(&t) {
                    if nested {
                        self.cov.hit("core/hop-dropped-nested-unit");
                        return;
                    }
                    self.cov.hit("core/hop-runs-target-unit-first");
                    let u = self.units.remove(&t).unwrap();
                    self.stack[top].resume = Some((to, frame));
                    self.stack.push(u);
                    return;
                }
            } else if !self.registered[t] {
                self.cov.hit("runtime/hop-to-unregistered");
                return;
            }
            let mut frame = frame;
            match fate {
                Fate::Drop => {
                    self.cov.hit("fault/hop-lost");
                    self.log(|| format!("  drop {from}->{to} {}", frame.short()));
                    return;
                }
                Fate::Garble => {
                    self.cov.hit("fault/garbled-hop");
                    frame.garble();
                }
                _ => {}
            }
            let Some(out) = self.call(t, Input::Hop { from, frame }) else {
                return;
            };
            if !out.hops.is_empty() {
                // a target may send one reply to its caller and nothing else
                self.cov.hit("core/target-send-dropped");
            }
            if let Reply::Frame(f) = out.reply {
                let run = &mut self.stack[top];
                let left = cap_iters.saturating_sub(run.iters);
                if run.replies.len() >= left {
                    self.cov.hit("core/reply-dropped-no-iterations-left");
                } else {
                    run.replies.push_back((to, f));
                }
            }
            return;
        }

        if let Some((rfrom, f)) = self.stack[top].replies.pop_front() {
            let run = &mut self.stack[top];
            run.iters += 1;
            if run.iters > cap_iters {
                self.cov.hit("core/iteration-cap");
                run.replies.clear();
                return;
            }
            let mut f = f;
            match fate {
                Fate::Drop => {
                    self.cov.hit("fault/reply-lost");
                    if is_nostate(&f) {
                        self.cov.hit(nostate_label(&f, "lost"));
                    }
                    self.log(|| format!("  drop reply {rfrom}->{from} {}", f.short()));
                    return;
                }
                Fate::Garble => {
                    self.cov.hit("fault/garbled-hop");
                    f.garble();
                }
                _ => {}
            }
            let Some(out) = self.call(
                b,
                Input::Hop {
                    from: rfrom,
                    frame: f,
                },
            ) else {
                return;
            };
            let run = &mut self.stack[top];
            if let Reply::Frame(f) = out.reply {
                // a message back to the replying delegate is a new hop
                run.hops.push_back((rfrom, f));
            }
            run.hops.extend(out.hops);
            return;
        }

        // nothing left: the run is done
        let run = self.stack.pop().unwrap();
        self.finish_request(run.id);
    }

    /// Core step candidates: advance the active run, else start a loop
    /// item or a pending unit; idle sessions make their next request.
    fn core_candidates(&self) -> Vec<(u8, usize, usize)> {
        let mut c = vec![];
        if !self.stack.is_empty() {
            c.push((3, 0, 0));
        } else {
            for i in 0..self.lq.len() {
                c.push((4, i, 0));
            }
            for b in self.units.keys() {
                c.push((5, *b, 0));
            }
        }
        for (sid, s) in &self.sessions {
            if s.run.is_none() {
                c.push((1, *sid, 0));
            }
        }
        c
    }

    // ---------------------------------------------------------- actions

    pub fn apply(&mut self, a: &Action) {
        self.step_no += 1;
        let n = self.step_no;
        self.log(|| format!("[{n}] {a:?}"));
        match a.clone() {
            Action::Publish => {
                if self.published < self.ledger.len() {
                    self.published += 1;
                    let r = self.ledger[self.published - 1];
                    if r.withdrawal {
                        self.cov.hit("publish/withdrawal");
                    }
                    if r.v == ROLLBACK {
                        self.cov.hit("publish/rollback");
                    }
                }
            }
            Action::Load { client, fetch, ops } => self.load(client, fetch, ops),
            Action::Step { pick, fate } => {
                let c = self.candidates();
                if !c.is_empty() {
                    let (kind, a, b) = c[pick as usize % c.len()];
                    match kind {
                        0 => {
                            let hop = self.runs.get_mut(&a).unwrap().queue.remove(b).unwrap();
                            self.deliver(Some(a), hop, fate);
                        }
                        1 => self.session_next(a),
                        3 => self.core_advance(fate),
                        4 => self.core_start_item(a),
                        5 => {
                            let u = self.units.remove(&a).unwrap();
                            self.stack.push(u);
                        }
                        _ => {
                            let hop = self.limbo.remove(b);
                            self.deliver(None, hop, Fate::Deliver);
                        }
                    }
                    self.gc_runs();
                }
            }
            Action::Wakeup { b } => {
                let b = b as usize % NBUILDS;
                if self.registered[b] {
                    if self.core() {
                        self.lq.push_back(LoopItem::Wakeup(b));
                    } else {
                        self.start_unprompted(b, Input::Wakeup);
                    }
                }
            }
            Action::Crash => {
                self.cov.hit("fault/crash-between-calls");
                self.crash_node();
            }
            Action::ArmWriteFault { after, fault } => {
                self.faults.armed = Some((after as u32, fault));
            }
            Action::ArmReadFault { after } => {
                self.faults.read_armed = Some(after as u32);
            }
            Action::Quota { limit } => {
                self.faults.quota = limit.map(|l| l as usize);
            }
            Action::Unregister { b } => {
                let b = b as usize % NBUILDS;
                if self.registered[b] {
                    self.cov.hit("fault/unregister");
                }
                self.registered[b] = false;
            }
            Action::Restore { b, snap, secret } => {
                let b = b as usize % NBUILDS;
                let h = &self.history[b];
                let s = h[snap as usize % h.len()].clone();
                match secret {
                    None => {
                        self.cov.hit("fault/restore-whole");
                        self.stores[b] = s;
                    }
                    Some(k) => {
                        let names: Vec<SName> = s
                            .secrets
                            .keys()
                            .chain(self.stores[b].secrets.keys())
                            .copied()
                            .collect::<BTreeSet<_>>()
                            .into_iter()
                            .collect();
                        if names.is_empty() {
                            return;
                        }
                        let n = names[k as usize % names.len()];
                        self.cov.hit("fault/restore-secret");
                        if let SName::E(id, _) = n {
                            self.tainted.insert(id);
                        }
                        match s.secrets.get(&n) {
                            Some(v) => {
                                self.stores[b].secrets.insert(n, v.clone());
                            }
                            None => {
                                self.stores[b].secrets.remove(&n);
                            }
                        }
                    }
                }
                self.vols[b] = Volatile::default();
                self.taint_unheld();
                self.restored = true;
            }
            Action::Wipe { b } => {
                let b = b as usize % NBUILDS;
                self.cov.hit("fault/wipe");
                self.stores[b] = Store::default();
                self.vols[b] = Volatile::default();
                self.taint_unheld();
                self.restored = true;
            }
            Action::Garble {
                b,
                pick,
                undecryptable,
            } => {
                let b = b as usize % NBUILDS;
                let es: Vec<SName> = self.stores[b]
                    .secrets
                    .iter()
                    .filter(|(_, v)| !matches!(v, SVal::Garbled | SVal::Undecryptable))
                    .map(|(n, _)| *n)
                    .collect();
                if !es.is_empty() {
                    let n = es[pick as usize % es.len()];
                    let had_state = self.stores[b].has_state();
                    self.cov.hit("fault/garble-secret");
                    self.cov.hit(&format!(
                        "fault/{}/{}",
                        if undecryptable {
                            "undecryptable"
                        } else {
                            "malformed"
                        },
                        match n {
                            SName::Succ => "succ",
                            SName::Parts => "parts",
                            SName::Idx => "index",
                            SName::E(..) => "entry",
                            SName::X(_) => "progress",
                            SName::Rx => "rx",
                            SName::Gc => "gc",
                        }
                    ));
                    if let SName::E(id, _) = n {
                        self.tainted.insert(id);
                    }
                    self.stores[b].secrets.insert(
                        n,
                        if undecryptable {
                            SVal::Undecryptable
                        } else {
                            SVal::Garbled
                        },
                    );
                    self.garbled = true;
                    // 4.4: an unreadable vault:succ is a loss of vault:succ,
                    // and a store that now reads as NONE (index and
                    // vault:parts both unreadable) is the same as a wipe:
                    // stated residuals of the same class as restores.
                    let reads_none = !self.stores[b].index_lost() && self.stores[b].idx().is_none();
                    if (n == SName::Succ && undecryptable) || (had_state && reads_none) {
                        self.cov.hit("fault/garble-equivalent-to-wipe-or-restore");
                        self.restored = true;
                    }
                    self.taint_unheld();
                }
            }
            Action::Cached { op, b } => {
                let target = match b {
                    Some(b) => Some(ver(b as usize % NBUILDS)),
                    None => self.cached_target,
                };
                if let Some(v) = target {
                    self.cov.hit("client/cached-caller");
                    let b = bi(v);
                    if self.registered[b] {
                        if self.core() {
                            self.client_op(None, b, op);
                        } else {
                            self.do_op(b, op, None);
                        }
                    }
                }
            }
        }
        self.check_state();
    }

    // ---------------------------------------------------------- clients (5.2)

    fn load(&mut self, client: u8, fetch: Fetch, ops: Vec<Op>) {
        let client = client % CLIENTS.len() as u8;
        let bundle: Vec<Ver> = CLIENTS[client as usize].to_vec();
        if client == 2 {
            self.cov.hit("client/old-lineage");
        }
        let (fetched, nonwd) = match fetch {
            Fetch::Newest => {
                let n = self.newest_published();
                (
                    n,
                    n.filter(|r| r.withdrawal)
                        .and_then(|w| self.newest_nonwd_below(w)),
                )
            }
            Fetch::Unreachable => {
                self.cov.hit("fault/pointer-unreachable");
                (None, None)
            }
            Fetch::Stale(k) => {
                if self.cfg.stale_pointer && self.published > 0 {
                    self.cov.hit("adv/stale-pointer");
                    let r = self.ledger[k as usize % self.published];
                    (
                        Some(r),
                        if r.withdrawal {
                            self.newest_nonwd_below(r)
                        } else {
                            None
                        },
                    )
                } else {
                    let n = self.newest_published();
                    (
                        n,
                        n.filter(|r| r.withdrawal)
                            .and_then(|w| self.newest_nonwd_below(w)),
                    )
                }
            }
        };
        let id = self.next_session;
        self.next_session += 1;
        self.sessions.insert(
            id,
            Session {
                client,
                bundle,
                fetched,
                fetched_nonwd: nonwd,
                phase: Phase::Poke(0),
                statuses: BTreeMap::new(),
                rounds: 0,
                again: BTreeSet::new(),
                ops: ops.into(),
                target: None,
                run: None,
            },
        );
        self.session_next(id);
    }

    fn session_next(&mut self, sid: usize) {
        let Some(s) = self.sessions.get(&sid).cloned() else {
            return;
        };
        match s.phase.clone() {
            Phase::Poke(i) => {
                if i >= s.bundle.len() {
                    self.sessions.get_mut(&sid).unwrap().phase = Phase::Decide;
                    return self.session_next(sid);
                }
                let v = s.bundle[i];
                self.sessions.get_mut(&sid).unwrap().phase = Phase::Poke(i + 1);
                if s.rounds > 0 && !s.again.contains(&v) {
                    return self.session_next(sid);
                }
                let b = bi(v);
                self.registered[b] = true;
                let mut flags = 0;
                // pause copying toward a target this client cannot register
                if let Some(r) = s.fetched {
                    if !r.withdrawal && !s.bundle.contains(&r.v) {
                        flags |= build::POKE_PAUSE;
                    }
                }
                if self.core() {
                    let rec = s.fetched;
                    return self.client_request(sid, b, Input::Poke { flags, rec });
                }
                let r = self.new_run(RunKind::Client(sid));
                self.sessions.get_mut(&sid).unwrap().run = Some(r);
                let out = self.call(
                    b,
                    Input::Poke {
                        flags,
                        rec: s.fetched,
                    },
                );
                let Some(out) = out else { return };
                let st = match out.reply {
                    Reply::Status(st) => Some(st),
                    _ => None,
                };
                self.enqueue(r, v, out.hops);
                if let Some(sess) = self.sessions.get_mut(&sid) {
                    sess.statuses.insert(v, st);
                }
                self.gc_runs();
            }
            Phase::Decide => self.decide(sid),
            Phase::Ops => {
                let Some(t) = s.target else {
                    self.sessions.get_mut(&sid).unwrap().phase = Phase::Done;
                    return;
                };
                let mut sess = s.clone();
                let Some(op) = sess.ops.pop_front() else {
                    self.sessions.remove(&sid);
                    return;
                };
                self.sessions.insert(sid, sess);
                let b = bi(t);
                self.cached_target = Some(t);
                if self.core() {
                    self.client_op(Some(sid), b, op);
                } else {
                    self.do_op(b, op, Some(sid));
                }
            }
            Phase::Done => {
                self.sessions.remove(&sid);
            }
        }
    }

    fn decide(&mut self, sid: usize) {
        let s = self.sessions.get(&sid).cloned().unwrap();
        // repeat pokes while a build reports progress (at most 8 rounds)
        let again: BTreeSet<Ver> = s
            .statuses
            .iter()
            .filter(|(_, st)| st.as_ref().is_some_and(|st| st.sent))
            .map(|(v, _)| *v)
            .collect();
        // Poke bit 4 is reserved since revision 8 (F6): a partial copy is
        // never discarded on a page's request.
        if !again.is_empty() && s.rounds < 8 {
            let sess = self.sessions.get_mut(&sid).unwrap();
            sess.rounds += 1;
            sess.again = again;
            sess.phase = Phase::Poke(0);
            return self.session_next(sid);
        }
        let states: BTreeMap<Ver, Option<Seen>> = s
            .bundle
            .iter()
            .map(|v| {
                (
                    *v,
                    s.statuses.get(v).cloned().flatten().map(|st| Seen {
                        state: st.state,
                        lost: st.index_lost,
                    }),
                )
            })
            .collect();
        let create = match s.fetched {
            Some(r) if !r.withdrawal => Some(r),
            Some(_) => s.fetched_nonwd,
            None => None,
        };
        let route = route(&states, create);
        self.log(|| format!("  courier client {} route {route:?}", s.client));
        let sess = self.sessions.get_mut(&sid).unwrap();
        match route {
            Route::Writer(v) => {
                sess.target = Some(v);
                sess.phase = Phase::Ops;
            }
            Route::ReadOnly(v) => {
                // 4.5: reads use the damaged build; the UI offers the repair
                // (export every slot it knows, ResetPartition, re-import),
                // after the session's own requests.
                self.cov.hit("4.5/courier-selects-damaged-build");
                sess.target = Some(v);
                sess.phase = Phase::Ops;
                for slot in 0..4 {
                    sess.ops.push_back(Op::Export { slot });
                }
                sess.ops.push_back(Op::Reset);
                for slot in 0..4 {
                    sess.ops.push_back(Op::ImportExported { slot });
                }
            }
            Route::Create(v) => {
                sess.target = Some(v);
                sess.phase = Phase::Ops;
                if self.core() {
                    let input = Input::Poke {
                        flags: build::POKE_ARM,
                        rec: Some(Rec::build(v)),
                    };
                    return self.client_request(sid, bi(v), input);
                }
                let r = self.new_run(RunKind::Client(sid));
                self.sessions.get_mut(&sid).unwrap().run = Some(r);
                let out = self.call(
                    bi(v),
                    Input::Poke {
                        flags: build::POKE_ARM,
                        rec: Some(Rec::build(v)),
                    },
                );
                if let Some(out) = out {
                    self.enqueue(r, v, out.hops);
                }
                self.gc_runs();
            }
            Route::Unavailable => {
                self.cov.hit("5.2/unavailable");
                self.sessions.remove(&sid);
            }
        }
    }

    fn do_op(&mut self, b: usize, op: Op, sid: Option<usize>) {
        let mut op = op;
        let mut repair_import: Option<(usize, u16, u32)> = None;
        // 4.5 step 6: re-import an exported seed the UI checked against the
        // slot's expected public key (the UI's own data: the oracle).
        if let Op::ImportExported { slot } = op {
            let Some(sid) = sid else { return };
            let id = (KIND_KEY, slot);
            let p = self.oracle.get(&id).cloned().unwrap_or_default();
            let seed = self.exports.get(&sid).and_then(|e| e.get(&slot)).copied();
            match seed {
                Some(seed) if p.allows(&Some(key_entry(slot, seed))) => {
                    op = Op::Import {
                        slot,
                        seed,
                        replace: true,
                    };
                    repair_import = Some((sid, slot, seed));
                }
                _ => {
                    if self.reset_done.contains(&sid) && !p.allows(&None) {
                        // "these keys could not be recovered" (4.5 step 7):
                        // a stated residual
                        self.cov.hit("4.5/repair-key-not-recovered");
                        self.tainted.insert(id);
                    }
                    return;
                }
            }
        }
        if let Op::Batch { slot, expected } = &mut op {
            if *expected == 0 {
                *expected = self
                    .oracle
                    .get(&(KIND_KEY, *slot))
                    .and_then(|p| p.acked.as_ref())
                    .map(|e| e.content)
                    .unwrap_or(1);
            }
        }
        let intended = intended_value(&op, &self.oracle);
        let res = self.call(b, Input::Op(op.clone()));
        let Some(out) = res else {
            // unknown outcome: the change may or may not have happened
            if let Some((id, v)) = intended {
                self.oracle.entry(id).or_default().maybe.push(v);
            }
            return;
        };
        let Reply::Op(r) = out.reply else { return };
        self.log(|| format!("  op {op:?} at {} -> {r:?}", ver(b)));
        if let Some((rsid, slot, _seed)) = repair_import {
            // The UI follows Moved and retries Busy and NotHere (a handover
            // of the reset partition may be under way); it gives up after a
            // bounded number of tries, and the seed it held is then lost.
            let id = (KIND_KEY, slot);
            let tries = self.repair_tries.entry((rsid, slot)).or_insert(0);
            match &r {
                OpRes::Key(_) => {
                    if let Some(e) = self.exports.get_mut(&rsid) {
                        e.remove(&slot);
                    }
                }
                OpRes::Moved(_) | OpRes::Busy | OpRes::NotHere if *tries < 8 => {
                    *tries += 1;
                    self.cov.hit("4.5/repair-import-retried");
                    if let Some(sess) = self.sessions.get_mut(&rsid) {
                        if let OpRes::Moved(rec) = &r {
                            sess.target = Some(rec.v);
                        }
                        sess.ops.push_front(Op::ImportExported { slot });
                    }
                }
                _ => {
                    self.cov.hit("4.5/repair-import-gave-up");
                    if let Some(e) = self.exports.get_mut(&rsid) {
                        e.remove(&slot);
                    }
                    self.repair_interrupted.insert(id);
                }
            }
        }
        match (&op, &r, sid) {
            (Op::Export { slot }, OpRes::Key(k), Some(sid)) => {
                self.exports.entry(sid).or_default().insert(*slot, *k);
            }
            (Op::Reset, OpRes::Ok, Some(sid)) => {
                self.cov.hit("4.5/repair-reset-done");
                self.reset_done.insert(sid);
            }
            _ => {}
        }
        match (&op, &r) {
            (Op::PublicKey { slot }, OpRes::Key(k)) | (Op::Batch { slot, .. }, OpRes::Key(k)) => {
                let id = (KIND_KEY, *slot);
                if !self.restored && !self.tainted.contains(&id) {
                    let p = self.oracle.get(&id).cloned().unwrap_or_default();
                    if !p.allows(&Some(key_entry(*slot, *k))) && self.in_repair_flow(id, &p) {
                        self.cov.hit("finding/I3-read-in-repair-window");
                    } else if !p.allows(&Some(key_entry(*slot, *k))) {
                        self.fail(
                            if self.stores[b].index_lost() {
                                "I3-direct-read"
                            } else {
                                "I3"
                            },
                            format!(
                                "build {} answered slot {slot} with key {k}; possible {p:?}",
                                ver(b)
                            ),
                        );
                    }
                }
            }
            (Op::PublicKey { slot }, OpRes::Absent) => {
                let id = (KIND_KEY, *slot);
                if !self.restored && !self.tainted.contains(&id) {
                    let p = self.oracle.get(&id).cloned().unwrap_or_default();
                    if !p.allows(&None) && self.in_repair_flow(id, &p) {
                        // 4.5: between ResetPartition and the re-import the
                        // reset writer answers Absent for a key it held
                        self.cov.hit("finding/I3-read-in-repair-window");
                    } else if !p.allows(&None) {
                        self.fail(
                            "I3",
                            format!(
                                "build {} answered slot {slot} Absent; possible {p:?}",
                                ver(b)
                            ),
                        );
                    }
                }
            }
            _ => {}
        }
        let acked = matches!(
            (&op, &r),
            (Op::Generate { .. }, OpRes::Key(_))
                | (Op::Import { .. }, OpRes::Key(_))
                | (Op::Delete { .. }, OpRes::Ok)
                | (Op::PutExt { .. }, OpRes::Ok)
        );
        if acked {
            if let Some((id, v)) = intended {
                self.cov.hit("oracle/acked-change");
                self.oracle.insert(
                    id,
                    Possible {
                        acked: v,
                        maybe: vec![],
                    },
                );
            }
        }
    }

    // ---------------------------------------------------------- invariants

    fn check_events(&mut self) {
        let evs = std::mem::take(&mut self.events);
        for e in evs {
            let Event::Delete {
                build,
                name,
                named_by_committed,
            } = e;
            if named_by_committed {
                self.fail(
                    "I6",
                    format!("build {build} deleted {name:?}, which its committed index names"),
                );
            }
        }
    }

    fn check_transition(
        &mut self,
        b: usize,
        before: &Index,
        before_lost: bool,
        after: &Index,
        notes: &[Note],
    ) {
        let v = ver(b);
        // I4: no unseal without a "did not take over" answer from the target.
        // A ResetPartition over a lost index (4.5) is checked by I1-reset.
        let was_reset = notes.iter().any(|n| matches!(n, Note::Reset));
        if let (PState::Sealed { target, m, .. }, PState::Writer(_), false) =
            (&before.state, &after.state, was_reset)
        {
            let intent = notes
                .iter()
                .any(|n| matches!(n, Note::UnsealIntent { target: t, m: mm } if *t == target.v && mm == m));
            if !intent {
                self.fail(
                    "I4",
                    format!("build {v} unsealed from {} without an answer", target.v),
                );
            } else if self.stores[bi(target.v)].idx_or_none().state.taken_over() == Some((v, *m)) {
                self.fail(
                    "I4",
                    format!("build {v} unsealed while its target {} has taken over from it at the same manifest", target.v),
                );
            }
        }
        // I4 (ground truth): at every unseal, the target has not taken over
        // from this build at that manifest.
        for n in notes {
            if let Note::Unsealed { target, m, .. } = n {
                if !self.stores[bi(*target)].index_lost()
                    && self.stores[bi(*target)].idx_or_none().state.taken_over() == Some((v, *m))
                {
                    self.fail(
                        "I4",
                        format!(
                            "build {v} unsealed while its target {target} has taken over from it at the same manifest"
                        ),
                    );
                }
            }
        }
        // I4b (the fence I4 protects): a take-over of (P, m) must not happen
        // after P has unsealed from m, or both builds act as owners.
        for n in notes {
            if let Note::TookOver { from, m } = n {
                let p = self.stores[bi(*from)].idx_or_none().state;
                let still_sealed = matches!(&p, PState::Sealed { target, m: pm, .. } if target.v == v && pm == m)
                    || matches!(&p, PState::Retired { to, m: pm, .. } if to.v == v && pm == m);
                // a predecessor whose index is lost (4.5) is read-only and
                // answers nothing: neither sealed nor unsealed is known
                let lost = self.stores[bi(*from)].index_lost();
                if !still_sealed && !self.restored && !lost {
                    self.fail(
                        "I4b",
                        format!(
                            "build {v} took over from {from} at m {:04x} but {from} is {} (it unsealed or moved on first)",
                            m & 0xffff,
                            p.code()
                        ),
                    );
                }
            }
        }
        // I5: creation only with no state anywhere
        let reset = notes.iter().any(|n| matches!(n, Note::Reset));
        if reset && !self.stores[b].index_lost() && matches!(after.state, PState::Writer(_)) {
            // 4.5: resetting a damaged build while another build is WRITER
            // or SEALED makes a second writer.
            self.cov.hit("4.5/reset-applied");
            for o in 0..NBUILDS {
                if o != b
                    && !self.stores[o].index_lost()
                    && matches!(
                        self.stores[o].idx_or_none().state,
                        PState::Writer(_) | PState::Sealed { .. }
                    )
                    && !self.restored
                {
                    self.fail(
                        "I1-reset",
                        format!(
                            "build {v} was reset to WRITER while build {} is {}",
                            ver(o),
                            self.stores[o].idx_or_none().state.code()
                        ),
                    );
                }
            }
        }
        let created = notes.iter().any(|n| matches!(n, Note::Created))
            || (before.state.is_none()
                && !before_lost
                && !reset
                && matches!(&after.state, PState::Writer(w) if w.taken_over.is_none()));
        if created {
            self.cov.hit("I5/creation");
            for o in 0..NBUILDS {
                if o != b && self.stores[o].has_state() {
                    self.fail(
                        if self.restored {
                            // 5.3: "The guarantee fails only if a
                            // predecessor's vault:succ or index is restored
                            // or wiped (4.4)": counted apart.
                            "I5-after-restore"
                        } else {
                            "I5"
                        },
                        format!(
                            "build {v} created the partition while build {} holds state ({})",
                            ver(o),
                            self.stores[o].idx_or_none().state.code()
                        ),
                    );
                }
            }
        }
        if notes.iter().any(|n| matches!(n, Note::SealedCorruptSent)) {
            self.sealed_corrupt_sent += 1;
        }
    }

    /// A key a live repair session has exported and not yet re-imported.
    fn in_repair_flow(&self, id: Ident, p: &Possible) -> bool {
        id.0 == KIND_KEY
            && self.sessions.keys().any(|sid| {
                self.exports
                    .get(sid)
                    .and_then(|e| e.get(&id.1))
                    .is_some_and(|seed| p.allows(&Some(key_entry(id.1, *seed))))
            })
    }

    fn accepting_writers(&self) -> Vec<Ver> {
        (0..NBUILDS)
            .filter(|b| {
                !self.stores[*b].index_lost()
                    && matches!(self.stores[*b].idx_or_none().state, PState::Writer(ref w) if !w.awaiting)
            })
            .map(ver)
            .collect()
    }

    /// The value a build's committed store holds for an identity. A build
    /// whose index is lost holds what the direct-read rule of 4.5 finds.
    fn held_value(&self, b: usize, id: Ident) -> Result<Option<Entry>, ()> {
        if self.stores[b].index_lost() {
            let vals: Vec<Entry> = [false, true]
                .iter()
                .filter_map(
                    |par| match self.stores[b].secrets.get(&SName::E(id, *par)) {
                        Some(SVal::E(e)) if e.ident() == id => Some(e.clone()),
                        _ => None,
                    },
                )
                .collect();
            return match vals.as_slice() {
                [] => Ok(None),
                [e] => Ok(Some(e.clone())),
                [a, b] if a == b => Ok(Some(a.clone())),
                _ => Err(()),
            };
        }
        let idx = self.stores[b].idx_or_none();
        let Some(ie) = idx.entries.get(&id) else {
            return Ok(None);
        };
        match self.stores[b].secrets.get(&SName::E(id, ie.parity)) {
            Some(SVal::E(e)) if e.digest() == ie.digest => Ok(Some(e.clone())),
            _ => Err(()),
        }
    }

    /// After the operator destroys or rolls back storage, an acknowledged
    /// value that no build holds any more is lost by the operator, not by
    /// the protocol: exclude it from I2.
    fn taint_unheld(&mut self) {
        let oracle = self.oracle.clone();
        for (id, p) in &oracle {
            let held =
                (0..NBUILDS).any(|b| matches!(self.held_value(b, *id), Ok(ref v) if p.allows(v)));
            if !held {
                self.cov.hit("restore/acknowledged-value-destroyed");
                self.tainted.insert(*id);
            }
        }
    }

    /// The writer chosen by 5.2 by a courier that sees every build.
    pub fn omniscient_writer(&self) -> Route {
        let states: BTreeMap<Ver, Option<Seen>> = (0..NBUILDS)
            .map(|b| {
                (
                    ver(b),
                    Some(Seen {
                        state: self.stores[b].idx_or_none().state,
                        lost: self.stores[b].index_lost(),
                    }),
                )
            })
            .collect();
        route(&states, None)
    }

    fn check_state(&mut self) {
        if self.violation.is_some() {
            return;
        }
        let armed = (0..NBUILDS)
            .filter(|b| {
                matches!(
                    self.stores[*b].idx_or_none().state,
                    PState::None { armed: Some(_), .. }
                )
            })
            .count();
        if armed >= 2 {
            // decision 1 condition: two new builds racing to create
            self.cov.hit("5.3/two-builds-armed-at-once");
        }
        // I1
        let w = self.accepting_writers();
        if w.len() > 1 && !self.restored {
            self.fail("I1", format!("two builds accept changes: {w:?}"));
        }
        // I6 (state form): every name a committed index uses exists
        for b in 0..NBUILDS {
            let idx = self.stores[b].idx_or_none();
            for (id, ie) in &idx.entries {
                if !self.stores[b]
                    .secrets
                    .contains_key(&SName::E(*id, ie.parity))
                    && !self.restored
                    && !self.tainted.contains(id)
                {
                    self.fail(
                        "I6",
                        format!(
                            "build {} index names {:?} parity {} but the secret is gone",
                            ver(b),
                            id,
                            ie.parity
                        ),
                    );
                }
            }
        }
        // I2 / I8: acknowledged values held by the chosen writer
        let oracle = self.oracle.clone();
        match self.omniscient_writer() {
            Route::Writer(v) | Route::ReadOnly(v) => {
                let b = bi(v);
                for (id, p) in &oracle {
                    if self.tainted.contains(id) {
                        continue;
                    }
                    if self.restored {
                        continue;
                    }
                    if self.in_repair_flow(*id, p) {
                        // 4.5 steps 3 to 6: between ResetPartition and the
                        // re-import the key is held by the running repair
                        // flow; it is lost if the flow ends first.
                        self.cov.hit("4.5/key-held-by-repair-flow");
                        continue;
                    }
                    let inv = if id.0 == KIND_UNKNOWN {
                        "I8"
                    } else if self.stores[b].index_lost() {
                        "I2-direct-read"
                    } else if self.repair_interrupted.contains(id) {
                        "I2-repair-interrupted"
                    } else {
                        "I2"
                    };
                    match self.held_value(b, *id) {
                        Ok(val) => {
                            if !p.allows(&val) {
                                self.fail(
                                    inv,
                                    format!(
                                        "writer {v} holds {val:?} for {id:?}; acknowledged {p:?}"
                                    ),
                                );
                                return;
                            }
                        }
                        Err(()) => {
                            self.fail(inv, format!("writer {v} cannot read {id:?}"));
                            return;
                        }
                    }
                }
                // I3 (state form): every build that would answer reads
                if !self.restored {
                    for o in 0..NBUILDS {
                        let st = self.stores[o].idx_or_none().state;
                        if self.stores[o].index_lost()
                            || !matches!(st, PState::Writer(_) | PState::Sealed { .. })
                        {
                            continue;
                        }
                        for (id, p) in &oracle {
                            if id.0 != KIND_KEY || self.tainted.contains(id) {
                                continue;
                            }
                            if let Ok(val) = self.held_value(o, *id) {
                                if !p.allows(&val) && self.in_repair_flow(*id, p) {
                                    self.cov.hit("finding/I3-state-in-repair-window");
                                } else if !p.allows(&val) {
                                    self.fail(
                                        "I3",
                                        format!(
                                            "build {} ({}) would answer {val:?} for {id:?}; acknowledged {p:?}",
                                            ver(o),
                                            st.code()
                                        ),
                                    );
                                    return;
                                }
                            }
                        }
                    }
                }
            }
            _ => {
                let any_acked = oracle
                    .iter()
                    .any(|(id, p)| !self.tainted.contains(id) && !p.allows(&None));
                if any_acked && !self.restored {
                    let states: Vec<String> = (0..NBUILDS)
                        .map(|b| {
                            format!("{}:{}", ver(b), self.stores[b].idx_or_none().state.code())
                        })
                        .collect();
                    let lost = (0..NBUILDS)
                        .filter(|b| self.stores[*b].index_lost())
                        .count();
                    self.fail(
                        if lost >= 2 {
                            // 5.2 step 4: "if two report state 7, vault
                            // unavailable"
                            "I2-two-index-lost"
                        } else {
                            "I2"
                        },
                        format!("acknowledged keys exist but 5.2 chooses no writer: {states:?}"),
                    );
                } else if any_acked {
                    // with restores or wipes: some build's committed index on disk
                    for (id, p) in &oracle {
                        if self.tainted.contains(id) || p.acked.is_none() {
                            continue;
                        }
                        let found = (0..NBUILDS)
                            .any(|b| matches!(self.held_value(b, *id), Ok(ref v) if p.allows(v)));
                        if !found {
                            self.fail(
                                "I2",
                                format!("no build's committed index holds {id:?} = {p:?}"),
                            );
                            return;
                        }
                    }
                }
            }
        }
    }

    /// Run with faults stopped and clients loading with every build
    /// registered, then check I7 (and the restore form of I1).
    pub fn quiesce(&mut self) {
        if self.violation.is_some() {
            return;
        }
        self.log(|| "== quiescence".to_string());
        self.faults = FaultPlan::default();
        self.limbo.clear();
        let adversarial = self.cfg.adversarial;
        self.cfg.adversarial = false;
        for _ in 0..self.cfg.quiesce_rounds {
            self.apply(&Action::Load {
                client: 0,
                fetch: Fetch::Newest,
                ops: vec![],
            });
            self.drain();
            for b in 0..NBUILDS {
                self.apply(&Action::Wakeup { b: b as u8 });
                self.drain();
            }
            if self.violation.is_some() {
                return;
            }
        }
        self.cfg.adversarial = adversarial;
        let w = self.accepting_writers();
        // "by the first step that lets the two interact": while the domain
        // is stopped nothing copies, so two writers need not meet.
        let stopped = self.newest_published().is_some_and(|r| r.withdrawal);
        if self.restored && w.len() > 1 && !stopped {
            let reported = w
                .iter()
                .any(|v| self.stores[bi(*v)].idx_or_none().problems & PROBLEM_ANOTHER_WRITER != 0);
            if !reported {
                self.fail(
                    "I1-restore-unreported",
                    format!(
                        "after restores two builds accept changes and neither reports it: {w:?}"
                    ),
                );
                return;
            }
        }
        let i7_scope =
            !self.restored && !self.garbled && !self.cfg.adversarial && !self.cfg.stale_pointer;
        let Some(newest) = self.newest_published() else {
            return;
        };
        if !i7_scope || newest.withdrawal || !(0..NBUILDS).any(|b| self.stores[b].has_state()) {
            return;
        }
        self.cov.hit("I7/checked");
        let nb = bi(newest.v);
        let st = self.stores[nb].idx_or_none().state;
        if !matches!(st, PState::Writer(ref w) if !w.awaiting) {
            let states: Vec<String> = (0..NBUILDS)
                .map(|b| format!("{}:{}", ver(b), self.stores[b].idx_or_none().state.code()))
                .collect();
            self.fail(
                "I7",
                format!(
                    "after quiescence build {} is {} not WRITER; states {states:?}",
                    newest.v,
                    st.code()
                ),
            );
            return;
        }
        for v in self.held.clone() {
            if v != newest.v
                && !matches!(
                    self.stores[bi(v)].idx_or_none().state,
                    PState::Retired { .. }
                )
            {
                self.fail(
                    "I7",
                    format!(
                        "after quiescence build {v} held the partition and is {}",
                        self.stores[bi(v)].idx_or_none().state.code()
                    ),
                );
                return;
            }
        }
    }

    /// Nothing left for a Step to do.
    pub fn idle(&self) -> bool {
        self.candidates().is_empty()
    }

    /// The index states in build `b`'s snapshot history, in the order a
    /// `Restore { snap }` indexes them.
    pub fn snapshot_states(&self, b: usize) -> Vec<PState> {
        self.history[b]
            .iter()
            .map(|s| s.idx_or_none().state)
            .collect()
    }

    /// Process every pending hop and session call, delivering everything.
    pub fn drain(&mut self) {
        for _ in 0..2000 {
            if self.candidates().is_empty() || self.violation.is_some() {
                return;
            }
            self.apply(&Action::Step {
                pick: 0,
                fate: Fate::Deliver,
            });
        }
    }
}

fn key_entry(slot: u16, k: u32) -> Entry {
    Entry {
        kind: KIND_KEY,
        key: slot,
        flagged: false,
        content: k,
        ext: vec![],
    }
}

/// The value a change would leave, for the oracle.
fn intended_value(op: &Op, _oracle: &BTreeMap<Ident, Possible>) -> Option<(Ident, Option<Entry>)> {
    match op {
        Op::Generate { slot, seed } => Some(((KIND_KEY, *slot), Some(key_entry(*slot, *seed)))),
        Op::Import { slot, seed, .. } => Some(((KIND_KEY, *slot), Some(key_entry(*slot, *seed)))),
        Op::Delete { slot } => Some(((KIND_KEY, *slot), None)),
        Op::PutExt { key, content } => Some((
            (KIND_UNKNOWN, *key),
            Some(Entry {
                kind: KIND_UNKNOWN,
                key: *key,
                flagged: false,
                content: *content,
                ext: vec![0xE0, *key as u8, *content as u8],
            }),
        )),
        _ => None,
    }
}

/// Coverage label for a lost or duplicated 0x0B: to a creation probe, or
/// to an awaiting successor's Query (decision 1).
fn nostate_label(f: &Frame, what: &str) -> &'static str {
    let probe = matches!(f, Frame::CompleteAck { m: 0, .. });
    match (probe, what) {
        (true, "lost") => "5.3/nostate-answer-lost",
        (false, "lost") => "dec1/awaiting-nostate-answer-lost",
        (true, _) => "adv/nostate-answer-duplicated",
        (false, _) => "adv/awaiting-nostate-answer-duplicated",
    }
}

/// A CompleteAck "no state, your record stored" (0x0B).
fn is_nostate(f: &Frame) -> bool {
    matches!(
        f,
        Frame::CompleteAck {
            status: CStatus::NoState,
            ..
        }
    )
}

fn short_reply(r: &Reply) -> String {
    match r {
        Reply::None => "-".into(),
        Reply::Status(s) if s.index_lost => {
            format!("Status(INDEX-LOST(7), rec {})", s.record_result)
        }
        Reply::Status(s) => format!("Status({}, rec {})", s.state.code(), s.record_result),
        Reply::Op(o) => format!("{o:?}"),
        Reply::Frame(f) => f.short(),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
    Writer(Ver),
    Create(Ver),
    /// 5.2 step 4: no writer, one build reports partition_state 7 (index
    /// lost); callers use it for reads and the UI offers the repair of 4.5.
    ReadOnly(Ver),
    Unavailable,
}

/// What a probe of one build reports: its partition state, or
/// partition_state 7 "unknown: index lost".
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Seen {
    pub state: PState,
    pub lost: bool,
}

/// 5.2 steps 3 to 6. `None` in `states` is a build that did not answer.
pub fn route(states: &BTreeMap<Ver, Option<Seen>>, create: Option<Rec>) -> Route {
    let st = |v: &Ver| -> Option<&PState> {
        match states.get(v) {
            Some(Some(s)) if !s.lost => Some(&s.state),
            _ => None,
        }
    };
    let writers: Vec<Ver> = states
        .keys()
        .filter(|v| matches!(st(v), Some(PState::Writer(_))))
        .copied()
        .collect();
    if let Some(v) = writers.iter().max() {
        return Route::Writer(*v);
    }
    let sealed: Vec<Ver> = states
        .keys()
        .filter(|v| matches!(st(v), Some(PState::Sealed { .. })))
        .copied()
        .collect();
    if let Some(v) = sealed.iter().max() {
        return Route::Writer(*v);
    }
    let lost: Vec<Ver> = states
        .iter()
        .filter(|(_, s)| matches!(s, Some(Seen { lost: true, .. })))
        .map(|(v, _)| *v)
        .collect();
    match lost.as_slice() {
        [v] => return Route::ReadOnly(*v),
        [] => {}
        _ => return Route::Unavailable,
    }
    let retired: Vec<Ver> = states
        .keys()
        .filter(|v| matches!(st(v), Some(PState::Retired { .. })))
        .copied()
        .collect();
    if let Some(&start) = retired.first() {
        let mut v = start;
        for _ in 0..NBUILDS + 1 {
            match st(&v) {
                Some(PState::Retired { to, .. }) => v = to.v,
                Some(PState::Writer(_)) | Some(PState::Sealed { .. }) => return Route::Writer(v),
                _ => return Route::Unavailable,
            }
        }
        return Route::Unavailable;
    }
    if states.values().any(|s| {
        s.is_none()
            || matches!(
                s,
                Some(Seen {
                    state: PState::Receiving { .. },
                    ..
                })
            )
    }) {
        return Route::Unavailable;
    }
    match create {
        Some(r) if states.contains_key(&r.v) => Route::Create(r.v),
        _ => Route::Unavailable,
    }
}
