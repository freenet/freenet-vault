//! Seeded schedule generation, running, and shrinking (15.5).

use crate::build::Op;
use crate::cov::Cov;
use crate::store::WriteFault;
use crate::types::*;
use crate::world::*;

pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Rng {
        Rng(seed ^ 0x05ee_d0fb_a11e_u64)
    }
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    pub fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n.max(1)
    }
    pub fn chance(&mut self, p: f64) -> bool {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64 <= p
    }
}

/// A ledger a real release process allows (14): versions only grow; the
/// reserved rollback 50 is published or not; withdrawals at x5 versions.
pub fn gen_ledger(rng: &mut Rng, withdrawals: bool) -> Vec<Rec> {
    let mut l = vec![Rec::build(10)];
    for v in [20, 30, 40] {
        if rng.chance(0.2) && withdrawals {
            l.push(Rec::withdrawal(v - 5));
        }
        if rng.chance(0.9) || v == 20 {
            l.push(Rec::build(v));
        }
    }
    if rng.chance(0.5) {
        l.push(Rec::build(ROLLBACK));
    }
    if rng.chance(0.15) && withdrawals {
        l.push(Rec::withdrawal(55));
    }
    if rng.chance(0.7) {
        l.push(Rec::build(60));
    }
    if rng.chance(0.1) && withdrawals {
        l.push(Rec::withdrawal(65));
    }
    l
}

fn gen_op(rng: &mut Rng) -> Op {
    let slot = rng.below(4) as u16;
    match rng.below(10) {
        0 | 1 => Op::Generate {
            slot,
            seed: 100 + rng.below(1_000_000) as u32,
        },
        2 | 3 => Op::Import {
            slot,
            seed: 1 + rng.below(3) as u32,
            replace: rng.chance(0.5),
        },
        4 => Op::Delete { slot },
        5 | 6 => Op::PublicKey { slot },
        7 => Op::Batch {
            slot,
            expected: if rng.chance(0.8) {
                0
            } else {
                1 + rng.below(3) as u32
            },
        },
        8 => Op::PutExt {
            key: rng.below(2) as u16,
            content: rng.below(1000) as u32,
        },
        _ => Op::RaiseMark {
            caller: rng.below(3) as u16,
            rec: rng.below(10) as u32,
        },
    }
}

/// A change that adds or removes an identity (Busy family).
fn gen_change(rng: &mut Rng) -> Op {
    match rng.below(5) {
        0 | 1 => Op::Delete {
            slot: rng.below(4) as u16,
        },
        2 => Op::Generate {
            slot: rng.below(4) as u16,
            seed: 100 + rng.below(1_000_000) as u32,
        },
        3 => Op::PutExt {
            key: rng.below(2) as u16,
            content: rng.below(1000) as u32,
        },
        _ => Op::RaiseMark {
            caller: rng.below(3) as u16,
            rec: rng.below(10) as u32,
        },
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Profile {
    pub fault: f64,
    pub restores: bool,
    pub family: Family,
}

/// Scenario families, chosen by seed so that one PR run of consecutive
/// seeds covers each. General seeds generate exactly what they did before
/// the families existed (committed traces stay reproducible).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    General,
    /// Restores, wipes and crashes at a high rate, so that a build is set
    /// back while its successors move on (the RECEIVING(lower/higher) and
    /// "not from P" rows of 7.6 are reachable only that way).
    RestoreHeavy,
    /// Many changes per load, so that a writer runs near the entry
    /// maximum while copying and the receiver's staging fills (8).
    Busy,
    /// Damaged and undecryptable secrets (the index and vault:parts
    /// included), read faults and write faults, with no restores or wipes,
    /// so that index loss (4.5) is checked where I1 and I3 apply.
    Damage,
}

pub fn family_of(seed: u64) -> Family {
    match seed % 8 {
        5 => Family::Damage,
        6 => Family::RestoreHeavy,
        7 => Family::Busy,
        _ => Family::General,
    }
}

pub fn gen_scenario(seed: u64, cfg: &Cfg) -> Scenario {
    let mut rng = Rng::new(seed);
    let ledger = gen_ledger(&mut rng, cfg.withdrawals);
    let family = family_of(seed);
    let mut prof = Profile {
        fault: [0.0, 0.03, 0.08, 0.15][rng.below(4) as usize],
        restores: rng.chance(0.2),
        family,
    };
    if family == Family::RestoreHeavy {
        prof.restores = true;
        prof.fault = prof.fault.max(0.08);
    }
    if family == Family::Busy {
        prof.fault = prof.fault.max(0.08);
    }
    if family == Family::Damage {
        prof.restores = false;
        prof.fault = prof.fault.max(0.08);
    }
    let n = 60 + rng.below(241) as usize;
    let mut actions = vec![
        Action::Publish,
        Action::Load {
            client: 0,
            fetch: Fetch::Newest,
            ops: vec![
                Op::Generate {
                    slot: 0,
                    seed: 100 + rng.below(1_000_000) as u32,
                },
                Op::PutExt { key: 0, content: 1 },
            ],
        },
    ];
    if family == Family::Busy {
        // start the writer at the entry maximum
        let fill: Vec<Op> = (0..4)
            .map(|slot| Op::Generate {
                slot,
                seed: 100 + rng.below(1_000_000) as u32,
            })
            .chain([Op::PutExt { key: 1, content: 2 }])
            .collect();
        actions.push(Action::Load {
            client: 0,
            fetch: Fetch::Newest,
            ops: fill,
        });
    }
    while actions.len() < n {
        let f = prof.fault;
        let r = rng.below(1000) as f64 / 1000.0;
        let a = if r < 0.55 {
            let fate = if rng.chance(f) {
                match rng.below(if cfg.adversarial { 5 } else { 3 }) {
                    0 | 1 => Fate::Drop,
                    2 if cfg.garble_hops => Fate::Garble,
                    2 => Fate::Drop,
                    3 => Fate::Delay,
                    _ => Fate::Duplicate,
                }
            } else {
                Fate::Deliver
            };
            Action::Step {
                pick: rng.below(64) as u16,
                fate,
            }
        } else if r < 0.65 {
            let nops = if prof.family == Family::Busy {
                rng.below(9) as usize
            } else {
                rng.below(4) as usize
            };
            Action::Load {
                client: rng.below(CLIENTS.len() as u64) as u8,
                fetch: if rng.chance(f + 0.02) {
                    Fetch::Unreachable
                } else if cfg.stale_pointer && rng.chance(0.2) {
                    Fetch::Stale(rng.below(8) as u8)
                } else {
                    Fetch::Newest
                },
                ops: (0..nops).map(|_| gen_op(&mut rng)).collect(),
            }
        } else if r < 0.73 {
            Action::Wakeup {
                b: rng.below(NBUILDS as u64) as u8,
            }
        } else if r < 0.77 {
            Action::Publish
        } else if r < 0.80 || (prof.family == Family::Busy && r < 0.90) {
            Action::Cached {
                op: if prof.family == Family::Busy {
                    gen_change(&mut rng)
                } else {
                    gen_op(&mut rng)
                },
                b: if rng.chance(0.5) {
                    Some(rng.below(NBUILDS as u64) as u8)
                } else {
                    None
                },
            }
        } else if prof.family == Family::RestoreHeavy && rng.chance(0.5) {
            match rng.below(5) {
                0 | 1 => Action::Restore {
                    b: rng.below(NBUILDS as u64) as u8,
                    snap: rng.below(64) as u16,
                    secret: if rng.chance(0.3) {
                        Some(rng.below(64) as u16)
                    } else {
                        None
                    },
                },
                2 => Action::Wipe {
                    b: rng.below(NBUILDS as u64) as u8,
                },
                3 => Action::Garble {
                    b: rng.below(NBUILDS as u64) as u8,
                    pick: rng.below(64) as u16,
                    undecryptable: rng.chance(0.5),
                },
                _ => Action::Crash,
            }
        } else if prof.family == Family::Damage && rng.chance(0.4) {
            match rng.below(4) {
                0 | 1 => Action::Garble {
                    b: rng.below(NBUILDS as u64) as u8,
                    pick: rng.below(64) as u16,
                    undecryptable: rng.chance(0.5),
                },
                2 => Action::ArmReadFault {
                    after: rng.below(24) as u8,
                },
                _ => Action::Crash,
            }
        } else if !rng.chance(f * 4.0) {
            continue;
        } else {
            match rng.below(11) {
                0 => Action::Crash,
                1..=3 => Action::ArmWriteFault {
                    after: rng.below(8) as u8,
                    fault: [
                        WriteFault::CrashBefore,
                        WriteFault::CrashAfter,
                        WriteFault::Fail,
                        WriteFault::DurableButError,
                        WriteFault::LandedButError,
                    ][rng.below(5) as usize],
                },
                10 => Action::ArmReadFault {
                    after: rng.below(24) as u8,
                },
                4 => Action::Quota {
                    limit: if rng.chance(0.5) {
                        Some(3 + rng.below(8) as u8)
                    } else {
                        None
                    },
                },
                5 | 6 => Action::Unregister {
                    b: rng.below(NBUILDS as u64) as u8,
                },
                _ if !prof.restores => continue,
                7 => Action::Restore {
                    b: rng.below(NBUILDS as u64) as u8,
                    snap: rng.below(64) as u16,
                    secret: if rng.chance(0.5) {
                        Some(rng.below(64) as u16)
                    } else {
                        None
                    },
                },
                8 => Action::Wipe {
                    b: rng.below(NBUILDS as u64) as u8,
                },
                _ => Action::Garble {
                    b: rng.below(NBUILDS as u64) as u8,
                    pick: rng.below(64) as u16,
                    undecryptable: rng.chance(0.5),
                },
            }
        };
        actions.push(a);
    }
    Scenario { ledger, actions }
}

pub struct Outcome {
    pub violation: Option<Violation>,
    pub cov: Cov,
    pub trace: Vec<String>,
    pub sealed_corrupt_sent: u64,
}

pub fn run(cfg: &Cfg, sc: &Scenario) -> Outcome {
    let mut w = World::new(cfg.clone(), sc.ledger.clone());
    for a in &sc.actions {
        w.apply(a);
        if w.violation.is_some() {
            break;
        }
    }
    w.quiesce();
    Outcome {
        violation: w.violation.clone(),
        cov: w.cov.clone(),
        trace: std::mem::take(&mut w.trace),
        sealed_corrupt_sent: w.sealed_corrupt_sent,
    }
}

/// Delta-debugging over the action list, keeping the same invariant.
pub fn shrink(cfg: &Cfg, sc: &Scenario, inv: &str) -> Scenario {
    let fails = |s: &Scenario| run(cfg, s).violation.is_some_and(|v| v.inv == inv);
    let mut cur = sc.clone();
    let mut chunk = cur.actions.len() / 2;
    let mut budget = 4000;
    while chunk >= 1 && budget > 0 {
        let mut i = 0;
        let mut progressed = false;
        while i < cur.actions.len() && budget > 0 {
            budget -= 1;
            let mut cand = cur.clone();
            let end = (i + chunk).min(cand.actions.len());
            cand.actions.drain(i..end);
            if fails(&cand) {
                cur = cand;
                progressed = true;
            } else {
                i += chunk;
            }
        }
        if !progressed {
            chunk /= 2;
        }
    }
    // simplify fates and ops where possible
    for i in 0..cur.actions.len() {
        if let Action::Step { pick, fate } = cur.actions[i].clone() {
            if pick != 0 || fate != Fate::Deliver {
                for (p, f) in [(0, fate), (pick, Fate::Deliver), (0, Fate::Deliver)] {
                    let mut cand = cur.clone();
                    cand.actions[i] = Action::Step { pick: p, fate: f };
                    if fails(&cand) {
                        cur = cand;
                        break;
                    }
                }
            }
        }
    }
    cur
}

/// Seeds replayed on every run, each with a coverage counter that ordinary
/// runs of a few thousand consecutive seeds reach too rarely (15.5:
/// "every row ... at least once per pull-request run"). Found with
/// `vault-model --find <counter>`; `coverage_seeds_still_hit_their_rows`
/// fails if a generator change moves one off its row.
pub const COVERAGE_SEEDS: &[(u64, &str)] = &[
    (4954, "7.6/RECEIVING(higher)/Chunk"),
    (5630, "7.6/other-writer-or-not-from-P/Abort"),
    (9445, "7.6/stopped/Complete"),
    (9445, "7.5/completeack/Stopped"),
    (9445, "sent/CompleteAck/Stopped"),
    (12214, "7.6/RECEIVING(lower)/Complete"),
    (47871, "4.3/corrupt-rewritten-flagged"),
    (64534, "7.6/RECEIVING(higher)/Complete"),
    (64534, "7.5/completeack/HigherBuild"),
    (64534, "sent/CompleteAck/HigherBuild"),
];
