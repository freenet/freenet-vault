//! The handover between builds (protocol sections 3, 5, 6, 7).
//!
//! This module follows the executable model of the protocol
//! (`crates/freenet-vault-model/src/build.rs`) transition by transition: the
//! function names below are the model's, and so are the coverage counters
//! (`hit!`) and transition notes, which the conformance harness reads.
//!
//! What it adds to the operations of `ops.rs`:
//!
//! - Poke (6, first row): record acceptance (3), the pause and arm flags
//!   (7.5, 13.1), creation probes (5.3), and a step (7.7).
//! - Wake-ups and NodeStarted: a step when there is work (7.7).
//! - Vault-to-vault frames (12.3): the receiver role (7.2, 7.4, 7.6), the
//!   sender role (7.3 to 7.5), and the predecessor role for Query (7.4, 7.6),
//!   plus the answers to this build's own Query (6).
//!
//! Volatile state (the in-flight marks and the mirror sweep's progress) lives
//! in the delegate context ([`crate::ctx`]); everything else is durable.

use crate::ctx::{Ctx, Ident, Vol};
use crate::domain::Domain;
use crate::hit;
use crate::host::{replace_secret, Host};
use crate::limits;
use crate::storage::index::{Index, State};
use crate::storage::{self, names, CopyRead, Store, Sweep};
use crate::succ::{accept_record as store_record, Succ};
use crate::trace::{self, Mutant, Note};
use freenet_vault_common::codec::{Reader, Writer};
use freenet_vault_common::entry::{Entry, KIND_CALLER_MARK};
use freenet_vault_common::frame::{types, Frame};
use freenet_vault_common::handover::{
    chunk_status, cstatus, outcome, Ack, Chunk, Complete, CompleteAck, RequestHeader, Short,
};
use freenet_vault_common::hash::{chunk_digest, delegate_key_empty_params, transfer_id};
use freenet_vault_common::record::PointerRecord;
use freenet_vault_common::status::{
    partition_state, poke_flags, problems, record_state, refused, step_result, HandoverStatus,
    Poke, Status,
};
use std::collections::{BTreeMap, BTreeSet};

type Rec = [u8; 100];
type Digest = [u8; 32];

/// Hops to send: (target's code hash, frame). The target's delegate key is
/// `S` of that code hash with empty parameters (2, 10).
pub type Hops = Vec<([u8; 32], Vec<u8>)>;

/// Whether a frame type is a vault-to-vault frame (12.3).
pub fn is_handover_frame(t: u8) -> bool {
    (types::CHUNK..=types::QUERY).contains(&t)
}

fn version(r: &Rec) -> u32 {
    PointerRecord::decode(r).version
}

fn is_withdrawal(r: &Rec) -> bool {
    PointerRecord::decode(r).is_withdrawal()
}

/// The delegate key a record names, `S(R)` (2).
pub fn key_of(r: &Rec) -> [u8; 32] {
    delegate_key_empty_params(&PointerRecord::decode(r).code_hash)
}

fn code_of(r: &Rec) -> [u8; 32] {
    PointerRecord::decode(r).code_hash
}

fn highest(s: &Succ) -> Option<Rec> {
    match (s.current, s.withdrawal) {
        (Some(c), Some(w)) => Some(if version(&w) > version(&c) { w } else { c }),
        (a, b) => a.or(b),
    }
}

/// The mark policy of a receiver (7.2, 9): a mark is stored only for a caller
/// the domain accepts, whose record verifies and is at or above the
/// compiled-in minimum. Anything else is "dropped by policy" (0x03).
fn mark_accepted(d: &Domain, e: &Entry) -> bool {
    #[cfg(any(test, feature = "testing"))]
    if let Some(f) = crate::testing::mark_policy() {
        return f(d.own_version, e);
    }
    if e.key.len() < 33 {
        return false;
    }
    let (author, app) = e.key.split_at(32);
    let author: [u8; 32] = author.try_into().expect("32 bytes");
    let Some(c) = d.caller_delegate(&author, app) else {
        return false;
    };
    let Ok(rec) = <Rec>::try_from(e.content.as_slice()) else {
        return false;
    };
    let r = PointerRecord::decode(&rec);
    r.verify(&author, app).is_ok() && r.version >= c.min_version
}

// ------------------------------------------------------------ durable lists

/// `vault:x`: `"FVPX" 4 ; count 2 ; count x { kind 1 ; key_len 2 ; key ; digest 32 }`.
pub fn encode_prog(p: &BTreeMap<Ident, Digest>) -> Vec<u8> {
    let mut w = Writer::new();
    w.bytes(b"FVPX").len_u16(p.len(), "count");
    for ((k, key), d) in p {
        w.u8(*k).len_u16(key.len(), "key").bytes(key).bytes(d);
    }
    w.into_vec()
}

pub fn decode_prog(b: &[u8]) -> Option<BTreeMap<Ident, Digest>> {
    let mut r = Reader::new(b);
    if r.take(4, "magic").ok()? != b"FVPX" {
        return None;
    }
    let n = r.u16("count").ok()? as usize;
    let mut out = BTreeMap::new();
    for _ in 0..n {
        let k = r.u8("kind").ok()?;
        let l = r.u16("key").ok()? as usize;
        let key = r.take(l, "key").ok()?.to_vec();
        out.insert((k, key), r.array("digest").ok()?);
    }
    r.finish().ok()?;
    Some(out)
}

/// `vault:rx`: `"FVRX" 4 ; count 2 ; count x digest 32 (ascending)`.
pub fn encode_rx(s: &BTreeSet<Digest>) -> Vec<u8> {
    let mut w = Writer::new();
    w.bytes(b"FVRX").len_u16(s.len(), "count");
    for d in s {
        w.bytes(d);
    }
    w.into_vec()
}

pub fn decode_rx(b: &[u8]) -> Option<BTreeSet<Digest>> {
    let mut r = Reader::new(b);
    if r.take(4, "magic").ok()? != b"FVRX" {
        return None;
    }
    let n = r.u16("count").ok()? as usize;
    let mut out = BTreeSet::new();
    for _ in 0..n {
        out.insert(r.array("digest").ok()?);
    }
    r.finish().ok()?;
    Some(out)
}

/// Public for the conformance harness's storage abstraction.
pub mod layout {
    pub use super::{decode_prog, decode_rx, encode_prog, encode_rx};
}

/// Clears the fields a state does not have, so that every index this build
/// writes has one representation per state (5.1).
pub fn canonical(ix: &mut Index) {
    let h = &mut ix.ho;
    match ix.state {
        State::None => {
            ix.peer_record = None;
            ix.awaiting_retirement = false;
            h.taken_over = None;
            h.own_record = None;
            h.m = None;
            h.paused = None;
            h.receiving_from = 0;
            h.store_failed = false;
            if ix.armed.is_none() {
                h.confirmed.clear();
            }
        }
        State::Writer => {
            ix.armed = None;
            ix.peer_record = None;
            h.m = None;
            h.receiving_from = 0;
            h.store_failed = false;
            h.confirmed.clear();
        }
        State::Sealed => {
            ix.armed = None;
            h.receiving_from = 0;
            h.store_failed = false;
            h.confirmed.clear();
        }
        State::Receiving => {
            ix.armed = None;
            ix.peer_record = None;
            ix.awaiting_retirement = false;
            h.taken_over = None;
            h.own_record = None;
            h.m = None;
            h.paused = None;
            h.confirmed.clear();
        }
        State::Retired => {
            ix.armed = None;
            ix.awaiting_retirement = false;
            h.paused = None;
            h.receiving_from = 0;
            h.store_failed = false;
            h.confirmed.clear();
        }
    }
    if h.taken_over.is_none() {
        h.own_record = None;
    }
}

// ------------------------------------------------------------ the call

/// What a handover call produces.
pub struct Out {
    /// The reply to the caller (a page's HandoverStatus, a CompleteAck or
    /// Ack to the sending delegate), or nothing.
    pub reply: Option<Vec<u8>>,
    pub hops: Hops,
}

pub struct Cx<'a, H: Host> {
    d: &'a Domain,
    h: &'a mut H,
    part: [u8; 32],
    vol: Vol,
    out: Hops,
    /// The sweep found an entry the index names whose secret reads as absent
    /// (problems bit 1, revision 10.2).
    saw_missing: bool,
}

impl<'a, H: Host> Cx<'a, H> {
    fn new(d: &'a Domain, h: &'a mut H, vol: Vol) -> Self {
        Self {
            part: d.partition(),
            d,
            h,
            vol,
            out: Vec::new(),
            saw_missing: false,
        }
    }

    fn own(&self) -> u32 {
        self.d.own_version
    }

    fn idx_raw(&self) -> Option<Index> {
        self.h
            .get_secret(&names::index(&self.part))
            .and_then(|b| Index::decode(&b).ok())
    }

    /// The committed index as read now (NONE when absent or malformed and not
    /// lost; only called when the index is not lost).
    fn idx(&self) -> Index {
        self.idx_raw().unwrap_or_else(Index::none)
    }

    fn succ(&self) -> Succ {
        Succ::load(self.d, &*self.h).unwrap_or_default()
    }

    fn parts_listed(&self) -> bool {
        storage::parts_lists(&*self.h, &self.part)
    }

    /// Commits an index (4.2). After a failed write the index is read back:
    /// `true` when the disk holds what was intended. A commit that makes the
    /// index WRITER or SEALED lists the partition (inside `Store::commit`);
    /// callers check [`parts_listed`](Self::parts_listed) before any answer
    /// that depends on it.
    fn commit(&mut self, new: &Index) -> bool {
        let mut new = new.clone();
        canonical(&mut new);
        let Ok(mut st) = Store::open(&mut *self.h, self.part) else {
            return false;
        };
        if st.commit(new.clone()).is_ok() {
            return true;
        }
        self.idx_raw().as_ref() == Some(&new)
    }

    fn gc_add(&mut self, add: &[Vec<u8>]) -> bool {
        match Store::open(&mut *self.h, self.part) {
            Ok(mut st) => st.add_gc(add).is_ok(),
            Err(_) => false,
        }
    }

    fn process_gc(&mut self) {
        if let Ok(mut st) = Store::open(&mut *self.h, self.part) {
            st.process_gc();
        }
    }

    fn rx(&self) -> BTreeSet<Digest> {
        self.h
            .get_secret(&names::received_dropped(&self.part))
            .and_then(|b| decode_rx(&b))
            .unwrap_or_default()
    }

    fn put_rx(&mut self, s: &BTreeSet<Digest>) -> bool {
        replace_secret(self.h, &names::received_dropped(&self.part), &encode_rx(s))
    }

    fn prog(&self, tv: u32) -> BTreeMap<Ident, Digest> {
        self.h
            .get_secret(&names::progress(tv, &self.part))
            .and_then(|b| decode_prog(&b))
            .unwrap_or_default()
    }

    fn put_prog(&mut self, tv: u32, p: &BTreeMap<Ident, Digest>) -> bool {
        replace_secret(self.h, &names::progress(tv, &self.part), &encode_prog(p))
    }

    fn send(&mut self, to: [u8; 32], frame: Vec<u8>) {
        self.out.push((to, frame));
    }

    /// A predecessor's code hash, by version.
    fn pred_code(&self, v: u32) -> Option<[u8; 32]> {
        self.d
            .predecessors
            .iter()
            .find(|(pv, _)| *pv == v)
            .map(|(_, c)| *c)
    }

    fn tid(&self, sender_version: u32, target: &Rec) -> Digest {
        transfer_id(&self.d.author_vk, sender_version, target)
    }

    /// Creation bar (3): a non-withdrawal record above OWN_VERSION.
    fn creation_bar(&self) -> bool {
        let s = self.succ();
        if trace::mutant(Mutant::WithdrawalLiftsBar) && s.stopped() {
            hit!("mutant/withdrawal-lifts-bar");
            return false;
        }
        s.current.is_some_and(|c| version(&c) > self.own())
    }

    // -------------------------------------------------------- records (3)

    /// Section 3. Returns the step_result (12.4) and whether a record was
    /// stored. Storing one clears any creation arming and confirmations.
    fn accept_record(&mut self, rec: &Rec) -> (u8, bool) {
        let before = Succ::load(self.d, &*self.h);
        let mut s = before.unwrap_or_default();
        let r = PointerRecord::decode(rec);
        let floor = s.floor(self.own());
        if r.verify(&self.d.author_vk, self.d.app_id).is_ok() {
            if r.version < floor || r.version == self.own() {
                hit!("3/not-newer");
            } else if r.version == floor {
                if s.current.as_ref() == Some(rec) || s.withdrawal.as_ref() == Some(rec) {
                    hit!("3/retry");
                } else {
                    hit!("3/equivocation");
                }
            } else if r.is_withdrawal() {
                hit!("3/withdrawal-stored");
            } else {
                hit!("3/record-stored");
            }
        }
        let a = store_record(self.d, self.h, &mut s, rec);
        if a.storage_failure {
            hit!("3/record-write-failed-read-back");
        }
        let stored = Succ::load(self.d, &*self.h).ok() != before.ok();
        if stored {
            let mut idx = self.idx();
            if idx.state == State::None && (idx.armed.is_some() || !idx.ho.confirmed.is_empty()) {
                idx.armed = None;
                idx.ho.confirmed.clear();
                hit!("5.1/arming-cleared-by-record");
                self.commit(&idx);
            }
        }
        (a.step_result, stored)
    }

    fn abort_trigger(&self, target: &Rec) -> bool {
        let s = self.succ();
        if trace::mutant(Mutant::UnsealOnHigherRecord) {
            return false;
        }
        s.stopped() || s.successor().is_some_and(|c| version(&c) > version(target))
    }

    fn copy_target(&self, idx: &Index) -> Option<Rec> {
        if idx.state != State::Writer {
            return None;
        }
        if idx.awaiting_retirement && !trace::mutant(Mutant::CopyWhileAwaiting) {
            return None;
        }
        let s = self.succ();
        if s.stopped() {
            return None;
        }
        let t = s.successor()?;
        if idx.ho.paused == Some(version(&t)) {
            None
        } else {
            Some(t)
        }
    }

    fn has_work(&self) -> bool {
        let idx = self.idx();
        let sweep_due = !self.vol.swept && self.parts_listed() && idx.state == State::Writer;
        let gc = !storage::pending_gc_names(&*self.h, &self.part).is_empty();
        gc || sweep_due
            || idx.state == State::Sealed
            || (idx.state == State::Writer && idx.awaiting_retirement)
            || self.copy_target(&idx).is_some()
    }

    // -------------------------------------------------------- poke (6)

    fn poke(&mut self, flags: u8, rec: Option<Rec>, own_page: bool) -> (u8, bool) {
        let out_before = self.out.len();
        let mut rr = step_result::NOTHING;
        if let Some(r) = &rec {
            rr = self.accept_record(r).0;
        }
        let flags = if own_page { flags } else { 0 };
        let mut idx = self.idx();
        let succ = self.succ();
        if flags & poke_flags::PAUSE_COPYING != 0 {
            if let (State::Writer, Some(t)) = (idx.state, succ.successor()) {
                let tv = version(&t);
                if !succ.stopped() && idx.ho.paused != Some(tv) {
                    idx.ho.paused = Some(tv);
                    idx.problems |= problems::COPYING_PAUSED;
                    hit!("7.5/pause-set");
                    self.commit(&idx);
                }
            }
        } else if idx.state == State::Writer && idx.ho.paused.is_some() {
            idx.ho.paused = None;
            idx.problems &= !problems::COPYING_PAUSED;
            hit!("7.5/pause-cleared-by-poke");
            self.commit(&idx);
        }
        if flags & 0b1_0000 != 0 {
            hit!("12.4/poke-bit-4-ignored");
        }
        if flags & poke_flags::ARM != 0 {
            let idx = self.idx();
            if let (State::None, Some(r)) = (idx.state, rec) {
                let pr = PointerRecord::decode(&r);
                let stopped = self.succ().stopped();
                if idx.armed.is_some() {
                    hit!("13.1/arm-already-armed");
                } else if pr.version == self.own()
                    && !pr.is_withdrawal()
                    && pr.verify(&self.d.author_vk, self.d.app_id).is_ok()
                {
                    if self.creation_bar() {
                        hit!("3/creation-bar-refused-arm");
                    } else if stopped && !trace::mutant(Mutant::CreateWhileStopped) {
                        hit!("3/arm-refused-stopped");
                    } else {
                        if stopped {
                            hit!("mutant/armed-while-stopped");
                        }
                        // 5.3 step 1: the arming record with an empty
                        // confirmed set.
                        let mut n = idx.clone();
                        n.armed = Some(r);
                        n.ho.confirmed.clear();
                        if self.commit(&n) {
                            hit!("13.1/armed");
                        }
                    }
                } else {
                    hit!("13.1/arm-refused");
                }
            }
        }
        // 5.3: a poke to an armed build sends creation probes (Query with a
        // zero manifest digest) to its unconfirmed predecessors.
        let idx = self.idx();
        if let (State::None, Some(ar)) = (idx.state, idx.armed) {
            let unconfirmed: Vec<(u32, [u8; 32])> = self
                .d
                .predecessors
                .iter()
                .filter(|(v, _)| !idx.ho.confirmed.contains(v))
                .copied()
                .collect();
            if unconfirmed.is_empty() {
                hit!("5.3/armed-all-confirmed");
            }
            for (_, key) in unconfirmed {
                hit!("5.3/probe-sent");
                let q = Short {
                    record: ar,
                    partition: self.part,
                    manifest_digest: [0; 32],
                    ext: vec![],
                };
                if let Ok(f) = q.encode(types::QUERY) {
                    self.send(key, f);
                }
            }
        }
        self.step(limits::get().window_poke);
        (rr, self.out.len() > out_before)
    }

    // -------------------------------------------------------- step (7.7)

    fn step(&mut self, window: usize) -> bool {
        self.vol.in_flight.clear();
        self.vol.complete_in_flight = false;
        self.sweep(window);
        let before = self.out.len();
        let idx = self.idx();
        match idx.state {
            State::Writer if idx.awaiting_retirement => {
                hit!("7.7/step-query");
                if let (Some((pv, m)), Some(own)) = (idx.ho.taken_over, idx.ho.own_record) {
                    if let Some(key) = self.pred_code(pv) {
                        let q = Short {
                            record: own,
                            partition: self.part,
                            manifest_digest: m,
                            ext: vec![],
                        };
                        if let Ok(f) = q.encode(types::QUERY) {
                            self.send(key, f);
                        }
                    }
                }
                if trace::mutant(Mutant::CopyWhileAwaiting) {
                    if let Some(t) = self.copy_target(&idx) {
                        hit!("mutant/copy-while-awaiting");
                        if self.pending(&t).is_empty() {
                            self.seal(&t);
                        } else {
                            self.send_pending(&t, window);
                        }
                    }
                }
            }
            State::Sealed => {
                let (Some(target), Some(m)) = (idx.peer_record, idx.ho.m) else {
                    return false;
                };
                if self.abort_trigger(&target) {
                    hit!("7.5/step-abort");
                    let a = Short {
                        record: target,
                        partition: self.part,
                        manifest_digest: m,
                        ext: vec![],
                    };
                    if let Ok(f) = a.encode(types::ABORT) {
                        self.send(code_of(&target), f);
                    }
                } else {
                    let sent = self.send_pending(&target, window.saturating_sub(1));
                    if self.pending(&target).is_empty() {
                        hit!("7.5/step-resend-complete");
                        self.send_complete(&target, m);
                    } else if sent == 0 {
                        self.send_complete(&target, m);
                    }
                }
            }
            State::Writer => {
                if let Some(t) = self.copy_target(&idx) {
                    if self.pending(&t).is_empty() {
                        self.seal(&t);
                    } else {
                        hit!("7.7/step-copy");
                        self.send_pending(&t, window);
                    }
                }
            }
            _ => {}
        }
        self.out.len() > before
    }

    /// The mirror sweep (7.7) of a listed WRITER whose sweep has not finished
    /// since it started or took over, bounded per step.
    fn sweep(&mut self, window: usize) {
        if self.vol.swept || !self.parts_listed() || self.idx().state != State::Writer {
            return;
        }
        let budget = window.max(1) * limits::get().sweep_per_message;
        let cursor = self.vol.sweep_cursor.clone();
        let Ok(mut st) = Store::open(&mut *self.h, self.part) else {
            return;
        };
        let r = st.mirror_sweep(budget, cursor.as_ref());
        self.saw_missing |= st.saw_missing();
        match r {
            Sweep::Finished => {
                self.vol.swept = true;
                self.vol.sweep_cursor = None;
                trace::note(Note::SweepDone);
                hit!("7.7/sweep-finished");
            }
            Sweep::Budget(c) => {
                hit!("7.7/sweep-budget-reached");
                self.vol.sweep_cursor = Some(c);
            }
            Sweep::Stopped => {}
        }
    }

    /// Entries not acknowledged at their current digest and not in flight:
    /// marks first, then the others in identity order.
    fn pending(&self, t: &Rec) -> Vec<Ident> {
        let idx = self.idx();
        let prog = self.prog(version(t));
        let mut v: Vec<Ident> = idx
            .entries
            .iter()
            .map(|e| ((e.kind, e.key.clone()), e.digest))
            .filter(|(id, d)| prog.get(id) != Some(d) && !self.vol.in_flight.contains(id))
            .map(|(id, _)| id)
            .collect();
        v.sort_by(|a, b| (a.0 != KIND_CALLER_MARK, a).cmp(&(b.0 != KIND_CALLER_MARK, b)));
        v
    }

    fn send_pending(&mut self, t: &Rec, max_msgs: usize) -> usize {
        let chunk_max = limits::get().chunk_max;
        let sealed = self.idx().state == State::Sealed;
        let mut sent = 0;
        while sent < max_msgs {
            let pend = self.pending(t);
            if pend.is_empty() {
                break;
            }
            let mut entries = Vec::new();
            for id in pend.into_iter().take(chunk_max) {
                self.vol.in_flight.insert(id.clone());
                let r = match Store::open(&mut *self.h, self.part) {
                    Ok(mut st) => st.read_for_copy(id.0, &id.1, sealed),
                    Err(_) => CopyRead::Missing,
                };
                if let CopyRead::Bytes(b) = r {
                    entries.push(b);
                }
            }
            if entries.is_empty() {
                continue;
            }
            let c = Chunk {
                record: *t,
                partition: self.part,
                entries,
                ext: vec![],
            };
            if let Ok(f) = c.encode() {
                self.send(code_of(t), f);
                sent += 1;
            }
        }
        sent
    }

    fn manifest(&self) -> Vec<Digest> {
        let mut v: Vec<Digest> = self.idx().entries.iter().map(|e| e.digest).collect();
        v.sort_unstable();
        v.dedup();
        v
    }

    fn send_complete(&mut self, t: &Rec, m: Digest) {
        let digests = self.manifest();
        self.vol.complete_in_flight = true;
        let c = Complete {
            record: *t,
            partition: self.part,
            manifest_digest: m,
            digests,
            ext: vec![],
        };
        if let Ok(f) = c.encode() {
            self.send(code_of(t), f);
        }
    }

    /// 7.4: one index write to SEALED(target, m), then Complete.
    fn seal(&mut self, t: &Rec) {
        let idx = self.idx();
        if idx.state != State::Writer {
            return;
        }
        let m = freenet_vault_common::hash::manifest_digest(&self.manifest());
        let mut n = idx.clone();
        n.state = State::Sealed;
        n.peer_record = Some(*t);
        n.ho.m = Some(m);
        if self.commit(&n) {
            hit!("7.4/sealed");
            self.send_complete(t, m);
        }
    }

    // -------------------------------------------------------- hops (6)

    fn hop(&mut self, key: &[u8; 32], payload: &[u8]) -> Option<Vec<u8>> {
        let Ok(f) = Frame::decode(payload) else {
            hit!("6/ignored");
            return None;
        };
        let idx = self.idx();
        let s = self.succ();
        let sealed_target = (idx.state == State::Sealed)
            .then_some(idx.peer_record)
            .flatten();
        let successor = [s.current, sealed_target]
            .into_iter()
            .flatten()
            .find(|r| &key_of(r) == key);
        let pred = self
            .d
            .predecessors
            .iter()
            .find(|(_, c)| &delegate_key_empty_params(c) == key)
            .map(|(v, _)| *v);
        match f.frame_type {
            types::CHUNK | types::COMPLETE | types::ABORT | types::RETIRED if pred.is_some() => {
                hit!("6/receiver-role");
                self.receiver(pred.expect("checked"), f.frame_type, f.body)
            }
            types::ACK | types::COMPLETE_ACK if successor.is_some() => {
                hit!("6/ack-from-successor");
                let t = successor.expect("checked");
                if f.frame_type == types::ACK {
                    if let Ok(a) = Ack::decode(f.body) {
                        self.on_ack(&t, a);
                    }
                } else if let Ok(a) = CompleteAck::decode(f.body) {
                    self.on_cack(&t, a);
                }
                None
            }
            types::QUERY => {
                let q = Short::decode(f.body).ok();
                let ok = q.as_ref().is_some_and(|q| {
                    let r = PointerRecord::decode(&q.record);
                    r.verify(&self.d.author_vk, self.d.app_id).is_ok()
                        && !r.is_withdrawal()
                        && &key_of(&q.record) == key
                        && r.version > self.own()
                        && q.partition == self.part
                });
                if ok {
                    hit!("6/predecessor-role");
                    let q = q.expect("checked");
                    self.on_query(q.record, q.manifest_digest)
                } else {
                    hit!("6/ignored");
                    None
                }
            }
            types::COMPLETE_ACK if pred.is_some() => {
                let pv = pred.expect("checked");
                let Ok(a) = CompleteAck::decode(f.body) else {
                    hit!("6/ignored");
                    return None;
                };
                if idx.state == State::Writer
                    && idx.awaiting_retirement
                    && idx.ho.taken_over == Some((pv, a.manifest_digest))
                {
                    hit!("6/query-answer/awaiting");
                    self.on_query_answer(a.status);
                } else if idx.state == State::None
                    && idx.armed.is_some()
                    && a.manifest_digest == [0; 32]
                {
                    hit!("6/query-answer/armed");
                    self.on_probe_answer(pv, a.status);
                } else {
                    hit!("6/ignored");
                    hit!("6/ignored/answer-from-predecessor");
                }
                None
            }
            _ => {
                hit!("6/ignored");
                None
            }
        }
    }

    // -------------------------------------------------------- receiver (7.6)

    fn receiver(&mut self, from: u32, ftype: u8, body: &[u8]) -> Option<Vec<u8>> {
        let idx = self.idx();
        let s = self.succ();
        let fname = match ftype {
            types::CHUNK => "Chunk",
            types::COMPLETE => "Complete",
            types::ABORT => "Abort",
            _ => "Retired",
        };
        let _ = fname;
        // Strict decode; a request that does not decode is "malformed", and
        // its leading fields are read on their own for the answer.
        let chunk = (ftype == types::CHUNK)
            .then(|| Chunk::decode(body).ok())
            .flatten();
        let complete = (ftype == types::COMPLETE)
            .then(|| Complete::decode(body).ok())
            .flatten();
        let short = matches!(ftype, types::ABORT | types::RETIRED)
            .then(|| Short::decode(body).ok())
            .flatten();
        let malformed = chunk.is_none() && complete.is_none() && short.is_none();
        let header = RequestHeader::peek(ftype, body)?;
        let rec = header.record;
        let echo = header.manifest_digest.unwrap_or([0; 32]);
        let tid = self.tid(from, &rec);
        let part = self.part;
        let cdig = chunk_digest(body);
        let ack = |status: u8, outcomes: Vec<(Digest, u8)>, succ: Option<Rec>| {
            hit!("sent/Ack/{status}");
            Ack {
                transfer_id: tid,
                chunk_digest: cdig,
                partition: part,
                status,
                succ_record: succ,
                outcomes,
                ext: vec![],
            }
            .encode()
            .ok()
        };
        let cack = |status: u8, missing: Vec<Digest>, succ: Option<Rec>| {
            let mut missing = missing;
            missing.sort_unstable();
            CompleteAck {
                transfer_id: tid,
                partition: part,
                manifest_digest: echo,
                status,
                succ_record: succ,
                missing,
                ext: vec![],
            }
            .encode()
            .ok()
        };
        let hs = highest(&s);

        // Rows "taken over from P at m'" take precedence over every other
        // row (7.6), including "stopped" and "malformed".
        let stopped_first = trace::mutant(Mutant::StoppedBeforeTakenOver)
            && s.stopped()
            && idx.ho.taken_over.is_some_and(|(pv, _)| pv == from);
        if stopped_first {
            hit!("mutant/stopped-before-taken-over");
            return match ftype {
                types::CHUNK => ack(chunk_status::STOPPED, vec![], s.withdrawal),
                types::COMPLETE => cack(cstatus::STOPPED, vec![], s.withdrawal),
                types::ABORT => cack(cstatus::ABORTED, vec![], hs),
                _ => None,
            };
        }
        if let Some((pv, m2)) = idx.ho.taken_over {
            if pv == from {
                hit!("7.6/taken-over-from-P/{fname}");
                return match ftype {
                    types::CHUNK => ack(chunk_status::ANOTHER_WRITER, vec![], hs),
                    types::COMPLETE | types::ABORT => {
                        if !malformed && echo == m2 {
                            cack(cstatus::ALREADY_WRITER, vec![], hs)
                        } else {
                            cack(cstatus::DIFFERENT_MANIFEST, vec![], hs)
                        }
                    }
                    _ => {
                        if !malformed && echo == m2 {
                            if idx.state == State::Writer && idx.awaiting_retirement {
                                let mut n = idx.clone();
                                n.awaiting_retirement = false;
                                if self.commit(&n) {
                                    hit!("7.4/awaiting-cleared-by-retired");
                                    trace::note(Note::AwaitingCleared);
                                }
                            }
                            cack(cstatus::NOTED, vec![], hs)
                        } else {
                            hit!("7.6/taken-over-from-P/Retired-other-m-ignored");
                            None
                        }
                    }
                };
            }
        }

        if malformed || header.partition != self.part {
            hit!("7.6/malformed/{fname}");
            return match ftype {
                types::CHUNK => ack(chunk_status::MALFORMED, vec![], hs),
                _ => cack(cstatus::MALFORMED, vec![], hs),
            };
        }
        let r = PointerRecord::decode(&rec);
        if r.version != self.own()
            || r.is_withdrawal()
            || r.verify(&self.d.author_vk, self.d.app_id).is_err()
        {
            hit!("12.3/record-not-mine/{fname}");
            return match ftype {
                types::CHUNK => ack(chunk_status::RECORD_NOT_MINE, vec![], hs),
                _ => cack(cstatus::MALFORMED, vec![], hs),
            };
        }

        let recv_from = (idx.state == State::Receiving).then_some(idx.ho.receiving_from);
        match idx.state {
            State::Writer | State::Sealed | State::Retired => {
                hit!("7.6/other-writer-or-not-from-P/{fname}");
                match ftype {
                    types::CHUNK => ack(chunk_status::ANOTHER_WRITER, vec![], hs),
                    types::COMPLETE => cack(cstatus::ANOTHER_WRITER, vec![], hs),
                    types::ABORT => cack(cstatus::ABORTED, vec![], hs),
                    _ => None,
                }
            }
            State::None | State::Receiving if s.stopped() => {
                hit!("7.6/stopped/{fname}");
                match ftype {
                    types::CHUNK => ack(chunk_status::STOPPED, vec![], s.withdrawal),
                    types::COMPLETE => cack(cstatus::STOPPED, vec![], s.withdrawal),
                    types::ABORT => cack(cstatus::ABORTED, vec![], hs),
                    _ => None,
                }
            }
            State::None => {
                hit!("7.6/NONE/{fname}");
                match ftype {
                    types::CHUNK => {
                        let entries = chunk.expect("decoded").entries;
                        let mut n = idx.clone();
                        n.state = State::Receiving;
                        n.ho.receiving_from = from;
                        n.ho.store_failed = false;
                        self.put_rx(&BTreeSet::new());
                        if !self.commit(&n) {
                            // Still NONE on disk: nothing stored.
                            let outs = entries
                                .iter()
                                .map(|e| {
                                    (
                                        freenet_vault_common::hash::entry_digest(e),
                                        outcome::STORAGE_FAILURE,
                                    )
                                })
                                .collect();
                            return ack(chunk_status::PROCESSED, outs, hs);
                        }
                        Some(self.process_chunk(from, tid, cdig, entries)).flatten()
                    }
                    types::COMPLETE => {
                        let c = complete.expect("decoded");
                        if c.digests.is_empty() {
                            let mut n = idx.clone();
                            n.state = State::Receiving;
                            n.ho.receiving_from = from;
                            n.ho.store_failed = false;
                            if !self.commit(&n) {
                                return cack(cstatus::STORAGE_FAILURE, vec![], hs);
                            }
                            self.take_over(from, &rec, tid, c)
                        } else {
                            let missing = c
                                .digests
                                .into_iter()
                                .take(limits::get().missing_max)
                                .collect();
                            cack(cstatus::MISSING, missing, hs)
                        }
                    }
                    types::ABORT => cack(cstatus::ABORTED, vec![], hs),
                    _ => None,
                }
            }
            State::Receiving if recv_from == Some(from) => {
                hit!("7.6/RECEIVING(P)/{fname}");
                match ftype {
                    types::CHUNK => {
                        self.process_chunk(from, tid, cdig, chunk.expect("decoded").entries)
                    }
                    types::COMPLETE => self.take_over(from, &rec, tid, complete.expect("decoded")),
                    types::ABORT => cack(cstatus::ABORTED, vec![], hs),
                    _ => None,
                }
            }
            State::Receiving if recv_from.is_some_and(|q| q < from) => {
                hit!("7.6/RECEIVING(lower)/{fname}");
                match ftype {
                    types::CHUNK => {
                        let entries = chunk.expect("decoded").entries;
                        if !self.discard_to(&idx, from) {
                            let outs = entries
                                .iter()
                                .map(|e| {
                                    (
                                        freenet_vault_common::hash::entry_digest(e),
                                        outcome::STORAGE_FAILURE,
                                    )
                                })
                                .collect();
                            return ack(chunk_status::PROCESSED, outs, hs);
                        }
                        self.process_chunk(from, tid, cdig, entries)
                    }
                    types::COMPLETE => {
                        self.discard_to(&idx, from);
                        let missing = complete
                            .expect("decoded")
                            .digests
                            .into_iter()
                            .take(limits::get().missing_max)
                            .collect();
                        cack(cstatus::MISSING, missing, hs)
                    }
                    types::ABORT => cack(cstatus::ABORTED, vec![], hs),
                    _ => None,
                }
            }
            State::Receiving => {
                hit!("7.6/RECEIVING(higher)/{fname}");
                match ftype {
                    types::CHUNK => ack(chunk_status::HIGHER_BUILD, vec![], hs),
                    types::COMPLETE => cack(cstatus::HIGHER_BUILD, vec![], hs),
                    types::ABORT => cack(cstatus::ABORTED, vec![], hs),
                    _ => None,
                }
            }
        }
    }

    /// Drops every entry (through `vault:gc`) and writes RECEIVING(from).
    fn discard_to(&mut self, idx: &Index, from: u32) -> bool {
        let names: Vec<Vec<u8>> = idx
            .entries
            .iter()
            .map(|e| names::entry(&self.part, e.kind, &e.key, e.parity))
            .collect();
        if !names.is_empty() && !self.gc_add(&names) {
            return false;
        }
        self.put_rx(&BTreeSet::new());
        let mut n = idx.clone();
        n.entries.clear();
        n.state = State::Receiving;
        n.ho.receiving_from = from;
        n.ho.store_failed = false;
        if !self.commit(&n) {
            return false;
        }
        self.process_gc();
        true
    }

    fn process_chunk(
        &mut self,
        from: u32,
        tid: Digest,
        cdig: Digest,
        entries: Vec<Vec<u8>>,
    ) -> Option<Vec<u8>> {
        let mut idx = self.idx();
        let s = self.succ();
        let mut rx = self.rx();
        let rx0 = rx.clone();
        let lim = limits::get();
        let mut outcomes: Vec<(Digest, u8)> = Vec::new();
        let mut plan: Vec<(usize, Entry, Vec<u8>)> = Vec::new();
        let mut new_count = 0usize;
        let mut new_bytes = 0usize;
        for raw in &entries {
            let d = freenet_vault_common::hash::entry_digest(raw);
            let e = Entry::decode(raw).expect("checked by the chunk decoder");
            if e.kind == KIND_CALLER_MARK && !mark_accepted(self.d, &e) {
                hit!("7.2/outcome-policy-dropped");
                rx.insert(d);
                outcomes.push((d, outcome::POLICY_DROPPED));
                continue;
            }
            let named = idx.find(e.kind, &e.key).map(|i| idx.entries[i].clone());
            if named.as_ref().is_some_and(|x| x.digest == d) {
                hit!("7.2/outcome-identical");
                outcomes.push((d, outcome::IDENTICAL));
                continue;
            }
            let old_len = named.as_ref().map(|x| x.len as usize).unwrap_or(0);
            let full_count = named.is_none() && idx.entries.len() + new_count >= lim.max_entries;
            let full_bytes = idx.total_bytes() + new_bytes - old_len + raw.len() > lim.max_bytes;
            if full_count || full_bytes {
                hit!("7.2/outcome-staging-full");
                outcomes.push((d, outcome::STAGING_FULL));
                continue;
            }
            if named.is_none() {
                new_count += 1;
            }
            new_bytes += raw.len();
            new_bytes -= old_len.min(new_bytes);
            plan.push((outcomes.len(), e, raw.clone()));
            outcomes.push((d, outcome::STORED));
        }
        let mut failed = false;
        let mut first_written: Option<(u8, Vec<u8>)> = None;
        for (i, e, raw) in &plan {
            let named = idx.find(e.kind, &e.key).map(|j| idx.entries[j].parity);
            let wrote = match Store::open(&mut *self.h, self.part) {
                Ok(mut st) => st.receive_entry(e.kind, &e.key, raw, named),
                Err(_) => Err(storage::StorageFailure),
            };
            match wrote {
                Ok(parity) => {
                    idx.upsert(storage::index::IndexEntry {
                        kind: e.kind,
                        key: e.key.clone(),
                        parity,
                        len: raw.len() as u16,
                        digest: freenet_vault_common::hash::entry_digest(raw),
                    });
                    first_written.get_or_insert((e.kind, e.key.clone()));
                    hit!("7.2/outcome-stored");
                    hit!("4.2/receiver/single-copy-written");
                }
                Err(_) => {
                    outcomes[*i].1 = outcome::STORAGE_FAILURE;
                    hit!("7.2/outcome-storage-failure");
                    failed = true;
                }
            }
        }
        if rx != rx0 && !self.put_rx(&rx) {
            for o in outcomes.iter_mut() {
                if o.1 == outcome::POLICY_DROPPED {
                    o.1 = outcome::STORAGE_FAILURE;
                }
            }
            failed = true;
        }
        let prev_failed = idx.state == State::Receiving && idx.ho.store_failed;
        idx.state = State::Receiving;
        idx.ho.receiving_from = from;
        idx.ho.store_failed = prev_failed || failed;
        if let Some((k, key)) = first_written {
            trace::note(Note::EntryStep(3, k, key));
        }
        if !self.commit(&idx) {
            let disk = self.idx();
            for o in outcomes.iter_mut() {
                if o.1 == outcome::STORED && !disk.entries.iter().any(|x| x.digest == o.0) {
                    o.1 = outcome::STORAGE_FAILURE;
                }
            }
        } else {
            self.process_gc();
        }
        hit!("sent/Ack/{}", chunk_status::PROCESSED);
        Ack {
            transfer_id: tid,
            chunk_digest: cdig,
            partition: self.part,
            status: chunk_status::PROCESSED,
            succ_record: highest(&s),
            outcomes,
            ext: vec![],
        }
        .encode()
        .ok()
    }

    /// 7.4 step 2: take over, or answer "missing".
    fn take_over(&mut self, from: u32, own_rec: &Rec, tid: Digest, c: Complete) -> Option<Vec<u8>> {
        let idx = self.idx();
        let hs = highest(&self.succ());
        let part = self.part;
        let m = c.manifest_digest;
        let cack = |status: u8, missing: Vec<Digest>| {
            let mut missing = missing;
            missing.sort_unstable();
            CompleteAck {
                transfer_id: tid,
                partition: part,
                manifest_digest: m,
                status,
                succ_record: hs,
                missing,
                ext: vec![],
            }
            .encode()
            .ok()
        };
        if idx.state == State::Receiving && idx.ho.store_failed {
            hit!("7.4/complete-storage-failure-flag");
            let mut n = idx.clone();
            n.ho.store_failed = false;
            n.ho.receiving_from = from;
            self.commit(&n);
            return cack(cstatus::STORAGE_FAILURE, vec![]);
        }
        let listed: BTreeSet<Digest> = c.digests.iter().copied().collect();
        let rx = self.rx();
        let drop: Vec<storage::index::IndexEntry> = idx
            .entries
            .iter()
            .filter(|e| !listed.contains(&e.digest))
            .cloned()
            .collect();
        let mut n = idx.clone();
        if !drop.is_empty() {
            hit!("7.4/unlisted-dropped");
            let names: Vec<Vec<u8>> = drop
                .iter()
                .map(|e| names::entry(&self.part, e.kind, &e.key, e.parity))
                .collect();
            if !self.gc_add(&names) {
                return cack(cstatus::STORAGE_FAILURE, vec![]);
            }
            for e in &drop {
                n.remove(e.kind, &e.key);
            }
        }
        let held: BTreeSet<Digest> = n
            .entries
            .iter()
            .map(|e| e.digest)
            .chain(rx.iter().copied())
            .collect();
        let missing: Vec<Digest> = listed.difference(&held).copied().collect();
        if missing.is_empty() || trace::mutant(Mutant::MissingAsAccepted) {
            if !missing.is_empty() {
                hit!("mutant/missing-as-accepted");
            }
            n.state = State::Writer;
            n.awaiting_retirement = true;
            n.ho.taken_over = Some((from, m));
            n.ho.own_record = Some(*own_rec);
            n.ho.paused = None;
            if self.commit(&n) {
                hit!("7.4/took-over");
                // The new writer mirrors what it took over (7.7).
                self.vol.swept = false;
                self.vol.sweep_cursor = None;
                trace::note(Note::TookOver { from, m });
                // "accepted" leaves only after the partition is listed and
                // the listing reads back (4.2, F16).
                if !self.parts_listed() {
                    if trace::mutant(Mutant::AnswerBeforeListing) {
                        hit!("mutant/accepted-before-listing");
                    } else {
                        hit!("4.2/take-over-not-listed-no-answer");
                        return None;
                    }
                }
                self.process_gc();
                cack(cstatus::ACCEPTED, vec![])
            } else {
                cack(cstatus::STORAGE_FAILURE, vec![])
            }
        } else {
            if !drop.is_empty() && self.commit(&n) {
                self.process_gc();
            }
            hit!("7.4/missing");
            cack(
                cstatus::MISSING,
                missing
                    .into_iter()
                    .take(limits::get().missing_max)
                    .collect(),
            )
        }
    }

    // -------------------------------------------------------- sender (7.3 to 7.5)

    fn ident_of(idx: &Index, d: &Digest) -> Option<Ident> {
        idx.entries
            .iter()
            .find(|e| &e.digest == d)
            .map(|e| (e.kind, e.key.clone()))
    }

    fn on_ack(&mut self, from_rec: &Rec, a: Ack) {
        let idx = self.idx();
        let target = match idx.state {
            State::Sealed => idx.peer_record,
            State::Writer => self.succ().successor(),
            _ => None,
        };
        let Some(t) = target else {
            hit!("7.3/ack-ignored-no-target");
            return;
        };
        if key_of(from_rec) != key_of(&t) || a.transfer_id != self.tid(self.own(), &t) {
            hit!("7.3/ack-ignored-transfer-mismatch");
            return;
        }
        let status_name = match a.status {
            chunk_status::PROCESSED => "Processed",
            chunk_status::MALFORMED => "Malformed",
            chunk_status::RECORD_NOT_MINE => "NotMine",
            chunk_status::STOPPED => "Stopped",
            chunk_status::HIGHER_BUILD => "HigherBuild",
            chunk_status::ANOTHER_WRITER => "AnotherWriter",
            chunk_status::STAGING_FULL => "StagingFull",
            _ => "other",
        };
        let _ = status_name;
        hit!("7.3/ack/{status_name}");
        let tv = version(&t);
        let mut prog = self.prog(tv);
        let prog0 = prog.clone();
        let mut seal_now = false;
        let mut n = idx.clone();
        match a.status {
            chunk_status::PROCESSED => {
                for (d, o) in &a.outcomes {
                    if let Some(id) = Self::ident_of(&idx, d) {
                        self.vol.in_flight.remove(&id);
                        if outcome::delivered(*o) {
                            prog.insert(id, *d);
                        }
                    }
                    if *o == outcome::STAGING_FULL {
                        seal_now = true;
                    }
                }
                let gone: Vec<Ident> = self
                    .vol
                    .in_flight
                    .iter()
                    .filter(|id| idx.find(id.0, &id.1).is_none())
                    .cloned()
                    .collect();
                for id in gone {
                    self.vol.in_flight.remove(&id);
                }
                if n.state == State::Writer
                    && n.ho.paused == Some(tv)
                    && n.problems & problems::COPYING_PAUSED != 0
                {
                    n.ho.paused = None;
                    n.problems &= !problems::COPYING_PAUSED;
                    hit!("7.5/pause-cleared-by-ack");
                }
            }
            chunk_status::STOPPED => {
                if let Some(r) = a.succ_record.filter(is_withdrawal) {
                    self.accept_record(&r);
                }
                n = self.idx();
            }
            chunk_status::HIGHER_BUILD | chunk_status::ANOTHER_WRITER => {
                if n.state == State::Writer {
                    n.ho.paused = Some(tv);
                }
                n.problems |= if a.status == chunk_status::HIGHER_BUILD {
                    problems::RECEIVER_HIGHER_BUILD
                } else {
                    problems::ANOTHER_WRITER
                };
            }
            chunk_status::STAGING_FULL => seal_now = true,
            _ => {}
        }
        if seal_now {
            n.problems |= problems::STAGING_FULL;
        }
        if n != idx {
            self.commit(&n);
        }
        if prog != prog0 {
            self.put_prog(tv, &prog);
        }
        if let Some(r) = a.succ_record.filter(|r| !is_withdrawal(r)) {
            self.accept_record(&r);
        }
        self.next_message(seal_now);
    }

    /// "Send at most one further message."
    fn next_message(&mut self, seal_now: bool) {
        let idx = self.idx();
        match idx.state {
            State::Writer => {
                let Some(t) = self.copy_target(&idx) else {
                    return;
                };
                if seal_now {
                    hit!("7.3/seal-now-staging-full");
                    return self.seal(&t);
                }
                if !self.pending(&t).is_empty() {
                    self.send_pending(&t, 1);
                } else if self.vol.in_flight.is_empty() {
                    self.seal(&t);
                }
            }
            State::Sealed => {
                let (Some(target), Some(m)) = (idx.peer_record, idx.ho.m) else {
                    return;
                };
                if self.abort_trigger(&target) {
                    return;
                }
                if !self.pending(&target).is_empty() {
                    self.send_pending(&target, 1);
                } else if self.vol.in_flight.is_empty() && !self.vol.complete_in_flight {
                    self.send_complete(&target, m);
                }
            }
            _ => {}
        }
    }

    fn on_cack(&mut self, from_rec: &Rec, a: CompleteAck) {
        let idx = self.idx();
        let (State::Sealed, Some(target), Some(sm)) = (idx.state, idx.peer_record, idx.ho.m) else {
            hit!("7.5/completeack-ignored-not-sealed");
            return;
        };
        if key_of(from_rec) != key_of(&target)
            || a.transfer_id != self.tid(self.own(), &target)
            || a.manifest_digest != sm
        {
            hit!("7.5/completeack-ignored-mismatch");
            return;
        }
        let name = match a.status {
            cstatus::ACCEPTED => "Accepted",
            cstatus::MISSING => "Missing",
            cstatus::ALREADY_WRITER => "AlreadyWriter",
            cstatus::STOPPED => "Stopped",
            cstatus::HIGHER_BUILD => "HigherBuild",
            cstatus::STORAGE_FAILURE => "StorageFailure",
            cstatus::ABORTED => "Aborted",
            cstatus::ANOTHER_WRITER => "AnotherWriter",
            cstatus::DIFFERENT_MANIFEST => "DifferentManifest",
            cstatus::MALFORMED => "Malformed",
            cstatus::NOTED => "Noted",
            cstatus::NO_STATE => "NoState",
            _ => "other",
        };
        let _ = name;
        hit!("7.5/completeack/{name}");
        if a.status == cstatus::STOPPED {
            if let Some(r) = a.succ_record.filter(is_withdrawal) {
                self.accept_record(&r);
            }
        }
        if let Some(r) = a.succ_record.filter(|r| !is_withdrawal(r)) {
            self.accept_record(&r);
        }
        let idx = self.idx();
        let m = sm;
        match a.status {
            cstatus::ACCEPTED | cstatus::ALREADY_WRITER if self.retire(&idx, &target, m) => {
                let r = Short {
                    record: target,
                    partition: self.part,
                    manifest_digest: m,
                    ext: vec![],
                };
                if let Ok(f) = r.encode(types::RETIRED) {
                    self.send(code_of(&target), f);
                }
            }
            cstatus::ACCEPTED | cstatus::ALREADY_WRITER => {}
            cstatus::MISSING => {
                self.vol.complete_in_flight = false;
                let tv = version(&target);
                let mut prog = self.prog(tv);
                for d in &a.missing {
                    if let Some(id) = Self::ident_of(&idx, d) {
                        prog.remove(&id);
                        self.vol.in_flight.remove(&id);
                    }
                }
                self.put_prog(tv, &prog);
                self.next_message(false);
            }
            cstatus::DIFFERENT_MANIFEST => {
                let mut n = idx.clone();
                n.problems |= problems::ANOTHER_WRITER;
                if n != idx {
                    self.commit(&n);
                }
            }
            s if cstatus::unseals(s) => {
                let mut n = idx.clone();
                n.state = State::Writer;
                trace::note(Note::UnsealIntent {
                    target: version(&target),
                    m,
                });
                if self.commit(&n) {
                    hit!("7.5/unsealed");
                    trace::note(Note::Unsealed {
                        target: version(&target),
                        m,
                        cause: s,
                    });
                    self.vol.in_flight.clear();
                    self.next_message(false);
                }
            }
            _ => {}
        }
    }

    /// Writes RETIRED(to target, m), unlists and reads that back, then
    /// deletes progress toward the target. `true` once Retired may be sent.
    fn retire(&mut self, idx: &Index, target: &Rec, m: Digest) -> bool {
        let mut n = idx.clone();
        n.state = State::Retired;
        n.peer_record = Some(*target);
        n.ho.m = Some(m);
        if !self.commit(&n) {
            return false;
        }
        hit!("7.4/retired");
        trace::note(Note::Retired {
            to: version(target),
            m,
        });
        if trace::mutant(Mutant::NeverUnlist) || trace::mutant(Mutant::RelistRetired) {
            if self.parts_listed() {
                hit!("mutant/retired-left-listed");
            }
        } else if trace::mutant(Mutant::RetiredBeforeUnlist) {
            hit!("mutant/retired-sent-before-unlist");
        } else if storage::unlist(self.h, &self.part).is_err() {
            return false;
        }
        let _ = self
            .h
            .remove_secret(&names::progress(version(target), &self.part));
        true
    }

    // -------------------------------------------------------- predecessor role

    /// 7.6 Query table. A zero `m` is a creation probe (5.3).
    fn on_query(&mut self, rec: Rec, m: Digest) -> Option<Vec<u8>> {
        let idx = self.idx();
        let probe = m == [0; 32];
        if probe {
            hit!("5.3/probe-received");
        }
        let tid = self.tid(self.own(), &rec);
        let part = self.part;
        let cack = |status: u8, succ: Option<Rec>| {
            CompleteAck {
                transfer_id: tid,
                partition: part,
                manifest_digest: m,
                status,
                succ_record: succ,
                missing: vec![],
                ext: vec![],
            }
            .encode()
            .ok()
        };
        let to_querier = idx.peer_record.as_ref() == Some(&rec);
        let same_m = idx.ho.m == Some(m);
        if trace::mutant(Mutant::QueryRetiredToOther)
            && idx.state == State::Retired
            && !probe
            && !(to_querier && same_m)
        {
            hit!("mutant/query-retired-to-other");
            return cack(cstatus::NOTED, highest(&self.succ()));
        }
        match idx.state {
            State::Retired if to_querier && same_m && !probe => {
                hit!("7.6q/RETIRED-to-querier-same-m");
                cack(cstatus::NOTED, highest(&self.succ()))
            }
            State::Sealed if to_querier && same_m && !probe => {
                hit!("7.6q/SEALED-toward-querier-same-m");
                if self.retire(&idx, &rec, m) {
                    cack(cstatus::NOTED, highest(&self.succ()))
                } else if self.idx().state == State::Retired {
                    hit!("4.2/retired-not-unlisted-no-answer");
                    None
                } else {
                    cack(cstatus::STORAGE_FAILURE, highest(&self.succ()))
                }
            }
            State::None if probe => self.none_probe(rec, tid),
            State::None => {
                hit!("7.6q/NONE/query");
                self.accept_record(&rec);
                let s = self.succ();
                if s.current.is_some_and(|c| version(&c) >= version(&rec)) {
                    hit!("7.6q/NONE-record-stored");
                    cack(cstatus::NO_STATE, highest(&s))
                } else {
                    hit!("7.6q/NONE-storage-failure");
                    cack(cstatus::STORAGE_FAILURE, highest(&s))
                }
            }
            st => {
                hit!("7.6q/anything-else");
                if st == State::Retired {
                    hit!("7.6q/anything-else/RETIRED-elsewhere-or-other-m");
                    if probe {
                        hit!("7.6q/RETIRED/probe-0x07");
                    }
                }
                if st == State::Sealed && probe {
                    hit!("7.6q/SEALED/probe-0x07");
                }
                if probe {
                    hit!("5.3/probe-answered-state");
                }
                cack(cstatus::ANOTHER_WRITER, highest(&self.succ()))
            }
        }
    }

    /// 7.6, creation-probe column, NONE: 0x0B only if it stores, or already
    /// holds as current, the querier's record; with a floor at or above the
    /// querier's version, 0x03 when the floor comes from a withdrawal, else
    /// 0x07.
    fn none_probe(&mut self, rec: Rec, tid: Digest) -> Option<Vec<u8>> {
        hit!("7.6q/NONE/probe");
        let part = self.part;
        let qack = |status: u8, succ: Option<Rec>| {
            CompleteAck {
                transfer_id: tid,
                partition: part,
                manifest_digest: [0; 32],
                status,
                succ_record: succ,
                missing: vec![],
                ext: vec![],
            }
            .encode()
            .ok()
        };
        if trace::mutant(Mutant::NoState0x0BWithoutStoring) {
            hit!("mutant/0x0B-without-storing");
            return qack(cstatus::NO_STATE, highest(&self.succ()));
        }
        let s = self.succ();
        if s.current == Some(rec) {
            hit!("7.6q/NONE/probe-already-current-0x0B");
            return qack(cstatus::NO_STATE, highest(&s));
        }
        let cur = s.current.as_ref().map(version).unwrap_or(0);
        let wd = s.withdrawal.as_ref().map(version).unwrap_or(0);
        let floor = self.own().max(cur).max(wd);
        if floor >= version(&rec) {
            if wd >= cur && wd >= version(&rec) {
                hit!("7.6q/NONE/probe-stopped-0x03");
                return qack(cstatus::STOPPED, highest(&s));
            }
            hit!("7.6q/NONE/probe-higher-record-0x07");
            return qack(cstatus::ANOTHER_WRITER, highest(&s));
        }
        self.accept_record(&rec);
        let s = self.succ();
        if s.current == Some(rec) {
            hit!("7.6q/NONE-record-stored");
            qack(cstatus::NO_STATE, highest(&s))
        } else {
            hit!("7.6q/NONE-storage-failure");
            qack(cstatus::STORAGE_FAILURE, highest(&s))
        }
    }

    /// Section 6 row, awaiting: the answer to this build's Query from the
    /// build it took over from, at the m it took over at.
    fn on_query_answer(&mut self, status: u8) {
        let idx = self.idx();
        if idx.state != State::Writer {
            return;
        }
        if trace::mutant(Mutant::IgnoreQueryAnswer) {
            hit!("mutant/query-answer-ignored");
            return;
        }
        let mut n = idx.clone();
        let clears = status == cstatus::NOTED
            || status == cstatus::NO_STATE
            || (trace::mutant(Mutant::ClearAwaitingWithoutAnswer) && {
                hit!("mutant/awaiting-cleared-without-answer");
                true
            });
        if clears {
            n.awaiting_retirement = false;
            if self.commit(&n) {
                hit!(
                    "6/query-answer/awaiting-cleared/{}",
                    if status == cstatus::NO_STATE {
                        "NoState"
                    } else {
                        "Noted"
                    }
                );
                trace::note(Note::AwaitingCleared);
            }
        } else if status == cstatus::ANOTHER_WRITER {
            hit!("6/query-answer/awaiting/AnotherWriter");
            n.problems |= problems::ANOTHER_WRITER;
            if n != idx {
                self.commit(&n);
            }
        } else {
            hit!("6/query-answer/awaiting/other/{status}");
        }
    }

    /// 5.3 step 3: the answer to a creation probe, applied in the call that
    /// delivers it.
    fn on_probe_answer(&mut self, p: u32, status: u8) {
        let idx = self.idx();
        if idx.state != State::None || idx.armed.is_none() {
            return;
        }
        let confirms = status == cstatus::NO_STATE
            || (trace::mutant(Mutant::CreateWithUnansweredProbe) && {
                hit!("mutant/probe-confirmed-without-0x0B");
                true
            });
        if confirms {
            if idx.ho.confirmed.contains(&p) {
                hit!("5.3/confirmed-again");
                return;
            }
            let mut n = idx.clone();
            n.ho.confirmed.push(p);
            n.ho.confirmed.sort_unstable();
            if self.commit(&n) {
                hit!("5.3/confirmed");
            }
        } else if status == cstatus::ANOTHER_WRITER {
            // The predecessor holds state: clear the arming.
            let mut n = idx.clone();
            n.armed = None;
            n.ho.confirmed.clear();
            if self.commit(&n) {
                hit!("5.3/arming-cleared-by-state-answer");
            }
        } else {
            hit!("5.3/probe-answer-other/{status}");
        }
    }
}

/// HandoverStatus (12.4). `idx` is `None` when the index is lost (state 7).
pub fn handover_status(
    d: &Domain,
    succ: Option<&Succ>,
    idx: Option<&Index>,
    step: u8,
    extra_problems: u8,
    own_page: bool,
) -> Status {
    let (rs, floor) = match succ {
        Some(s) => (s.record_state(), s.floor(d.own_version)),
        None => (record_state::STORED_MALFORMED, d.own_version),
    };
    let mut h = HandoverStatus {
        request_id: 0,
        own_version: d.own_version,
        floor_version: floor,
        record_state: rs,
        step_result: step,
        partition_state: 0,
        peer_record: [0; 100],
        receiving_from: 0,
        taken_over_from: 0,
        taken_over_manifest: [0; 32],
        manifest_digest: [0; 32],
        problems: extra_problems,
        lost_entries: 0,
    };
    match idx {
        Some(ix) => {
            h.partition_state = match ix.state {
                State::None if ix.armed.is_some() => partition_state::NONE_ARMED,
                State::None => partition_state::NONE,
                State::Writer if ix.awaiting_retirement => partition_state::WRITER_AWAITING,
                State::Writer => partition_state::WRITER,
                State::Sealed => partition_state::SEALED,
                State::Receiving => partition_state::RECEIVING,
                State::Retired => partition_state::RETIRED,
            };
            h.peer_record = match ix.state {
                State::Sealed | State::Retired => ix.peer_record.unwrap_or([0; 100]),
                _ => [0; 100],
            };
            if ix.state == State::Receiving {
                h.receiving_from = ix.ho.receiving_from;
            }
            if let Some((v, m)) = ix.ho.taken_over {
                h.taken_over_from = v;
                h.taken_over_manifest = m;
            }
            if let (State::Sealed | State::Retired, Some(m)) = (ix.state, ix.ho.m) {
                h.manifest_digest = m;
            }
            h.problems |= ix.problems;
            h.lost_entries = ix.lost_entries;
        }
        None => {
            h.problems |= problems::STORAGE_FAILURE | problems::INDEX_LOST;
            h.partition_state = partition_state::UNKNOWN_INDEX_LOST;
        }
    }
    if !own_page {
        h = h.redacted();
    }
    Status::Handover(h)
}

fn encode_status(s: Status) -> Vec<u8> {
    s.encode().unwrap_or_default()
}

// ------------------------------------------------------------ entry points

/// Runs `f` with the volatile state from the context, and writes the
/// context back.
fn with_cx<H: Host, T>(d: &Domain, h: &mut H, f: impl FnOnce(&mut Cx<H>) -> T) -> (T, Hops) {
    let before = Ctx::load(&*h);
    let mut ctx = before.clone();
    let vol = std::mem::take(&mut ctx.vol);
    let mut cx = Cx::new(d, h, vol);
    let r = f(&mut cx);
    let Cx { vol, out, h, .. } = cx;
    ctx.vol = vol;
    ctx.store(h, &before);
    (r, out)
}

/// A Poke (6, first row), from a page. `own_page`: from one of the domain's
/// own pages (flags are honoured only then; status fields after step_result
/// go only to them).
pub fn poke<H: Host>(d: &Domain, h: &mut H, own_page: bool, body: &[u8]) -> Out {
    let refusal = |reason| Out {
        reply: Some(encode_status(Status::Refused {
            request_id: 0,
            reason,
        })),
        hops: vec![],
    };
    let Ok(p) = Poke::decode(body) else {
        return refusal(refused::MALFORMED);
    };
    if p.partition != d.partition() {
        return refusal(refused::MALFORMED);
    }
    hit!("6/poke");
    // Index lost (4.5): no record storage, flags ignored, state 7.
    if Store::fault(&*h, &d.partition()).is_some() {
        hit!("4.5/index-lost-call");
        hit!("4.5/lost/poke-reports-state-7");
        let succ = Succ::load(d, &*h).ok();
        return Out {
            reply: Some(encode_status(handover_status(
                d,
                succ.as_ref(),
                None,
                step_result::NOTHING,
                0,
                own_page,
            ))),
            hops: vec![],
        };
    }
    // A malformed stored record (3): no record handling, no flags, no step;
    // report it and keep serving as whatever it was.
    if Succ::load(d, &*h).is_err() {
        hit!("3/record-malformed-call");
        let ix = Index::decode(
            &h.get_secret(&names::index(&d.partition()))
                .unwrap_or_default(),
        )
        .unwrap_or_else(|_| Index::none());
        return Out {
            reply: Some(encode_status(handover_status(
                d,
                None,
                Some(&ix),
                step_result::NOTHING,
                0,
                own_page,
            ))),
            hops: vec![],
        };
    }
    let ((rr, sent, saw_missing), hops) = with_cx(d, h, |cx| {
        let (rr, sent) = cx.poke(p.flags, p.record, own_page);
        (rr, sent, cx.saw_missing)
    });
    let step = if rr != step_result::NOTHING {
        rr
    } else if sent {
        step_result::MESSAGES_SENT
    } else {
        step_result::NOTHING
    };
    let mut extra = 0;
    if h.writes_refused() {
        extra |= problems::STORAGE_FAILURE;
    }
    let ix = Index::decode(
        &h.get_secret(&names::index(&d.partition()))
            .unwrap_or_default(),
    )
    .unwrap_or_else(|_| Index::none());
    let succ = Succ::load(d, &*h).ok();
    if saw_missing {
        extra |= problems::CORRUPT_OR_LOST;
    }
    Out {
        reply: Some(encode_status(handover_status(
            d,
            succ.as_ref(),
            Some(&ix),
            step,
            extra,
            own_page,
        ))),
        hops,
    }
}

/// A wake-up or NodeStarted (6): a step with the wake-up window if this
/// build has work (7.7).
pub fn wakeup<H: Host>(d: &Domain, h: &mut H) -> Hops {
    hit!("6/wakeup");
    if Store::fault(&*h, &d.partition()).is_some() || Succ::load(d, &*h).is_err() {
        return vec![];
    }
    with_cx(d, h, |cx| {
        if cx.has_work() {
            cx.step(limits::get().window_wakeup);
        }
    })
    .1
}

/// A vault-to-vault frame from the delegate `key` (6). `None`: no reply.
pub fn hop<H: Host>(d: &Domain, h: &mut H, key: &[u8; 32], payload: &[u8]) -> Out {
    // Index lost (4.5): no reply to any vault-to-vault frame.
    if Store::fault(&*h, &d.partition()).is_some() {
        hit!("4.5/index-lost-call");
        hit!("4.5/lost/hop-not-answered");
        if let Ok(f) = Frame::decode(payload) {
            if f.frame_type == types::QUERY {
                hit!("7.6q/index-lost");
                if Short::decode(f.body).is_ok_and(|q| q.manifest_digest == [0; 32]) {
                    hit!("5.3/probe-to-index-lost-build");
                }
            }
        }
        return Out {
            reply: None,
            hops: vec![],
        };
    }
    if Succ::load(d, &*h).is_err() {
        hit!("3/record-malformed-call");
        hit!("3/record-malformed-refuses-handover");
        return Out {
            reply: None,
            hops: vec![],
        };
    }
    let (reply, hops) = with_cx(d, h, |cx| cx.hop(key, payload));
    if let Some(r) = &reply {
        if let Ok(f) = Frame::decode(r) {
            if f.frame_type == types::COMPLETE_ACK {
                if let Ok(a) = CompleteAck::decode(f.body) {
                    let _ = a;
                    hit!("sent/CompleteAck/{}", cstatus_name(a.status));
                }
            }
        }
    }
    Out { reply, hops }
}

/// The model's name for a CompleteAck status (coverage counters).
pub fn cstatus_name(s: u8) -> &'static str {
    match s {
        cstatus::ACCEPTED => "Accepted",
        cstatus::MISSING => "Missing",
        cstatus::ALREADY_WRITER => "AlreadyWriter",
        cstatus::STOPPED => "Stopped",
        cstatus::HIGHER_BUILD => "HigherBuild",
        cstatus::STORAGE_FAILURE => "StorageFailure",
        cstatus::ABORTED => "Aborted",
        cstatus::ANOTHER_WRITER => "AnotherWriter",
        cstatus::DIFFERENT_MANIFEST => "DifferentManifest",
        cstatus::MALFORMED => "Malformed",
        cstatus::NOTED => "Noted",
        cstatus::NO_STATE => "NoState",
        _ => "other",
    }
}

/// A domain record offered by SubmitRecord (3): accepted exactly as on a
/// Poke, with no flags and no step. Nothing is stored while the index is
/// lost (4.5) or `vault:succ` is malformed (3).
pub fn submit_domain_record<H: Host>(d: &Domain, h: &mut H, rec: &Rec, own_page: bool) -> Status {
    if Store::fault(&*h, &d.partition()).is_some() {
        let succ = Succ::load(d, &*h).ok();
        return handover_status(d, succ.as_ref(), None, step_result::NOTHING, 0, own_page);
    }
    let read_ix = |h: &H| {
        Index::decode(
            &h.get_secret(&names::index(&d.partition()))
                .unwrap_or_default(),
        )
        .unwrap_or_else(|_| Index::none())
    };
    // A malformed stored record is never read as "no record" (3): nothing
    // replaces it, not even a record that verifies (the floor it held is
    // unknown, so any record could lower it). Refused(7), as before.
    if Succ::load(d, &*h).is_err() {
        hit!("3/record-malformed-call");
        return Status::Refused {
            request_id: 0,
            reason: refused::STORED_RECORD_MALFORMED,
        };
    }
    let ((step, _), _) = with_cx(d, h, |cx| cx.accept_record(rec));
    let extra = if h.writes_refused() {
        problems::STORAGE_FAILURE
    } else {
        0
    };
    let ix = read_ix(h);
    let succ = Succ::load(d, &*h).ok();
    handover_status(d, succ.as_ref(), Some(&ix), step, extra, own_page)
}

/// Whether every predecessor has confirmed under the current arming (5.3).
pub fn all_confirmed(d: &Domain, ix: &Index) -> bool {
    if trace::mutant(Mutant::CreateWithUnansweredProbe) {
        return true;
    }
    d.predecessors
        .iter()
        .all(|(v, _)| ix.ho.confirmed.contains(v))
}
