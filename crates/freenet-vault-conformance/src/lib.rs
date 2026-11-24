//! Conformance harness: the freenet-vault library's handover, driven by the
//! simulation model (protocol 15).
//!
//! The model's world (generator, scheduler, delivery modes, fault plan,
//! invariants I1 to I8 and AVAIL, directed scenarios, coverage gate and
//! mutation check) calls each vault build through
//! `freenet_vault_model::build::BuildImpl`. [`LibBuild`] implements it with
//! the REAL library: every call goes through `freenet_vault::process`, and
//! every secret the library reads or writes goes through the model's own
//! fault-injecting host (`freenet_vault_model::store::Host`), so crashes,
//! failed and landed-but-failed writes, read faults, undecryptable and
//! garbled secrets, restores and wipes reach the library exactly as the
//! model's own build sees them.
//!
//! The model stores abstract values; the library stores bytes. The bridge
//! translates both ways ([`codec`]): a secret the library writes is decoded
//! into the model's value (so the invariants check the library's real
//! state), and a value the library reads is encoded back. Every write is
//! checked to round-trip; the exact bytes are kept, so the library always
//! reads back what it wrote. Divergences the world cannot express (a status
//! that disagrees with the index it reports, a lossy decode) are collected
//! as findings and printed by the runner.

pub mod codec;

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::panic::{catch_unwind, resume_unwind, AssertUnwindSafe};
use std::rc::Rc;

use codec::{Tables, P};
use freenet_stdlib::prelude::{
    ApplicationMessage, ClientResponse, CodeHash, ContractInstanceId, DelegateContext, DelegateKey,
    DelegateMessage, InboundDelegateMsg, MessageOrigin, OutboundDelegateMsg, UserInputResponse,
};
use freenet_vault::trace::{self as ltrace, Ev};
use freenet_vault::Host as LibHost;
use freenet_vault_common::frame::{self, types, Frame as WFrame};
use freenet_vault_common::ops::{
    BatchItem, CallerProof, OpResult, Operation, Request, RequestHeader, SubmitRecord,
};
use freenet_vault_common::status::{
    partition_state as ps, record_state, step_result, Poke, Status as WStatus,
};
use freenet_vault_model::build::{
    self, BuildDef, BuildImpl, Input, Note, Op, OpRes, Output, Params, Reply, Status, Volatile,
};
use freenet_vault_model::cov::Cov;
use freenet_vault_model::store::{Crash, Event, FaultPlan, Host as MHost, Store, WErr};
use freenet_vault_model::types::*;

/// Unwinds out of the library when the model's host crashes the node.
struct CrashSignal;

thread_local! {
    static EVENTS: RefCell<Vec<Ev>> = const { RefCell::new(Vec::new()) };
    static ODD_MARKS_FROM: Cell<u32> = const { Cell::new(u32::MAX) };
    static TABLES: Rc<RefCell<Tables>> = Rc::new(RefCell::new(Tables::default()));
}

/// The bridge's tables and findings on this thread (shared by every world).
pub fn tables() -> Rc<RefCell<Tables>> {
    TABLES.with(|t| t.clone())
}

/// Installs the library as the model's build implementation on this thread,
/// with its trace sink, the model's mark policy and a panic hook that keeps
/// simulated crashes quiet.
pub fn install() {
    ltrace::set_sink(Some(Box::new(|e| EVENTS.with(|b| b.borrow_mut().push(e)))));
    freenet_vault::testing::set_mark_policy(Some(mark_policy));
    build::set_build_impl(Some(Rc::new(|| Box::new(LibBuild) as Box<dyn BuildImpl>)));
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if info.payload().is::<CrashSignal>() {
            return;
        }
        prev(info)
    }));
}

/// The model's policy (`Params::reject_odd_marks_from`): builds at or above
/// it drop marks whose caller record version is odd.
fn mark_policy(own: u32, e: &freenet_vault_common::entry::Entry) -> bool {
    if e.kind != KIND_MARK {
        return true;
    }
    let Some(v) = codec::mark_version(e) else {
        return false;
    };
    !(own >= ODD_MARKS_FROM.with(|c| c.get()) && v % 2 == 1)
}

fn lib_mutant(m: build::Mutant) -> Option<ltrace::Mutant> {
    use build::Mutant as M;
    use ltrace::Mutant as L;
    Some(match m {
        M::RetiredBeforeUnlist => L::RetiredBeforeUnlist,
        M::NeverUnlist => L::NeverUnlist,
        M::RelistRetired => L::RelistRetired,
        M::PartsBeforeIndex => L::PartsBeforeIndex,
        M::CreateWhileStopped => L::CreateWhileStopped,
        M::NoState0x0BWithoutStoring => L::NoState0x0BWithoutStoring,
        M::MirrorBeforeCommit => L::MirrorBeforeCommit,
        M::NoStep1 => L::NoStep1,
        M::DeleteCommitBeforeMirrorAbsent => L::DeleteCommitBeforeMirrorAbsent,
        M::SweepUncheckedDigest => L::SweepUncheckedDigest,
        M::DirectReadSingleCopy => L::DirectReadSingleCopy,
        M::DirectReadChooses => L::DirectReadChooses,
        M::DirectReadIgnoresEflagsOrKey => L::DirectReadIgnoresEflagsOrKey,
        M::DirectReadAbsent => L::DirectReadAbsent,
        M::ListNoneOrReceiving => L::ListNoneOrReceiving,
        M::AnswerBeforeListing => L::AnswerBeforeListing,
        M::MalformedListedIsNone => L::MalformedListedIsNone,
        M::MalformedUnlistedIsLost => L::MalformedUnlistedIsLost,
        M::WriteWithoutRemove => L::WriteWithoutRemove,
        M::DirectReadDespiteSuccessor => L::DirectReadDespiteSuccessor,
        _ => return None,
    })
}

/// A library-only mutant to run instead of the model's (the 15.5 base
/// mutants the model does not carry), for the conformance mutation check.
pub fn set_extra_mutant(m: Option<ltrace::Mutant>) {
    EXTRA_MUTANT.with(|c| c.set(m));
}

thread_local! {
    static EXTRA_MUTANT: Cell<Option<ltrace::Mutant>> = const { Cell::new(None) };
}

/// The library as one vault build.
pub struct LibBuild;

/// The library's host for one call: the model's host, through the codec.
struct BHost<'a, 'b> {
    h: &'a mut MHost<'b>,
    t: &'a RefCell<Tables>,
    own: Ver,
    ctx: Vec<u8>,
    seed: Option<[u8; 32]>,
    rng: u64,
    removed_undecryptable: Option<SName>,
}

impl LibHost for BHost<'_, '_> {
    fn get_secret(&self, key: &[u8]) -> Option<Vec<u8>> {
        let n = self.t.borrow_mut().name_of(key)?;
        let v = self.h.read(&n)?;
        Some(self.t.borrow_mut().encode(self.own, n, &v))
    }

    fn set_secret(&mut self, key: &[u8], value: &[u8]) -> bool {
        let n = self.t.borrow_mut().name_of(key).unwrap_or_else(|| {
            panic!(
                "library wrote an unmapped secret {:?}: {:?}",
                String::from_utf8_lossy(key),
                freenet_vault_common::entry::Entry::decode(value)
            )
        });
        let v = self.t.borrow_mut().decode(self.own, n, value);
        if self.removed_undecryptable.take() == Some(n) {
            EVENTS.with(|b| {
                b.borrow_mut().push(Ev::Hit(format!(
                    "4.2/remove-before-write/{}",
                    build::sname_kind(&n)
                )))
            });
        }
        let fired = self.h.faults.fired.len();
        let r = self.h.set(n, v);
        if self.h.faults.fired.len() > fired {
            EVENTS.with(|b| b.borrow_mut().push(Ev::Hit(FAULTED.into())));
        }
        match r {
            Ok(()) => true,
            Err(WErr::Fail) => false,
            Err(WErr::Crash) => std::panic::panic_any(CrashSignal),
        }
    }

    fn remove_secret(&mut self, key: &[u8]) -> bool {
        let Some(n) = self.t.borrow_mut().name_of(key) else {
            return false;
        };
        let present = self.h.store.secrets.contains_key(&n);
        if matches!(self.h.store.secrets.get(&n), Some(SVal::Undecryptable)) {
            self.removed_undecryptable = Some(n);
        }
        let fired = self.h.faults.fired.len();
        let r = self.h.del(n);
        if self.h.faults.fired.len() > fired {
            EVENTS.with(|b| b.borrow_mut().push(Ev::Hit(FAULTED.into())));
        }
        match r {
            Ok(()) => present,
            Err(WErr::Fail) => false,
            Err(WErr::Crash) => std::panic::panic_any(CrashSignal),
        }
    }

    fn read_context(&self) -> Vec<u8> {
        self.ctx.clone()
    }

    fn write_context(&mut self, data: &[u8]) -> bool {
        self.ctx = data.to_vec();
        true
    }

    fn random_bytes(&mut self, out: &mut [u8]) {
        if out.len() == 32 {
            if let Some(s) = self.seed.take() {
                out.copy_from_slice(&s);
                return;
            }
        }
        for b in out.iter_mut() {
            self.rng = self
                .rng
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            *b = (self.rng >> 33) as u8 | 1;
        }
    }
}

/// The marker a faulted write leaves in the event stream (the model's
/// `Note::Faulted`).
const FAULTED: &str = "\u{0}faulted";

impl BuildImpl for LibBuild {
    fn call(
        &mut self,
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
        freenet_vault::limits::set_for_tests(Some(freenet_vault::limits::Limits {
            max_entries: p.max_entries,
            max_bytes: freenet_vault::limits::V1.max_bytes,
            chunk_max: p.chunk_max,
            window_poke: p.window_poke,
            window_wakeup: p.window_wakeup,
            missing_max: p.missing_max,
            // the model sweeps the whole partition in one step
            sweep_per_message: 1 << 20,
        }));
        ODD_MARKS_FROM.with(|c| c.set(p.reject_odd_marks_from));
        let m = EXTRA_MUTANT
            .with(|c| c.get())
            .or_else(|| p.mutant.and_then(lib_mutant));
        ltrace::set_mutant(m);
        EVENTS.with(|b| b.borrow_mut().clear());
        let t = tables();
        let d = codec::domain(def, p);
        let mut host = MHost::new(def.v, store, faults, events);
        host.list_cap = p.list_cap;
        let mut bh = BHost {
            h: &mut host,
            t: &t,
            own: def.v,
            ctx: vol.ext.clone(),
            seed: None,
            removed_undecryptable: None,
            rng: 0x5eed ^ def.v as u64,
        };
        let r = catch_unwind(AssertUnwindSafe(|| drive(&d, def, &mut bh, input)));
        let ctx = std::mem::take(&mut bh.ctx);
        drop(bh);
        host.finish();
        // events, in order: coverage hits, transition notes, faulted writes
        let evs = EVENTS.with(|b| std::mem::take(&mut *b.borrow_mut()));
        for e in evs {
            match e {
                Ev::Hit(h) if h == FAULTED => notes.push(Note::Faulted),
                Ev::Hit(h) => cov.hit(&h),
                Ev::Note(n) => {
                    if let Some(n) = t.borrow_mut().note(n) {
                        notes.push(n);
                    }
                }
            }
        }
        for n in std::mem::take(&mut host.refused_undecryptable) {
            cov.hit(&format!(
                "6323/set-refused-over-undecryptable/{}",
                build::sname_kind(&n)
            ));
        }
        let out = match r {
            Ok(o) => o,
            Err(payload) if payload.is::<CrashSignal>() => return Err(Crash),
            Err(payload) => resume_unwind(payload),
        };
        // the volatile state: the library's context
        let c = freenet_vault::ctx::Ctx::decode(&ctx).unwrap_or_default();
        vol.swept = c.vol.swept;
        vol.complete_in_flight = c.vol.complete_in_flight;
        vol.in_flight = c
            .vol
            .in_flight
            .iter()
            .filter_map(|(k, key)| codec::key_of(*k, key).map(|x| (*k, x)))
            .collect();
        vol.ext = ctx;
        let poisoned = host.poisoned.get();
        if poisoned {
            cov.hit("4.0/call-poisoned");
            if host.refused_poisoned > 0 {
                cov.hit("4.0/write-refused-after-failed-read");
            }
        }
        let (reply, hops) = finish(&t, def, host.store, out, poisoned);
        if let Reply::Frame(Frame::Ack { status, .. }) = &reply {
            cov.hit(&format!("sent/Ack/{status:?}"));
        }
        Ok(Output {
            reply,
            hops,
            writes: host.writes,
            poisoned,
        })
    }
}

/// What one call produced, before it is mapped back.
enum Raw {
    Op(Op, Option<Vec<u8>>),
    Hop(Vec<OutboundDelegateMsg>),
    Wakeup(Vec<OutboundDelegateMsg>),
    Poke(Vec<OutboundDelegateMsg>),
}

fn page_origin() -> MessageOrigin {
    MessageOrigin::WebApp(ContractInstanceId::new(codec::page_id()))
}

fn dkey(v: Ver) -> DelegateKey {
    DelegateKey::new(codec::dkey(v), CodeHash::new(codec::code(v)))
}

fn run<H: LibHost>(
    d: &freenet_vault::Domain,
    h: &mut H,
    origin: Option<MessageOrigin>,
    msg: InboundDelegateMsg,
) -> Vec<OutboundDelegateMsg> {
    freenet_vault::process(d, h, &[], origin.as_ref(), msg).unwrap_or_default()
}

fn from_page<H: LibHost>(
    d: &freenet_vault::Domain,
    h: &mut H,
    payload: Vec<u8>,
) -> Vec<OutboundDelegateMsg> {
    run(
        d,
        h,
        Some(page_origin()),
        InboundDelegateMsg::ApplicationMessage(ApplicationMessage::new(payload)),
    )
}

fn header(rid: u64) -> RequestHeader {
    RequestHeader {
        request_id: rid,
        proof: None,
    }
}

fn req(op: Operation) -> Vec<u8> {
    Request {
        header: header(1),
        op,
        ext: vec![],
    }
    .encode()
    .expect("request encodes")
}

fn app_reply(out: &[OutboundDelegateMsg]) -> Option<Vec<u8>> {
    out.iter().find_map(|m| match m {
        OutboundDelegateMsg::ApplicationMessage(a) => Some(a.payload.clone()),
        _ => None,
    })
}

fn drive(d: &freenet_vault::Domain, def: &BuildDef, h: &mut BHost, input: Input) -> Raw {
    match input {
        Input::Poke { flags, rec } => {
            let payload = Poke {
                flags,
                partition: P(),
                record: rec.map(codec::rec_bytes),
                ext: vec![],
            }
            .encode()
            .expect("poke encodes");
            Raw::Poke(from_page(d, h, payload))
        }
        Input::Wakeup => Raw::Wakeup(run(
            d,
            h,
            None,
            InboundDelegateMsg::WakeupFired {
                tag: freenet_vault::WAKEUP_TAG.to_vec(),
            },
        )),
        Input::Hop { from, frame } => {
            let payload = h.t.borrow_mut().frame_to_wire(from, def.v, &frame);
            let msg = DelegateMessage::new(dkey(def.v), dkey(from), payload);
            Raw::Hop(run(
                d,
                h,
                Some(MessageOrigin::Delegate(dkey(from))),
                InboundDelegateMsg::DelegateMessage(msg),
            ))
        }
        Input::Op(op) => {
            let slot = |s: u16| codec::slot32(s).to_vec();
            let payload = match &op {
                Op::Generate { slot: s, seed } => {
                    h.seed = Some(h.t.borrow_mut().seed32(*seed));
                    req(Operation::Generate {
                        slot: Some(slot(*s)),
                    })
                }
                Op::Import {
                    slot: s,
                    seed,
                    replace,
                } => req(Operation::Import {
                    slot: slot(*s),
                    seed: h.t.borrow_mut().seed32(*seed),
                    replace: *replace,
                }),
                Op::Delete { slot: s } => req(Operation::Delete { slot: slot(*s) }),
                Op::PublicKey { slot: s } => req(Operation::PublicKey { slot: slot(*s) }),
                Op::Batch { slot: s, expected } => {
                    let seed = h.t.borrow_mut().seed32(*expected);
                    req(Operation::Batch {
                        slot: slot(*s),
                        expected_public_key: freenet_vault::crypto::public_key(&seed),
                        items: vec![BatchItem::Sign(b"conformance".to_vec())],
                    })
                }
                Op::Export { slot: s } => req(Operation::Export { slot: slot(*s) }),
                Op::PutExt { key, content } => {
                    let e = Entry {
                        kind: KIND_UNKNOWN,
                        key: *key,
                        flagged: false,
                        content: *content,
                        ext: vec![0xE0, *key as u8, *content as u8],
                    };
                    let body = h.t.borrow_mut().entry_bytes(&e);
                    // a build whose code does not write the unknown kind has
                    // no such request: the frame is unknown to it
                    let ft = if def.writes_unknown_kind {
                        freenet_vault::testing::PUT_UNKNOWN
                    } else {
                        0xFD
                    };
                    frame::encode(ft, &body).expect("frame encodes")
                }
                Op::RaiseMark { caller, rec } => {
                    // The caller's own build (record version `rec`) submits
                    // its record: the caller proof raises the mark (9), as
                    // any request from a newer caller build does.
                    let record = codec::caller_record(*caller, *rec);
                    let payload = SubmitRecord {
                        header: RequestHeader {
                            request_id: 1,
                            proof: Some(CallerProof {
                                author_vk: codec::caller_vk(*caller),
                                app_id: codec::caller_app(*caller).to_vec(),
                                record,
                            }),
                        },
                        author_vk: codec::caller_vk(*caller),
                        app_id: codec::caller_app(*caller).to_vec(),
                        record,
                        ext: vec![],
                    }
                    .encode()
                    .expect("submit encodes");
                    let code =
                        freenet_vault_common::record::PointerRecord::decode(&record).code_hash;
                    let key = DelegateKey::new(
                        freenet_vault_common::hash::delegate_key_empty_params(&code),
                        CodeHash::new(code),
                    );
                    let out = run(
                        d,
                        h,
                        Some(MessageOrigin::Delegate(key.clone())),
                        InboundDelegateMsg::DelegateMessage(DelegateMessage::new(
                            dkey(def.v),
                            key,
                            payload,
                        )),
                    );
                    let reply = out.iter().find_map(|m| match m {
                        OutboundDelegateMsg::SendDelegateMessage(dm) => Some(dm.payload.clone()),
                        _ => None,
                    });
                    return Raw::Op(op, reply);
                }
            };
            let out = from_page(d, h, payload);
            if matches!(op, Op::Export { .. }) {
                if let Some(OutboundDelegateMsg::RequestUserInput(r)) = out.first() {
                    let ans = run(
                        d,
                        h,
                        Some(page_origin()),
                        InboundDelegateMsg::UserResponse(UserInputResponse {
                            request_id: r.request_id,
                            response: ClientResponse::new(freenet_vault::consent::ALLOW.to_vec()),
                            context: DelegateContext::default(),
                        }),
                    );
                    return Raw::Op(op, app_reply(&ans));
                }
            }
            Raw::Op(op, app_reply(&out))
        }
    }
}

/// Maps a call's raw output back to the model's reply and hops.
fn finish(
    t: &RefCell<Tables>,
    def: &BuildDef,
    store: &Store,
    raw: Raw,
    poisoned: bool,
) -> (Reply, Vec<(Ver, Frame)>) {
    let mut tb = t.borrow_mut();
    let hops_of = |tb: &mut Tables, msgs: &[OutboundDelegateMsg], skip_reply: bool| {
        let mut hops = vec![];
        let mut reply = None;
        for m in msgs {
            if let OutboundDelegateMsg::SendDelegateMessage(dm) = m {
                let to = tb.ver_of_key(dm.target.bytes());
                let Some(f) = tb.wire_to_frame(def.v, &dm.payload) else {
                    tb.finding(format!("build {} sent an undecodable hop", def.v));
                    continue;
                };
                let is_reply = matches!(f, Frame::Ack { .. } | Frame::CompleteAck { .. });
                if skip_reply && is_reply && reply.is_none() {
                    reply = Some(f);
                    continue;
                }
                match to {
                    Some(v) => hops.push((v, f)),
                    None => tb.finding(format!("build {} sent a hop to an unknown key", def.v)),
                }
            }
        }
        (reply, hops)
    };
    match raw {
        Raw::Wakeup(out) => {
            let (_, hops) = hops_of(&mut tb, &out, false);
            (Reply::None, hops)
        }
        Raw::Hop(out) => {
            let (reply, hops) = hops_of(&mut tb, &out, true);
            (reply.map(Reply::Frame).unwrap_or(Reply::None), hops)
        }
        Raw::Poke(out) => {
            let (_, hops) = hops_of(&mut tb, &out, false);
            let reply = match app_reply(&out) {
                None => Reply::None,
                Some(bytes) => match decode_status(&bytes) {
                    Some(WStatus::Handover(h)) => {
                        Reply::Status(tb.status(def.v, store, &h, !hops.is_empty(), poisoned))
                    }
                    other => {
                        tb.finding(format!("build {} answered a Poke with {other:?}", def.v));
                        Reply::None
                    }
                },
            };
            (reply, hops)
        }
        Raw::Op(op, bytes) => {
            let Some(bytes) = bytes else {
                return (Reply::None, vec![]);
            };
            (Reply::Op(tb.op_result(def.v, &op, &bytes)), vec![])
        }
    }
}

fn decode_status(bytes: &[u8]) -> Option<WStatus> {
    let f = WFrame::decode(bytes).ok()?;
    WStatus::decode(f.frame_type, f.body).ok()
}

impl Tables {
    /// The model's status for a Poke reply: the library's HandoverStatus,
    /// with the state and the stored records read from the store the
    /// status describes (the model's status carries them in full; the wire
    /// status carries a summary, which is checked against them).
    fn status(
        &mut self,
        own: Ver,
        store: &Store,
        h: &freenet_vault_common::status::HandoverStatus,
        sent: bool,
        poisoned: bool,
    ) -> Status {
        let index_lost = h.partition_state == ps::UNKNOWN_INDEX_LOST;
        let state = if index_lost {
            PState::none()
        } else {
            store
                .idx()
                .map(|i| i.state.clone())
                .unwrap_or_else(PState::none)
        };
        // a poisoned call (4.0) is discarded: its reads may have missed
        if !index_lost && !poisoned {
            let want = match &state {
                PState::None { armed: Some(_), .. } => ps::NONE_ARMED,
                PState::None { .. } => ps::NONE,
                PState::Writer(w) if w.awaiting => ps::WRITER_AWAITING,
                PState::Writer(_) => ps::WRITER,
                PState::Sealed { .. } => ps::SEALED,
                PState::Receiving { .. } => ps::RECEIVING,
                PState::Retired { .. } => ps::RETIRED,
            };
            if want != h.partition_state {
                self.finding(format!(
                    "build {own}: HandoverStatus partition_state {} but the index is {}",
                    h.partition_state,
                    state.code()
                ));
            }
        }
        let (record_result, sent) = match h.step_result {
            step_result::MESSAGES_SENT => (0, true),
            s => (s, sent),
        };
        Status {
            state,
            index_lost,
            record_malformed: h.record_state == record_state::STORED_MALFORMED,
            problems: h.problems,
            succ: store.succ(),
            record_result,
            sent,
        }
    }

    fn op_result(&mut self, own: Ver, op: &Op, bytes: &[u8]) -> OpRes {
        let Ok(f) = WFrame::decode(bytes) else {
            self.finding(format!("build {own}: undecodable reply to {op:?}"));
            return OpRes::Refused(0);
        };
        if f.frame_type >= types::KEY_RESULT {
            let Ok((_, r)) = OpResult::decode(f.frame_type, f.body) else {
                self.finding(format!("build {own}: undecodable result to {op:?}"));
                return OpRes::Refused(0);
            };
            return match (r, op) {
                (OpResult::Key { public_key, .. }, _) => match self.seed_of_pk(&public_key) {
                    Some(s) => OpRes::Key(s),
                    None => {
                        self.finding(format!("build {own}: a key no model seed has, for {op:?}"));
                        OpRes::Key(u32::MAX)
                    }
                },
                (OpResult::Export { seed }, _) => match codec::seed_u32(&seed) {
                    Some(s) => OpRes::Key(s),
                    None => {
                        self.finding(format!(
                            "build {own}: Export served a seed no model value has"
                        ));
                        OpRes::Key(u32::MAX)
                    }
                },
                (OpResult::Batch(_), Op::Batch { expected, .. }) => OpRes::Key(*expected),
                (OpResult::Ok, _) => OpRes::Ok,
                (other, _) => {
                    self.finding(format!(
                        "build {own}: unexpected result {other:?} to {op:?}"
                    ));
                    OpRes::Refused(0)
                }
            };
        }
        match WStatus::decode(f.frame_type, f.body) {
            Ok(WStatus::Moved { record, .. }) => OpRes::Moved(codec::rec_of(&record)),
            Ok(WStatus::NotHere { .. }) => OpRes::NotHere,
            Ok(WStatus::Busy { .. }) => OpRes::Busy,
            Ok(WStatus::Absent { .. }) => OpRes::Absent,
            Ok(WStatus::Unusable { .. }) => OpRes::Unusable,
            // a caller build below its stored mark: the model's RaiseMark
            // answers Ok when the mark is already at or above it
            Ok(WStatus::Refused { reason, .. })
                if matches!(op, Op::RaiseMark { .. })
                    && reason == freenet_vault_common::status::refused::CALLER_NOT_AUTHORIZED =>
            {
                OpRes::Ok
            }
            Ok(WStatus::Refused { reason, .. }) => OpRes::Refused(reason),
            // a caller record (RaiseMark): raised, or already at or above
            Ok(WStatus::Handover(h)) => match h.step_result {
                step_result::RECORD_ACCEPTED | step_result::NOT_NEWER | step_result::NOTHING => {
                    OpRes::Ok
                }
                s => OpRes::Refused(100 + s),
            },
            Err(_) => {
                self.finding(format!("build {own}: undecodable status to {op:?}"));
                OpRes::Refused(0)
            }
        }
    }
}

/// Counts and first examples of the divergences the bridge saw.
pub fn report() -> String {
    let t = tables();
    let t = t.borrow();
    let mut s = String::new();
    let mut by: BTreeMap<String, (u64, String)> = BTreeMap::new();
    for f in &t.findings {
        let shape: String = f.chars().filter(|c| !c.is_ascii_digit()).collect();
        let e = by.entry(shape).or_insert((0, f.clone()));
        e.0 += 1;
    }
    for (_, (n, first)) in by {
        s.push_str(&format!("  {n:>7} x {first}\n"));
    }
    for (k, n) in &t.lossy {
        s.push_str(&format!("  lossy decode {k}: {n}\n"));
    }
    s
}
