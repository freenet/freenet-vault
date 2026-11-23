//! Operations, caller checks, routing and consent, driven through
//! [`crate::process`] with an in-memory host (spec 5, 6, 15; protocol 5.1,
//! 6, 9, 12.5).

use crate::domain::{CallerDelegate, Domain, PageContainer};
use crate::storage::index::State;
use crate::storage::{names, Store};
use crate::testing::{MemHost, WriteFault};
use crate::{crypto, process};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use freenet_stdlib::prelude::*;
use freenet_vault_common::entry::{Entry, KIND_KEY};
use freenet_vault_common::frame::{self, types, Frame};
use freenet_vault_common::hash;
use freenet_vault_common::ops::*;
use freenet_vault_common::record::signing_message;
use freenet_vault_common::status::*;

// ---- a test domain -------------------------------------------------------

const DOMAIN_SEED: [u8; 32] = [0xD0; 32];
const PUBLISHER_SEED: [u8; 32] = [0xB0; 32];
const CONTAINER: [u8; 32] = [0xC0; 32];
const CHAT_APP: &[u8] = b"test.chat-delegate";

fn vk(seed: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

static PAGES: std::sync::OnceLock<[PageContainer; 1]> = std::sync::OnceLock::new();
static CALLERS: std::sync::OnceLock<[CallerDelegate; 1]> = std::sync::OnceLock::new();
static PUBLISHERS: std::sync::OnceLock<[[u8; 32]; 1]> = std::sync::OnceLock::new();

fn domain() -> Domain {
    let publisher = vk(&PUBLISHER_SEED);
    Domain {
        author_vk: vk(&DOMAIN_SEED),
        app_id: b"test.vault",
        own_version: 1,
        predecessors: &[],
        page_containers: PAGES.get_or_init(|| {
            [PageContainer {
                code_hash: CONTAINER,
                publisher_vk: publisher,
            }]
        }),
        extra_page_ids: &[],
        caller_delegates: CALLERS.get_or_init(|| {
            [CallerDelegate {
                author_vk: publisher,
                app_id: CHAT_APP,
                min_version: 1,
            }]
        }),
        delegate_frames: &[types::BATCH, types::PUBLIC_KEY, types::SUBMIT_RECORD],
        publisher_keys: PUBLISHERS.get_or_init(|| [publisher]),
        slot_len: Some(32),
        max_key_slots: 4,
        max_caller_marks: 2,
        export_prompt: |_| "export?".into(),
    }
}

fn page_id() -> [u8; 32] {
    hash::contract_instance_id(&CONTAINER, &vk(&PUBLISHER_SEED))
}

fn record(seed: &[u8; 32], app_id: &[u8], version: u32, code_hash: [u8; 32]) -> [u8; 100] {
    let sk = SigningKey::from_bytes(seed);
    let msg = signing_message(&sk.verifying_key().to_bytes(), app_id, version, &code_hash);
    let mut out = [0u8; 100];
    out[..4].copy_from_slice(&version.to_be_bytes());
    out[4..36].copy_from_slice(&code_hash);
    out[36..].copy_from_slice(&sk.sign(&msg).to_bytes());
    out
}

fn domain_record(version: u32, code_hash: [u8; 32]) -> [u8; 100] {
    record(&DOMAIN_SEED, b"test.vault", version, code_hash)
}

/// A chat-delegate build: its code hash, record and stamped key.
struct ChatBuild {
    key: [u8; 32],
    header: RequestHeader,
}

fn chat(version: u32) -> ChatBuild {
    let code_hash = [version as u8; 32];
    ChatBuild {
        key: hash::delegate_key_empty_params(&code_hash),
        header: RequestHeader {
            request_id: 77,
            proof: Some(CallerProof {
                author_vk: vk(&PUBLISHER_SEED),
                app_id: CHAT_APP.to_vec(),
                record: record(&PUBLISHER_SEED, CHAT_APP, version, code_hash),
            }),
        },
    }
}

fn page_header(request_id: u64) -> RequestHeader {
    RequestHeader {
        request_id,
        proof: None,
    }
}

// ---- driving process() ---------------------------------------------------

#[derive(Debug, PartialEq)]
enum Reply {
    Op(u64, OpResult),
    St(Status),
}

fn decode_reply(bytes: &[u8]) -> Reply {
    let f = Frame::decode(bytes).expect("reply is a vault frame");
    if f.frame_type >= types::KEY_RESULT {
        let (rid, r) = OpResult::decode(f.frame_type, f.body).unwrap();
        Reply::Op(rid, r)
    } else {
        Reply::St(Status::decode(f.frame_type, f.body).unwrap())
    }
}

fn run(
    h: &mut MemHost,
    origin: Option<MessageOrigin>,
    msg: InboundDelegateMsg<'static>,
) -> Vec<OutboundDelegateMsg> {
    process(&domain(), h, &[], origin.as_ref(), msg).expect("process")
}

fn from_page_as(h: &mut MemHost, id: [u8; 32], payload: Vec<u8>) -> Vec<OutboundDelegateMsg> {
    run(
        h,
        Some(MessageOrigin::WebApp(ContractInstanceId::new(id))),
        InboundDelegateMsg::ApplicationMessage(ApplicationMessage::new(payload)),
    )
}

/// Sends from the domain's page and returns the single reply.
fn page(h: &mut MemHost, payload: Vec<u8>) -> Reply {
    single_app_reply(from_page_as(h, page_id(), payload))
}

fn single_app_reply(out: Vec<OutboundDelegateMsg>) -> Reply {
    assert_eq!(out.len(), 1, "{out:?}");
    match &out[0] {
        OutboundDelegateMsg::ApplicationMessage(m) => {
            assert!(m.processed);
            decode_reply(&m.payload)
        }
        other => panic!("expected an application message, got {other:?}"),
    }
}

fn delegate_key(key: [u8; 32]) -> DelegateKey {
    DelegateKey::new(key, CodeHash::new([0; 32]))
}

fn from_delegate_raw(
    h: &mut MemHost,
    key: [u8; 32],
    sender: [u8; 32],
    payload: Vec<u8>,
) -> Vec<OutboundDelegateMsg> {
    run(
        h,
        Some(MessageOrigin::Delegate(delegate_key(key))),
        InboundDelegateMsg::DelegateMessage(DelegateMessage::new(
            delegate_key([0xEE; 32]),
            delegate_key(sender),
            payload,
        )),
    )
}

/// Sends from a delegate and returns its single reply, which must be
/// addressed back to the caller.
fn from_delegate(h: &mut MemHost, key: [u8; 32], payload: Vec<u8>) -> Reply {
    let out = from_delegate_raw(h, key, key, payload);
    assert_eq!(out.len(), 1, "{out:?}");
    match &out[0] {
        OutboundDelegateMsg::SendDelegateMessage(m) => {
            assert_eq!(m.target.bytes(), key.as_slice());
            decode_reply(&m.payload)
        }
        other => panic!("expected a delegate message, got {other:?}"),
    }
}

fn req(header: RequestHeader, op: Operation) -> Vec<u8> {
    Request {
        header,
        op,
        ext: vec![],
    }
    .encode()
    .unwrap()
}

fn op(rid: u64, op: Operation) -> Vec<u8> {
    req(page_header(rid), op)
}

fn poke(flags: u8, record: Option<[u8; 100]>) -> Vec<u8> {
    Poke {
        flags,
        partition: domain().partition(),
        record,
        ext: vec![],
    }
    .encode()
    .unwrap()
}

fn refused(rid: u64, reason: u8) -> Reply {
    Reply::St(Status::Refused {
        request_id: rid,
        reason,
    })
}

fn handover(r: Reply) -> HandoverStatus {
    match r {
        Reply::St(Status::Handover(h)) => h,
        other => panic!("expected HandoverStatus, got {other:?}"),
    }
}

/// Arms the build with its own record, as the courier does.
fn arm(h: &mut MemHost) {
    let s = handover(page(
        h,
        poke(poke_flags::ARM, Some(domain_record(1, [0x11; 32]))),
    ));
    assert_eq!(s.partition_state, partition_state::NONE_ARMED);
}

/// A writer holding one generated key; returns (slot, public key).
fn writer_with_key(h: &mut MemHost) -> (Vec<u8>, [u8; 32]) {
    arm(h);
    match page(h, op(1, Operation::Generate { slot: None })) {
        Reply::Op(1, OpResult::Key { slot, public_key }) => (slot, public_key),
        other => panic!("{other:?}"),
    }
}

fn seed_of(h: &MemHost, slot: &[u8]) -> [u8; 32] {
    let p = domain().partition();
    let ix = crate::storage::index::Index::decode(&h.secrets[&names::index(&p)]).unwrap();
    let ie = &ix.entries[ix.find(KIND_KEY, slot).unwrap()];
    let e = Entry::decode(&h.secrets[&names::entry(&p, KIND_KEY, slot, ie.parity)]).unwrap();
    e.content.try_into().unwrap()
}

fn set_state(h: &mut MemHost, f: impl FnOnce(&mut crate::storage::index::Index)) {
    let mut s = Store::open(h, domain().partition()).unwrap();
    s.update(f).unwrap();
}

/// Stores a seed directly, as if it had arrived by a handover copy.
fn plant_key(h: &mut MemHost, slot: &[u8], seed: [u8; 32]) {
    let mut s = Store::open(h, domain().partition()).unwrap();
    let q = crate::storage::Quota {
        max_key_slots: 100,
        max_caller_marks: 100,
    };
    s.put(
        &Entry::new(KIND_KEY, slot.to_vec(), seed.to_vec()),
        &q,
        |_| {},
    )
    .unwrap();
}

fn batch(rid: u64, slot: &[u8], expected: [u8; 32], items: Vec<BatchItem>) -> Operation {
    let _ = rid;
    Operation::Batch {
        slot: slot.to_vec(),
        expected_public_key: expected,
        items,
    }
}

// ---- callers (spec 5, 15) ------------------------------------------------

#[test]
fn no_origin_is_refused_origin_required() {
    let mut h = MemHost::new();
    let out = run(
        &mut h,
        None,
        InboundDelegateMsg::ApplicationMessage(ApplicationMessage::new(op(
            5,
            Operation::PublicKey { slot: vec![1; 32] },
        ))),
    );
    assert_eq!(single_app_reply(out), refused(5, refused::ORIGIN_REQUIRED));
}

#[test]
fn every_operation_from_another_page_is_refused() {
    let mut h = MemHost::new();
    let (slot, pk) = writer_with_key(&mut h);
    // Same container code under another publisher (#972 R5), and unknown code.
    let other_publisher = hash::contract_instance_id(&CONTAINER, &[9; 32]);
    let unknown_code = hash::contract_instance_id(&[9; 32], &vk(&PUBLISHER_SEED));
    for id in [other_publisher, unknown_code] {
        for o in [
            Operation::Generate { slot: None },
            Operation::Import {
                slot: slot.clone(),
                seed: [1; 32],
                replace: true,
            },
            Operation::Delete { slot: slot.clone() },
            Operation::PublicKey { slot: slot.clone() },
            Operation::List {
                after: vec![],
                max: 10,
            },
            batch(3, &slot, pk, vec![BatchItem::Sign(b"x".to_vec())]),
            Operation::Export { slot: slot.clone() },
        ] {
            let r = single_app_reply(from_page_as(&mut h, id, op(3, o)));
            assert_eq!(r, refused(3, refused::CALLER_NOT_AUTHORIZED));
        }
    }
    // The key is untouched.
    assert_eq!(
        page(&mut h, op(4, Operation::PublicKey { slot: slot.clone() })),
        Reply::Op(
            4,
            OpResult::Key {
                slot,
                public_key: pk
            }
        )
    );
}

#[test]
fn a_page_sending_a_caller_proof_is_refused() {
    let mut h = MemHost::new();
    let (slot, _) = writer_with_key(&mut h);
    let r = page(&mut h, req(chat(3).header, Operation::PublicKey { slot }));
    assert_eq!(r, refused(77, refused::CALLER_NOT_AUTHORIZED));
}

#[test]
fn delegate_proof_failures_are_refused() {
    let mut h = MemHost::new();
    let (slot, _) = writer_with_key(&mut h);
    let pk_op = || Operation::PublicKey { slot: slot.clone() };
    let c = chat(3);
    // No proof.
    assert_eq!(
        from_delegate(&mut h, c.key, req(page_header(8), pk_op())),
        refused(8, refused::CALLER_NOT_AUTHORIZED)
    );
    // The stamped key is not the record's (another build).
    assert_eq!(
        from_delegate(&mut h, chat(4).key, req(c.header.clone(), pk_op())),
        refused(77, refused::CALLER_NOT_AUTHORIZED)
    );
    // The same code under non-empty parameters (D3).
    let mut kp = blake3::Hasher::new();
    kp.update(&[3u8; 32]);
    kp.update(b"params");
    let keyed: [u8; 32] = *kp.finalize().as_bytes();
    assert_eq!(
        from_delegate(&mut h, keyed, req(c.header.clone(), pk_op())),
        refused(77, refused::CALLER_NOT_AUTHORIZED)
    );
    // A record signed by someone else.
    let mut forged = c.header.clone();
    forged.proof.as_mut().unwrap().record = record(&[0x99; 32], CHAT_APP, 3, [3; 32]);
    assert_eq!(
        from_delegate(&mut h, c.key, req(forged, pk_op())),
        refused(77, refused::CALLER_NOT_AUTHORIZED)
    );
    // A caller the domain does not accept.
    let mut other_app = c.header.clone();
    let p = other_app.proof.as_mut().unwrap();
    p.app_id = b"test.other".to_vec();
    p.record = record(&PUBLISHER_SEED, b"test.other", 3, [3; 32]);
    assert_eq!(
        from_delegate(&mut h, c.key, req(other_app, pk_op())),
        refused(77, refused::CALLER_NOT_AUTHORIZED)
    );
    // A withdrawal record as proof.
    let mut wd = c.header.clone();
    wd.proof.as_mut().unwrap().record = record(&PUBLISHER_SEED, CHAT_APP, 3, [0; 32]);
    assert_eq!(
        from_delegate(
            &mut h,
            hash::delegate_key_empty_params(&[0; 32]),
            req(wd, pk_op())
        ),
        refused(77, refused::CALLER_NOT_AUTHORIZED)
    );
    // And the valid caller is served.
    assert!(matches!(
        from_delegate(&mut h, c.key, req(c.header, pk_op())),
        Reply::Op(77, OpResult::Key { .. })
    ));
}

#[test]
fn the_chat_delegate_may_use_only_batch_public_key_and_submit_record() {
    let mut h = MemHost::new();
    let (slot, _) = writer_with_key(&mut h);
    let c = chat(3);
    for o in [
        Operation::Generate { slot: None },
        Operation::Import {
            slot: slot.clone(),
            seed: [1; 32],
            replace: true,
        },
        Operation::Delete { slot: slot.clone() },
        Operation::List {
            after: vec![],
            max: 10,
        },
        Operation::Export { slot: slot.clone() },
    ] {
        assert_eq!(
            from_delegate(&mut h, c.key, req(c.header.clone(), o)),
            refused(77, refused::OPERATION_NOT_ALLOWED)
        );
    }
    // The key survived.
    assert!(matches!(
        from_delegate(
            &mut h,
            c.key,
            req(c.header.clone(), Operation::PublicKey { slot })
        ),
        Reply::Op(_, OpResult::Key { .. })
    ));
}

#[test]
fn delegate_messages_the_vault_does_not_handle_are_ignored() {
    let mut h = MemHost::new();
    let (slot, _) = writer_with_key(&mut h);
    let c = chat(3);
    // Sender differs from the attested origin.
    assert!(from_delegate_raw(
        &mut h,
        c.key,
        [1; 32],
        req(
            c.header.clone(),
            Operation::PublicKey { slot: slot.clone() }
        )
    )
    .is_empty());
    // Handover frames, unknown frame types, non-vault bytes, status frames.
    for payload in [
        frame::encode(types::CHUNK, &[0; 10]).unwrap(),
        frame::encode(types::COMPLETE, &[]).unwrap(),
        frame::encode(0x30, &[]).unwrap(),
        b"hello".to_vec(),
        Status::Busy {
            request_id: 0,
            partition: [0; 32],
        }
        .encode()
        .unwrap(),
        poke(poke_flags::ARM, None),
    ] {
        assert!(from_delegate_raw(&mut h, c.key, c.key, payload).is_empty());
    }
    // An ApplicationMessage claiming a delegate origin is refused.
    let out = run(
        &mut h,
        Some(MessageOrigin::Delegate(delegate_key(c.key))),
        InboundDelegateMsg::ApplicationMessage(ApplicationMessage::new(req(
            c.header,
            Operation::PublicKey { slot },
        ))),
    );
    assert_eq!(
        single_app_reply(out),
        refused(77, refused::CALLER_NOT_AUTHORIZED)
    );
}

#[test]
fn unknown_frames_and_retire_to_from_a_page_answer_refused_10() {
    let mut h = MemHost::new();
    assert_eq!(
        page(&mut h, frame::encode(0x30, &[]).unwrap()),
        refused(0, refused::UNKNOWN_FRAME)
    );
    assert_eq!(
        page(&mut h, frame::encode(0x87, &[0; 100]).unwrap()),
        refused(0, refused::UNKNOWN_FRAME)
    );
    assert_eq!(
        page(&mut h, frame::encode(types::CHUNK, &[]).unwrap()),
        refused(0, refused::UNKNOWN_FRAME)
    );
    assert_eq!(
        page(&mut h, b"not a vault frame".to_vec()),
        refused(0, refused::MALFORMED)
    );
    // A malformed operation keeps its request id.
    let mut bad = op(9, Operation::PublicKey { slot: vec![1; 32] });
    bad.push(0);
    bad[9] += 1; // body_len, so the envelope stays well formed
    assert_eq!(page(&mut h, bad), refused(9, refused::MALFORMED));
}

#[test]
fn non_empty_parameters_and_processed_messages_fail() {
    let mut h = MemHost::new();
    let msg = InboundDelegateMsg::ApplicationMessage(ApplicationMessage::new(poke(0, None)));
    let origin = MessageOrigin::WebApp(ContractInstanceId::new(page_id()));
    assert!(process(&domain(), &mut h, b"x", Some(&origin), msg).is_err());
    let msg = InboundDelegateMsg::ApplicationMessage(
        ApplicationMessage::new(poke(0, None)).processed(true),
    );
    assert!(process(&domain(), &mut h, &[], Some(&origin), msg).is_err());
}

// ---- creation and routing (protocol 3, 5.1) -----------------------------

#[test]
fn nothing_is_created_until_armed() {
    let mut h = MemHost::new();
    let p = domain().partition();
    assert_eq!(
        page(&mut h, op(1, Operation::Generate { slot: None })),
        Reply::St(Status::NotHere {
            request_id: 1,
            partition: p
        })
    );
    assert!(h.secrets.is_empty());
    arm(&mut h);
    let Reply::Op(2, OpResult::Key { slot, public_key }) =
        page(&mut h, op(2, Operation::Generate { slot: None }))
    else {
        panic!()
    };
    assert_eq!(slot, public_key.to_vec(), "self-named: slot = public key");
    assert_eq!(crypto::public_key(&seed_of(&h, &slot)), public_key);
    let s = handover(page(&mut h, poke(0, None)));
    assert_eq!(s.partition_state, partition_state::WRITER);
    assert!(h.secrets.contains_key(names::PARTS));
}

#[test]
fn arming_needs_the_own_page_a_valid_record_at_own_version() {
    let mut h = MemHost::new();
    let other = hash::contract_instance_id(&[9; 32], &[9; 32]);
    // From another page: flags ignored, status redacted.
    let r = single_app_reply(from_page_as(
        &mut h,
        other,
        poke(poke_flags::ARM, Some(domain_record(1, [1; 32]))),
    ));
    assert_eq!(handover(r).partition_state, 0);
    // Read unredacted from the own page: still not armed.
    assert_eq!(
        handover(page(&mut h, poke(0, None))).partition_state,
        partition_state::NONE
    );
    for bad in [
        domain_record(2, [1; 32]),                      // not OWN_VERSION
        record(&[0x99; 32], b"test.vault", 1, [1; 32]), // wrong signer
        domain_record(1, [0; 32]),                      // a withdrawal
    ] {
        let s = handover(page(&mut h, poke(poke_flags::ARM, Some(bad))));
        assert_ne!(s.partition_state, partition_state::NONE_ARMED, "{bad:?}");
        // Records above own version are accepted, so reset between cases.
        h.secrets.clear();
    }
    assert_eq!(
        page(&mut h, op(1, Operation::Generate { slot: None })),
        Reply::St(Status::NotHere {
            request_id: 1,
            partition: domain().partition()
        })
    );
}

/// Protocol test 8's tail: arm v1, then a newer record arrives, then a
/// change on v1 answers Moved(R2).
#[test]
fn a_newer_record_disarms_and_routes_to_the_successor() {
    let mut h = MemHost::new();
    arm(&mut h);
    let r2 = domain_record(2, [0x22; 32]);
    let s = handover(page(&mut h, poke(0, Some(r2))));
    assert_eq!(s.step_result, step_result::RECORD_ACCEPTED);
    assert_eq!(s.record_state, record_state::SUCCESSOR);
    assert_eq!(s.partition_state, partition_state::NONE);
    assert_eq!(
        page(&mut h, op(1, Operation::Generate { slot: None })),
        Reply::St(Status::Moved {
            request_id: 1,
            partition: domain().partition(),
            record: r2
        })
    );
}

/// Arming is re-checked at creation: if the write clearing it fails, a
/// change still does not create while a newer record is known.
#[test]
fn creation_rechecks_for_a_newer_record_when_disarming_failed() {
    let mut h = MemHost::new();
    arm(&mut h);
    let idx = names::index(&domain().partition());
    h.set_fault(move |name| {
        if name == idx.as_slice() {
            WriteFault::Fail
        } else {
            WriteFault::None
        }
    });
    let r2 = domain_record(2, [0x22; 32]);
    let s = handover(page(&mut h, poke(0, Some(r2))));
    assert_eq!(s.step_result, step_result::RECORD_ACCEPTED);
    assert_eq!(
        s.partition_state,
        partition_state::NONE_ARMED,
        "clearing failed"
    );
    assert_ne!(s.problems & problems::STORAGE_FAILURE, 0);
    h.clear_fault();
    assert_eq!(
        page(&mut h, op(1, Operation::Generate { slot: None })),
        Reply::St(Status::Moved {
            request_id: 1,
            partition: domain().partition(),
            record: r2
        })
    );
    assert!(h.names_with_prefix(b"vault:e:").is_empty());
}

#[test]
fn submit_record_from_another_page_is_refused() {
    let mut h = MemHost::new();
    writer_with_key(&mut h);
    let s = SubmitRecord {
        header: page_header(6),
        author_vk: vk(&PUBLISHER_SEED),
        app_id: CHAT_APP.to_vec(),
        record: record(&PUBLISHER_SEED, CHAT_APP, 9, [0; 32]),
        ext: vec![],
    };
    let other = hash::contract_instance_id(&CONTAINER, &[9; 32]);
    assert_eq!(
        single_app_reply(from_page_as(&mut h, other, s.encode().unwrap())),
        refused(6, refused::CALLER_NOT_AUTHORIZED)
    );
    // The withdrawal was not stored: version 5 still serves.
    assert!(matches!(
        chat_pk(&mut h, 5, &[1; 32]),
        Reply::St(Status::Absent { .. })
    ));
}

#[test]
fn record_acceptance_rules() {
    let mut h = MemHost::new();
    let step = |h: &mut MemHost, r| handover(page(h, poke(0, Some(r)))).step_result;
    assert_eq!(
        step(&mut h, record(&[0x99; 32], b"test.vault", 3, [3; 32])),
        step_result::INVALID
    );
    assert_eq!(
        step(&mut h, domain_record(1, [1; 32])),
        step_result::NOT_NEWER
    );
    assert_eq!(
        step(&mut h, domain_record(3, [3; 32])),
        step_result::RECORD_ACCEPTED
    );
    assert_eq!(
        step(&mut h, domain_record(3, [3; 32])),
        step_result::RECORD_ACCEPTED
    );
    assert_eq!(
        step(&mut h, domain_record(3, [4; 32])),
        step_result::EQUIVOCATION
    );
    assert_eq!(
        step(&mut h, domain_record(2, [2; 32])),
        step_result::NOT_NEWER
    );
    // A withdrawal above current stops the domain.
    assert_eq!(
        step(&mut h, domain_record(4, [0; 32])),
        step_result::RECORD_ACCEPTED
    );
    let s = handover(page(&mut h, poke(0, None)));
    assert_eq!(s.record_state, record_state::STOPPED);
    assert_eq!(s.floor_version, 4);
}

#[test]
fn a_malformed_stored_record_refuses_record_handling() {
    let mut h = MemHost::new();
    h.secrets.insert(names::SUCC.to_vec(), vec![1, 2, 3]);
    let s = handover(page(
        &mut h,
        poke(poke_flags::ARM, Some(domain_record(1, [1; 32]))),
    ));
    assert_eq!(s.record_state, record_state::STORED_MALFORMED);
    assert_eq!(s.partition_state, partition_state::NONE);
    let sub = SubmitRecord {
        header: page_header(4),
        author_vk: domain().author_vk,
        app_id: b"test.vault".to_vec(),
        record: domain_record(2, [2; 32]),
        ext: vec![],
    };
    assert_eq!(
        page(&mut h, sub.encode().unwrap()),
        refused(4, refused::STORED_RECORD_MALFORMED)
    );
}

#[test]
fn states_route_operations() {
    let mut h = MemHost::new();
    let (slot, pk) = writer_with_key(&mut h);
    let p = domain().partition();
    let read = |h: &mut MemHost| page(h, op(2, Operation::PublicKey { slot: slot.clone() }));
    let change = |h: &mut MemHost| page(h, op(3, Operation::Delete { slot: slot.clone() }));
    let ok_read = Reply::Op(
        2,
        OpResult::Key {
            slot: slot.clone(),
            public_key: pk,
        },
    );
    let busy = Reply::St(Status::Busy {
        request_id: 3,
        partition: p,
    });

    // Writer awaiting its predecessor's retirement: reads work, changes Busy.
    set_state(&mut h, |ix| ix.awaiting_retirement = true);
    assert_eq!(read(&mut h), ok_read);
    assert_eq!(change(&mut h), busy);
    // Sealed: the same.
    set_state(&mut h, |ix| {
        ix.awaiting_retirement = false;
        ix.state = State::Sealed;
    });
    assert_eq!(read(&mut h), ok_read);
    assert_eq!(change(&mut h), busy);
    assert_eq!(
        page(&mut h, op(4, Operation::Generate { slot: None })),
        Reply::St(Status::Busy {
            request_id: 4,
            partition: p
        })
    );
    // Receiving: NotHere for everything.
    set_state(&mut h, |ix| ix.state = State::Receiving);
    assert_eq!(
        read(&mut h),
        Reply::St(Status::NotHere {
            request_id: 2,
            partition: p
        })
    );
    // Retired: Moved(retired_to) always.
    let r2 = domain_record(2, [2; 32]);
    set_state(&mut h, |ix| {
        ix.state = State::Retired;
        ix.peer_record = Some(r2);
    });
    assert_eq!(
        read(&mut h),
        Reply::St(Status::Moved {
            request_id: 2,
            partition: p,
            record: r2
        })
    );
    assert_eq!(
        change(&mut h),
        Reply::St(Status::Moved {
            request_id: 3,
            partition: p,
            record: r2
        })
    );
    // The key is still there underneath.
    assert_eq!(crypto::public_key(&seed_of(&h, &slot)), pk);
}

// ---- the operations (spec 6) --------------------------------------------

#[test]
fn generate_named_and_occupied() {
    let mut h = MemHost::new();
    arm(&mut h);
    let slot = vec![0x42; 32];
    let Reply::Op(
        _,
        OpResult::Key {
            slot: s,
            public_key,
        },
    ) = page(
        &mut h,
        op(
            1,
            Operation::Generate {
                slot: Some(slot.clone()),
            },
        ),
    )
    else {
        panic!()
    };
    assert_eq!(s, slot);
    assert_eq!(crypto::public_key(&seed_of(&h, &slot)), public_key);
    assert_eq!(
        page(
            &mut h,
            op(
                2,
                Operation::Generate {
                    slot: Some(slot.clone())
                }
            )
        ),
        refused(2, refused::SLOT_OCCUPIED)
    );
    // Wrong slot length for the domain.
    assert_eq!(
        page(
            &mut h,
            op(
                3,
                Operation::Generate {
                    slot: Some(vec![1; 31])
                }
            )
        ),
        refused(3, refused::MALFORMED)
    );
}

#[test]
fn generate_refuses_a_zero_random_source() {
    let mut h = MemHost::new();
    arm(&mut h);
    h.zero_rng = true;
    assert_eq!(
        page(&mut h, op(1, Operation::Generate { slot: None })),
        refused(1, refused::STORAGE_FAILURE)
    );
    assert!(h.names_with_prefix(b"vault:e:").is_empty());
}

#[test]
fn import_same_key_is_a_no_op_and_a_different_key_needs_replace() {
    let mut h = MemHost::new();
    arm(&mut h);
    let slot = vec![7; 32];
    let a = [0xA1; 32];
    let b = [0xB2; 32];
    let imp = |seed, replace| Operation::Import {
        slot: slot.clone(),
        seed,
        replace,
    };
    let key = |seed| {
        Reply::Op(
            1,
            OpResult::Key {
                slot: slot.clone(),
                public_key: crypto::public_key(&seed),
            },
        )
    };
    assert_eq!(page(&mut h, op(1, imp(a, false))), key(a));
    let writes = h.writes;
    assert_eq!(page(&mut h, op(1, imp(a, false))), key(a));
    assert_eq!(h.writes, writes, "same key: no write");
    assert_eq!(
        page(&mut h, op(2, imp(b, false))),
        refused(2, refused::SLOT_OCCUPIED)
    );
    assert_eq!(seed_of(&h, &slot), a);
    assert_eq!(page(&mut h, op(1, imp(b, true))), key(b));
    assert_eq!(seed_of(&h, &slot), b);
}

#[test]
fn import_of_the_same_seed_rewrites_a_corrupt_slot_clean() {
    let mut h = MemHost::new();
    arm(&mut h);
    let slot = vec![7; 32];
    let seed = [0xA1; 32];
    page(
        &mut h,
        op(
            1,
            Operation::Import {
                slot: slot.clone(),
                seed,
                replace: false,
            },
        ),
    );
    // Corrupt the stored bytes so they still parse; the next read flags them.
    let p = domain().partition();
    let name = names::entry(&p, KIND_KEY, &slot, 0);
    let mut b = h.secrets[&name].clone();
    b[40] ^= 1;
    h.secrets.insert(name, b);
    let unusable = Reply::St(Status::Unusable {
        request_id: 2,
        partition: p,
        slot: slot.clone(),
        reason: unusable::CORRUPT,
    });
    assert_eq!(
        page(&mut h, op(2, Operation::PublicKey { slot: slot.clone() })),
        unusable
    );
    assert_eq!(
        page(&mut h, op(2, Operation::PublicKey { slot: slot.clone() })),
        unusable
    );
    // The original seed differs from the flagged bytes, so it needs replace;
    // the flagged seed itself is "the same key" and rewrites clean.
    let mut flagged = seed;
    flagged[40 - 38] ^= 1;
    assert_eq!(
        page(
            &mut h,
            op(
                3,
                Operation::Import {
                    slot: slot.clone(),
                    seed: flagged,
                    replace: false
                }
            )
        ),
        Reply::Op(
            3,
            OpResult::Key {
                slot: slot.clone(),
                public_key: crypto::public_key(&flagged)
            }
        )
    );
    assert!(matches!(
        page(&mut h, op(4, Operation::PublicKey { slot: slot.clone() })),
        Reply::Op(4, OpResult::Key { .. })
    ));
    page(
        &mut h,
        op(
            5,
            Operation::Import {
                slot: slot.clone(),
                seed,
                replace: true,
            },
        ),
    );
    assert_eq!(seed_of(&h, &slot), seed);
}

#[test]
fn publisher_keys_are_refused_at_import_generate_and_every_use() {
    let mut h = MemHost::new();
    arm(&mut h);
    let p = domain().partition();
    for (i, seed) in [PUBLISHER_SEED, DOMAIN_SEED].into_iter().enumerate() {
        let slot = vec![i as u8 + 1; 32];
        assert_eq!(
            page(
                &mut h,
                op(
                    1,
                    Operation::Import {
                        slot: slot.clone(),
                        seed,
                        replace: true
                    }
                )
            ),
            Reply::St(Status::Unusable {
                request_id: 1,
                partition: p,
                slot: slot.clone(),
                reason: unusable::PUBLISHER_KEY
            })
        );
    }
    assert!(h.names_with_prefix(b"vault:e:").is_empty());
    // A publisher key that arrived another way (a handover copy) is never served.
    page(
        &mut h,
        op(
            1,
            Operation::Generate {
                slot: Some(vec![9; 32]),
            },
        ),
    );
    let slot = vec![5; 32];
    plant_key(&mut h, &slot, PUBLISHER_SEED);
    let un = |rid| {
        Reply::St(Status::Unusable {
            request_id: rid,
            partition: p,
            slot: slot.clone(),
            reason: unusable::PUBLISHER_KEY,
        })
    };
    assert_eq!(
        page(&mut h, op(2, Operation::PublicKey { slot: slot.clone() })),
        un(2)
    );
    assert_eq!(
        page(
            &mut h,
            op(
                3,
                batch(3, &slot, vk(&PUBLISHER_SEED), vec![BatchItem::Sign(vec![])])
            )
        ),
        un(3)
    );
    assert_eq!(
        page(&mut h, op(4, Operation::Export { slot: slot.clone() })),
        un(4)
    );
    let c = chat(3);
    assert_eq!(
        from_delegate(
            &mut h,
            c.key,
            req(
                c.header,
                batch(0, &slot, vk(&PUBLISHER_SEED), vec![BatchItem::Sign(vec![])])
            )
        ),
        Reply::St(Status::Unusable {
            request_id: 77,
            partition: p,
            slot: slot.clone(),
            reason: unusable::PUBLISHER_KEY
        })
    );
    let Reply::Op(_, OpResult::List { items, .. }) = page(
        &mut h,
        op(
            5,
            Operation::List {
                after: vec![],
                max: 10,
            },
        ),
    ) else {
        panic!()
    };
    assert_eq!(
        items.iter().find(|i| i.slot == slot).unwrap().status,
        LIST_UNUSABLE
    );
    // Delete still works.
    assert_eq!(
        page(&mut h, op(6, Operation::Delete { slot: slot.clone() })),
        Reply::Op(6, OpResult::Ok)
    );
}

#[test]
fn delete_then_absent_and_delete_is_idempotent() {
    let mut h = MemHost::new();
    let (slot, _) = writer_with_key(&mut h);
    let p = domain().partition();
    assert_eq!(
        page(&mut h, op(2, Operation::Delete { slot: slot.clone() })),
        Reply::Op(2, OpResult::Ok)
    );
    assert_eq!(
        page(&mut h, op(3, Operation::PublicKey { slot: slot.clone() })),
        Reply::St(Status::Absent {
            request_id: 3,
            partition: p,
            slot: slot.clone()
        })
    );
    assert_eq!(
        page(&mut h, op(4, Operation::Delete { slot: slot.clone() })),
        Reply::Op(4, OpResult::Ok)
    );
    assert!(h.names_with_prefix(b"vault:e:").is_empty());
}

#[test]
fn list_is_ascending_after_exclusive_with_more() {
    let mut h = MemHost::new();
    arm(&mut h);
    for s in [3u8, 1, 4, 2] {
        page(
            &mut h,
            op(
                1,
                Operation::Import {
                    slot: vec![s; 32],
                    seed: [s + 10; 32],
                    replace: false,
                },
            ),
        );
    }
    let list =
        |h: &mut MemHost, after: Vec<u8>, max| match page(h, op(9, Operation::List { after, max }))
        {
            Reply::Op(9, OpResult::List { items, more }) => {
                (items.iter().map(|i| i.slot[0]).collect::<Vec<_>>(), more)
            }
            other => panic!("{other:?}"),
        };
    assert_eq!(list(&mut h, vec![], 256), (vec![1, 2, 3, 4], false));
    assert_eq!(list(&mut h, vec![], 2), (vec![1, 2], true));
    assert_eq!(list(&mut h, vec![2; 32], 2), (vec![3, 4], false));
    assert_eq!(list(&mut h, vec![4; 32], 2), (vec![], false));
    let Reply::Op(_, OpResult::List { items, .. }) = page(
        &mut h,
        op(
            9,
            Operation::List {
                after: vec![],
                max: 1,
            },
        ),
    ) else {
        panic!()
    };
    assert_eq!(items[0].public_key, crypto::public_key(&[11; 32]));
    assert_eq!(items[0].status, LIST_OK);
}

#[test]
fn list_reports_a_corrupt_slot_with_its_flagged_key() {
    let mut h = MemHost::new();
    arm(&mut h);
    let slot = vec![1; 32];
    page(
        &mut h,
        op(
            1,
            Operation::Import {
                slot: slot.clone(),
                seed: [10; 32],
                replace: false,
            },
        ),
    );
    let name = names::entry(&domain().partition(), KIND_KEY, &slot, 0);
    let mut b = h.secrets[&name].clone();
    b[38] ^= 1;
    h.secrets.insert(name, b);
    let Reply::Op(_, OpResult::List { items, .. }) = page(
        &mut h,
        op(
            9,
            Operation::List {
                after: vec![],
                max: 10,
            },
        ),
    ) else {
        panic!()
    };
    let mut flagged = [10u8; 32];
    flagged[0] ^= 1;
    assert_eq!(
        items,
        vec![ListItem {
            slot,
            public_key: crypto::public_key(&flagged),
            status: LIST_CORRUPT
        }]
    );
}

#[test]
fn quota_is_refused() {
    let mut h = MemHost::new();
    arm(&mut h);
    for s in 0..4u8 {
        page(
            &mut h,
            op(
                1,
                Operation::Generate {
                    slot: Some(vec![s; 32]),
                },
            ),
        );
    }
    assert_eq!(
        page(&mut h, op(2, Operation::Generate { slot: None })),
        refused(2, refused::QUOTA)
    );
}

#[test]
fn batch_items() {
    let mut h = MemHost::new();
    let (slot, pk) = writer_with_key(&mut h);
    let seed = seed_of(&h, &slot);
    let low_order = [0u8; 32];
    let peer = [9u8; 32];
    let r = page(
        &mut h,
        op(
            5,
            batch(
                5,
                &slot,
                pk,
                vec![
                    BatchItem::Sign(b"hello".to_vec()),
                    BatchItem::Sign(b"freenet-pointer/state-v1 forged".to_vec()),
                    BatchItem::KeyAgreement(low_order),
                    BatchItem::KeyAgreement(peer),
                    BatchItem::Derive {
                        context: "ctx".into(),
                        data: b"data".to_vec(),
                    },
                    BatchItem::Sign(vec![0x42; 65_536]),
                ],
            ),
        ),
    );
    let Reply::Op(5, OpResult::Batch(res)) = r else {
        panic!("{r:?}")
    };
    assert_eq!(res.len(), 6);
    let v = VerifyingKey::from_bytes(&pk).unwrap();
    assert_eq!(res[0].status, ITEM_OK);
    v.verify_strict(
        b"hello",
        &ed25519_dalek::Signature::from_slice(&res[0].bytes).unwrap(),
    )
    .unwrap();
    assert_eq!(
        res[1],
        ItemResult {
            status: ITEM_FORBIDDEN_SIGNING_DOMAIN,
            bytes: vec![]
        }
    );
    assert_eq!(
        res[2],
        ItemResult {
            status: ITEM_OK,
            bytes: vec![0; 32]
        }
    );
    assert_eq!(res[3].bytes, crypto::key_agreement(&seed, &peer).to_vec());
    assert_eq!(res[4].bytes, crypto::derive(&seed, "ctx", b"data").to_vec());
    assert_eq!(res[5].bytes.len(), 64);
}

#[test]
fn batch_refusals() {
    let mut h = MemHost::new();
    let (slot, pk) = writer_with_key(&mut h);
    let p = domain().partition();
    let mut wrong = pk;
    wrong[0] ^= 1;
    let sign = || vec![BatchItem::Sign(b"x".to_vec())];
    assert_eq!(
        page(&mut h, op(1, batch(1, &slot, wrong, sign()))),
        refused(1, refused::PUBLIC_KEY_MISMATCH)
    );
    assert_eq!(
        page(&mut h, op(2, batch(2, &[9; 32], pk, sign()))),
        Reply::St(Status::Absent {
            request_id: 2,
            partition: p,
            slot: vec![9; 32]
        })
    );
    assert_eq!(
        page(&mut h, op(3, batch(3, &[9; 31], pk, sign()))),
        refused(3, refused::MALFORMED)
    );
}

// ---- Export and consent --------------------------------------------------

fn export_prompt(h: &mut MemHost, slot: &[u8], rid: u64) -> u32 {
    let out = from_page_as(
        h,
        page_id(),
        op(
            rid,
            Operation::Export {
                slot: slot.to_vec(),
            },
        ),
    );
    assert_eq!(out.len(), 1);
    match &out[0] {
        OutboundDelegateMsg::RequestUserInput(r) => {
            assert_eq!(r.responses.len(), 2);
            r.request_id
        }
        other => panic!("expected a prompt, got {other:?}"),
    }
}

fn answer(
    h: &mut MemHost,
    origin: [u8; 32],
    prompt_id: u32,
    response: &[u8],
) -> Result<Vec<OutboundDelegateMsg>, DelegateError> {
    process(
        &domain(),
        h,
        &[],
        Some(&MessageOrigin::WebApp(ContractInstanceId::new(origin))),
        InboundDelegateMsg::UserResponse(UserInputResponse {
            request_id: prompt_id,
            response: ClientResponse::new(response.to_vec()),
            context: DelegateContext::default(),
        }),
    )
}

#[test]
fn export_asks_every_time_and_returns_the_seed_only_on_allow() {
    let mut h = MemHost::new();
    let (slot, _) = writer_with_key(&mut h);
    let seed = seed_of(&h, &slot);
    let id = export_prompt(&mut h, &slot, 11);
    let out = answer(&mut h, page_id(), id, b"Allow").unwrap();
    assert_eq!(
        single_app_reply(out),
        Reply::Op(11, OpResult::Export { seed })
    );
    // The answer is spent.
    assert!(answer(&mut h, page_id(), id, b"Allow").is_err());
    // Asked again; denied and timed out (empty answer) are refusals.
    for resp in [b"Deny".as_slice(), b"", b"allow"] {
        let id = export_prompt(&mut h, &slot, 12);
        assert_eq!(
            single_app_reply(answer(&mut h, page_id(), id, resp).unwrap()),
            refused(12, refused::CONSENT_DENIED)
        );
    }
}

#[test]
fn an_answer_for_another_prompt_or_origin_is_refused() {
    let mut h = MemHost::new();
    let (slot, _) = writer_with_key(&mut h);
    let id = export_prompt(&mut h, &slot, 11);
    assert!(answer(&mut h, page_id(), id.wrapping_add(1), b"Allow").is_err());
    assert!(answer(&mut h, [9; 32], id, b"Allow").is_err());
    let out = process(
        &domain(),
        &mut h,
        &[],
        None,
        InboundDelegateMsg::UserResponse(UserInputResponse {
            request_id: id,
            response: ClientResponse::new(b"Allow".to_vec()),
            context: DelegateContext::default(),
        }),
    );
    assert!(out.is_err());
}

#[test]
fn no_prompt_for_any_other_inbound_kind() {
    let mut h = MemHost::new();
    let (slot, _) = writer_with_key(&mut h);
    let c = chat(3);
    let out = from_delegate_raw(
        &mut h,
        c.key,
        c.key,
        req(c.header, Operation::Export { slot: slot.clone() }),
    );
    assert!(out
        .iter()
        .all(|m| !matches!(m, OutboundDelegateMsg::RequestUserInput(_))));
    for msg in [
        InboundDelegateMsg::WakeupFired {
            tag: b"handover".to_vec(),
        },
        InboundDelegateMsg::ApplicationMessage(ApplicationMessage::new(op(
            1,
            Operation::Export { slot: slot.clone() },
        ))),
    ] {
        let out = process(&domain(), &mut h, &[], None, msg).unwrap();
        assert!(out
            .iter()
            .all(|m| !matches!(m, OutboundDelegateMsg::RequestUserInput(_))));
    }
}

// ---- caller marks (protocol 9) -------------------------------------------

fn chat_pk(h: &mut MemHost, version: u32, slot: &[u8]) -> Reply {
    let c = chat(version);
    from_delegate(
        h,
        c.key,
        req(
            c.header,
            Operation::PublicKey {
                slot: slot.to_vec(),
            },
        ),
    )
}

fn submit_caller_record(h: &mut MemHost, rec: [u8; 100]) -> Reply {
    let s = SubmitRecord {
        header: page_header(6),
        author_vk: vk(&PUBLISHER_SEED),
        app_id: CHAT_APP.to_vec(),
        record: rec,
        ext: vec![],
    };
    page(h, s.encode().unwrap())
}

#[test]
fn caller_marks_raise_and_refuse_lower_versions() {
    let mut h = MemHost::new();
    let (slot, _) = writer_with_key(&mut h);
    let ok = |r: Reply| matches!(r, Reply::Op(77, OpResult::Key { .. }));
    assert!(ok(chat_pk(&mut h, 5, &slot)));
    assert_eq!(
        chat_pk(&mut h, 4, &slot),
        refused(77, refused::CALLER_NOT_AUTHORIZED)
    );
    assert!(ok(chat_pk(&mut h, 5, &slot)));
    assert!(ok(chat_pk(&mut h, 6, &slot)));
    assert_eq!(
        chat_pk(&mut h, 5, &slot),
        refused(77, refused::CALLER_NOT_AUTHORIZED)
    );
}

#[test]
fn a_caller_withdrawal_blocks_until_a_higher_record() {
    let mut h = MemHost::new();
    let (slot, _) = writer_with_key(&mut h);
    assert!(matches!(chat_pk(&mut h, 5, &slot), Reply::Op(..)));
    let s = handover(submit_caller_record(
        &mut h,
        record(&PUBLISHER_SEED, CHAT_APP, 7, [0; 32]),
    ));
    assert_eq!(s.step_result, step_result::RECORD_ACCEPTED);
    assert_eq!(
        chat_pk(&mut h, 6, &slot),
        refused(77, refused::CALLER_NOT_AUTHORIZED)
    );
    assert_eq!(
        chat_pk(&mut h, 7, &slot),
        refused(77, refused::CALLER_NOT_AUTHORIZED)
    );
    assert!(matches!(chat_pk(&mut h, 8, &slot), Reply::Op(..)));
}

#[test]
fn submit_record_for_callers() {
    let mut h = MemHost::new();
    writer_with_key(&mut h);
    let step = |h: &mut MemHost, r| handover(submit_caller_record(h, r)).step_result;
    assert_eq!(
        step(&mut h, record(&[0x99; 32], CHAT_APP, 3, [3; 32])),
        step_result::INVALID
    );
    assert_eq!(
        step(&mut h, record(&PUBLISHER_SEED, CHAT_APP, 3, [3; 32])),
        step_result::RECORD_ACCEPTED
    );
    assert_eq!(
        step(&mut h, record(&PUBLISHER_SEED, CHAT_APP, 3, [3; 32])),
        step_result::RECORD_ACCEPTED
    );
    assert_eq!(
        step(&mut h, record(&PUBLISHER_SEED, CHAT_APP, 3, [4; 32])),
        step_result::EQUIVOCATION
    );
    assert_eq!(
        step(&mut h, record(&PUBLISHER_SEED, CHAT_APP, 2, [2; 32])),
        step_result::NOT_NEWER
    );
    // A record for a caller the domain does not accept.
    let s = SubmitRecord {
        header: page_header(6),
        author_vk: vk(&PUBLISHER_SEED),
        app_id: b"test.other".to_vec(),
        record: record(&PUBLISHER_SEED, b"test.other", 3, [3; 32]),
        ext: vec![],
    };
    assert_eq!(
        page(&mut h, s.encode().unwrap()),
        refused(6, refused::CALLER_NOT_AUTHORIZED)
    );
    // From the chat delegate: allowed, and the status is redacted.
    let c = chat(3);
    let s = SubmitRecord {
        header: c.header.clone(),
        author_vk: vk(&PUBLISHER_SEED),
        app_id: CHAT_APP.to_vec(),
        record: record(&PUBLISHER_SEED, CHAT_APP, 9, [9; 32]),
        ext: vec![],
    };
    let hs = handover(from_delegate(&mut h, c.key, s.encode().unwrap()));
    assert_eq!(hs.step_result, step_result::RECORD_ACCEPTED);
    assert_eq!(hs.request_id, 77);
    assert_eq!(hs.partition_state, 0, "redacted for a delegate");
    // Version 3 is now below the mark.
    assert_eq!(
        chat_pk(&mut h, 3, &[0; 32]),
        refused(77, refused::CALLER_NOT_AUTHORIZED)
    );
}

#[test]
fn a_raise_during_a_seal_is_busy_and_one_needing_none_is_served() {
    let mut h = MemHost::new();
    let (slot, pk) = writer_with_key(&mut h);
    assert!(matches!(chat_pk(&mut h, 5, &slot), Reply::Op(..)));
    set_state(&mut h, |ix| ix.state = State::Sealed);
    let p = domain().partition();
    assert_eq!(
        chat_pk(&mut h, 6, &slot),
        Reply::St(Status::Busy {
            request_id: 77,
            partition: p
        })
    );
    assert_eq!(
        chat_pk(&mut h, 5, &slot),
        Reply::Op(
            77,
            OpResult::Key {
                slot: slot.clone(),
                public_key: pk
            }
        )
    );
    assert_eq!(
        submit_caller_record(&mut h, record(&PUBLISHER_SEED, CHAT_APP, 9, [0; 32])),
        Reply::St(Status::Busy {
            request_id: 6,
            partition: p
        })
    );
}

/// Storage exhaustion (spec 11): reads keep working, a request needing a
/// mark raise is refused, changes fail.
#[test]
fn a_full_store_keeps_reads_and_refuses_raises_and_changes() {
    let mut h = MemHost::new();
    let (slot, pk) = writer_with_key(&mut h);
    let seed = seed_of(&h, &slot);
    assert!(matches!(chat_pk(&mut h, 5, &slot), Reply::Op(..)));
    h.set_fault(|_| WriteFault::Fail);
    assert_eq!(
        chat_pk(&mut h, 6, &slot),
        refused(77, refused::STORAGE_FAILURE)
    );
    assert_eq!(
        chat_pk(&mut h, 5, &slot),
        Reply::Op(
            77,
            OpResult::Key {
                slot: slot.clone(),
                public_key: pk
            }
        )
    );
    assert!(matches!(
        page(
            &mut h,
            op(1, batch(1, &slot, pk, vec![BatchItem::Sign(vec![1])]))
        ),
        Reply::Op(1, OpResult::Batch(_))
    ));
    assert!(matches!(
        page(
            &mut h,
            op(
                2,
                Operation::List {
                    after: vec![],
                    max: 9
                }
            )
        ),
        Reply::Op(2, OpResult::List { .. })
    ));
    let id = export_prompt(&mut h, &slot, 3);
    assert_eq!(
        single_app_reply(answer(&mut h, page_id(), id, b"Allow").unwrap()),
        Reply::Op(3, OpResult::Export { seed })
    );
    assert_eq!(
        page(&mut h, op(4, Operation::Generate { slot: None })),
        refused(4, refused::STORAGE_FAILURE)
    );
    assert_eq!(
        page(&mut h, op(5, Operation::Delete { slot: slot.clone() })),
        refused(5, refused::STORAGE_FAILURE)
    );
    assert_eq!(
        page(
            &mut h,
            op(
                6,
                Operation::Import {
                    slot: vec![8; 32],
                    seed: [8; 32],
                    replace: false
                }
            )
        ),
        refused(6, refused::STORAGE_FAILURE)
    );
    h.clear_fault();
    assert_eq!(crypto::public_key(&seed_of(&h, &slot)), pk);
}

mod review;
mod river_cross;
