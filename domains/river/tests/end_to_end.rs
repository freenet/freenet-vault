//! River's real constants through `process`: River's published web container
//! as the page origin, River's real `river.chat-delegate` pointer record
//! (version 11, signed by River's publishing key) as the caller proof, and the
//! chat delegate's real code hash as its stamped key.
//!
//! Needs `--features placeholder-key`: the author key is still the placeholder
//! (seed `[0x52; 32]`), which is what lets this test sign vault records. When
//! the real author key replaces it, the file is skipped by design (it is gated
//! on the feature) and the key-dependent parts need a signing fixture.
#![cfg(feature = "placeholder-key")]

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use freenet_stdlib::prelude::*;
use freenet_vault::process;
use freenet_vault::testing::MemHost;
use freenet_vault_common::frame::{types, Frame};
use freenet_vault_common::hash::delegate_key_empty_params;
use freenet_vault_common::ops::*;
use freenet_vault_common::record::signing_message;
use freenet_vault_common::status::{poke_flags, Poke, Status};
use river_vault::{RIVER, RIVER_PAGE_CONTAINERS, RIVER_PUBLISHER_VK};

/// River's `river.chat-delegate` record, version 11 (river
/// `pointer-records.toml` at origin/main 4d137e66), and its code hash.
const CHAT_RECORD_V11: &str = "0000000b4fbc0f3a4940d1dace00415337d3cfae7ea3eceac03a8877a2b62fc9455bf4c4749cc8eb4b8e1305ed5857f4be5a8491c4a4713cb5f5be6f9a4eb88494ef8bf8ce10a1ee5c31234f4bd01d4453eb4ee8f51341f8f1656a563bda067fc424f50b";
const CHAT_CODE_HASH: &str = "4fbc0f3a4940d1dace00415337d3cfae7ea3eceac03a8877a2b62fc9455bf4c4";

fn unhex<const N: usize>(s: &str) -> [u8; N] {
    let v: Vec<u8> = (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect();
    v.try_into().unwrap()
}

fn page_origin() -> MessageOrigin {
    MessageOrigin::WebApp(ContractInstanceId::new(
        RIVER_PAGE_CONTAINERS[0].instance_id(),
    ))
}

fn from_page(h: &mut MemHost, payload: Vec<u8>) -> (u8, Vec<u8>) {
    let out = process(
        &RIVER,
        h,
        &[],
        Some(&page_origin()),
        InboundDelegateMsg::ApplicationMessage(ApplicationMessage::new(payload)),
    )
    .unwrap();
    let [OutboundDelegateMsg::ApplicationMessage(m)] = out.as_slice() else {
        panic!("{out:?}")
    };
    let f = Frame::decode(&m.payload).unwrap();
    (f.frame_type, f.body.to_vec())
}

fn from_chat(h: &mut MemHost, key: [u8; 32], payload: Vec<u8>) -> (u8, Vec<u8>) {
    let dk = |k: [u8; 32]| DelegateKey::new(k, CodeHash::new([0; 32]));
    let out = process(
        &RIVER,
        h,
        &[],
        Some(&MessageOrigin::Delegate(dk(key))),
        InboundDelegateMsg::DelegateMessage(DelegateMessage::new(dk([0xEE; 32]), dk(key), payload)),
    )
    .unwrap();
    let [OutboundDelegateMsg::SendDelegateMessage(m)] = out.as_slice() else {
        panic!("{out:?}")
    };
    let f = Frame::decode(&m.payload).unwrap();
    (f.frame_type, f.body.to_vec())
}

fn vault_record_v1() -> [u8; 100] {
    let sk = SigningKey::from_bytes(&[0x52; 32]);
    let code_hash = [0x11; 32];
    let msg = signing_message(&RIVER.author_vk, RIVER.app_id, 1, &code_hash);
    let mut out = [0u8; 100];
    out[..4].copy_from_slice(&1u32.to_be_bytes());
    out[4..36].copy_from_slice(&code_hash);
    out[36..].copy_from_slice(&sk.sign(&msg).to_bytes());
    out
}

fn chat_header(record: [u8; 100]) -> RequestHeader {
    RequestHeader {
        request_id: 5,
        proof: Some(CallerProof {
            author_vk: RIVER_PUBLISHER_VK,
            app_id: b"river.chat-delegate".to_vec(),
            record,
        }),
    }
}

#[test]
fn rivers_real_page_chat_delegate_and_record_work_through_process() {
    let mut h = MemHost::new();
    let record_v11: [u8; 100] = unhex(CHAT_RECORD_V11);
    let chat_key = delegate_key_empty_params(&unhex(CHAT_CODE_HASH));

    // Arm the vault with its own record, as River's courier does, then create
    // a key from River's page.
    let poke = Poke {
        flags: poke_flags::ARM,
        partition: RIVER.partition(),
        record: Some(vault_record_v1()),
        ext: vec![],
    }
    .encode()
    .unwrap();
    let (t, _) = from_page(&mut h, poke);
    assert_eq!(t, types::HANDOVER_STATUS);
    let gen = Request {
        header: RequestHeader {
            request_id: 1,
            proof: None,
        },
        op: Operation::Generate {
            slot: Some(vec![0x42; 32]),
        },
        ext: vec![],
    }
    .encode()
    .unwrap();
    let (t, body) = from_page(&mut h, gen);
    assert_eq!(t, types::KEY_RESULT);
    let (_, OpResult::Key { slot, public_key }) = OpResult::decode(t, &body).unwrap() else {
        panic!()
    };

    // The chat delegate, with its real record, signs through the vault.
    let batch = |header: RequestHeader| {
        Request {
            header,
            op: Operation::Batch {
                slot: slot.clone(),
                expected_public_key: public_key,
                items: vec![BatchItem::Sign(b"a message".to_vec())],
            },
            ext: vec![],
        }
        .encode()
        .unwrap()
    };
    let (t, body) = from_chat(&mut h, chat_key, batch(chat_header(record_v11)));
    assert_eq!(t, types::BATCH_RESULT, "{:?}", Status::decode(t, &body));
    let (rid, OpResult::Batch(items)) = OpResult::decode(t, &body).unwrap() else {
        panic!()
    };
    assert_eq!(rid, 5);
    let sig = Signature::from_bytes(&items[0].bytes.clone().try_into().unwrap());
    VerifyingKey::from_bytes(&public_key)
        .unwrap()
        .verify_strict(b"a message", &sig)
        .expect("the vault's signature verifies under the key's public half");

    // A forged record, or a stamped key that is not the record's build, is refused.
    let mut forged = record_v11;
    forged[50] ^= 1;
    for (key, record) in [(chat_key, forged), ([0x99; 32], record_v11)] {
        let (t, body) = from_chat(&mut h, key, batch(chat_header(record)));
        assert_eq!(t, types::REFUSED);
        assert_eq!(
            Status::decode(t, &body).unwrap(),
            Status::Refused {
                request_id: 5,
                reason: freenet_vault_common::status::refused::CALLER_NOT_AUTHORIZED
            }
        );
    }
}

fn chat_request(op: Operation, record: [u8; 100], app_id: &[u8]) -> Vec<u8> {
    Request {
        header: RequestHeader {
            request_id: 5,
            proof: Some(CallerProof {
                author_vk: RIVER_PUBLISHER_VK,
                app_id: app_id.to_vec(),
                record,
            }),
        },
        op,
        ext: vec![],
    }
    .encode()
    .unwrap()
}

fn refusal(h: &mut MemHost, key: [u8; 32], payload: Vec<u8>) -> u8 {
    let (t, body) = from_chat(h, key, payload);
    assert_eq!(t, types::REFUSED);
    match Status::decode(t, &body).unwrap() {
        Status::Refused { reason, .. } => reason,
        other => panic!("{other:?}"),
    }
}

/// Spec 7: the chat delegate may use only Batch, PublicKey and SubmitRecord,
/// and only as the app its record names.
#[test]
fn the_chat_delegate_is_refused_everything_but_batch_public_key_and_submit_record() {
    use freenet_vault_common::status::refused;
    let mut h = MemHost::new();
    let record_v11: [u8; 100] = unhex(CHAT_RECORD_V11);
    let key = delegate_key_empty_params(&unhex(CHAT_CODE_HASH));
    let app = b"river.chat-delegate";
    let slot = vec![0x42; 32];
    for op in [
        Operation::Generate { slot: None },
        Operation::Import {
            slot: slot.clone(),
            seed: [1; 32],
            replace: true,
        },
        Operation::Delete { slot: slot.clone() },
        Operation::Export { slot: slot.clone() },
        Operation::List {
            after: vec![],
            max: 10,
        },
    ] {
        assert_eq!(
            refusal(&mut h, key, chat_request(op, record_v11, app)),
            refused::OPERATION_NOT_ALLOWED
        );
    }
    // The same record presented as another app is not a valid proof.
    for other in [&b"river.room-contract"[..], b"river.vault", b"x"] {
        assert_eq!(
            refusal(
                &mut h,
                key,
                chat_request(
                    Operation::PublicKey { slot: slot.clone() },
                    record_v11,
                    other
                )
            ),
            refused::CALLER_NOT_AUTHORIZED
        );
    }
}

/// The constants the vault's authorisation rests on, pinned to River's data.
#[test]
fn rivers_constants_are_pinned() {
    assert_eq!(
        RIVER.delegate_frames,
        [types::BATCH, types::PUBLIC_KEY, types::SUBMIT_RECORD]
    );
    assert_eq!(RIVER.publisher_keys, [RIVER_PUBLISHER_VK]);
    assert_eq!(RIVER.slot_len, Some(32));
    let record_v11: [u8; 100] = unhex(CHAT_RECORD_V11);
    let delegates = river_vault::RIVER_CALLER_DELEGATES;
    assert_eq!(delegates.len(), 1);
    assert_eq!(delegates[0].author_vk, RIVER_PUBLISHER_VK);
    assert_eq!(delegates[0].app_id, b"river.chat-delegate");
    // The compiled-in floor is River's chat delegate's current version.
    assert_eq!(
        delegates[0].min_version,
        u32::from_be_bytes(record_v11[..4].try_into().unwrap())
    );
}

/// The vault's key for a delegate registered with empty parameters equals
/// the stdlib's own derivation, so the check the node's stamp is compared
/// against cannot drift from what the node computes.
#[test]
fn the_empty_parameter_delegate_key_equals_the_stdlibs() {
    let code: [u8; 32] = unhex(CHAT_CODE_HASH);
    let b58 = bs58::encode(code)
        .with_alphabet(bs58::Alphabet::BITCOIN)
        .into_string();
    let theirs = DelegateKey::from_params(b58, &Parameters::from(Vec::<u8>::new())).unwrap();
    assert_eq!(theirs.bytes(), delegate_key_empty_params(&code).as_slice());
}
