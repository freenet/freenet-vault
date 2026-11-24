//! `process` on arbitrary input, in a vault holding a key and a caller mark,
//! under a domain whose keys the harness holds, so the authorised paths are
//! reached: a page, a delegate with no proof, a delegate carrying a valid
//! signed proof, and a page frame built around the fuzz bytes. It must not
//! panic, a reply that is not a result or a HandoverStatus must leave storage
//! unchanged, and no reply may carry the stored seed in a field that is not an
//! echo of the request.
#![no_main]

use ed25519_dalek::{Signer, SigningKey};
use freenet_stdlib::prelude::*;
use freenet_vault::testing::MemHost;
use freenet_vault::{process, CallerDelegate, Domain, PageContainer};
use freenet_vault_common::frame::{self, types, Frame};
use freenet_vault_common::hash::{contract_instance_id, delegate_key_empty_params};
use freenet_vault_common::ops::{Operation, Request, RequestHeader};
use freenet_vault_common::record::signing_message;
use freenet_vault_common::status::{poke_flags, Poke};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

const AUTHOR_SEED: [u8; 32] = [0xD0; 32];
const PUBLISHER_SEED: [u8; 32] = [0xB0; 32];
const CONTAINER: [u8; 32] = [0xC0; 32];
const SEED: [u8; 32] = [0x5A; 32];
const CHAT_APP: &[u8] = b"fuzz.chat";

fn vk(seed: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

fn dom() -> &'static Domain {
    static DOM: OnceLock<Domain> = OnceLock::new();
    DOM.get_or_init(|| {
        let publisher = vk(&PUBLISHER_SEED);
        Domain {
            author_vk: vk(&AUTHOR_SEED),
            app_id: b"fuzz.vault",
            own_version: 1,
            predecessors: &[],
            page_containers: Box::leak(Box::new([PageContainer {
                code_hash: CONTAINER,
                publisher_vk: publisher,
            }])),
            extra_page_ids: &[],
            caller_delegates: Box::leak(Box::new([CallerDelegate {
                author_vk: publisher,
                app_id: CHAT_APP,
                min_version: 1,
            }])),
            delegate_frames: &[types::BATCH, types::PUBLIC_KEY, types::SUBMIT_RECORD],
            publisher_keys: Box::leak(Box::new([publisher])),
            slot_len: Some(32),
            max_key_slots: 4,
            max_caller_marks: 2,
            export_prompt: |_| "export?".into(),
        }
    })
}

fn record(seed: &[u8; 32], app: &[u8], version: u32, code_hash: [u8; 32]) -> [u8; 100] {
    let sk = SigningKey::from_bytes(seed);
    let msg = signing_message(&sk.verifying_key().to_bytes(), app, version, &code_hash);
    let mut out = [0u8; 100];
    out[..4].copy_from_slice(&version.to_be_bytes());
    out[4..36].copy_from_slice(&code_hash);
    out[36..].copy_from_slice(&sk.sign(&msg).to_bytes());
    out
}

fn dk(k: [u8; 32]) -> DelegateKey {
    DelegateKey::new(k, CodeHash::new([0; 32]))
}

fn page_origin() -> MessageOrigin {
    MessageOrigin::WebApp(ContractInstanceId::new(contract_instance_id(
        &CONTAINER,
        &vk(&PUBLISHER_SEED),
    )))
}

fn page_msg(payload: Vec<u8>) -> InboundDelegateMsg<'static> {
    InboundDelegateMsg::ApplicationMessage(ApplicationMessage::new(payload))
}

/// Armed, holding one key, with the chat delegate's mark at version 5.
fn vault() -> MemHost {
    let mut h = MemHost::new();
    let poke = Poke {
        flags: poke_flags::ARM,
        partition: dom().partition(),
        record: Some(record(&AUTHOR_SEED, b"fuzz.vault", 1, [0x11; 32])),
        ext: vec![],
    }
    .encode()
    .unwrap();
    let origin = page_origin();
    let _ = process(dom(), &mut h, &[], Some(&origin), page_msg(poke));
    let import = Request {
        header: RequestHeader {
            request_id: 1,
            proof: None,
        },
        op: Operation::Import {
            slot: vec![0x42; 32],
            seed: SEED,
            replace: false,
        },
        ext: vec![],
    }
    .encode()
    .unwrap();
    let _ = process(dom(), &mut h, &[], Some(&origin), page_msg(import));
    // The chat delegate's first valid request writes its mark.
    let (key, proof) = chat_proof();
    let mut body = proof;
    body.extend_from_slice(&[1, 0x42]);
    body.extend_from_slice(&[0, 0]);
    let _ = send_delegate(&mut h, key, frame::encode(types::PUBLIC_KEY, &body).unwrap());
    h
}

/// The chat delegate's stamped key and a request header carrying its record.
fn chat_proof() -> ([u8; 32], Vec<u8>) {
    let code = [5u8; 32];
    let rec = record(&PUBLISHER_SEED, CHAT_APP, 5, code);
    let mut h = 77u64.to_be_bytes().to_vec();
    h.push(1);
    h.extend_from_slice(&vk(&PUBLISHER_SEED));
    h.push(CHAT_APP.len() as u8);
    h.extend_from_slice(CHAT_APP);
    h.extend_from_slice(&rec);
    (delegate_key_empty_params(&code), h)
}

fn send_delegate(h: &mut MemHost, key: [u8; 32], payload: Vec<u8>) -> Vec<OutboundDelegateMsg> {
    process(
        dom(),
        h,
        &[],
        Some(&MessageOrigin::Delegate(dk(key))),
        InboundDelegateMsg::DelegateMessage(DelegateMessage::new(dk([0xEE; 32]), dk(key), payload)),
    )
    .unwrap_or_default()
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let base = vault();
    let mut h = MemHost::new();
    h.secrets = base.secrets.clone();
    let before = h.secrets.clone();
    let (chat_key, chat_header) = chat_proof();
    let rest = &data[2..];
    let ty = [0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x21][(data[1] % 8) as usize];
    let out = match data[0] % 4 {
        // Raw bytes from a page.
        0 => process(dom(), &mut h, &[], Some(&page_origin()), page_msg(data.to_vec())),
        // Raw bytes from a delegate: no proof, so the refusal paths.
        1 => Ok(send_delegate(&mut h, chat_key, data.to_vec())),
        // The chat delegate with its valid proof and fuzzed operation bytes.
        2 => {
            let body = [chat_header.as_slice(), rest].concat();
            Ok(send_delegate(&mut h, chat_key, frame::encode(ty, &body).unwrap()))
        }
        // A page, with a request header and fuzzed operation bytes.
        _ => {
            let body = [&[0u8; 9][..], rest].concat();
            process(
                dom(),
                &mut h,
                &[],
                Some(&page_origin()),
                page_msg(frame::encode(ty, &body).unwrap()),
            )
        }
    };
    let mut may_change = false;
    if let Ok(out) = out {
        for m in out {
            let bytes = match &m {
                OutboundDelegateMsg::ApplicationMessage(a) => &a.payload,
                OutboundDelegateMsg::SendDelegateMessage(d) => &d.payload,
                _ => continue,
            };
            let Ok(f) = Frame::decode(bytes) else { continue };
            if f.frame_type >= types::KEY_RESULT || f.frame_type == types::HANDOVER_STATUS {
                may_change = true;
            }
            // Absent, Unusable, KeyResult and ListResult echo the request's
            // slot, which the fuzzer can choose to equal the seed.
            let echoes = matches!(f.frame_type, 0x43 | 0x45 | 0xA0 | 0xA2);
            if !echoes {
                assert!(
                    !bytes.windows(32).any(|w| w == SEED),
                    "a reply carries the seed"
                );
            }
        }
    }
    if !may_change {
        assert_eq!(h.secrets, before, "a refusal changed storage");
    }
});
