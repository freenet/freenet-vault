//! `process` on arbitrary bytes, from a page and from the chat delegate, in a
//! vault holding a key: it must not panic, a refusal must change nothing, and
//! no reply may carry the stored seed.
#![no_main]

use freenet_stdlib::prelude::*;
use freenet_vault::process;
use freenet_vault::testing::MemHost;
use freenet_vault_common::frame::{types, Frame};
use freenet_vault_common::ops::{Operation, Request, RequestHeader};
use freenet_vault_common::record::signing_message;
use freenet_vault_common::status::{poke_flags, Poke, Status};
use libfuzzer_sys::fuzz_target;
use river_vault::{RIVER, RIVER_PAGE_CONTAINERS};

fn dk(k: [u8; 32]) -> DelegateKey {
    DelegateKey::new(k, CodeHash::new([0; 32]))
}

fn vault_with_key() -> (MemHost, [u8; 32]) {
    use ed25519_dalek::Signer;
    let mut h = MemHost::new();
    let page = MessageOrigin::WebApp(ContractInstanceId::new(RIVER_PAGE_CONTAINERS[0].instance_id()));
    let msg = signing_message(&RIVER.author_vk, RIVER.app_id, 1, &[0x11; 32]);
    let mut record = [0u8; 100];
    record[..4].copy_from_slice(&1u32.to_be_bytes());
    record[4..36].copy_from_slice(&[0x11; 32]);
    record[36..].copy_from_slice(
        &ed25519_dalek::SigningKey::from_bytes(&[0x52; 32])
            .sign(&msg)
            .to_bytes(),
    );
    let poke = Poke {
        flags: poke_flags::ARM,
        partition: RIVER.partition(),
        record: Some(record),
        ext: vec![],
    }
    .encode()
    .unwrap();
    let _ = process(
        &RIVER,
        &mut h,
        &[],
        Some(&page),
        InboundDelegateMsg::ApplicationMessage(ApplicationMessage::new(poke)),
    );
    let gen = Request {
        header: RequestHeader {
            request_id: 1,
            proof: None,
        },
        op: Operation::Import {
            slot: vec![0x42; 32],
            seed: [0x5A; 32],
            replace: false,
        },
        ext: vec![],
    }
    .encode()
    .unwrap();
    let _ = process(
        &RIVER,
        &mut h,
        &[],
        Some(&page),
        InboundDelegateMsg::ApplicationMessage(ApplicationMessage::new(gen)),
    );
    (h, [0x5A; 32])
}

fuzz_target!(|data: &[u8]| {
    let (base, seed) = vault_with_key();
    for as_delegate in [false, true] {
        let mut h = MemHost::new();
        h.secrets = base.secrets.clone();
        let before = h.secrets.clone();
        let (origin, msg) = if as_delegate {
            (
                MessageOrigin::Delegate(dk([7; 32])),
                InboundDelegateMsg::DelegateMessage(DelegateMessage::new(
                    dk([0xEE; 32]),
                    dk([7; 32]),
                    data.to_vec(),
                )),
            )
        } else {
            (
                MessageOrigin::WebApp(ContractInstanceId::new(
                    RIVER_PAGE_CONTAINERS[0].instance_id(),
                )),
                InboundDelegateMsg::ApplicationMessage(ApplicationMessage::new(data.to_vec())),
            )
        };
        let mut may_change = false;
        if let Ok(out) = process(&RIVER, &mut h, &[], Some(&origin), msg) {
            for m in out {
                let bytes = match &m {
                    OutboundDelegateMsg::ApplicationMessage(a) => &a.payload,
                    OutboundDelegateMsg::SendDelegateMessage(d) => &d.payload,
                    _ => continue,
                };
                assert!(!bytes.windows(32).any(|w| w == seed), "a reply carries a seed");
                if let Ok(f) = Frame::decode(bytes) {
                    if f.frame_type >= types::KEY_RESULT || f.frame_type == types::HANDOVER_STATUS {
                        may_change = true;
                    } else {
                        let _ = Status::decode(f.frame_type, f.body);
                    }
                }
            }
        }
        if !may_change {
            assert_eq!(h.secrets, before, "a refusal changed storage");
        }
    }
});
