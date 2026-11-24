//! Both edges of every frozen bound on the DECODING side, which faces hostile
//! input: the last value is accepted and the first value over is refused. The
//! bodies are built by hand, so the encoder (which refuses these values
//! itself) is not involved.

use freenet_vault_common::entry::Entry;
use freenet_vault_common::frame::types;
use freenet_vault_common::ops::*;

const PAGE: [u8; 9] = [0, 0, 0, 0, 0, 0, 0, 1, 0];
const NO_EXT: [u8; 2] = [0, 0];

fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.iter().flat_map(|p| p.iter().copied()).collect()
}

fn ok(ty: u8, body: &[u8]) {
    Request::decode(ty, body).unwrap_or_else(|e| panic!("refused a valid body: {e}"));
}

fn refused(ty: u8, body: &[u8]) {
    assert!(
        Request::decode(ty, body).is_err(),
        "accepted an invalid body"
    );
}

fn delete_with_slot(n: usize) -> Vec<u8> {
    cat(&[&PAGE, &[n as u8], &vec![7; n], &NO_EXT])
}

#[test]
fn slot_length_1_to_64() {
    ok(types::DELETE, &delete_with_slot(1));
    ok(types::DELETE, &delete_with_slot(64));
    refused(types::DELETE, &delete_with_slot(0));
    refused(types::DELETE, &delete_with_slot(65));
}

#[test]
fn list_after_and_max() {
    let list = |after: usize, max: u16| {
        cat(&[
            &PAGE,
            &[after as u8],
            &vec![1; after],
            &max.to_be_bytes(),
            &NO_EXT,
        ])
    };
    ok(types::LIST, &list(0, 1));
    ok(types::LIST, &list(64, 256));
    refused(types::LIST, &list(65, 1));
    refused(types::LIST, &list(0, 0));
    refused(types::LIST, &list(0, 257));
}

fn batch(count: u16, items: &[u8]) -> Vec<u8> {
    cat(&[
        &PAGE,
        &[1, 0xEE],
        &[0x11; 32],
        &count.to_be_bytes(),
        items,
        &NO_EXT,
    ])
}

#[test]
fn batch_item_count_1_to_256() {
    let ka = |n: usize| cat(&vec![&[&[2u8][..], &[0x22; 32]].concat()[..]; n]);
    ok(types::BATCH, &batch(1, &ka(1)));
    ok(types::BATCH, &batch(256, &ka(256)));
    refused(types::BATCH, &batch(257, &ka(257)));
    refused(types::BATCH, &batch(0, &[]));
    // A count larger than the items present is not accepted either.
    refused(types::BATCH, &batch(2, &ka(1)));
}

#[test]
fn sign_and_derive_data_up_to_65536() {
    let sign = |n: usize| cat(&[&[1], &(n as u32).to_be_bytes(), &vec![0; n]]);
    ok(types::BATCH, &batch(1, &sign(0)));
    ok(types::BATCH, &batch(1, &sign(65_536)));
    refused(types::BATCH, &batch(1, &sign(65_537)));
    let derive = |ctx: usize, data: usize| {
        cat(&[
            &[3],
            &(ctx as u16).to_be_bytes(),
            &vec![b'c'; ctx],
            &(data as u32).to_be_bytes(),
            &vec![0; data],
        ])
    };
    ok(types::BATCH, &batch(1, &derive(1, 0)));
    ok(types::BATCH, &batch(1, &derive(256, 65_536)));
    refused(types::BATCH, &batch(1, &derive(0, 0)));
    refused(types::BATCH, &batch(1, &derive(257, 0)));
    refused(types::BATCH, &batch(1, &derive(1, 65_537)));
}

#[test]
fn app_id_1_to_64_in_a_proof_and_in_submit_record() {
    let proof = |n: usize| {
        cat(&[
            &[0, 0, 0, 0, 0, 0, 0, 1, 1],
            &[0x01; 32],
            &[n as u8],
            &vec![b'a'; n],
            &[0x02; 100],
        ])
    };
    let del = |n: usize| cat(&[&proof(n), &[1, 7], &NO_EXT]);
    ok(types::DELETE, &del(1));
    ok(types::DELETE, &del(64));
    refused(types::DELETE, &del(0));
    refused(types::DELETE, &del(65));
    let submit = |n: usize| {
        cat(&[
            &PAGE,
            &[0x33; 32],
            &[n as u8],
            &vec![b'a'; n],
            &[0x66; 100],
            &NO_EXT,
        ])
    };
    assert!(SubmitRecord::decode(&submit(1)).is_ok());
    assert!(SubmitRecord::decode(&submit(64)).is_ok());
    assert!(SubmitRecord::decode(&submit(0)).is_err());
    assert!(SubmitRecord::decode(&submit(65)).is_err());
}

/// An operation request body is at most 1 MiB: exactly 1 MiB is accepted.
#[test]
fn request_body_exactly_one_mib() {
    let sign64k = cat(&[&[1], &65_536u32.to_be_bytes(), &vec![0; 65_536]]);
    let items: Vec<u8> = (0..15).flat_map(|_| sign64k.clone()).collect();
    // PAGE 9 + slot 2 + expected 32 + count 2 + items + ext_len 2 + ext.
    let fixed = 9 + 2 + 32 + 2 + items.len() + 2;
    let pad = 1_048_576 - fixed;
    assert!(pad <= 65_535);
    let body = |pad: usize| {
        cat(&[
            &PAGE,
            &[1, 0xEE],
            &[0x11; 32],
            &15u16.to_be_bytes(),
            &items,
            &(pad as u16).to_be_bytes(),
            &vec![0; pad],
        ])
    };
    let exact = body(pad);
    assert_eq!(exact.len(), 1_048_576);
    ok(types::BATCH, &exact);
    let over = body(pad + 1);
    assert_eq!(over.len(), 1_048_577);
    refused(types::BATCH, &over);
}

#[test]
fn entry_bounds_on_decode() {
    let entry = |kind: u8, key: usize, content: usize, ext: usize| {
        cat(&[
            &[kind, 0],
            &(key as u16).to_be_bytes(),
            &vec![1; key],
            &(content as u16).to_be_bytes(),
            &vec![2; content],
            &(ext as u16).to_be_bytes(),
            &vec![3; ext],
        ])
    };
    // Key 1..=256.
    assert!(Entry::decode(&entry(0x10, 1, 0, 0)).is_ok());
    assert!(Entry::decode(&entry(0x10, 256, 0, 0)).is_ok());
    assert!(Entry::decode(&entry(0x10, 0, 0, 0)).is_err());
    assert!(Entry::decode(&entry(0x10, 257, 0, 0)).is_err());
    // Kind 0 is reserved and refused.
    assert!(Entry::decode(&entry(0, 1, 0, 0)).is_err());
    // Content of the defined kinds is exactly 32 and 100 bytes.
    assert!(Entry::decode(&entry(1, 1, 32, 0)).is_ok());
    assert!(Entry::decode(&entry(1, 1, 31, 0)).is_err());
    assert!(Entry::decode(&entry(1, 1, 33, 0)).is_err());
    assert!(Entry::decode(&entry(2, 1, 100, 0)).is_ok());
    assert!(Entry::decode(&entry(2, 1, 99, 0)).is_err());
    assert!(Entry::decode(&entry(2, 1, 101, 0)).is_err());
    // The whole entry is at most 65,399 bytes: 9 bytes of framing with a
    // 1-byte key leaves 65,390 for content and extension.
    let at = entry(0x10, 1, 65_390, 0);
    assert_eq!(at.len(), 65_399);
    assert!(Entry::decode(&at).is_ok());
    let over = entry(0x10, 1, 65_391, 0);
    assert_eq!(over.len(), 65_400);
    assert!(Entry::decode(&over).is_err());
    // An extension of any length that fits is accepted, up to the total.
    assert!(Entry::decode(&entry(0x10, 1, 0, 65_390)).is_ok());
}

#[test]
fn result_counts_on_decode() {
    let list = |n: usize| {
        let row = cat(&[&[1, 1], &[0; 32], &[0]]);
        cat(&[
            &[0; 8],
            &(n as u16).to_be_bytes(),
            &vec![row; n].concat(),
            &[0],
            &NO_EXT,
        ])
    };
    assert!(OpResult::decode(types::LIST_RESULT, &list(256)).is_ok());
    assert!(OpResult::decode(types::LIST_RESULT, &list(257)).is_err());
    let batch = |n: usize| {
        let item = [0u8, 0, 0];
        cat(&[
            &[0; 8],
            &(n as u16).to_be_bytes(),
            &vec![item; n].concat(),
            &NO_EXT,
        ])
    };
    assert!(OpResult::decode(types::BATCH_RESULT, &batch(256)).is_ok());
    assert!(OpResult::decode(types::BATCH_RESULT, &batch(257)).is_err());
}

/// The whole reply frame (10 header bytes + body) is at most 65,536: a batch
/// result with one item of 65,511 payload bytes is the largest accepted.
#[test]
fn reply_frame_exactly_65536_bytes() {
    let result = |payload: usize| {
        cat(&[
            &[0, 0, 0, 0, 0, 0, 0, 1],
            &1u16.to_be_bytes(),
            &[0],
            &(payload as u16).to_be_bytes(),
            &vec![5; payload],
            &NO_EXT,
        ])
    };
    let last = result(65_511);
    assert_eq!(10 + last.len(), 65_536);
    assert!(OpResult::decode(types::BATCH_RESULT, &last).is_ok());
    assert!(OpResult::decode(types::BATCH_RESULT, &result(65_512)).is_err());
    assert!(OpResult::decode(types::BATCH_RESULT, &result(65_535)).is_err());
}

/// Generate: mode 1 is "generated slot" (length 0); mode 0 names a slot of 1
/// to 64 bytes. Every other pairing is refused.
#[test]
fn generate_named_slot_bounds() {
    let generate = |mode: u8, n: usize| cat(&[&PAGE, &[mode, n as u8], &vec![9; n], &NO_EXT]);
    ok(types::GENERATE, &generate(1, 0));
    ok(types::GENERATE, &generate(0, 1));
    ok(types::GENERATE, &generate(0, 64));
    refused(types::GENERATE, &generate(0, 0));
    refused(types::GENERATE, &generate(0, 65));
    refused(types::GENERATE, &generate(1, 1));
    refused(types::GENERATE, &generate(2, 0));
}
