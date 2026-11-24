//! Byte-for-byte vectors for every request, result and entry layout, written
//! out by hand from the handover protocol (revision 7, 12.1 to 12.5) and not
//! produced by the encoders. Each is checked in both directions: the encoder
//! must produce exactly these bytes and the decoder must read them back. A
//! change that moves a field in the encoder and the decoder together (so every
//! round-trip test stays green) fails here.

use freenet_vault_common::entry::Entry;
use freenet_vault_common::frame::Frame;
use freenet_vault_common::ops::*;
use freenet_vault_common::status::Poke;

/// `"FVLT" 01 type body_len(4, big-endian) body`.
fn frame(ty: u8, body: &[u8]) -> Vec<u8> {
    let mut v = b"FVLT".to_vec();
    v.push(1);
    v.push(ty);
    v.extend((body.len() as u32).to_be_bytes());
    v.extend_from_slice(body);
    v
}

fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.iter().flat_map(|p| p.iter().copied()).collect()
}

const RID: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
const RID_N: u64 = 0x0102030405060708;
/// proof_kind 0: a page or a native app.
const PAGE: [u8; 9] = [1, 2, 3, 4, 5, 6, 7, 8, 0];
const NO_EXT: [u8; 2] = [0, 0];

fn page_header() -> RequestHeader {
    RequestHeader {
        request_id: RID_N,
        proof: None,
    }
}

fn check(req: Request, expected_frame: Vec<u8>) {
    assert_eq!(
        req.encode().unwrap(),
        expected_frame,
        "encoder: {:?}",
        req.op
    );
    let f = Frame::decode(&expected_frame).unwrap();
    assert_eq!(f.frame_type, req.op.frame_type());
    assert_eq!(Request::decode(f.frame_type, f.body).unwrap(), req);
}

fn page_req(op: Operation) -> Request {
    Request {
        header: page_header(),
        op,
        ext: vec![],
    }
}

#[test]
fn generate_import_delete_public_key_export_list_vectors() {
    // Generate, self-named: mode 1, slot_len 0.
    check(
        page_req(Operation::Generate { slot: None }),
        frame(0x80, &cat(&[&PAGE, &[1, 0], &NO_EXT])),
    );
    // Generate, named: mode 0, slot_len, slot.
    check(
        page_req(Operation::Generate {
            slot: Some(vec![0xEE, 0xEF]),
        }),
        frame(0x80, &cat(&[&PAGE, &[0, 2, 0xEE, 0xEF], &NO_EXT])),
    );
    // Import: slot_len, slot, seed 32, replace 1.
    check(
        page_req(Operation::Import {
            slot: vec![0xAA, 0xBB],
            seed: [0x55; 32],
            replace: true,
        }),
        frame(
            0x81,
            &cat(&[&PAGE, &[2, 0xAA, 0xBB], &[0x55; 32], &[1], &NO_EXT]),
        ),
    );
    check(
        page_req(Operation::Import {
            slot: vec![0xAA],
            seed: [0x56; 32],
            replace: false,
        }),
        frame(0x81, &cat(&[&PAGE, &[1, 0xAA], &[0x56; 32], &[0], &NO_EXT])),
    );
    // Delete 0x82, PublicKey 0x83, Export 0x86: slot_len, slot.
    for (ty, op) in [
        (0x82, Operation::Delete { slot: vec![7] }),
        (0x83, Operation::PublicKey { slot: vec![7] }),
        (0x86, Operation::Export { slot: vec![7] }),
    ] {
        check(page_req(op), frame(ty, &cat(&[&PAGE, &[1, 7], &NO_EXT])));
    }
    // List 0x84: after_len, after, max 2.
    check(
        page_req(Operation::List {
            after: vec![1, 2],
            max: 255,
        }),
        frame(0x84, &cat(&[&PAGE, &[2, 1, 2], &[0, 255], &NO_EXT])),
    );
    check(
        page_req(Operation::List {
            after: vec![],
            max: 256,
        }),
        frame(0x84, &cat(&[&PAGE, &[0], &[1, 0], &NO_EXT])),
    );
}

#[test]
fn batch_vectors_with_every_item_kind() {
    // slot_len, slot, expected_public_key 32, count 2, items.
    // Sign: op 1, data_len 4, data. KeyAgreement: op 2, peer 32.
    // Derive: op 3, context_len 2, context, data_len 4, data.
    let items = cat(&[
        &[1, 0, 0, 0, 3, 9, 8, 7],
        &[2],
        &[0x22; 32],
        &[3, 0, 2, b'c', b'x', 0, 0, 0, 1, 0x44],
    ]);
    check(
        page_req(Operation::Batch {
            slot: vec![0xEE],
            expected_public_key: [0x11; 32],
            items: vec![
                BatchItem::Sign(vec![9, 8, 7]),
                BatchItem::KeyAgreement([0x22; 32]),
                BatchItem::Derive {
                    context: "cx".into(),
                    data: vec![0x44],
                },
            ],
        }),
        frame(
            0x85,
            &cat(&[&PAGE, &[1, 0xEE], &[0x11; 32], &[0, 3], &items, &NO_EXT]),
        ),
    );
    // An empty Sign and a Derive with empty data are valid items.
    check(
        page_req(Operation::Batch {
            slot: vec![0xEE],
            expected_public_key: [0x11; 32],
            items: vec![
                BatchItem::Sign(vec![]),
                BatchItem::Derive {
                    context: "z".into(),
                    data: vec![],
                },
            ],
        }),
        frame(
            0x85,
            &cat(&[
                &PAGE,
                &[1, 0xEE],
                &[0x11; 32],
                &[0, 2],
                &[1, 0, 0, 0, 0],
                &[3, 0, 1, b'z', 0, 0, 0, 0],
                &NO_EXT,
            ]),
        ),
    );
}

#[test]
fn proof_kind_1_header_and_extensions_vectors() {
    // request_id 8, proof_kind 1, author_vk 32, app_id_len 1, app_id, record 100.
    let header = cat(&[&RID, &[1], &[0x01; 32], &[3], b"app", &[0x02; 100]]);
    let req = Request {
        header: RequestHeader {
            request_id: RID_N,
            proof: Some(CallerProof {
                author_vk: [0x01; 32],
                app_id: b"app".to_vec(),
                record: [0x02; 100],
            }),
        },
        op: Operation::PublicKey { slot: vec![7] },
        ext: vec![0xAB, 0xCD, 0xEF],
    };
    check(
        req,
        frame(0x83, &cat(&[&header, &[1, 7], &[0, 3, 0xAB, 0xCD, 0xEF]])),
    );
}

#[test]
fn submit_record_vector() {
    let header = cat(&[&RID, &[1], &[0x01; 32], &[3], b"app", &[0x02; 100]]);
    // header, author_vk 32, app_id_len 1, app_id, record 100, ext.
    let body = cat(&[&header, &[0x33; 32], &[4], b"abcd", &[0x66; 100], &NO_EXT]);
    let want = frame(0x21, &body);
    let s = SubmitRecord {
        header: RequestHeader {
            request_id: RID_N,
            proof: Some(CallerProof {
                author_vk: [0x01; 32],
                app_id: b"app".to_vec(),
                record: [0x02; 100],
            }),
        },
        author_vk: [0x33; 32],
        app_id: b"abcd".to_vec(),
        record: [0x66; 100],
        ext: vec![],
    };
    assert_eq!(s.encode().unwrap(), want);
    let f = Frame::decode(&want).unwrap();
    assert_eq!(SubmitRecord::decode(f.body).unwrap(), s);
    // From a page: proof_kind 0.
    let from_page = SubmitRecord {
        header: page_header(),
        ..s
    };
    let want = frame(
        0x21,
        &cat(&[&PAGE, &[0x33; 32], &[4], b"abcd", &[0x66; 100], &NO_EXT]),
    );
    assert_eq!(from_page.encode().unwrap(), want);
}

fn check_result(r: OpResult, ty: u8, body: &[u8]) {
    let want = frame(ty, body);
    assert_eq!(r.encode(RID_N).unwrap(), want, "encoder: {r:?}");
    let f = Frame::decode(&want).unwrap();
    assert_eq!(f.frame_type, ty);
    assert_eq!(OpResult::decode(f.frame_type, f.body).unwrap(), (RID_N, r));
}

#[test]
fn result_frame_vectors_0xa0_to_0xa4() {
    // 0xA0 KeyResult: request_id 8, slot_len, slot, public_key 32, ext.
    check_result(
        OpResult::Key {
            slot: vec![0xEE, 0xEF],
            public_key: [0x77; 32],
        },
        0xA0,
        &cat(&[&RID, &[2, 0xEE, 0xEF], &[0x77; 32], &NO_EXT]),
    );
    // 0xA1 Ok: request_id 8, ext.
    check_result(OpResult::Ok, 0xA1, &cat(&[&RID, &NO_EXT]));
    // 0xA2 ListResult: request_id 8, count 2, rows {slot_len, slot,
    // public_key 32, status 1}, more 1, ext.
    check_result(
        OpResult::List {
            items: vec![
                ListItem {
                    slot: vec![1],
                    public_key: [0x10; 32],
                    status: LIST_OK,
                },
                ListItem {
                    slot: vec![2, 3],
                    public_key: [0x20; 32],
                    status: LIST_CORRUPT,
                },
                ListItem {
                    slot: vec![4],
                    public_key: [0x30; 32],
                    status: LIST_UNUSABLE,
                },
            ],
            more: true,
        },
        0xA2,
        &cat(&[
            &RID,
            &[0, 3],
            &[1, 1],
            &[0x10; 32],
            &[0],
            &[2, 2, 3],
            &[0x20; 32],
            &[1],
            &[1, 4],
            &[0x30; 32],
            &[2],
            &[1],
            &NO_EXT,
        ]),
    );
    check_result(
        OpResult::List {
            items: vec![],
            more: false,
        },
        0xA2,
        &cat(&[&RID, &[0, 0], &[0], &NO_EXT]),
    );
    // 0xA3 BatchResult: request_id 8, count 2, items {status 1, len 2, bytes}, ext.
    check_result(
        OpResult::Batch(vec![
            ItemResult {
                status: ITEM_OK,
                bytes: vec![0xAA; 32],
            },
            ItemResult {
                status: ITEM_FORBIDDEN_SIGNING_DOMAIN,
                bytes: vec![],
            },
        ]),
        0xA3,
        &cat(&[
            &RID,
            &[0, 2],
            &[0, 0, 32],
            &[0xAA; 32],
            &[11, 0, 0],
            &NO_EXT,
        ]),
    );
    // 0xA4 ExportResult: request_id 8, seed 32, ext.
    check_result(
        OpResult::Export { seed: [0x99; 32] },
        0xA4,
        &cat(&[&RID, &[0x99; 32], &NO_EXT]),
    );
}

#[test]
fn a_result_with_an_extension_decodes_and_drops_it() {
    // The extension is accepted at any length and not kept (forward compat).
    let f = frame(0xA1, &cat(&[&RID, &[0, 2, 0xDE, 0xAD]]));
    let fr = Frame::decode(&f).unwrap();
    assert_eq!(
        OpResult::decode(fr.frame_type, fr.body).unwrap(),
        (RID_N, OpResult::Ok)
    );
}

#[test]
fn poke_with_no_record_vector() {
    // flags 1, partition 32, record_present 1 (0), record 100 (zero-filled), ext.
    let p = Poke {
        flags: 0b0001_0001,
        partition: [0x33; 32],
        record: None,
        ext: vec![],
    };
    let want = frame(
        0x20,
        &cat(&[&[0b0001_0001], &[0x33; 32], &[0], &[0; 100], &NO_EXT]),
    );
    assert_eq!(p.encode().unwrap(), want);
    let f = Frame::decode(&want).unwrap();
    assert_eq!(Poke::decode(f.body).unwrap(), p);
}

#[test]
fn entry_vectors_for_both_kinds_flags_and_extensions() {
    // kind 1 ; eflags 1 ; key_len 2 ; key ; content_len 2 ; content ; ext_len 2 ; ext
    let kind2 = Entry::new(2, vec![0xA1, 0xA2, 0xA3], vec![0x66; 100]);
    let want = cat(&[
        &[2, 0, 0, 3, 0xA1, 0xA2, 0xA3],
        &[0, 100],
        &[0x66; 100],
        &NO_EXT,
    ]);
    assert_eq!(kind2.encode().unwrap(), want);
    assert_eq!(Entry::decode(&want).unwrap(), kind2);

    // A key entry flagged corrupt (eflags bit 0) with unknown bits set, and an extension.
    let flagged = Entry {
        kind: 1,
        eflags: 0x81,
        key: vec![5],
        content: vec![9; 32],
        ext: vec![7, 7, 7],
    };
    let want = cat(&[&[1, 0x81, 0, 1, 5], &[0, 32], &[9; 32], &[0, 3, 7, 7, 7]]);
    assert_eq!(flagged.encode().unwrap(), want);
    assert_eq!(Entry::decode(&want).unwrap(), flagged);

    // A reserved kind carries any content verbatim.
    let reserved = Entry {
        kind: 0x30,
        eflags: 0,
        key: vec![1, 2],
        content: vec![0xDD; 5],
        ext: vec![],
    };
    let want = cat(&[&[0x30, 0, 0, 2, 1, 2], &[0, 5], &[0xDD; 5], &NO_EXT]);
    assert_eq!(reserved.encode().unwrap(), want);
    assert_eq!(Entry::decode(&want).unwrap(), reserved);
}

/// ResetPartition 0x88 (protocol 12.5): RequestHeader, then `confirm 32`.
#[test]
fn reset_partition_vector_and_confirm_hash() {
    check(
        page_req(Operation::ResetPartition {
            confirm: [0x33; 32],
        }),
        frame(0x88, &cat(&[&PAGE, &[0x33; 32], &NO_EXT])),
    );
    // confirm = BLAKE3("freenet-vault/reset/v1" || partition), recomputed with
    // b3sum over the ASCII tag followed by 32 bytes of 0x07.
    let want: [u8; 32] = [
        0x49, 0xa8, 0x82, 0x52, 0x0b, 0x68, 0xbb, 0x17, 0x68, 0x53, 0x47, 0x62, 0x7e, 0x39, 0x54,
        0x26, 0x6d, 0x42, 0xd3, 0xd8, 0xf7, 0xf9, 0x16, 0x4c, 0xa5, 0xaa, 0xb5, 0x7f, 0xf5, 0x1d,
        0xbc, 0x3d,
    ];
    assert_eq!(freenet_vault_common::hash::reset_confirm(&[0x07; 32]), want);
}
