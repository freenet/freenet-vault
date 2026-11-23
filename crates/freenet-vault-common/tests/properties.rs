//! Decoders never panic, and what a decoder accepts re-encodes to the same
//! bytes (the formats are canonical). Inputs are random bytes and damaged
//! valid frames from a fixed-seed generator, so a failure reproduces.

use freenet_vault_common::entry::Entry;
use freenet_vault_common::frame::{self, types, Frame};
use freenet_vault_common::ops::*;
use freenet_vault_common::status::{HandoverStatus, Poke, Status};

struct Rng(blake3::OutputReader);

impl Rng {
    fn new(label: &str) -> Self {
        let mut h = blake3::Hasher::new();
        h.update(label.as_bytes());
        Self(h.finalize_xof())
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        let mut v = vec![0u8; n];
        self.0.fill(&mut v);
        v
    }
    fn below(&mut self, n: usize) -> usize {
        let b = self.bytes(4);
        u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize % n
    }
}

fn damage(rng: &mut Rng, valid: &[u8]) -> Vec<u8> {
    let mut f = valid.to_vec();
    for _ in 0..1 + rng.below(3) {
        if f.is_empty() {
            break;
        }
        let at = rng.below(f.len());
        f[at] ^= (rng.bytes(1)[0]) | 1;
    }
    match rng.below(4) {
        0 => f.truncate(rng.below(f.len() + 1)),
        1 => {
            let n = 1 + rng.below(4);
            f.extend(rng.bytes(n))
        }
        _ => {}
    }
    f
}

fn valid_bodies() -> Vec<(u8, Vec<u8>)> {
    let header = RequestHeader {
        request_id: 7,
        proof: Some(CallerProof {
            author_vk: [1; 32],
            app_id: b"app".to_vec(),
            record: [2; 100],
        }),
    };
    let page = RequestHeader {
        request_id: 7,
        proof: None,
    };
    let reqs = [
        Operation::Generate { slot: None },
        Operation::Generate {
            slot: Some(vec![5; 32]),
        },
        Operation::Import {
            slot: vec![5; 32],
            seed: [6; 32],
            replace: true,
        },
        Operation::Delete { slot: vec![5; 32] },
        Operation::PublicKey { slot: vec![5; 32] },
        Operation::List {
            after: vec![1, 2],
            max: 9,
        },
        Operation::Batch {
            slot: vec![5; 32],
            expected_public_key: [7; 32],
            items: vec![
                BatchItem::Sign(vec![1, 2, 3]),
                BatchItem::KeyAgreement([8; 32]),
                BatchItem::Derive {
                    context: "ctx".into(),
                    data: vec![9],
                },
            ],
        },
        Operation::Export { slot: vec![5; 32] },
    ];
    let mut out = vec![];
    for op in reqs {
        for h in [&header, &page] {
            let r = Request {
                header: h.clone(),
                op: op.clone(),
                ext: vec![3, 4],
            };
            out.push((r.op.frame_type(), r.encode_body().unwrap()));
        }
    }
    let s = SubmitRecord {
        header: header.clone(),
        author_vk: [1; 32],
        app_id: b"app".to_vec(),
        record: [2; 100],
        ext: vec![],
    };
    out.push((
        types::SUBMIT_RECORD,
        Frame::decode(&s.encode().unwrap()).unwrap().body.to_vec(),
    ));
    out
}

/// Decodes `body` as every request type; anything accepted must re-encode to
/// exactly the same body.
fn check_request(frame_type: u8, body: &[u8]) {
    if frame_type == types::SUBMIT_RECORD {
        if let Ok(s) = SubmitRecord::decode(body) {
            let again = s.encode().expect("an accepted SubmitRecord re-encodes");
            assert_eq!(Frame::decode(&again).unwrap().body, body);
        }
    } else if let Ok(r) = Request::decode(frame_type, body) {
        let again = r.encode_body().expect("an accepted request re-encodes");
        assert_eq!(again, body, "request type {frame_type:#x}");
    }
}

#[test]
fn request_decoders_never_panic_and_accepted_input_is_canonical() {
    let mut rng = Rng::new("request fuzz");
    let valid = valid_bodies();
    // The valid ones themselves are accepted and canonical.
    for (t, b) in &valid {
        check_request(*t, b);
        if *t == types::SUBMIT_RECORD {
            assert!(SubmitRecord::decode(b).is_ok());
        } else {
            assert!(Request::decode(*t, b).is_ok(), "type {t:#x}");
        }
    }
    for i in 0..20_000 {
        let (t, body) = if i % 2 == 0 {
            let n = rng.below(300);
            ((0x80 + rng.below(8)) as u8, rng.bytes(n))
        } else {
            let (t, b) = &valid[rng.below(valid.len())];
            (*t, damage(&mut rng, b))
        };
        check_request(t, &body);
    }
}

#[test]
fn envelope_result_status_poke_entry_decoders_never_panic() {
    let mut rng = Rng::new("other decoder fuzz");
    let status_valid = [
        Status::Refused {
            request_id: 1,
            reason: 3,
        }
        .encode()
        .unwrap(),
        Status::Absent {
            request_id: 1,
            partition: [1; 32],
            slot: vec![2; 32],
        }
        .encode()
        .unwrap(),
        Status::Handover(HandoverStatus {
            request_id: 1,
            own_version: 2,
            floor_version: 3,
            record_state: 1,
            step_result: 2,
            partition_state: 1,
            peer_record: [4; 100],
            receiving_from: 5,
            taken_over_from: 6,
            taken_over_manifest: [7; 32],
            manifest_digest: [8; 32],
            problems: 9,
            lost_entries: 10,
        })
        .encode()
        .unwrap(),
        Poke {
            flags: 2,
            partition: [1; 32],
            record: Some([2; 100]),
            ext: vec![],
        }
        .encode()
        .unwrap(),
        OpResult::Batch(vec![ItemResult {
            status: 0,
            bytes: vec![1; 64],
        }])
        .encode(1)
        .unwrap(),
        OpResult::List {
            items: vec![ListItem {
                slot: vec![1; 32],
                public_key: [2; 32],
                status: 0,
            }],
            more: true,
        }
        .encode(1)
        .unwrap(),
        OpResult::Key {
            slot: vec![1; 32],
            public_key: [2; 32],
        }
        .encode(1)
        .unwrap(),
    ];
    let entries = [
        Entry::new(1, vec![1; 32], vec![2; 32]).encode().unwrap(),
        Entry::new(2, vec![1; 40], vec![2; 100]).encode().unwrap(),
        Entry::new(0x30, vec![1], vec![2; 500]).encode().unwrap(),
    ];
    for i in 0..20_000 {
        // Envelope and body decoders on whatever comes.
        let raw = if i % 2 == 0 {
            let n = rng.below(200);
            rng.bytes(n)
        } else {
            {
                let k = rng.below(status_valid.len());
                damage(&mut rng, &status_valid[k])
            }
        };
        if let Ok(f) = Frame::decode(&raw) {
            // Accepted envelopes re-encode exactly.
            assert_eq!(frame::encode(f.frame_type, f.body).unwrap(), raw);
            if let Ok(s) = Status::decode(f.frame_type, f.body) {
                assert_eq!(s.encode().unwrap(), raw, "status {:#x}", f.frame_type);
            }
            if f.frame_type == types::POKE {
                if let Ok(p) = Poke::decode(f.body) {
                    assert_eq!(p.encode().unwrap(), raw);
                }
            }
            if f.frame_type >= types::KEY_RESULT {
                if let Ok((rid, r)) = OpResult::decode(f.frame_type, f.body) {
                    assert_eq!(r.encode(rid).unwrap(), raw, "result {:#x}", f.frame_type);
                }
            }
        }
        // Entries.
        let k = rng.below(entries.len());
        let e = damage(&mut rng, &entries[k]);
        if let Ok(entry) = Entry::decode(&e) {
            assert_eq!(entry.encode().unwrap(), e);
        }
        let n = rng.below(120);
        let _ = Entry::decode(&rng.bytes(n));
    }
}
