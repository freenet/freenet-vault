//! Tests added after the first review round (REVIEW items 1 to 11 and the
//! "Tests to add" list): export of a corrupt slot, the caller-mark gate on
//! SubmitRecord, compiled-in `min_version`, unreadable secrets, stored
//! successor verification, quota edges, a crash-point sweep through
//! `process`, and a no-panic / no-change-on-refusal property check.

use super::*;
use crate::storage::index::Index;
use crate::storage::Read;
use freenet_vault_common::entry::{EFLAG_CORRUPT, KIND_CALLER_MARK};

// ---- helpers -------------------------------------------------------------

/// The secret name of the stored copy of `(kind, key)`.
fn entry_name_of(h: &MemHost, kind: u8, key: &[u8]) -> Vec<u8> {
    let p = domain().partition();
    let ix = Index::decode(&h.secrets[&names::index(&p)]).unwrap();
    let ie = &ix.entries[ix.find(kind, key).unwrap()];
    names::entry(&p, kind, key, ie.parity)
}

/// Changes a seed byte so the bytes still parse but fail the digest; the next
/// read flags the entry corrupt.
fn tamper_seed(h: &mut MemHost, slot: &[u8]) {
    let name = entry_name_of(h, KIND_KEY, slot);
    let mut b = h.secrets[&name].clone();
    // kind 1 + eflags 1 + key_len 2 + key 32 + content_len 2 = 38.
    b[40] ^= 1;
    h.secrets.insert(name, b);
}

fn mark_key() -> Vec<u8> {
    [vk(&PUBLISHER_SEED).as_slice(), CHAT_APP].concat()
}

fn chat_with(version: u32, code_hash: [u8; 32]) -> ChatBuild {
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

/// A delegate request under an explicit domain; returns the reply, or `None`
/// when the vault stayed silent.
fn send_in(dom: &Domain, h: &mut MemHost, key: [u8; 32], payload: Vec<u8>) -> Option<Reply> {
    let out = process(
        dom,
        h,
        &[],
        Some(&MessageOrigin::Delegate(delegate_key(key))),
        InboundDelegateMsg::DelegateMessage(DelegateMessage::new(
            delegate_key([0xEE; 32]),
            delegate_key(key),
            payload,
        )),
    )
    .expect("process");
    match out.as_slice() {
        [] => None,
        [OutboundDelegateMsg::SendDelegateMessage(m)] => Some(decode_reply(&m.payload)),
        other => panic!("{other:?}"),
    }
}

fn pk_req(c: &ChatBuild, slot: &[u8]) -> Vec<u8> {
    req(
        c.header.clone(),
        Operation::PublicKey {
            slot: slot.to_vec(),
        },
    )
}

fn leaked_domain(callers: Vec<CallerDelegate>, max_caller_marks: usize) -> Domain {
    Domain {
        caller_delegates: Box::leak(callers.into_boxed_slice()),
        max_caller_marks,
        ..domain()
    }
}

fn chat_caller(min_version: u32) -> CallerDelegate {
    CallerDelegate {
        author_vk: vk(&PUBLISHER_SEED),
        app_id: CHAT_APP,
        min_version,
    }
}

fn submit_domain_record_from(h: &mut MemHost, c: &ChatBuild, rec: [u8; 100]) -> Reply {
    let s = SubmitRecord {
        header: c.header.clone(),
        author_vk: vk(&DOMAIN_SEED),
        app_id: b"test.vault".to_vec(),
        record: rec,
        ext: vec![],
    };
    from_delegate(h, c.key, s.encode().unwrap())
}

fn is_key_result(r: &Reply) -> bool {
    matches!(r, Reply::Op(_, OpResult::Key { .. }))
}

fn secrets_with_prefix(h: &MemHost, prefix: &[u8]) -> usize {
    h.names_with_prefix(prefix).len()
}

// ---- item 1: HandoverStatus is the revision 7 layout ---------------------

#[test]
fn a_poke_reply_is_the_revision_7_frame() {
    let mut h = MemHost::new();
    let out = from_page_as(
        &mut h,
        page_id(),
        poke(poke_flags::ARM, Some(domain_record(1, [0x11; 32]))),
    );
    let OutboundDelegateMsg::ApplicationMessage(m) = &out[0] else {
        panic!("{out:?}")
    };
    let f = Frame::decode(&m.payload).unwrap();
    assert_eq!(f.frame_type, types::HANDOVER_STATUS);
    // 8 + 4 + 4 + 1 + 1 + 1 + 100 + 4 + 4 + 32 + 32 + 1 + 2 + 2 (revision 7).
    assert_eq!(f.body.len(), 196);
    assert_eq!(f.body[19..19 + 100], [0u8; 100], "no peer record yet");
}

// ---- item 2: Export on a corrupt slot ------------------------------------

#[test]
fn export_of_a_corrupt_slot_is_allowed_after_consent_and_repairs() {
    let mut h = MemHost::new();
    let (slot, pk) = writer_with_key(&mut h);
    let seed = seed_of(&h, &slot);
    tamper_seed(&mut h, &slot);
    let p = domain().partition();
    // Every other use answers Unusable(2) (this read flags the entry).
    assert_eq!(
        page(&mut h, op(2, Operation::PublicKey { slot: slot.clone() })),
        Reply::St(Status::Unusable {
            request_id: 2,
            partition: p,
            slot: slot.clone(),
            reason: unusable::CORRUPT,
        })
    );
    // Export asks, and on Allow returns the flagged bytes' seed.
    let mut flagged = seed;
    flagged[2] ^= 1;
    let id = export_prompt(&mut h, &slot, 3);
    assert_eq!(
        single_app_reply(answer(&mut h, page_id(), id, b"Allow").unwrap()),
        Reply::Op(3, OpResult::Export { seed: flagged })
    );
    // The page sees the derived key is not the identity it expects and
    // re-Imports the right seed with replace.
    assert_ne!(crypto::public_key(&flagged), pk);
    assert!(is_key_result(&page(
        &mut h,
        op(
            4,
            Operation::Import {
                slot: slot.clone(),
                seed,
                replace: true
            }
        )
    )));
    assert_eq!(
        page(&mut h, op(5, Operation::PublicKey { slot: slot.clone() })),
        Reply::Op(
            5,
            OpResult::Key {
                slot: slot.clone(),
                public_key: pk
            }
        )
    );
}

/// The answer reads the slot again: what is there when the user answers is
/// what is exported, or Absent if it is gone.
#[test]
fn an_export_answer_reads_the_slot_as_it_is_when_the_user_answers() {
    // Deleted between prompt and answer.
    let mut h = MemHost::new();
    let (slot, _) = writer_with_key(&mut h);
    let id = export_prompt(&mut h, &slot, 3);
    page(&mut h, op(4, Operation::Delete { slot: slot.clone() }));
    assert_eq!(
        single_app_reply(answer(&mut h, page_id(), id, b"Allow").unwrap()),
        Reply::St(Status::Absent {
            request_id: 3,
            partition: domain().partition(),
            slot: slot.clone()
        })
    );
    // Replaced: the new key is exported, never a stale copy.
    let mut h = MemHost::new();
    let (slot, _) = writer_with_key(&mut h);
    let id = export_prompt(&mut h, &slot, 3);
    page(
        &mut h,
        op(
            4,
            Operation::Import {
                slot: slot.clone(),
                seed: [0x77; 32],
                replace: true,
            },
        ),
    );
    assert_eq!(
        single_app_reply(answer(&mut h, page_id(), id, b"Allow").unwrap()),
        Reply::Op(3, OpResult::Export { seed: [0x77; 32] })
    );
    // Flagged corrupt in between: still exportable.
    let mut h = MemHost::new();
    let (slot, _) = writer_with_key(&mut h);
    let seed = seed_of(&h, &slot);
    let id = export_prompt(&mut h, &slot, 3);
    tamper_seed(&mut h, &slot);
    let mut flagged = seed;
    flagged[2] ^= 1;
    assert_eq!(
        single_app_reply(answer(&mut h, page_id(), id, b"Allow").unwrap()),
        Reply::Op(3, OpResult::Export { seed: flagged })
    );
    // Denied: nothing leaves, whatever the slot holds.
    let mut h = MemHost::new();
    let (slot, _) = writer_with_key(&mut h);
    let id = export_prompt(&mut h, &slot, 3);
    assert_eq!(
        single_app_reply(answer(&mut h, page_id(), id, b"Deny").unwrap()),
        refused(3, refused::CONSENT_DENIED)
    );
}

/// Bytes that do not parse as an entry are not exportable: a sealed vault
/// does not drop them, and Export answers Unusable(2).
#[test]
fn export_of_an_unparseable_sealed_slot_is_unusable() {
    let mut h = MemHost::new();
    let (slot, _) = writer_with_key(&mut h);
    let name = entry_name_of(&h, KIND_KEY, &slot);
    h.secrets.insert(name, vec![0xFF; 5]);
    set_state(&mut h, |ix| ix.state = State::Sealed);
    assert_eq!(
        page(&mut h, op(2, Operation::Export { slot: slot.clone() })),
        Reply::St(Status::Unusable {
            request_id: 2,
            partition: domain().partition(),
            slot,
            reason: unusable::CORRUPT,
        })
    );
}

// ---- item 3: SubmitRecord and the caller mark ----------------------------

#[test]
fn a_delegate_submit_record_is_held_to_its_caller_mark() {
    let mut h = MemHost::new();
    let (slot, _) = writer_with_key(&mut h);
    assert!(is_key_result(&chat_pk(&mut h, 5, &slot)));
    // A stale build (4 < mark 5) cannot submit.
    assert_eq!(
        submit_domain_record_from(&mut h, &chat(4), domain_record(2, [0x22; 32])),
        refused(77, refused::CALLER_NOT_AUTHORIZED)
    );
    // A newer build submits, and its version raises the mark.
    let hs = handover(submit_domain_record_from(
        &mut h,
        &chat(6),
        domain_record(2, [0x22; 32]),
    ));
    assert_eq!(hs.step_result, step_result::RECORD_ACCEPTED);
    assert_eq!(
        chat_pk(&mut h, 5, &slot),
        refused(77, refused::CALLER_NOT_AUTHORIZED),
        "version 5 is below the mark the submission raised"
    );
    assert!(is_key_result(&chat_pk(&mut h, 6, &slot)));
}

#[test]
fn a_caller_withdrawal_also_blocks_submit_record() {
    let mut h = MemHost::new();
    writer_with_key(&mut h);
    let s = handover(submit_caller_record(
        &mut h,
        record(&PUBLISHER_SEED, CHAT_APP, 7, [0; 32]),
    ));
    assert_eq!(s.step_result, step_result::RECORD_ACCEPTED);
    for v in [5, 7] {
        assert_eq!(
            submit_domain_record_from(&mut h, &chat(v), domain_record(2, [0x22; 32])),
            refused(77, refused::CALLER_NOT_AUTHORIZED),
            "version {v}"
        );
    }
    assert!(matches!(
        submit_domain_record_from(&mut h, &chat(8), domain_record(2, [0x22; 32])),
        Reply::St(Status::Handover(_))
    ));
}

#[test]
fn a_submit_record_needing_a_raise_is_busy_while_sealed() {
    let mut h = MemHost::new();
    let (slot, _) = writer_with_key(&mut h);
    assert!(is_key_result(&chat_pk(&mut h, 5, &slot)));
    set_state(&mut h, |ix| ix.state = State::Sealed);
    let p = domain().partition();
    assert_eq!(
        submit_domain_record_from(&mut h, &chat(6), domain_record(2, [0x22; 32])),
        Reply::St(Status::Busy {
            request_id: 77,
            partition: p
        })
    );
    // One needing no raise is served.
    assert!(matches!(
        submit_domain_record_from(&mut h, &chat(5), domain_record(2, [0x22; 32])),
        Reply::St(Status::Handover(_))
    ));
}

/// A vault that holds no keys has nowhere to keep a raised mark, so a
/// SubmitRecord needing one is answered as every operation is.
#[test]
fn a_delegate_submit_record_to_a_vault_that_is_not_serving_is_routed() {
    let mut h = MemHost::new();
    assert_eq!(
        submit_domain_record_from(&mut h, &chat(3), domain_record(2, [0x22; 32])),
        Reply::St(Status::NotHere {
            request_id: 77,
            partition: domain().partition()
        })
    );
    let r2 = domain_record(2, [0x22; 32]);
    page(&mut h, poke(0, Some(r2)));
    assert_eq!(
        submit_domain_record_from(&mut h, &chat(3), r2),
        Reply::St(Status::Moved {
            request_id: 77,
            partition: domain().partition(),
            record: r2
        })
    );
    assert_eq!(
        secrets_with_prefix(&h, b"vault:e:"),
        0,
        "no mark was written"
    );
}

// ---- spec decision 3: compiled-in min_version ----------------------------

#[test]
fn min_version_floors_a_fresh_vault_and_one_that_lost_its_mark() {
    let dom = leaked_domain(vec![chat_caller(5)], 2);
    let mut h = MemHost::new();
    let (slot, _) = writer_with_key(&mut h);
    let go = |h: &mut MemHost, v: u32| send_in(&dom, h, chat(v).key, pk_req(&chat(v), &slot));
    // No mark stored yet: below the compiled-in minimum is refused anyway.
    assert_eq!(
        go(&mut h, 4),
        Some(refused(77, refused::CALLER_NOT_AUTHORIZED))
    );
    assert!(is_key_result(&go(&mut h, 5).unwrap()));
    assert!(is_key_result(&go(&mut h, 7).unwrap()));
    // The mark (7) is destroyed beyond parsing: it no longer binds, but the
    // minimum still does, and the next raise rewrites it.
    let name = entry_name_of(&h, KIND_CALLER_MARK, &mark_key());
    h.secrets.insert(name, vec![0xFF; 5]);
    assert_eq!(
        go(&mut h, 4),
        Some(refused(77, refused::CALLER_NOT_AUTHORIZED))
    );
    assert!(is_key_result(&go(&mut h, 5).unwrap()), "floor is 5 again");
    assert_eq!(
        go(&mut h, 4),
        Some(refused(77, refused::CALLER_NOT_AUTHORIZED))
    );
}

/// A mark whose secret does not read (maybe transiently) is served at the
/// compiled-in floor and is never overwritten on that evidence.
#[test]
fn an_unreadable_mark_is_not_overwritten() {
    let dom = leaked_domain(vec![chat_caller(5)], 2);
    let mut h = MemHost::new();
    let (slot, _) = writer_with_key(&mut h);
    let go = |h: &mut MemHost, v: u32| send_in(&dom, h, chat(v).key, pk_req(&chat(v), &slot));
    assert!(is_key_result(&go(&mut h, 8).unwrap()));
    let name = entry_name_of(&h, KIND_CALLER_MARK, &mark_key());
    h.hidden.insert(name.clone());
    let before = h.secrets.clone();
    assert!(
        is_key_result(&go(&mut h, 5).unwrap()),
        "served at the floor"
    );
    assert!(is_key_result(&go(&mut h, 9).unwrap()));
    assert_eq!(h.secrets, before, "nothing was written or removed");
    h.hidden.clear();
    // The mark (8) survived.
    assert_eq!(
        go(&mut h, 5),
        Some(refused(77, refused::CALLER_NOT_AUTHORIZED))
    );
    assert!(is_key_result(&go(&mut h, 8).unwrap()));
}

// ---- caller-mark edge cases on the operation path ------------------------

#[test]
fn an_equal_version_different_record_is_refused() {
    let mut h = MemHost::new();
    let (slot, _) = writer_with_key(&mut h);
    let a = chat_with(5, [5; 32]);
    let b = chat_with(5, [0x55; 32]);
    assert!(is_key_result(&from_delegate(
        &mut h,
        a.key,
        pk_req(&a, &slot)
    )));
    assert_eq!(
        from_delegate(&mut h, b.key, pk_req(&b, &slot)),
        refused(77, refused::CALLER_NOT_AUTHORIZED)
    );
    // The byte-identical record is still served.
    assert!(is_key_result(&from_delegate(
        &mut h,
        a.key,
        pk_req(&a, &slot)
    )));
}

#[test]
fn a_mark_flagged_corrupt_still_binds_and_one_that_does_not_verify_does_not() {
    let mut h = MemHost::new();
    let (slot, _) = writer_with_key(&mut h);
    let q = crate::storage::Quota {
        max_key_slots: 100,
        max_caller_marks: 100,
    };
    let plant = |h: &mut MemHost, e: Entry| {
        let mut s = Store::open(h, domain().partition()).unwrap();
        s.put(&e, &q, |_| {}).unwrap();
    };
    // A valid mark at 5, flagged corrupt by an earlier read.
    let mut flagged = Entry::new(
        KIND_CALLER_MARK,
        mark_key(),
        record(&PUBLISHER_SEED, CHAT_APP, 5, [5; 32]).to_vec(),
    );
    flagged.eflags = EFLAG_CORRUPT;
    plant(&mut h, flagged);
    assert_eq!(
        chat_pk(&mut h, 4, &slot),
        refused(77, refused::CALLER_NOT_AUTHORIZED)
    );
    assert!(is_key_result(&chat_pk(&mut h, 5, &slot)));
    // A "mark" signed by another key does not verify: no floor beyond the
    // compiled-in one, and the next raise replaces it.
    plant(
        &mut h,
        Entry::new(
            KIND_CALLER_MARK,
            mark_key(),
            record(&[0x99; 32], CHAT_APP, 9, [9; 32]).to_vec(),
        ),
    );
    assert!(is_key_result(&chat_pk(&mut h, 2, &slot)));
}

// ---- item 8: stored successor records are verified on load --------------

#[test]
fn a_stored_successor_that_no_longer_verifies_is_never_returned() {
    let mut h = MemHost::new();
    let r2 = domain_record(2, [0x22; 32]);
    page(&mut h, poke(0, Some(r2)));
    let moved = |rid| {
        Reply::St(Status::Moved {
            request_id: rid,
            partition: domain().partition(),
            record: r2,
        })
    };
    assert_eq!(
        page(&mut h, op(1, Operation::Generate { slot: None })),
        moved(1)
    );
    // Flip a bit inside the stored current record (layout: "FVSU" 4, format
    // 1, present 1, then the record).
    let mut b = h.secrets[names::SUCC].clone();
    b[6 + 10] ^= 1;
    h.secrets.insert(names::SUCC.to_vec(), b);
    let s = handover(page(&mut h, poke(0, None)));
    assert_eq!(s.record_state, record_state::STORED_MALFORMED);
    // Not Moved with an invalid record: nothing to point at.
    assert_eq!(
        page(&mut h, op(2, Operation::Generate { slot: None })),
        Reply::St(Status::NotHere {
            request_id: 2,
            partition: domain().partition()
        })
    );
    assert_eq!(
        page(
            &mut h,
            SubmitRecord {
                header: page_header(3),
                author_vk: vk(&DOMAIN_SEED),
                app_id: b"test.vault".to_vec(),
                record: domain_record(3, [0x33; 32]),
                ext: vec![],
            }
            .encode()
            .unwrap()
        ),
        refused(3, refused::STORED_RECORD_MALFORMED)
    );
}

#[test]
fn a_stored_withdrawal_and_a_stored_current_are_checked_for_their_role() {
    let mut h = MemHost::new();
    let w = domain_record(2, [0; 32]);
    page(&mut h, poke(0, Some(w)));
    assert_eq!(
        handover(page(&mut h, poke(0, None))).record_state,
        record_state::STOPPED
    );
    // A withdrawal stored where `current` belongs is malformed.
    let mut b = h.secrets[names::SUCC].clone();
    b[5] = 1; // current_present
    b[6..106].copy_from_slice(&w);
    h.secrets.insert(names::SUCC.to_vec(), b);
    assert_eq!(
        handover(page(&mut h, poke(0, None))).record_state,
        record_state::STORED_MALFORMED
    );
    // A current at or below OWN_VERSION is malformed too.
    let mut b = h.secrets[names::SUCC].clone();
    b[6..106].copy_from_slice(&domain_record(1, [0x11; 32]));
    b[106] = 0;
    h.secrets.insert(names::SUCC.to_vec(), b);
    assert_eq!(
        handover(page(&mut h, poke(0, None))).record_state,
        record_state::STORED_MALFORMED
    );
}

// ---- item 5 at the operation level ---------------------------------------

#[test]
fn a_transient_read_miss_destroys_nothing_and_answers_storage_failure() {
    let mut h = MemHost::new();
    let (slot, pk) = writer_with_key(&mut h);
    let seed = seed_of(&h, &slot);
    let name = entry_name_of(&h, KIND_KEY, &slot);
    h.hidden.insert(name);
    let before = h.secrets.clone();
    for o in [
        Operation::PublicKey { slot: slot.clone() },
        Operation::Export { slot: slot.clone() },
        Operation::Import {
            slot: slot.clone(),
            seed: [4; 32],
            replace: false,
        },
        batch(1, &slot, pk, vec![BatchItem::Sign(vec![1])]),
    ] {
        assert_eq!(page(&mut h, op(8, o)), refused(8, refused::STORAGE_FAILURE));
    }
    // List shows the slot as corrupt with no key; Generate refuses to reuse it.
    let Reply::Op(9, OpResult::List { items, .. }) = page(
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
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].status, LIST_CORRUPT);
    assert_eq!(h.secrets, before, "nothing changed");
    h.hidden.clear();
    assert_eq!(seed_of(&h, &slot), seed);
    assert_eq!(
        page(&mut h, op(10, Operation::PublicKey { slot: slot.clone() })),
        Reply::Op(
            10,
            OpResult::Key {
                slot,
                public_key: pk
            }
        )
    );
}

/// With replace, a page may overwrite an entry the host cannot read.
#[test]
fn import_with_replace_overwrites_an_unreadable_slot() {
    let mut h = MemHost::new();
    let (slot, _) = writer_with_key(&mut h);
    h.hidden.insert(entry_name_of(&h, KIND_KEY, &slot));
    assert!(is_key_result(&page(
        &mut h,
        op(
            2,
            Operation::Import {
                slot: slot.clone(),
                seed: [4; 32],
                replace: true
            }
        )
    )));
    h.hidden.clear();
    assert_eq!(seed_of(&h, &slot), [4; 32]);
}

// ---- quota boundaries ----------------------------------------------------

#[test]
fn key_slot_quota_edges() {
    let mut h = MemHost::new();
    arm(&mut h);
    // The domain allows 4 key slots.
    let mut slots = vec![];
    for i in 0..4u8 {
        match page(
            &mut h,
            op(
                i as u64,
                Operation::Generate {
                    slot: Some(vec![i + 1; 32]),
                },
            ),
        ) {
            Reply::Op(_, OpResult::Key { slot, .. }) => slots.push(slot),
            other => panic!("slot {i}: {other:?}"),
        }
    }
    assert_eq!(
        page(&mut h, op(5, Operation::Generate { slot: None })),
        refused(5, refused::QUOTA)
    );
    assert_eq!(
        page(
            &mut h,
            op(
                6,
                Operation::Import {
                    slot: vec![9; 32],
                    seed: [9; 32],
                    replace: false
                }
            )
        ),
        refused(6, refused::QUOTA)
    );
    // A replace of an existing slot adds no identity, so it fits at the limit.
    assert!(is_key_result(&page(
        &mut h,
        op(
            7,
            Operation::Import {
                slot: slots[0].clone(),
                seed: [3; 32],
                replace: true
            }
        )
    )));
    // After a delete there is room again.
    page(
        &mut h,
        op(
            8,
            Operation::Delete {
                slot: slots[1].clone(),
            },
        ),
    );
    assert!(is_key_result(&page(
        &mut h,
        op(9, Operation::Generate { slot: None })
    )));
}

#[test]
fn caller_mark_quota_edges() {
    let other = CallerDelegate {
        author_vk: vk(&PUBLISHER_SEED),
        app_id: b"test.other",
        min_version: 1,
    };
    let dom = leaked_domain(vec![chat_caller(1), other], 1);
    let mut h = MemHost::new();
    let (slot, _) = writer_with_key(&mut h);
    let chat_go = |h: &mut MemHost, v: u32| send_in(&dom, h, chat(v).key, pk_req(&chat(v), &slot));
    assert!(is_key_result(&chat_go(&mut h, 5).unwrap()));
    // A second caller needs a second mark: over the limit of 1.
    let code = [0x77; 32];
    let o = ChatBuild {
        key: hash::delegate_key_empty_params(&code),
        header: RequestHeader {
            request_id: 78,
            proof: Some(CallerProof {
                author_vk: vk(&PUBLISHER_SEED),
                app_id: b"test.other".to_vec(),
                record: record(&PUBLISHER_SEED, b"test.other", 3, code),
            }),
        },
    };
    assert_eq!(
        send_in(&dom, &mut h, o.key, pk_req(&o, &slot)),
        Some(refused(78, refused::QUOTA))
    );
    // The existing caller's raise replaces its mark and fits at the limit.
    assert!(is_key_result(&chat_go(&mut h, 6).unwrap()));
}

// ---- crash-point sweep through process() ---------------------------------

/// What must hold after any crash and the recovery calls that follow:
/// the index parses, every entry it names reads back with a matching digest,
/// no entry secret is untracked, and nothing is left in `vault:gc`.
fn assert_sound(h: &mut MemHost, what: &str) {
    let p = domain().partition();
    let named: Vec<Vec<u8>> = {
        let s = Store::open(h, p).unwrap_or_else(|_| panic!("{what}: index malformed"));
        s.index
            .entries
            .iter()
            .map(|e| names::entry(&p, e.kind, &e.key, e.parity))
            .collect()
    };
    for n in &named {
        let b = h
            .secrets
            .get(n)
            .unwrap_or_else(|| panic!("{what}: an indexed entry is missing"));
        let e = Entry::decode(b).unwrap_or_else(|_| panic!("{what}: an indexed entry is bad"));
        assert!(!e.is_flagged_corrupt(), "{what}");
    }
    for n in h.names_with_prefix(&names::entry_prefix(&p)) {
        assert!(named.contains(&n), "{what}: an untracked entry secret");
    }
    assert!(
        !h.secrets.contains_key(&names::gc(&p)),
        "{what}: vault:gc left behind"
    );
}

fn recover(h: &mut MemHost) {
    // Any call runs gc first; a List also reads every key.
    let _ = from_page_as(
        h,
        page_id(),
        op(
            900,
            Operation::List {
                after: vec![],
                max: 100,
            },
        ),
    );
}

/// Runs `act` with the process dying after the Nth mutation, for every N;
/// after each, restarts and recovers (itself crashed at every point too) and
/// checks `assert_sound` and the scenario's own `valid` condition.
fn sweep(
    what: &str,
    setup: fn(&mut MemHost),
    act: fn(&mut MemHost),
    valid: fn(&mut MemHost) -> bool,
) {
    let mut dry = MemHost::new();
    setup(&mut dry);
    let start = dry.mutations;
    act(&mut dry);
    let total = dry.mutations - start;
    assert!(total >= 2, "{what}: the action writes nothing to sweep");
    for n in 0..=total {
        let mut h = MemHost::new();
        setup(&mut h);
        h.crash_after(n);
        act(&mut h);
        let disk = h.restart();
        // The recovery call, crashed at every one of its own mutation points.
        let mut d = disk.restart();
        let s = d.mutations;
        recover(&mut d);
        let recover_total = d.mutations - s;
        for m in 0..=recover_total {
            let mut r = disk.restart();
            r.crash_after(m);
            recover(&mut r);
            let mut r = r.restart();
            let label = format!("{what}: crash {n} of {total}, recovery crash {m}");
            recover(&mut r);
            recover(&mut r);
            assert_sound(&mut r, &label);
            assert!(valid(&mut r), "{label}: state is neither old nor new");
        }
    }
}

fn setup_writer_with_key(h: &mut MemHost) {
    arm(h);
    plant_key(h, &[1; 32], [0xA1; 32]);
    set_state(h, |ix| {
        ix.state = State::Writer;
        ix.armed = None;
    });
}

fn slot_seed(h: &mut MemHost, slot: u8) -> Option<[u8; 32]> {
    let mut s = Store::open(h, domain().partition()).ok()?;
    match s.read(KIND_KEY, &[slot; 32], false) {
        Read::Ok(e) => e.content.try_into().ok(),
        _ => None,
    }
}

fn act_page(h: &mut MemHost, o: Operation) {
    let _ = from_page_as(h, page_id(), op(1, o));
}

#[test]
fn crash_sweep_generate() {
    sweep(
        "generate",
        setup_writer_with_key,
        |h| {
            act_page(
                h,
                Operation::Generate {
                    slot: Some(vec![2; 32]),
                },
            )
        },
        // The old key is untouched; the new one is there whole or not at all.
        |h| slot_seed(h, 1) == Some([0xA1; 32]),
    );
}

#[test]
fn crash_sweep_import_replace() {
    sweep(
        "import replace",
        setup_writer_with_key,
        |h| {
            act_page(
                h,
                Operation::Import {
                    slot: vec![1; 32],
                    seed: [0xB2; 32],
                    replace: true,
                },
            )
        },
        |h| matches!(slot_seed(h, 1), Some(s) if s == [0xA1; 32] || s == [0xB2; 32]),
    );
}

#[test]
fn crash_sweep_delete() {
    sweep(
        "delete",
        setup_writer_with_key,
        |h| act_page(h, Operation::Delete { slot: vec![1; 32] }),
        |h| matches!(slot_seed(h, 1), None | Some([0xA1, ..])),
    );
}

/// Creation: the first change on an armed vault writes the part list, the
/// entry, and the index that flips NONE to WRITER.
#[test]
fn crash_sweep_creation() {
    sweep(
        "creation",
        arm,
        |h| act_page(h, Operation::Generate { slot: None }),
        |h| {
            let s = Store::open(h, domain().partition()).unwrap();
            // Either still NONE and armed with no keys, or a writer with the key.
            match s.index.state {
                State::None => s.index.entries.is_empty() && s.index.armed.is_some(),
                State::Writer => s.index.entries.len() == 1,
                _ => false,
            }
        },
    );
}

#[test]
fn crash_sweep_caller_mark_raise() {
    sweep(
        "mark raise",
        setup_writer_with_key,
        |h| {
            let c = chat(5);
            let _ = from_delegate_raw(h, c.key, c.key, pk_req(&c, &[1; 32]));
        },
        |h| {
            // The mark is absent or the version-5 record, never half-written.
            let mut s = Store::open(h, domain().partition()).unwrap();
            match s.read(KIND_CALLER_MARK, &mark_key(), false) {
                Read::Absent => true,
                Read::Ok(e) => e.content == record(&PUBLISHER_SEED, CHAT_APP, 5, [5; 32]),
                _ => false,
            }
        },
    );
}

// ---- no panic, and no change on a refusal --------------------------------

fn prng(label: &str) -> impl FnMut(usize) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(label.as_bytes());
    let mut xof = hasher.finalize_xof();
    move |n| {
        let mut v = vec![0u8; n];
        xof.fill(&mut v);
        v
    }
}

fn states() -> Vec<(&'static str, MemHost)> {
    let fresh = MemHost::new();
    let mut armed = MemHost::new();
    arm(&mut armed);
    let mut writer = MemHost::new();
    let (slot, _) = writer_with_key(&mut writer);
    assert!(is_key_result(&chat_pk(&mut writer, 5, &slot)));
    let mut sealed = MemHost::new();
    writer_with_key(&mut sealed);
    set_state(&mut sealed, |ix| ix.state = State::Sealed);
    vec![
        ("none", fresh),
        ("armed", armed),
        ("writer", writer),
        ("sealed", sealed),
    ]
}

/// Valid frames of every kind, to be damaged.
fn seed_frames(slot: &[u8], pk: [u8; 32]) -> Vec<Vec<u8>> {
    let c = chat(5);
    vec![
        op(1, Operation::Generate { slot: None }),
        op(
            1,
            Operation::Import {
                slot: vec![3; 32],
                seed: [3; 32],
                replace: true,
            },
        ),
        op(
            1,
            Operation::Delete {
                slot: slot.to_vec(),
            },
        ),
        op(
            1,
            Operation::PublicKey {
                slot: slot.to_vec(),
            },
        ),
        op(
            1,
            Operation::List {
                after: vec![],
                max: 5,
            },
        ),
        op(
            1,
            batch(
                1,
                slot,
                pk,
                vec![
                    BatchItem::Sign(vec![1, 2, 3]),
                    BatchItem::KeyAgreement([9; 32]),
                    BatchItem::Derive {
                        context: "ctx".into(),
                        data: vec![1],
                    },
                ],
            ),
        ),
        op(
            1,
            Operation::Export {
                slot: slot.to_vec(),
            },
        ),
        pk_req(&c, slot),
        poke(poke_flags::ARM, Some(domain_record(1, [0x11; 32]))),
        poke(0, Some(domain_record(2, [0x22; 32]))),
        SubmitRecord {
            header: c.header.clone(),
            author_vk: vk(&DOMAIN_SEED),
            app_id: b"test.vault".to_vec(),
            record: domain_record(2, [0x22; 32]),
            ext: vec![],
        }
        .encode()
        .unwrap(),
    ]
}

#[test]
fn arbitrary_bytes_never_panic_and_a_refusal_changes_nothing() {
    let mut rnd = prng("vault process fuzz");
    let probe_slot = vec![0x5A; 32];
    let probe_pk = crypto::public_key(&[0x5A; 32]);
    let frames = seed_frames(&probe_slot, probe_pk);
    let c = chat(5);
    for (state, base) in states() {
        let seed_bytes: Vec<[u8; 32]> = base
            .secrets
            .values()
            .filter(|v| v.len() == 72)
            .map(|v| v[38..70].try_into().unwrap())
            .collect();
        for i in 0..400 {
            // A payload: random, an envelope around random, or a damaged valid frame.
            let payload = match i % 3 {
                0 => {
                    let n = rnd(1)[0] as usize % 200;
                    rnd(n)
                }
                1 => {
                    let mut f = b"FVLT\x01".to_vec();
                    f.extend(rnd(1));
                    let n = rnd(1)[0] as usize % 120;
                    let body = rnd(n);
                    f.extend((body.len() as u32).to_be_bytes());
                    f.extend(body);
                    f
                }
                _ => {
                    let mut f = frames[rnd(1)[0] as usize % frames.len()].clone();
                    for _ in 0..1 + rnd(1)[0] % 3 {
                        let at = rnd(2).iter().fold(0usize, |a, b| a * 256 + *b as usize) % f.len();
                        f[at] ^= rnd(1)[0] | 1;
                    }
                    match rnd(1)[0] % 4 {
                        0 => f.truncate(f.len() / 2),
                        1 => f.extend(rnd(3)),
                        _ => {}
                    }
                    f
                }
            };
            let mut h = MemHost::new();
            h.secrets = base.secrets.clone();
            let before = h.secrets.clone();
            let (origin, msg): (Option<MessageOrigin>, _) = match rnd(1)[0] % 3 {
                0 => (
                    Some(MessageOrigin::WebApp(ContractInstanceId::new(page_id()))),
                    InboundDelegateMsg::ApplicationMessage(ApplicationMessage::new(payload)),
                ),
                1 => (
                    Some(MessageOrigin::WebApp(ContractInstanceId::new([0x66; 32]))),
                    InboundDelegateMsg::ApplicationMessage(ApplicationMessage::new(payload)),
                ),
                _ => (
                    Some(MessageOrigin::Delegate(delegate_key(c.key))),
                    InboundDelegateMsg::DelegateMessage(DelegateMessage::new(
                        delegate_key([0xEE; 32]),
                        delegate_key(c.key),
                        payload,
                    )),
                ),
            };
            // No panic: process returns, Ok or Err.
            let out = process(&domain(), &mut h, &[], origin.as_ref(), msg);
            let mut may_change = false;
            if let Ok(out) = &out {
                for m in out {
                    let bytes = match m {
                        OutboundDelegateMsg::ApplicationMessage(a) => &a.payload,
                        OutboundDelegateMsg::SendDelegateMessage(d) => &d.payload,
                        _ => continue,
                    };
                    // No reply ever contains a stored seed.
                    for s in &seed_bytes {
                        assert!(
                            !bytes.windows(32).any(|w| w == s),
                            "{state}: a reply carries a seed"
                        );
                    }
                    match decode_reply(bytes) {
                        Reply::Op(..) | Reply::St(Status::Handover(_)) => may_change = true,
                        Reply::St(_) => {}
                    }
                }
            }
            if !may_change {
                assert_eq!(h.secrets, before, "{state}: a refusal changed storage");
            }
        }
    }
}
