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

/// Export's lookup never changes storage: an unparseable slot is reported
/// Unusable(2) and stays in the index, so a user who denies loses nothing.
#[test]
fn export_does_not_drop_an_unparseable_slot() {
    let mut h = MemHost::new();
    let (slot, _) = writer_with_key(&mut h);
    let name = entry_name_of(&h, KIND_KEY, &slot);
    h.secrets.insert(name, vec![0xFF; 5]);
    let before = h.secrets.clone();
    assert!(matches!(
        page(&mut h, op(2, Operation::Export { slot: slot.clone() })),
        Reply::St(Status::Unusable { .. })
    ));
    assert_eq!(h.secrets, before, "Export changed storage");
    // The same bytes are dropped by an ordinary read, as before.
    page(&mut h, op(3, Operation::PublicKey { slot: slot.clone() }));
    assert_ne!(h.secrets, before);
}

/// A submitted caller record replaces a mark that stays unreadable, but never
/// below the compiled-in minimum (the stuck-mark repair).
#[test]
fn a_submitted_record_replaces_a_mark_that_stays_unreadable() {
    let dom = leaked_domain(vec![chat_caller(3)], 2);
    let mut h = MemHost::new();
    let (slot, _) = writer_with_key(&mut h);
    let go = |h: &mut MemHost, v: u32| send_in(&dom, h, chat(v).key, pk_req(&chat(v), &slot));
    assert!(is_key_result(&go(&mut h, 8).unwrap()));
    let name = entry_name_of(&h, KIND_CALLER_MARK, &mark_key());
    h.hidden.insert(name);
    let submit = |h: &mut MemHost, v: u32| {
        let s = SubmitRecord {
            header: page_header(6),
            author_vk: vk(&PUBLISHER_SEED),
            app_id: CHAT_APP.to_vec(),
            record: record(&PUBLISHER_SEED, CHAT_APP, v, [v as u8; 32]),
            ext: vec![],
        };
        let out = process(
            &dom,
            h,
            &[],
            Some(&page_origin()),
            page_in(s.encode().unwrap()),
        );
        single_app_reply(out.unwrap())
    };
    // Below the compiled-in minimum: refused, nothing replaced.
    assert_eq!(
        submit(&mut h, 2),
        refused(6, refused::CALLER_NOT_AUTHORIZED)
    );
    // At or above it: the lost mark is replaced.
    let st = handover(submit(&mut h, 4));
    assert_eq!(st.step_result, step_result::RECORD_ACCEPTED);
    h.hidden.clear();
    assert_eq!(
        go(&mut h, 3),
        Some(refused(77, refused::CALLER_NOT_AUTHORIZED)),
        "the replacement mark (4) now binds"
    );
    assert!(is_key_result(&go(&mut h, 4).unwrap()));
}

fn page_origin() -> MessageOrigin {
    MessageOrigin::WebApp(ContractInstanceId::new(page_id()))
}

fn page_in(payload: Vec<u8>) -> InboundDelegateMsg<'static> {
    InboundDelegateMsg::ApplicationMessage(ApplicationMessage::new(payload))
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
                record: record(&[0x99; 32], b"test.vault", 3, [0x33; 32]),
                ext: vec![],
            }
            .encode()
            .unwrap()
        ),
        refused(3, refused::STORED_RECORD_MALFORMED)
    );
}

/// A permanently unusable `vault:succ` does not block creation for ever: a
/// verified, newer record replaces it.
#[test]
fn a_verified_record_replaces_an_unusable_vault_succ() {
    let mut h = MemHost::new();
    arm(&mut h);
    h.secrets.insert(names::SUCC.to_vec(), vec![9, 9, 9]);
    // Malformed: a change does not create (no_newer is unknown).
    assert_eq!(
        page(&mut h, op(1, Operation::Generate { slot: None })),
        Reply::St(Status::NotHere {
            request_id: 1,
            partition: domain().partition()
        })
    );
    // A Poke carrying the vault's own record at the version it is armed with
    // is not newer, so it cannot repair; a newer verified one does.
    let s = handover(page(&mut h, poke(0, Some(domain_record(1, [0x11; 32])))));
    assert_eq!(s.record_state, record_state::STORED_MALFORMED);
    let s = handover(page(&mut h, poke(0, Some(domain_record(2, [0x22; 32])))));
    assert_eq!(s.step_result, step_result::RECORD_ACCEPTED);
    assert_eq!(s.record_state, record_state::SUCCESSOR);
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

/// What must hold after any crash and the recovery calls that follow: the
/// index parses; every entry the index names exists and
/// matches its digest; no entry secret is untracked; nothing is left in the
/// gc lists. With `clean`, no entry is flagged corrupt and
/// the index counts no lost entries and no problems.
/// A named entry secret and the digest the index holds for it.
type NamedEntry = (Vec<u8>, [u8; 32]);

fn assert_sound(h: &mut MemHost, what: &str, clean: bool) {
    use freenet_vault_common::hash::entry_digest;
    let p = domain().partition();
    let named: Vec<NamedEntry> = {
        let s = Store::open(h, p).unwrap_or_else(|_| panic!("{what}: index malformed"));
        if clean {
            assert_eq!(s.index.lost_entries, 0, "{what}: lost entries");
            assert_eq!(s.index.problems, 0, "{what}: problems raised");
        }
        s.index
            .entries
            .iter()
            .map(|e| (names::entry(&p, e.kind, &e.key, e.parity), e.digest))
            .collect()
    };
    for (n, digest) in &named {
        let b = h
            .secrets
            .get(n)
            .unwrap_or_else(|| panic!("{what}: an indexed entry is missing"));
        assert_eq!(&entry_digest(b), digest, "{what}: digest differs");
        let e = Entry::decode(b).unwrap_or_else(|_| panic!("{what}: an indexed entry is bad"));
        if clean {
            assert!(!e.is_flagged_corrupt(), "{what}");
        }
    }
    for n in h.names_with_prefix(&names::entry_prefix(&p)) {
        assert!(
            named.iter().any(|(m, _)| m == &n),
            "{what}: an untracked entry secret"
        );
    }
    // A pending gc name may remain while no secret exists under it (a candidate
    // that never landed is dropped after a few passes); a secret left under a
    // pending name is caught by the untracked-entry check above.
    for n in crate::storage::pending_gc_names(h, &p) {
        assert!(
            !h.secrets.contains_key(&n) || named.iter().any(|(m, _)| m == &n),
            "{what}: a pending gc name still holds a secret"
        );
    }
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
    clean: bool,
) {
    let mut dry = MemHost::new();
    setup(&mut dry);
    let start = dry.mutations;
    act(&mut dry);
    let total = dry.mutations - start;
    assert!(total >= 1, "{what}: the action writes nothing to sweep");
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
            assert_sound(&mut r, &label, clean);
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
        true,
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
        true,
    );
}

#[test]
fn crash_sweep_delete() {
    sweep(
        "delete",
        setup_writer_with_key,
        |h| act_page(h, Operation::Delete { slot: vec![1; 32] }),
        |h| matches!(slot_seed(h, 1), None | Some([0xA1, ..])),
        true,
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
        true,
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
        true,
    );
}

#[test]
fn crash_sweep_import_of_a_new_slot() {
    sweep(
        "import new slot",
        setup_writer_with_key,
        |h| {
            act_page(
                h,
                Operation::Import {
                    slot: vec![2; 32],
                    seed: [0xC3; 32],
                    replace: false,
                },
            )
        },
        |h| {
            slot_seed(h, 1) == Some([0xA1; 32])
                && matches!(slot_seed(h, 2), None | Some([0xC3, ..]))
        },
        true,
    );
}

/// The corrupt-flag rewrite in `read()`: bytes that still parse are rewritten
/// flagged, at the other parity, with the index updated.
#[test]
fn crash_sweep_flagging_a_corrupt_entry() {
    sweep(
        "flag rewrite",
        |h| {
            setup_writer_with_key(h);
            tamper_seed(h, &[1; 32]);
        },
        |h| act_page(h, Operation::PublicKey { slot: vec![1; 32] }),
        |h| {
            let mut s = Store::open(h, domain().partition()).unwrap();
            // Flagged corrupt (the recovery's List flags it if the crash came first).
            matches!(s.read(KIND_KEY, &[1; 32], false), Read::Corrupt(Some(_)))
        },
        false,
    );
}

/// The read-drop: bytes that do not parse are removed from the index, counted
/// lost, and their copies gc'd.
#[test]
fn crash_sweep_dropping_an_unparseable_entry() {
    sweep(
        "read drop",
        |h| {
            setup_writer_with_key(h);
            let name = entry_name_of(h, KIND_KEY, &[1; 32]);
            h.secrets.insert(name, vec![0xFF; 5]);
        },
        |h| act_page(h, Operation::PublicKey { slot: vec![1; 32] }),
        |h| slot_seed(h, 1).is_none(),
        false,
    );
}

/// Poke arming writes the index of a partition that does not exist yet.
#[test]
fn crash_sweep_poke_arm() {
    sweep(
        "poke arm",
        |_| {},
        |h| {
            let _ = from_page_as(
                h,
                page_id(),
                poke(poke_flags::ARM, Some(domain_record(1, [0x11; 32]))),
            );
        },
        |h| {
            let s = Store::open(h, domain().partition()).unwrap();
            !s.has_index() || s.index.armed.is_some()
        },
        true,
    );
}

/// SubmitRecord of a domain record writes `vault:succ`.
#[test]
fn crash_sweep_submit_record() {
    sweep(
        "submit record",
        setup_writer_with_key,
        |h| {
            let s = SubmitRecord {
                header: page_header(2),
                author_vk: vk(&DOMAIN_SEED),
                app_id: b"test.vault".to_vec(),
                record: domain_record(2, [0x22; 32]),
                ext: vec![],
            };
            let _ = from_page_as(h, page_id(), s.encode().unwrap());
        },
        |h| crate::succ::Succ::load(&domain(), h).is_ok(),
        true,
    );
}

/// Creating the partition by a caller needs `ensure_part_listed`, the entry
/// and the index; a delegate cannot create (its operations are not changes),
/// so this is the page's Import into an armed, empty vault.
#[test]
fn crash_sweep_creation_by_import() {
    sweep(
        "creation by import",
        arm,
        |h| {
            act_page(
                h,
                Operation::Import {
                    slot: vec![1; 32],
                    seed: [0xA1; 32],
                    replace: false,
                },
            )
        },
        |h| {
            let s = Store::open(h, domain().partition()).unwrap();
            match s.index.state {
                State::None => s.index.entries.is_empty(),
                State::Writer => s.index.entries.len() == 1,
                _ => false,
            }
        },
        true,
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
            check_one(state, &base, origin, msg);
        }
    }
}

/// Runs one message against a copy of `base` and checks the invariants: no
/// panic, no reply carrying a stored seed, and no change to storage unless
/// the reply is a result or a HandoverStatus.
fn check_one(
    state: &str,
    base: &MemHost,
    origin: Option<MessageOrigin>,
    msg: InboundDelegateMsg<'static>,
) {
    let seed_bytes: Vec<[u8; 32]> = base
        .secrets
        .values()
        .filter(|v| v.len() == 72)
        .map(|v| v[38..70].try_into().unwrap())
        .collect();
    let mut h = MemHost::new();
    h.secrets = base.secrets.clone();
    let before = h.secrets.clone();
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

/// The decoders of persisted state run on every call, so a panic in one is a
/// trap that bricks the vault: none may panic on damaged bytes, including
/// damaged bodies with a correct checksum (which reach the parser), and an
/// index that decodes round-trips.
#[test]
fn persisted_state_decoders_never_panic() {
    use crate::consent::Pending;
    use crate::succ::Succ;
    let mut rnd = prng("persisted decoders");
    let mut h = MemHost::new();
    writer_with_key(&mut h);
    let slot = seed_slot_of(&h);
    chat_pk(&mut h, 5, &slot);
    page(&mut h, poke(0, Some(domain_record(2, [0x22; 32]))));
    let index = h.secrets[&names::index(&domain().partition())].clone();
    let succ = h.secrets[names::SUCC].clone();
    let pending = Pending {
        prompt_id: 7,
        origin: [3; 32],
        request_id: 9,
        slot: vec![1; 32],
    }
    .encode();
    assert_eq!(Pending::decode(&pending).unwrap().prompt_id, 7);
    for i in 0..20_000 {
        let mut damaged = |valid: &[u8], rechecksum: bool| {
            let mut v = valid.to_vec();
            for _ in 0..1 + rnd(1)[0] % 3 {
                let at = rnd(2).iter().fold(0usize, |a, b| a * 256 + *b as usize) % v.len();
                v[at] ^= rnd(1)[0] | 1;
            }
            if rechecksum && v.len() > 32 {
                let n = v.len() - 32;
                let sum = *blake3::hash(&v[..n]).as_bytes();
                v[n..].copy_from_slice(&sum);
            }
            match rnd(1)[0] % 4 {
                0 => v.truncate(rnd(1)[0] as usize % (v.len() + 1)),
                1 => v.extend(rnd(2)),
                _ => {}
            }
            v
        };
        let ix = damaged(&index, i % 2 == 0);
        if let Ok(decoded) = Index::decode(&ix) {
            assert_eq!(Index::decode(&decoded.encode()).unwrap(), decoded);
        }
        let _ = Succ::decode(&damaged(&succ, false));
        let _ = Pending::decode(&damaged(&pending, false));
        let n = rnd(1)[0] as usize % 150;
        let junk = rnd(n);
        let _ = (
            Index::decode(&junk),
            Succ::decode(&junk),
            Pending::decode(&junk),
        );
    }
}

/// The one slot of a vault holding one key (test helper).
fn seed_slot_of(h: &MemHost) -> Vec<u8> {
    let p = domain().partition();
    Index::decode(&h.secrets[&names::index(&p)])
        .unwrap()
        .entries
        .iter()
        .find(|e| e.kind == KIND_KEY)
        .unwrap()
        .key
        .clone()
}

/// The undamaged frames, including ones from a stale caller (below its mark,
/// the caller-mark gate's refusal), from every origin the vault can see.
#[test]
fn every_valid_frame_from_every_origin_obeys_the_same_invariants() {
    let slot = vec![0x5A; 32];
    let mut frames = seed_frames(&slot, crypto::public_key(&[0x5A; 32]));
    let stale = chat(4);
    frames.push(pk_req(&stale, &slot));
    frames.push(
        SubmitRecord {
            header: stale.header.clone(),
            author_vk: vk(&DOMAIN_SEED),
            app_id: b"test.vault".to_vec(),
            record: domain_record(2, [0x22; 32]),
            ext: vec![],
        }
        .encode()
        .unwrap(),
    );
    for (state, base) in states() {
        for payload in &frames {
            let page = |id: [u8; 32]| {
                (
                    Some(MessageOrigin::WebApp(ContractInstanceId::new(id))),
                    InboundDelegateMsg::ApplicationMessage(ApplicationMessage::new(
                        payload.clone(),
                    )),
                )
            };
            let mut cases = vec![
                page(page_id()),
                page([0x66; 32]),
                (
                    None,
                    InboundDelegateMsg::ApplicationMessage(ApplicationMessage::new(
                        payload.clone(),
                    )),
                ),
            ];
            for key in [chat(4).key, chat(5).key] {
                cases.push((
                    Some(MessageOrigin::Delegate(delegate_key(key))),
                    InboundDelegateMsg::DelegateMessage(DelegateMessage::new(
                        delegate_key([0xEE; 32]),
                        delegate_key(key),
                        payload.clone(),
                    )),
                ));
            }
            for (origin, msg) in cases {
                check_one(state, &base, origin, msg);
            }
        }
    }
}

// ---- round 3: the two sequences that deleted the last acknowledged key ----

/// Replaces `slot`'s seed through `process`; the reply is the page's answer.
fn import_replace(h: &mut MemHost, rid: u64, slot: &[u8], seed: [u8; 32]) -> Reply {
    page(
        h,
        op(
            rid,
            Operation::Import {
                slot: slot.to_vec(),
                seed,
                replace: true,
            },
        ),
    )
}

/// Round 3's first sequence needed a backup index; there is none now. What
/// remains of it: a replace whose index write fails is refused, the old key
/// stays, and the next call (index readable again) finds it intact.
#[test]
fn a_failed_index_write_refuses_the_replace_and_keeps_the_old_seed() {
    let p = domain().partition();
    let mut h = MemHost::new();
    arm(&mut h);
    let slot = vec![7; 32];
    let (a, b) = ([0xA1; 32], [0xB2; 32]);
    assert!(is_key_result(&import_replace(&mut h, 1, &slot, a)));
    let idx = names::index(&p);
    for fault in [WriteFault::Fail, WriteFault::GarbageButFail] {
        let mut d = h.restart();
        let idx = idx.clone();
        d.set_fault(move |n| {
            if n == idx.as_slice() {
                fault
            } else {
                WriteFault::None
            }
        });
        let r = import_replace(&mut d, 2, &slot, b);
        assert!(!is_key_result(&r), "{fault:?}: {r:?}");
        d.clear_fault();
        let mut d = d.restart();
        recover(&mut d);
        recover(&mut d);
        // Garbage in the index is not repaired in v1: the store stays
        // read-only (a stated residual). The key is rescued by Export.
        if fault == WriteFault::Fail {
            assert_eq!(seed_of(&d, &slot), a, "{fault:?}");
        } else {
            assert!(Store::open(&mut d, p).is_err());
        }
    }
}

/// Sequence 2: a replace crashes after writing its candidate and before the
/// index commit; the index still names the original. On restart the index
/// read and the partition list miss transiently while a gc list remains
/// readable. gc must not treat that as a fresh partition and delete the
/// original.
#[test]
fn a_blind_open_never_runs_gc_on_the_committed_original() {
    let p = domain().partition();
    let slot = vec![7; 32];
    let (a, b) = ([0xA1; 32], [0xB2; 32]);
    let mut total = 0;
    for n in 0..40 {
        let mut h = MemHost::new();
        arm(&mut h);
        assert!(is_key_result(&import_replace(&mut h, 1, &slot, a)));
        let start = h.mutations;
        h.crash_after(n);
        let _ = import_replace(&mut h, 2, &slot, b);
        if h.mutations - start < n {
            break;
        }
        total = n;
        let mut h = h.restart();
        h.hidden.insert(names::index(&p));
        h.hidden.insert(names::PARTS.to_vec());
        let _ = from_page_as(
            &mut h,
            page_id(),
            op(
                900,
                Operation::List {
                    after: vec![],
                    max: 100,
                },
            ),
        );
        h.hidden.clear();
        recover(&mut h);
        let s = seed_of(&h, &slot);
        assert!(s == a || s == b, "crash point {n}: the key was lost");
    }
    assert!(total > 2, "the sweep must reach the commit");
}

// ---- round 3: more crash sweeps ------------------------------------------

/// Export of a corrupt slot, flagged or not yet flagged, never mutates
/// storage at either stage (prompt or answer), so there is no write to crash
/// between: the sweep reduces to "zero mutations", and it is checked here.
#[test]
fn export_of_a_corrupt_slot_performs_no_writes() {
    for flag_first in [false, true] {
        let mut h = MemHost::new();
        setup_writer_with_key(&mut h);
        tamper_seed(&mut h, &[1; 32]);
        if flag_first {
            let _ = page(&mut h, op(2, Operation::PublicKey { slot: vec![1; 32] }));
        }
        let before = h.mutations;
        let disk = h.secrets.clone();
        let id = export_prompt(&mut h, &[1; 32], 11);
        let out = answer(&mut h, page_id(), id, b"Allow").unwrap();
        assert!(matches!(
            single_app_reply(out),
            Reply::Op(11, OpResult::Export { .. })
        ));
        assert_eq!(h.mutations, before, "flag_first={flag_first}");
        assert_eq!(h.secrets, disk, "flag_first={flag_first}");
    }
}

/// A mark whose bytes do not parse is replaced by a submitted record. The
/// process dies at every write of one submit; whatever state that leaves, the
/// page repeating the submit reaches the new mark, and storage stays sound
/// (this is the "never stuck" property, since the setup itself is unsound).
#[test]
fn crash_sweep_mark_repair_by_submit_record() {
    let setup = |h: &mut MemHost| {
        setup_writer_with_key(h);
        let c = chat(5);
        let _ = from_delegate_raw(h, c.key, c.key, pk_req(&c, &[1; 32]));
        let name = entry_name_of(h, KIND_CALLER_MARK, &mark_key());
        h.secrets.insert(name, vec![0xFF; 5]);
    };
    let act = |h: &mut MemHost| {
        let s = SubmitRecord {
            header: page_header(6),
            author_vk: vk(&PUBLISHER_SEED),
            app_id: CHAT_APP.to_vec(),
            record: record(&PUBLISHER_SEED, CHAT_APP, 6, [6; 32]),
            ext: vec![],
        };
        let _ = from_page_as(h, page_id(), s.encode().unwrap());
    };
    let mut dry = MemHost::new();
    setup(&mut dry);
    let start = dry.mutations;
    act(&mut dry);
    let total = dry.mutations - start;
    assert!(total >= 1);
    for n in 0..=total {
        let mut h = MemHost::new();
        setup(&mut h);
        h.crash_after(n);
        act(&mut h);
        let mut h = h.restart();
        recover(&mut h);
        act(&mut h);
        let label = format!("mark repair: crash {n} of {total}");
        let mut s = Store::open(&mut h, domain().partition()).unwrap();
        match s.read(KIND_CALLER_MARK, &mark_key(), false) {
            Read::Ok(e) => assert_eq!(
                e.content,
                record(&PUBLISHER_SEED, CHAT_APP, 6, [6; 32]),
                "{label}"
            ),
            other => panic!("{label}: the mark is {other:?}"),
        }
        drop(s);
        assert_sound(&mut h, &label, false);
    }
}

fn replace_key(h: &mut MemHost) {
    act_page(
        h,
        Operation::Import {
            slot: vec![1; 32],
            seed: [0xB2; 32],
            replace: true,
        },
    );
}

fn old_or_new(h: &mut MemHost) -> bool {
    matches!(slot_seed(h, 1), Some(s) if s == [0xA1; 32] || s == [0xB2; 32])
}

/// The index write fails during a replace, then the process dies at every
/// point: the key is the old or the new one.
#[test]
fn crash_sweep_replace_with_a_failing_index_write() {
    sweep(
        "index write fails",
        setup_writer_with_key,
        |h| {
            let idx = names::index(&domain().partition());
            h.set_fault(move |n| {
                if n == idx.as_slice() {
                    WriteFault::Fail
                } else {
                    WriteFault::None
                }
            });
            replace_key(h);
        },
        old_or_new,
        true,
    );
}

/// Writes that land but report failure, for the first index and for the
/// entry copies: the read-back decides, and the key is old or new.
#[test]
fn crash_sweep_replace_with_writes_that_land_but_report_failure() {
    sweep(
        "durable but failed",
        setup_writer_with_key,
        |h| {
            h.set_fault(|_| WriteFault::DurableButFail);
            replace_key(h);
        },
        old_or_new,
        true,
    );
}

// ---- round 4: unknown index state through process() -----------------------

/// A writer holding one key, with its index then made unreadable in the way
/// named: a miss while `vault:parts` lists the partition, or a torn first index.
fn broken_store(torn: bool) -> (MemHost, Vec<u8>) {
    let mut h = MemHost::new();
    let (slot, _) = writer_with_key(&mut h);
    let idx = names::index(&domain().partition());
    assert!(h.secrets.contains_key(names::PARTS));
    if torn {
        let b = h.secrets[&idx].clone();
        h.secrets.insert(idx, b[..b.len() - 5].to_vec());
    } else {
        h.secrets.remove(&idx);
    }
    (h, slot)
}

/// Every request is refused with storage failure and writes nothing; nothing
/// is removed either (a pending gc name keeps its secret).
fn assert_read_only_through_process(torn: bool) {
    let (mut h, slot) = broken_store(torn);
    let p = domain().partition();
    let stray = names::entry(&p, KIND_KEY, &[9; 32], 0);
    h.secrets.insert(stray.clone(), vec![1]);
    let gc = crate::storage::encode_gc_for_test(std::slice::from_ref(&stray));
    h.secrets.insert(names::gc(&p), gc.clone());
    h.secrets.insert(names::gc2(&p), gc);
    let before = h.secrets.clone();
    let m = h.mutations;
    for o in [
        Operation::Generate { slot: None },
        Operation::PublicKey { slot: slot.clone() },
        Operation::Delete { slot: slot.clone() },
        Operation::List {
            after: vec![],
            max: 10,
        },
        Operation::Import {
            slot: vec![3; 32],
            seed: [4; 32],
            replace: true,
        },
    ] {
        assert_eq!(
            page(&mut h, op(5, o)),
            refused(5, refused::STORAGE_FAILURE),
            "torn={torn}"
        );
    }
    // ARM and a record: no arming, and the status reports the failure.
    let st = handover(page(
        &mut h,
        poke(poke_flags::ARM, Some(domain_record(1, [0x11; 32]))),
    ));
    assert_ne!(st.problems & problems::STORAGE_FAILURE, 0, "torn={torn}");
    assert_eq!(h.secrets, before, "torn={torn}: storage changed");
    assert_eq!(h.mutations, m, "torn={torn}: a write was attempted");
}

#[test]
fn a_primary_miss_is_read_only_through_process() {
    assert_read_only_through_process(false);
}

#[test]
fn a_torn_first_index_is_read_only_through_process() {
    assert_read_only_through_process(true);
}

/// Export of a slot while the index is unknown: behind consent, the seed comes
/// back only when exactly one of the two entry copies decodes for the slot.
#[test]
fn export_in_read_only_mode_needs_consent_and_exactly_one_decodable_copy() {
    for torn in [false, true] {
        let (mut h, slot) = broken_store(torn);
        let p = domain().partition();
        let seed = {
            let n = names::entry(&p, KIND_KEY, &slot, 0);
            let e = Entry::decode(&h.secrets[&n]).unwrap();
            <[u8; 32]>::try_from(e.content.as_slice()).unwrap()
        };
        let copy0 = names::entry(&p, KIND_KEY, &slot, 0);
        let copy1 = names::entry(&p, KIND_KEY, &slot, 1);
        let good = h.secrets[&copy0].clone();
        // Denied: nothing is returned.
        let id = export_prompt(&mut h, &slot, 21);
        assert_eq!(
            single_app_reply(answer(&mut h, page_id(), id, b"Deny").unwrap()),
            refused(21, refused::CONSENT_DENIED)
        );
        // Zero copies decode.
        h.secrets.insert(copy0.clone(), vec![0xFF; 4]);
        let id = export_prompt(&mut h, &slot, 22);
        assert_eq!(
            single_app_reply(answer(&mut h, page_id(), id, b"Allow").unwrap()),
            refused(22, refused::STORAGE_FAILURE)
        );
        // Exactly one decodes: allowed.
        h.secrets.insert(copy0.clone(), good.clone());
        let id = export_prompt(&mut h, &slot, 23);
        assert_eq!(
            single_app_reply(answer(&mut h, page_id(), id, b"Allow").unwrap()),
            Reply::Op(23, OpResult::Export { seed })
        );
        // Two decode: refused.
        h.secrets.insert(copy1, good);
        let id = export_prompt(&mut h, &slot, 24);
        assert_eq!(
            single_app_reply(answer(&mut h, page_id(), id, b"Allow").unwrap()),
            refused(24, refused::STORAGE_FAILURE)
        );
    }
}

/// Both gc list copies unreadable while entries exist: a delete (which must
/// list names) fails and the lists are not rewritten.
#[test]
fn both_gc_lists_unreadable_blocks_a_delete_through_process() {
    let mut h = MemHost::new();
    let (slot, _) = writer_with_key(&mut h);
    let p = domain().partition();
    h.hidden.insert(names::gc(&p));
    h.hidden.insert(names::gc2(&p));
    let before = h.secrets.clone();
    assert_eq!(
        page(&mut h, op(5, Operation::Delete { slot: slot.clone() })),
        refused(5, refused::STORAGE_FAILURE)
    );
    assert_eq!(h.secrets, before);
    h.hidden.clear();
    assert!(matches!(
        page(&mut h, op(6, Operation::Delete { slot })),
        Reply::Op(6, OpResult::Ok)
    ));
}

/// An uncertain index commit, then a second write in the same call: a Batch of
/// delegate work cannot reach two commits, so the same-call property is pinned
/// at the store (`an_uncertain_commit_makes_the_rest_of_the_call_read_only`);
/// here the next process() call after a torn commit is read-only too.
#[test]
fn after_an_uncertain_commit_the_next_call_is_read_only_until_the_index_reads() {
    let mut h = MemHost::new();
    let (slot, _) = writer_with_key(&mut h);
    let idx = names::index(&domain().partition());
    h.set_fault(move |n| {
        if n == idx.as_slice() {
            WriteFault::GarbageButFail
        } else {
            WriteFault::None
        }
    });
    let r = import_replace(&mut h, 2, &slot, [0xB2; 32]);
    assert!(!is_key_result(&r), "{r:?}");
    h.clear_fault();
    assert_eq!(
        page(&mut h, op(3, Operation::PublicKey { slot })),
        refused(3, refused::STORAGE_FAILURE)
    );
}
