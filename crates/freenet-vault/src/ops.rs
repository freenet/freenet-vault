//! Request handling: routing by partition state (protocol 5.1), caller marks
//! (protocol 9), the operations (spec 6, protocol 12.5), SubmitRecord and
//! Poke.

use crate::caller::{self, Caller};
use crate::consent::{self, Pending};
use crate::crypto;
use crate::domain::Domain;
use crate::host::Host;
use crate::storage::index::State;
use crate::storage::{rescue_export_seed, reset_partition, PutError, Quota, Read, Store};
use crate::succ::{accept_record, Succ};
use freenet_vault_common::bounds::FORBIDDEN_SIGNING_PREFIX;
use freenet_vault_common::codec::Malformed;
use freenet_vault_common::entry::{Entry, KIND_CALLER_MARK, KIND_KEY};
use freenet_vault_common::frame::{types, Frame};
use freenet_vault_common::ops::{
    is_operation, BatchItem, ItemResult, ListItem, OpResult, Operation, Request, SubmitRecord,
    ITEM_FORBIDDEN_SIGNING_DOMAIN, ITEM_OK, LIST_CORRUPT, LIST_OK, LIST_UNUSABLE,
};
use freenet_vault_common::record::PointerRecord;
use freenet_vault_common::status::{
    partition_state, poke_flags, problems, refused, step_result, unusable, HandoverStatus, Poke,
    Status,
};
use zeroize::Zeroizing;

/// What a request produces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// A reply frame for the caller.
    Reply(Vec<u8>),
    /// Ask the user first (Export). The text is the prompt; the pending
    /// request is already in the context.
    Prompt { prompt_id: u32, text: String },
    /// No output at all (frames a delegate sent that this build ignores).
    Nothing,
}

/// A reply from an encoder result. An encoder fails only when a reply would
/// break a frozen bound, which the operations below never build; if it does,
/// the caller gets storage failure rather than a truncated frame.
fn reply(encoded: Result<Vec<u8>, Malformed>, request_id: u64) -> Outcome {
    match encoded {
        Ok(bytes) => Outcome::Reply(bytes),
        Err(_) => refusal(request_id, refused::STORAGE_FAILURE),
    }
}

fn refusal(request_id: u64, reason: u8) -> Outcome {
    // A Refused frame has a fixed 21-byte shape and cannot fail to encode.
    Outcome::Reply(
        Status::Refused { request_id, reason }
            .encode()
            .unwrap_or_default(),
    )
}

fn status(s: impl Into<Box<Status>>) -> Outcome {
    let s = s.into();
    let rid = s.request_id();
    reply(s.encode(), rid)
}

/// The request id of a frame body that carries one, for answering a request
/// that fails later checks.
fn peek_request_id(frame_type: u8, body: &[u8]) -> u64 {
    if is_operation(frame_type) || frame_type == types::SUBMIT_RECORD {
        Request::peek_request_id(body)
    } else {
        0
    }
}

/// A request from a page (`MessageOrigin::WebApp(id)`).
pub fn handle_page<H: Host>(
    domain: &Domain,
    host: &mut H,
    id: &[u8; 32],
    payload: &[u8],
) -> Outcome {
    let frame = match Frame::decode(payload) {
        Ok(f) => f,
        // Not a vault frame: River has no domain decoder, so it is malformed.
        Err(_) => return refusal(0, refused::MALFORMED),
    };
    let rid = peek_request_id(frame.frame_type, frame.body);
    match frame.frame_type {
        types::POKE => poke(domain, host, domain.is_own_page(id), frame.body),
        types::SUBMIT_RECORD => {
            let s = match SubmitRecord::decode(frame.body) {
                Ok(s) => s,
                Err(_) => return refusal(rid, refused::MALFORMED),
            };
            match caller::page(domain, id, &s.header) {
                Ok(c) => submit_record(domain, host, &c, &s),
                Err(reason) => refusal(rid, reason),
            }
        }
        t if is_operation(t) => {
            if !domain.is_own_page(id) {
                return refusal(rid, refused::CALLER_NOT_AUTHORIZED);
            }
            let req = match Request::decode(t, frame.body) {
                Ok(r) => r,
                Err(_) => return refusal(rid, refused::MALFORMED),
            };
            match caller::page(domain, id, &req.header) {
                Ok(c) => operation(domain, host, &c, req),
                Err(reason) => refusal(rid, reason),
            }
        }
        // Includes 0x87 (reserved since revision 7 removed RetireTo) and the
        // handover frames, which this build does not implement: callers treat
        // Refused(10) as "retry after the handover".
        _ => refusal(rid, refused::UNKNOWN_FRAME),
    }
}

/// A request from a delegate (`MessageOrigin::Delegate(key)`, sender ==
/// key). Anything but an operation or SubmitRecord is ignored: no state
/// change, no output (protocol 6).
pub fn handle_delegate<H: Host>(
    domain: &Domain,
    host: &mut H,
    key: &[u8; 32],
    payload: &[u8],
) -> Outcome {
    let Ok(frame) = Frame::decode(payload) else {
        return Outcome::Nothing;
    };
    let t = frame.frame_type;
    if !(is_operation(t) || t == types::SUBMIT_RECORD) {
        return Outcome::Nothing;
    }
    let rid = peek_request_id(t, frame.body);
    if t == types::SUBMIT_RECORD {
        let s = match SubmitRecord::decode(frame.body) {
            Ok(s) => s,
            Err(_) => return refusal(rid, refused::MALFORMED),
        };
        let c = match caller::delegate(domain, key, &s.header) {
            Ok(c) => c,
            Err(reason) => return refusal(rid, reason),
        };
        if !domain.delegate_frames.contains(&t) {
            return refusal(rid, refused::OPERATION_NOT_ALLOWED);
        }
        return submit_record(domain, host, &c, &s);
    }
    let req = match Request::decode(t, frame.body) {
        Ok(r) => r,
        Err(_) => return refusal(rid, refused::MALFORMED),
    };
    let c = match caller::delegate(domain, key, &req.header) {
        Ok(c) => c,
        Err(reason) => return refusal(rid, reason),
    };
    // Export is never offered to a delegate, whatever the domain lists.
    if !domain.delegate_frames.contains(&t) || t == types::EXPORT || t == types::RESET_PARTITION {
        return refusal(rid, refused::OPERATION_NOT_ALLOWED);
    }
    operation(domain, host, &c, req)
}

/// How a request is routed by the partition's state (protocol 5.1).
enum Route {
    Serve {
        sealed: bool,
        changes_busy: bool,
    },
    /// NONE, armed, and no newer record known: a change creates the partition.
    Create,
    Answer(Box<Status>),
}

fn armed_ok(domain: &Domain, armed: &Option<[u8; 100]>) -> bool {
    armed.as_ref().is_some_and(|a| {
        let r = PointerRecord::decode(a);
        r.version == domain.own_version
            && !r.is_withdrawal()
            && r.verify(&domain.author_vk, domain.app_id).is_ok()
    })
}

fn route<H: Host>(
    domain: &Domain,
    store: &Store<H>,
    succ: &Option<Succ>,
    is_change: bool,
    rid: u64,
) -> Route {
    let partition = domain.partition();
    let elsewhere = || match succ.as_ref().and_then(|s| s.successor()) {
        Some(record) => Route::Answer(Box::new(Status::Moved {
            request_id: rid,
            partition,
            record,
        })),
        None => Route::Answer(Box::new(Status::NotHere {
            request_id: rid,
            partition,
        })),
    };
    let ix = &store.index;
    match ix.state {
        State::None => {
            // Re-checked at creation: still armed with a valid record and no
            // non-withdrawn record above OWN_VERSION known (a malformed
            // stored record counts as unknown, so it never creates).
            let no_newer = succ.as_ref().is_some_and(|s| s.successor().is_none());
            if is_change && no_newer && armed_ok(domain, &ix.armed) {
                Route::Create
            } else {
                elsewhere()
            }
        }
        State::Writer => Route::Serve {
            sealed: false,
            changes_busy: ix.awaiting_retirement,
        },
        State::Sealed => Route::Serve {
            sealed: true,
            changes_busy: true,
        },
        State::Receiving => Route::Answer(Box::new(Status::NotHere {
            request_id: rid,
            partition,
        })),
        State::Retired => Route::Answer(Box::new(Status::Moved {
            request_id: rid,
            partition,
            record: ix.peer_record.unwrap_or([0; 100]),
        })),
    }
}

fn quota(domain: &Domain) -> Quota {
    Quota {
        max_key_slots: domain.max_key_slots,
        max_caller_marks: domain.max_caller_marks,
    }
}

fn put_error(rid: u64, e: PutError) -> Outcome {
    match e {
        PutError::Quota => refusal(rid, refused::QUOTA),
        PutError::Storage => refusal(rid, refused::STORAGE_FAILURE),
    }
}

/// What the store holds for a delegate caller's mark.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StoredMark {
    /// A mark the vault can read and verify.
    Mark([u8; 100]),
    /// None stored, or one that is lost or no longer verifies: the
    /// compiled-in `min_version` is the floor, and the next raise rewrites it
    /// (DESIGN-NOTES.md).
    NoFloor,
    /// The index names a mark whose secret is gone (a wipe or restore, or an
    /// undecryptable blob). The compiled-in floor applies; a valid request
    /// above `min_version` writes the mark again, and one at or below it
    /// leaves the entry alone (there is nothing to raise).
    Unreadable,
}

fn stored_mark<H: Host>(
    store: &mut Store<H>,
    key: &[u8],
    author: &[u8; 32],
    app_id: &[u8],
    sealed: bool,
) -> StoredMark {
    let e = match store.read(KIND_CALLER_MARK, key, sealed) {
        Read::Ok(e) => e,
        Read::Missing => return StoredMark::Unreadable,
        // A corrupt mark imposes no floor above `min_version` (spec 9); the
        // next valid raise rewrites it.
        _ => return StoredMark::NoFloor,
    };
    let Ok(bytes) = <[u8; 100]>::try_from(e.content.as_slice()) else {
        return StoredMark::NoFloor;
    };
    if PointerRecord::decode(&bytes)
        .verify(author, app_id)
        .is_err()
    {
        return StoredMark::NoFloor;
    }
    StoredMark::Mark(bytes)
}

/// Compares an offered caller record with the stored mark.
#[derive(Debug, PartialEq, Eq)]
enum MarkCmp {
    /// Higher than the mark (or no mark): the mark must be raised.
    Raise,
    /// Equal to the mark, byte for byte.
    Same,
    /// Below the mark, at or below a stored withdrawal, or a different
    /// record at the mark's version.
    Refuse,
}

fn compare_mark(offered: &[u8; 100], mark: StoredMark) -> MarkCmp {
    let mark = match mark {
        StoredMark::Mark(m) => m,
        StoredMark::NoFloor => return MarkCmp::Raise,
        // Served at the compiled-in floor; the stored entry is left alone.
        StoredMark::Unreadable => return MarkCmp::Same,
    };
    let mark = &mark;
    let (o, m) = (PointerRecord::decode(offered), PointerRecord::decode(mark));
    if o.version > m.version {
        MarkCmp::Raise
    } else if o.version == m.version && offered == mark && !m.is_withdrawal() {
        MarkCmp::Same
    } else {
        MarkCmp::Refuse
    }
}

fn raise_mark<H: Host>(
    store: &mut Store<H>,
    domain: &Domain,
    key: Vec<u8>,
    record: &[u8; 100],
    meta: impl FnOnce(&mut crate::storage::index::Index),
) -> Result<(), PutError> {
    let e = Entry::new(KIND_CALLER_MARK, key, record.to_vec());
    store.put(&e, &quota(domain), meta)
}

/// A seed and its public key.
type UsableKey = (Zeroizing<[u8; 32]>, [u8; 32]);

/// A usable key in `slot`, or the outcome that answers instead.
///
/// `allow_corrupt` is Export's: a slot flagged corrupt whose bytes still parse
/// as a 32-byte seed may be exported after consent, so the page can compare
/// the derived key with the identity it expects and re-Import it (protocol
/// 4.3, 12.5). Every other operation answers Unusable(2) for such a slot.
fn usable_seed<H: Host>(
    domain: &Domain,
    store: &mut Store<H>,
    slot: &[u8],
    sealed: bool,
    allow_corrupt: bool,
    rid: u64,
) -> Result<UsableKey, Outcome> {
    let partition = domain.partition();
    let unusable = |reason| -> Outcome {
        status(Status::Unusable {
            request_id: rid,
            partition,
            slot: slot.to_vec(),
            reason,
        })
    };
    // Export's lookup never changes storage (`allow_corrupt` reads like a
    // sealed vault): a user who clicks Deny must not lose bytes Export exists
    // to recover.
    let entry = match store.read(KIND_KEY, slot, sealed || allow_corrupt) {
        Read::Absent => {
            return Err(status(Status::Absent {
                request_id: rid,
                partition,
                slot: slot.to_vec(),
            }))
        }
        Read::Missing => return Err(refusal(rid, refused::STORAGE_FAILURE)),
        Read::Corrupt(Some(e)) if allow_corrupt => e,
        Read::Corrupt(_) => return Err(unusable(unusable::CORRUPT)),
        Read::Ok(e) => e,
    };
    let seed: Zeroizing<[u8; 32]> = Zeroizing::new(
        entry
            .content
            .as_slice()
            .try_into()
            .map_err(|_| unusable(unusable::CORRUPT))?,
    );
    let pk = crypto::public_key(&seed);
    if domain.is_publisher_key(&pk) {
        return Err(unusable(unusable::PUBLISHER_KEY));
    }
    Ok((seed, pk))
}

/// The caller-mark rules (spec 5, protocol 9) for a delegate caller: its
/// record must be at least the stored mark (the compiled-in `min_version` is
/// checked with the proof), a higher one raises the mark, and the raise is
/// Busy while changes are. `answer` is set when the partition is not served
/// here (Moved or NotHere): then a request that would need a raise gets that
/// answer, and one that needs none proceeds. `Some` is the outcome that
/// replaces the request.
#[allow(clippy::too_many_arguments)]
fn gate_caller<H: Host>(
    domain: &Domain,
    store: &mut Store<H>,
    caller: &Caller,
    sealed: bool,
    changes_busy: bool,
    create: impl FnOnce(&mut crate::storage::index::Index),
    answer: Option<Box<Status>>,
    rid: u64,
) -> Option<Outcome> {
    let Caller::Delegate {
        author_vk,
        app_id,
        record,
        ..
    } = caller
    else {
        return None;
    };
    let key = caller.mark_key()?;
    let mark = stored_mark(store, &key, author_vk, app_id, sealed);
    let cmp = match mark {
        // The mark is gone: a valid request above the compiled-in minimum
        // writes it again, one at the minimum has nothing to establish.
        StoredMark::Unreadable => {
            let min = domain
                .caller_delegate(author_vk, app_id)
                .map_or(0, |c| c.min_version);
            if PointerRecord::decode(record).version > min {
                MarkCmp::Raise
            } else {
                MarkCmp::Same
            }
        }
        m => compare_mark(record, m),
    };
    match cmp {
        MarkCmp::Refuse => Some(refusal(rid, refused::CALLER_NOT_AUTHORIZED)),
        MarkCmp::Same => None,
        MarkCmp::Raise => {
            if let Some(s) = answer {
                return Some(status(s));
            }
            // Read-only: the raise cannot be written, so the caller is served
            // on the record it offers (protocol 4.5: signing does not stop).
            if store.is_read_only() {
                return None;
            }
            if changes_busy {
                return Some(status(Status::Busy {
                    request_id: rid,
                    partition: domain.partition(),
                }));
            }
            // The floor is never silently lost: a failed raise refuses.
            raise_mark(store, domain, key, record, create)
                .err()
                .map(|e| put_error(rid, e))
        }
    }
}

fn key_result(rid: u64, slot: &[u8], public_key: [u8; 32]) -> Outcome {
    reply(
        OpResult::Key {
            slot: slot.to_vec(),
            public_key,
        }
        .encode(rid),
        rid,
    )
}

fn operation<H: Host>(domain: &Domain, host: &mut H, caller: &Caller, req: Request) -> Outcome {
    let rid = req.header.request_id;
    if let Some(slot) = req.op.slot() {
        if !domain.slot_ok(slot) {
            return refusal(rid, refused::MALFORMED);
        }
    }
    let is_change = matches!(
        req.op,
        Operation::Generate { .. } | Operation::Import { .. } | Operation::Delete { .. }
    );
    let succ = Succ::load(domain, host).ok();
    let fault = Store::fault_for_slot(&*host, &domain.partition(), req.op.slot());
    let mut store = match fault {
        None => match Store::open(host, domain.partition()) {
            Ok(s) => s,
            Err(_) => return refusal(rid, refused::STORAGE_FAILURE),
        },
        // The index state is unknown: read-only (protocol 4.5).
        Some(_) => match (&req.op, caller) {
            // A page may rescue a key with Export, behind the consent prompt.
            (Operation::Export { slot }, Caller::Page { id }) => {
                return ask(domain, host, id, rid, slot, false)
            }
            (Operation::ResetPartition { confirm }, Caller::Page { id }) => {
                return reset_request(domain, host, id, rid, confirm)
            }
            // Signing does not stop: the entry is found by its two parity
            // copies.
            (Operation::PublicKey { .. } | Operation::Batch { .. }, _) => {
                Store::open_blind(host, domain.partition())
            }
            _ => return refusal(rid, refused::STORAGE_FAILURE),
        },
    };
    if let Operation::ResetPartition { .. } = req.op {
        // The index reads fine: nothing to reset (protocol 4.5).
        return refusal(rid, refused::OPERATION_NOT_ALLOWED);
    }
    let (sealed, changes_busy, creating) = match route(domain, &store, &succ, is_change, rid) {
        Route::Answer(s) => return status(s),
        Route::Create => (false, false, true),
        Route::Serve {
            sealed,
            changes_busy,
        } => (sealed, changes_busy, false),
    };

    // Applied to the index in the commit that stores the first entry.
    let create = move |ix: &mut crate::storage::index::Index| {
        if creating {
            ix.state = State::Writer;
            ix.armed = None;
        }
    };

    if let Some(o) = gate_caller(
        domain,
        &mut store,
        caller,
        sealed,
        changes_busy,
        create,
        None,
        rid,
    ) {
        return o;
    }

    if is_change && changes_busy {
        return status(Status::Busy {
            request_id: rid,
            partition: domain.partition(),
        });
    }

    match req.op {
        Operation::Generate { slot } => {
            let mut seed = Zeroizing::new([0u8; 32]);
            for _ in 0..2 {
                store.host().random_bytes(seed.as_mut());
                if *seed != [0u8; 32] {
                    break;
                }
            }
            if *seed == [0u8; 32] {
                // The node's random source returned zeros twice.
                return refusal(rid, refused::STORAGE_FAILURE);
            }
            let pk = crypto::public_key(&seed);
            let slot = slot.unwrap_or_else(|| pk.to_vec());
            if !domain.slot_ok(&slot) {
                return refusal(rid, refused::MALFORMED);
            }
            if domain.is_publisher_key(&pk) {
                return status(Status::Unusable {
                    request_id: rid,
                    partition: domain.partition(),
                    slot,
                    reason: unusable::PUBLISHER_KEY,
                });
            }
            if store.index.find(KIND_KEY, &slot).is_some() {
                return refusal(rid, refused::SLOT_OCCUPIED);
            }
            let e = Entry::new(KIND_KEY, slot.clone(), seed.to_vec());
            match store.put(&e, &quota(domain), create) {
                Ok(()) => key_result(rid, &slot, pk),
                Err(e) => put_error(rid, e),
            }
        }
        Operation::Import {
            slot,
            seed,
            replace,
        } => {
            let seed = Zeroizing::new(seed);
            let pk = crypto::public_key(&seed);
            if domain.is_publisher_key(&pk) {
                return status(Status::Unusable {
                    request_id: rid,
                    partition: domain.partition(),
                    slot,
                    reason: unusable::PUBLISHER_KEY,
                });
            }
            let write = match store.read(KIND_KEY, &slot, false) {
                Read::Absent => true,
                // Same key: a no-op, except that it rewrites a slot marked corrupt.
                Read::Ok(e) if e.content == seed.as_slice() => false,
                Read::Corrupt(Some(e)) if e.content == seed.as_slice() => true,
                // The index names the slot but its secret is gone, so only an
                // explicit replace overwrites it.
                Read::Missing if !replace => {
                    return refusal(rid, refused::STORAGE_FAILURE);
                }
                // A different key needs replace.
                _ if replace => true,
                _ => return refusal(rid, refused::SLOT_OCCUPIED),
            };
            if write {
                let e = Entry::new(KIND_KEY, slot.clone(), seed.to_vec());
                if let Err(e) = store.put(&e, &quota(domain), create) {
                    return put_error(rid, e);
                }
            }
            key_result(rid, &slot, pk)
        }
        Operation::Delete { slot } => match store.delete(KIND_KEY, &slot) {
            Ok(()) => reply(OpResult::Ok.encode(rid), rid),
            Err(_) => refusal(rid, refused::STORAGE_FAILURE),
        },
        Operation::PublicKey { slot } => {
            match usable_seed(domain, &mut store, &slot, sealed, false, rid) {
                Ok((_, pk)) => key_result(rid, &slot, pk),
                Err(o) => o,
            }
        }
        Operation::List { after, max } => {
            list(domain, &mut store, &after, max as usize, sealed, rid)
        }
        Operation::Batch {
            slot,
            expected_public_key,
            items,
        } => {
            let (seed, pk) = match usable_seed(domain, &mut store, &slot, sealed, false, rid) {
                Ok(v) => v,
                Err(o) => return o,
            };
            if pk != expected_public_key {
                return refusal(rid, refused::PUBLIC_KEY_MISMATCH);
            }
            let results = items
                .iter()
                .map(|it| match it {
                    BatchItem::Sign(data) if data.starts_with(FORBIDDEN_SIGNING_PREFIX) => {
                        ItemResult {
                            status: ITEM_FORBIDDEN_SIGNING_DOMAIN,
                            bytes: Vec::new(),
                        }
                    }
                    BatchItem::Sign(data) => ItemResult {
                        status: ITEM_OK,
                        bytes: crypto::sign(&seed, data).to_vec(),
                    },
                    BatchItem::KeyAgreement(peer) => ItemResult {
                        status: ITEM_OK,
                        bytes: crypto::key_agreement(&seed, peer).to_vec(),
                    },
                    BatchItem::Derive { context, data } => ItemResult {
                        status: ITEM_OK,
                        bytes: crypto::derive(&seed, context, data).to_vec(),
                    },
                })
                .collect();
            reply(OpResult::Batch(results).encode(rid), rid)
        }
        Operation::ResetPartition { .. } => refusal(rid, refused::OPERATION_NOT_ALLOWED),
        Operation::Export { slot } => {
            let Caller::Page { id } = caller else {
                return refusal(rid, refused::OPERATION_NOT_ALLOWED);
            };
            if let Err(o) = usable_seed(domain, &mut store, &slot, sealed, true, rid) {
                return o;
            }
            ask(domain, store.host(), id, rid, &slot, false)
        }
    }
}

/// Stores the pending request and asks the user. The prompt does not depend on
/// the index, so it works while the store is read-only. `reset` asks to repair
/// the partition (ResetPartition) instead of to export `slot`.
fn ask<H: Host>(
    domain: &Domain,
    host: &mut H,
    origin: &[u8; 32],
    rid: u64,
    slot: &[u8],
    reset: bool,
) -> Outcome {
    let mut idb = [0u8; 4];
    let mut prompt_id = 0u32;
    for _ in 0..2 {
        host.random_bytes(&mut idb);
        prompt_id = u32::from_be_bytes(idb);
        if prompt_id != 0 {
            break;
        }
    }
    if prompt_id == 0 {
        return refusal(rid, refused::STORAGE_FAILURE);
    }
    let pending = Pending {
        prompt_id,
        origin: *origin,
        request_id: rid,
        slot: slot.to_vec(),
        reset,
    };
    if !host.write_context(&pending.encode()) {
        return refusal(rid, refused::STORAGE_FAILURE);
    }
    let text = if reset {
        consent::RESET_PROMPT.to_string()
    } else {
        (domain.export_prompt)(slot)
    };
    Outcome::Prompt { prompt_id, text }
}

/// ResetPartition, first half (protocol 4.5): a domain page, while the index
/// is lost, with the right `confirm`. The node then asks the user.
fn reset_request<H: Host>(
    domain: &Domain,
    host: &mut H,
    origin: &[u8; 32],
    rid: u64,
    confirm: &[u8; 32],
) -> Outcome {
    // A newer build is known: this one must not become a writer again.
    if Succ::load(domain, host)
        .ok()
        .is_some_and(|s| s.successor().is_some())
    {
        return refusal(rid, refused::OPERATION_NOT_ALLOWED);
    }
    if *confirm != freenet_vault_common::hash::reset_confirm(&domain.partition()) {
        return refusal(rid, refused::MALFORMED);
    }
    ask(domain, host, origin, rid, &[], true)
}

fn list<H: Host>(
    domain: &Domain,
    store: &mut Store<H>,
    after: &[u8],
    max: usize,
    sealed: bool,
    rid: u64,
) -> Outcome {
    let slots: Vec<Vec<u8>> = store
        .index
        .entries
        .iter()
        .filter(|e| e.kind == KIND_KEY && e.key.as_slice() > after)
        .map(|e| e.key.clone())
        .collect();
    let more = slots.len() > max;
    let mut items = Vec::new();
    for slot in slots.into_iter().take(max) {
        let item = match store.read(KIND_KEY, &slot, sealed) {
            Read::Absent => continue,
            // Named by the index, unreadable now: listed as corrupt with no
            // key. A page repairs it with Import (replace) or retries.
            Read::Missing => ListItem {
                slot,
                public_key: [0; 32],
                status: LIST_CORRUPT,
            },
            Read::Ok(e) => {
                let seed: Option<[u8; 32]> = e.content.as_slice().try_into().ok();
                let pk = seed.map(|s| crypto::public_key(&s)).unwrap_or([0; 32]);
                let status = if domain.is_publisher_key(&pk) {
                    LIST_UNUSABLE
                } else {
                    LIST_OK
                };
                ListItem {
                    slot,
                    public_key: pk,
                    status,
                }
            }
            Read::Corrupt(e) => {
                // Derived from the flagged bytes: informational only.
                let seed: Option<[u8; 32]> = e.and_then(|e| e.content.as_slice().try_into().ok());
                ListItem {
                    slot,
                    public_key: seed.map(|s| crypto::public_key(&s)).unwrap_or([0; 32]),
                    status: LIST_CORRUPT,
                }
            }
        };
        items.push(item);
    }
    reply(OpResult::List { items, more }.encode(rid), rid)
}

/// The answer to the consent prompt (spec 6). `Ok(None)` when the answer
/// does not belong to the pending prompt.
pub fn export_answer<H: Host>(
    domain: &Domain,
    host: &mut H,
    origin: &[u8; 32],
    prompt_id: u32,
    response: &[u8],
) -> Option<Outcome> {
    let pending = Pending::decode(&host.read_context())?;
    if pending.prompt_id != prompt_id || &pending.origin != origin {
        return None;
    }
    host.write_context(&[]);
    let rid = pending.request_id;
    if response != consent::ALLOW || !domain.is_own_page(origin) {
        return Some(refusal(rid, refused::CONSENT_DENIED));
    }
    if pending.reset {
        // Everything is checked again when the user answers: the index must
        // still be lost, and no newer build may have become known meanwhile.
        // (That no other build is WRITER or SEALED is the courier's check, from
        // the statuses it reads; the library cannot see other builds.)
        let p = domain.partition();
        if Succ::load(domain, host)
            .ok()
            .is_some_and(|s| s.successor().is_some())
        {
            return Some(refusal(rid, refused::OPERATION_NOT_ALLOWED));
        }
        return Some(match Store::fault(&*host, &p) {
            Some(_) => match reset_partition(host, &p) {
                Ok(()) => reply(OpResult::Ok.encode(rid), rid),
                Err(_) => refusal(rid, refused::STORAGE_FAILURE),
            },
            None => refusal(rid, refused::OPERATION_NOT_ALLOWED),
        });
    }
    let succ = Succ::load(domain, host).ok();
    let unknown = Store::fault_for_slot(&*host, &domain.partition(), Some(&pending.slot));
    let opened = match unknown {
        None => Store::open(host, domain.partition()).ok(),
        Some(_) => None,
    };
    let Some(mut store) = opened else {
        // Unknown index state: read-only. Rescue the key from the entry
        // copies themselves, and only when exactly one decodes.
        return Some(
            match rescue_export_seed(host, &domain.partition(), &pending.slot) {
                Some(seed) => reply(OpResult::Export { seed }.encode(rid), rid),
                None => refusal(rid, refused::STORAGE_FAILURE),
            },
        );
    };
    let sealed = match route(domain, &store, &succ, false, rid) {
        Route::Answer(s) => return Some(status(s)),
        Route::Serve { sealed, .. } => sealed,
        Route::Create => false,
    };
    // Read again: the slot may have changed, or been flagged corrupt, since
    // the prompt (corrupt is exportable, spec 6).
    Some(
        match usable_seed(domain, &mut store, &pending.slot, sealed, true, rid) {
            Ok((seed, _)) => reply(OpResult::Export { seed: *seed }.encode(rid), rid),
            Err(o) => o,
        },
    )
}

fn partition_state_of(store_state: State, armed: bool, awaiting: bool) -> u8 {
    match store_state {
        State::None if armed => partition_state::NONE_ARMED,
        State::None => partition_state::NONE,
        State::Writer if awaiting => partition_state::WRITER_AWAITING,
        State::Writer => partition_state::WRITER,
        State::Sealed => partition_state::SEALED,
        State::Receiving => partition_state::RECEIVING,
        State::Retired => partition_state::RETIRED,
    }
}

/// `problems` bits for an unknown index state: storage failure, and bit 6 when
/// the index is lost (protocol 4.5).
fn fault_bits<H: Host>(host: &H, partition: &[u8; 32]) -> u8 {
    match Store::fault(host, partition) {
        Some(_) => problems::STORAGE_FAILURE | problems::INDEX_LOST,
        None => 0,
    }
}

fn handover_status<H: Host>(
    domain: &Domain,
    succ: Option<&Succ>,
    store: Option<&Store<H>>,
    step: u8,
    extra_problems: u8,
    own_page: bool,
) -> Outcome {
    let (record_state, floor) = match succ {
        Some(s) => (s.record_state(), s.floor(domain.own_version)),
        None => (
            freenet_vault_common::status::record_state::STORED_MALFORMED,
            domain.own_version,
        ),
    };
    let mut h = HandoverStatus {
        request_id: 0,
        own_version: domain.own_version,
        floor_version: floor,
        record_state,
        step_result: step,
        partition_state: 0,
        peer_record: [0; 100],
        receiving_from: 0,
        taken_over_from: 0,
        taken_over_manifest: [0; 32],
        manifest_digest: [0; 32],
        problems: extra_problems,
        lost_entries: 0,
    };
    if let Some(s) = store {
        let ix = &s.index;
        h.partition_state =
            partition_state_of(ix.state, ix.armed.is_some(), ix.awaiting_retirement);
        h.peer_record = ix.peer_record.unwrap_or([0; 100]);
        h.problems |= ix.problems;
        h.lost_entries = ix.lost_entries;
    } else {
        h.problems |= problems::STORAGE_FAILURE;
        // Index lost (bit 6): state 7, unknown (protocol 4.5). A build in this
        // state is never NONE, so no other build is armed while it holds keys.
        if h.problems & problems::INDEX_LOST != 0 {
            h.partition_state = partition_state::UNKNOWN_INDEX_LOST;
        }
    }
    if !own_page {
        h = h.redacted();
    }
    status(Status::Handover(h))
}

/// Poke (protocol 6, first row): records from any page; flags only from the
/// domain's own pages. Only flag bit 1 (arm) is implemented; the other bits
/// belong to the handover.
fn poke<H: Host>(domain: &Domain, host: &mut H, own_page: bool, body: &[u8]) -> Outcome {
    let p = match Poke::decode(body) {
        Ok(p) => p,
        Err(_) => return refusal(0, refused::MALFORMED),
    };
    if p.partition != domain.partition() {
        return refusal(0, refused::MALFORMED);
    }
    let mut succ = match Succ::load(domain, host) {
        Ok(s) => s,
        // A `vault:succ` that no longer verifies is replaced by a record that
        // does (it verifies itself); without one, no record handling and no
        // flags.
        Err(_) => {
            if let Some(fresh) = p.record.as_ref().and_then(|r| repair_succ(domain, host, r)) {
                fresh
            } else {
                let bits = fault_bits(&*host, &domain.partition());
                let store = Store::open(host, domain.partition()).ok();
                return handover_status(
                    domain,
                    None,
                    store.as_ref(),
                    step_result::NOTHING,
                    bits,
                    own_page,
                );
            }
        }
    };
    let mut extra = 0;
    let mut step = step_result::NOTHING;
    if let Some(r) = &p.record {
        let a = accept_record(domain, host, &mut succ, r);
        step = a.step_result;
        if a.storage_failure {
            extra |= problems::STORAGE_FAILURE;
        }
    }
    let Ok(mut store) = Store::open(host, domain.partition()) else {
        extra |= fault_bits(&*host, &domain.partition());
        return handover_status::<H>(domain, Some(&succ), None, step, extra, own_page);
    };
    // Any newer record clears creation arming.
    if store.index.state == State::None
        && store.index.armed.is_some()
        && succ.successor().is_some()
        && store.update(|ix| ix.armed = None).is_err()
    {
        extra |= problems::STORAGE_FAILURE;
    }
    if own_page && p.flags & poke_flags::ARM != 0 {
        let can_arm = store.index.state == State::None
            && succ.successor().is_none()
            && armed_ok(domain, &p.record);
        if can_arm && store.update(|ix| ix.armed = p.record).is_err() {
            extra |= problems::STORAGE_FAILURE;
        }
    }
    handover_status(domain, Some(&succ), Some(&store), step, extra, own_page)
}

/// A `vault:succ` that no longer verifies is replaced by a record that
/// verifies and is newer than this build (the record verifies itself, so it
/// is not trusted on the stored bytes' say-so). `None` leaves it as it is.
/// What the unreadable store held is lost; it could not be trusted anyway.
fn repair_succ<H: Host>(domain: &Domain, host: &mut H, record: &[u8; 100]) -> Option<Succ> {
    let mut fresh = Succ::default();
    let a = accept_record(domain, host, &mut fresh, record);
    (a.step_result == step_result::RECORD_ACCEPTED && !a.storage_failure).then_some(fresh)
}

/// SubmitRecord: a domain record (protocol 3) or a caller record that may
/// raise a caller mark, including a caller withdrawal (protocol 9).
fn submit_record<H: Host>(
    domain: &Domain,
    host: &mut H,
    caller: &Caller,
    s: &SubmitRecord,
) -> Outcome {
    let rid = s.header.request_id;
    let own_page = matches!(caller, Caller::Page { .. });
    let with_rid = |o: Outcome| match o {
        Outcome::Reply(bytes) => {
            // Stamp the request id into the HandoverStatus reply.
            let decoded = Frame::decode(&bytes)
                .ok()
                .and_then(|f| Status::decode(f.frame_type, f.body).ok());
            match decoded {
                Some(Status::Handover(mut h)) => {
                    h.request_id = rid;
                    status(Status::Handover(h))
                }
                _ => Outcome::Reply(bytes),
            }
        }
        o => o,
    };
    // A delegate caller is held to its caller mark for SubmitRecord exactly as
    // for an operation (spec 5): a stale build cannot submit, and a newer one
    // raises the mark (Busy while changes are).
    if let Caller::Delegate { .. } = caller {
        let succ = Succ::load(domain, host).ok();
        let Ok(mut store) = Store::open(host, domain.partition()) else {
            return refusal(rid, refused::STORAGE_FAILURE);
        };
        let (sealed, changes_busy, answer) = match route(domain, &store, &succ, false, rid) {
            Route::Serve {
                sealed,
                changes_busy,
            } => (sealed, changes_busy, None),
            Route::Create => (false, false, None),
            // Not served here: read without rewriting anything.
            Route::Answer(st) => (true, true, Some(st)),
        };
        if let Some(o) = gate_caller(
            domain,
            &mut store,
            caller,
            sealed,
            changes_busy,
            |_| {},
            answer,
            rid,
        ) {
            return o;
        }
    }
    if s.author_vk == domain.author_vk && s.app_id == domain.app_id {
        let mut succ = match Succ::load(domain, host) {
            Ok(s) => s,
            Err(_) => match repair_succ(domain, host, &s.record) {
                Some(fresh) => fresh,
                None => return refusal(rid, refused::STORED_RECORD_MALFORMED),
            },
        };
        let a = accept_record(domain, host, &mut succ, &s.record);
        let mut extra = if a.storage_failure {
            problems::STORAGE_FAILURE
        } else {
            0
        };
        let store = match Store::open(host, domain.partition()) {
            Ok(mut st) => {
                if st.index.state == State::None
                    && st.index.armed.is_some()
                    && succ.successor().is_some()
                    && st.update(|ix| ix.armed = None).is_err()
                {
                    extra |= problems::STORAGE_FAILURE;
                }
                Some(st)
            }
            Err(_) => {
                extra |= fault_bits(&*host, &domain.partition());
                None
            }
        };
        return with_rid(handover_status(
            domain,
            Some(&succ),
            store.as_ref(),
            a.step_result,
            extra,
            own_page,
        ));
    }
    if s.author_vk == domain.author_vk || domain.caller_delegate(&s.author_vk, &s.app_id).is_none()
    {
        return refusal(rid, refused::CALLER_NOT_AUTHORIZED);
    }
    let offered = PointerRecord::decode(&s.record);
    let succ = Succ::load(domain, host).ok();
    let Ok(mut store) = Store::open(host, domain.partition()) else {
        return refusal(rid, refused::STORAGE_FAILURE);
    };
    let step = if offered.verify(&s.author_vk, &s.app_id).is_err() {
        step_result::INVALID
    } else {
        let changes_busy = match route(domain, &store, &succ, false, rid) {
            Route::Answer(st) => return status(st),
            Route::Serve { changes_busy, .. } => changes_busy,
            Route::Create => false,
        };
        let key = [s.author_vk.as_slice(), &s.app_id].concat();
        let sealed = store.index.state == State::Sealed;
        // A mark whose secret is gone is lost for good (a read in a completed
        // call is truthful, so there is nothing to retry): a submitted record
        // at or above the compiled-in minimum replaces it, so it is not stuck
        // for ever (it then lowers the floor to that record's version).
        let found = stored_mark(&mut store, &key, &s.author_vk, &s.app_id, sealed);
        let mark = match found {
            StoredMark::Mark(m) => Some(m),
            StoredMark::NoFloor => None,
            StoredMark::Unreadable => {
                let min = domain
                    .caller_delegate(&s.author_vk, &s.app_id)
                    .map_or(0, |c| c.min_version);
                if offered.version < min {
                    return refusal(rid, refused::CALLER_NOT_AUTHORIZED);
                }
                None
            }
        };
        let mark_version = mark.map(|m| PointerRecord::decode(&m).version);
        match mark_version {
            Some(v) if offered.version < v => step_result::NOT_NEWER,
            Some(v) if offered.version == v => {
                if mark.as_ref() == Some(&s.record) {
                    step_result::RECORD_ACCEPTED
                } else {
                    step_result::EQUIVOCATION
                }
            }
            _ => {
                if changes_busy {
                    return status(Status::Busy {
                        request_id: rid,
                        partition: domain.partition(),
                    });
                }
                if let Err(e) = raise_mark(&mut store, domain, key, &s.record, |_| {}) {
                    return put_error(rid, e);
                }
                step_result::RECORD_ACCEPTED
            }
        }
    };
    with_rid(handover_status(
        domain,
        succ.as_ref(),
        Some(&store),
        step,
        0,
        own_page,
    ))
}
