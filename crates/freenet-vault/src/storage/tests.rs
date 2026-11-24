//! Storage: write ordering, read-back after failed writes, gc, corruption,
//! quotas, verbatim carry-forward (protocol 4 and 8).

use super::index::State;
use super::*;
use crate::testing::{MemHost, WriteFault};
use freenet_vault_common::entry::{Entry, EFLAG_CORRUPT, KIND_CALLER_MARK, KIND_KEY};

const P: [u8; 32] = [0x50; 32];
const QUOTA: Quota = Quota {
    max_key_slots: 4,
    max_caller_marks: 2,
};

fn key_entry(slot: u8, seed: u8) -> Entry {
    Entry::new(KIND_KEY, vec![slot; 32], vec![seed; 32])
}

fn put(host: &mut MemHost, e: &Entry) -> Result<(), PutError> {
    let mut s = Store::open(host, P).unwrap();
    s.put(e, &QUOTA, |i| i.state = State::Writer)
}

fn read(host: &mut MemHost, slot: u8) -> Read {
    Store::open(host, P)
        .unwrap()
        .read(KIND_KEY, &[slot; 32], false)
}

fn entry_name(slot: u8, parity: u8) -> Vec<u8> {
    names::entry(&P, KIND_KEY, &[slot; 32], parity)
}

/// The names pending in either gc list copy.
fn gc_names(host: &MemHost) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = vec![];
    for n in [names::gc(&P), names::gc2(&P)] {
        if let Some(l) = host.secrets.get(&n).and_then(|b| decode_names(b)) {
            for g in l {
                if !out.contains(&g.name) {
                    out.push(g.name);
                }
            }
        }
    }
    out
}

/// Plants a gc list (both copies), as a crash leaves one.
fn set_gc(host: &mut MemHost, list: &[Vec<u8>]) {
    let l: Vec<GcName> = list
        .iter()
        .map(|n| GcName {
            name: n.clone(),
            uncertain: 0,
        })
        .collect();
    let b = encode_names(&l).unwrap();
    host.secrets.insert(names::gc(&P), b.clone());
    host.secrets.insert(names::gc2(&P), b);
}

fn index_on_disk(host: &MemHost) -> Option<Vec<u8>> {
    host.secrets.get(&names::index(&P)).cloned()
}

#[test]
fn put_writes_entry_then_index_and_reads_back() {
    let mut h = MemHost::new();
    let e = key_entry(1, 9);
    put(&mut h, &e).unwrap();
    assert_eq!(read(&mut h, 1), Read::Ok(e.clone()));
    // Stored exactly as encoded, at parity 0, and no gc left behind.
    assert_eq!(h.secrets[&entry_name(1, 0)], e.encode().unwrap());
    assert!(gc_names(&h).is_empty());
    let s = Store::open(&mut h, P).unwrap();
    assert_eq!(s.index.state, State::Writer);
    assert_eq!(s.index.entries.len(), 1);
}

#[test]
fn replace_flips_parity_and_removes_the_old_copy() {
    let mut h = MemHost::new();
    put(&mut h, &key_entry(1, 9)).unwrap();
    put(&mut h, &key_entry(1, 8)).unwrap();
    assert_eq!(read(&mut h, 1), Read::Ok(key_entry(1, 8)));
    assert!(h.secrets.contains_key(&entry_name(1, 1)));
    assert!(!h.secrets.contains_key(&entry_name(1, 0)));
    assert!(gc_names(&h).is_empty());
    put(&mut h, &key_entry(1, 7)).unwrap();
    assert!(h.secrets.contains_key(&entry_name(1, 0)));
    assert!(!h.secrets.contains_key(&entry_name(1, 1)));
}

#[test]
fn failed_entry_write_changes_nothing() {
    let mut h = MemHost::new();
    put(&mut h, &key_entry(1, 9)).unwrap();
    let before = h.secrets.clone();
    h.set_fault(|name| {
        if name.starts_with(b"vault:e:") {
            WriteFault::DurableButFail
        } else {
            WriteFault::None
        }
    });
    assert_eq!(put(&mut h, &key_entry(1, 8)), Err(PutError::Storage));
    assert_eq!(put(&mut h, &key_entry(2, 8)), Err(PutError::Storage));
    // Even a value that landed despite the error is removed: nothing references it.
    assert_eq!(h.secrets, before);
}

/// A failed index write with the old index provably on disk: the old value
/// stays served, the new copy is removed, and the gc list the replace wrote
/// (naming the old, still-referenced copy) never deletes it.
#[test]
fn failed_index_write_leaves_the_old_value_and_gc_cannot_delete_it() {
    let mut h = MemHost::new();
    put(&mut h, &key_entry(1, 9)).unwrap();
    let idx = names::index(&P);
    h.set_fault(move |name| {
        if name == idx.as_slice() {
            WriteFault::Fail
        } else {
            WriteFault::None
        }
    });
    assert_eq!(put(&mut h, &key_entry(1, 8)), Err(PutError::Storage));
    // The commit was uncertain, so the call removed nothing: the candidate is
    // still listed and is collected by the next call.
    assert!(h.secrets.contains_key(&entry_name(1, 1)));
    assert!(gc_names(&h).contains(&entry_name(1, 1)));
    h.clear_fault();
    let mut s = Store::open(&mut h, P).unwrap();
    s.process_gc();
    drop(s);
    assert!(!h.secrets.contains_key(&entry_name(1, 1)));
    assert!(gc_names(&h).is_empty());
    assert_eq!(read(&mut h, 1), Read::Ok(key_entry(1, 9)));
    // The same state as after a crash: a gc list naming both copies.
    h.clear_fault();
    set_gc(&mut h, &[entry_name(1, 0), entry_name(1, 1)]);
    for _ in 0..3 {
        // The second name never existed: removing it is confirmed (it is not
        // there), so it leaves the list.
        let mut s = Store::open(&mut h, P).unwrap();
        s.process_gc();
    }
    assert!(gc_names(&h).is_empty());
    assert_eq!(read(&mut h, 1), Read::Ok(key_entry(1, 9)));
}

/// A first-time index write that errors after the value became durable
/// (protocol 1): the read-back sees the new index, so the put succeeded.
#[test]
fn index_write_error_with_durable_value_is_a_success_after_read_back() {
    let mut h = MemHost::new();
    let idx = names::index(&P);
    h.set_fault(move |name| {
        if name == idx.as_slice() {
            WriteFault::DurableButFail
        } else {
            WriteFault::None
        }
    });
    put(&mut h, &key_entry(1, 9)).unwrap();
    h.clear_fault();
    assert_eq!(read(&mut h, 1), Read::Ok(key_entry(1, 9)));
}

#[test]
fn delete_removes_both_parities_and_clears_gc() {
    let mut h = MemHost::new();
    put(&mut h, &key_entry(1, 9)).unwrap();
    put(&mut h, &key_entry(2, 9)).unwrap();
    // A stray copy at the unused parity, as a failed earlier write may leave.
    h.secrets.insert(entry_name(1, 1), vec![1, 2, 3]);
    let mut s = Store::open(&mut h, P).unwrap();
    s.delete(KIND_KEY, &[1; 32]).unwrap();
    drop(s);
    assert!(h
        .names_with_prefix(&entry_name(1, 0)[..entry_name(1, 0).len() - 1])
        .is_empty());
    assert!(gc_names(&h).is_empty());
    assert_eq!(read(&mut h, 1), Read::Absent);
    assert_eq!(read(&mut h, 2), Read::Ok(key_entry(2, 9)));
    // Deleting an absent entry is a no-op.
    let mut s = Store::open(&mut h, P).unwrap();
    s.delete(KIND_KEY, &[1; 32]).unwrap();
}

#[test]
fn delete_whose_index_write_fails_keeps_the_entry() {
    let mut h = MemHost::new();
    put(&mut h, &key_entry(1, 9)).unwrap();
    let idx = names::index(&P);
    h.set_fault(move |name| {
        if name == idx.as_slice() {
            WriteFault::Fail
        } else {
            WriteFault::None
        }
    });
    let mut s = Store::open(&mut h, P).unwrap();
    assert_eq!(s.delete(KIND_KEY, &[1; 32]), Err(StorageFailure));
    drop(s);
    h.clear_fault();
    let mut s = Store::open(&mut h, P).unwrap();
    s.process_gc();
    drop(s);
    assert_eq!(read(&mut h, 1), Read::Ok(key_entry(1, 9)));
}

#[test]
fn gc_never_touches_names_outside_the_partition() {
    let mut h = MemHost::new();
    put(&mut h, &key_entry(1, 9)).unwrap();
    h.secrets.insert(b"vault:succ".to_vec(), vec![1]);
    set_gc(&mut h, &[b"vault:succ".to_vec()]);
    let mut s = Store::open(&mut h, P).unwrap();
    s.process_gc();
    drop(s);
    assert!(h.secrets.contains_key(b"vault:succ".as_slice()));
    assert!(gc_names(&h).is_empty());
}

/// Bytes that fail the digest but still parse are rewritten with eflags
/// bit 0 set; the flagged bytes become the entry's representation.
#[test]
fn corrupt_but_parseable_entry_is_flagged_and_kept() {
    let mut h = MemHost::new();
    put(&mut h, &key_entry(1, 9)).unwrap();
    let name = entry_name(1, 0);
    let mut tampered = h.secrets[&name].clone();
    tampered[40] ^= 0xFF; // a seed byte: still parses, fails the digest
    h.secrets.insert(name.clone(), tampered.clone());
    let Read::Corrupt(Some(e)) = read(&mut h, 1) else {
        panic!("expected corrupt")
    };
    assert!(e.is_flagged_corrupt());
    // Rewritten at the other parity, flag set, every other byte verbatim.
    let mut flagged = tampered.clone();
    flagged[1] |= EFLAG_CORRUPT;
    assert_eq!(h.secrets[&entry_name(1, 1)], flagged);
    assert!(!h.secrets.contains_key(&name));
    let s = Store::open(&mut h, P).unwrap();
    assert_eq!(
        s.index.problems & freenet_vault_common::status::problems::CORRUPT_OR_LOST,
        freenet_vault_common::status::problems::CORRUPT_OR_LOST
    );
    drop(s);
    // It now passes its digest and stays corrupt.
    assert!(matches!(read(&mut h, 1), Read::Corrupt(Some(_))));
}

#[test]
fn unparseable_or_missing_entry_leaves_the_index_and_is_counted() {
    let mut h = MemHost::new();
    put(&mut h, &key_entry(1, 9)).unwrap();
    put(&mut h, &key_entry(2, 9)).unwrap();
    h.secrets.insert(entry_name(1, 0), vec![0xFF; 5]);
    // Present bytes that do not parse: dropped and counted.
    assert_eq!(read(&mut h, 1), Read::Absent);
    let s = Store::open(&mut h, P).unwrap();
    assert_eq!(s.index.lost_entries, 1);
    assert_eq!(s.index.entries.len(), 1);
    drop(s);
    assert!(!h.secrets.contains_key(&entry_name(1, 0)));
}

/// An absent secret is absent, never corrupt: nothing is deleted, flagged or
/// counted, and the entry reads again once the host returns it (item 5).
#[test]
fn a_secret_that_does_not_read_is_never_destroyed() {
    let mut h = MemHost::new();
    put(&mut h, &key_entry(1, 9)).unwrap();
    let name = entry_name(1, 0);
    h.hidden.insert(name.clone());
    let before = h.secrets.clone();
    assert_eq!(read(&mut h, 1), Read::Missing);
    assert_eq!(read(&mut h, 1), Read::Missing);
    // Nothing was written or removed.
    assert_eq!(h.secrets, before);
    let s = Store::open(&mut h, P).unwrap();
    assert_eq!(s.index.lost_entries, 0);
    assert_eq!(s.index.problems, 0);
    assert_eq!(s.index.entries.len(), 1);
    drop(s);
    h.hidden.clear();
    assert_eq!(read(&mut h, 1), Read::Ok(key_entry(1, 9)));
    // Also when sealed.
    h.hidden.insert(name);
    let mut s = Store::open(&mut h, P).unwrap();
    assert_eq!(s.read(KIND_KEY, &[1; 32], true), Read::Missing);
}

/// A failed removal keeps its name listed and is retried by the next call
/// (item 6); the list is cleared only when every removal is confirmed.
#[test]
fn gc_keeps_names_whose_removal_failed_and_retries() {
    let mut h = MemHost::new();
    put(&mut h, &key_entry(1, 9)).unwrap();
    // The replace lists parity 0 for removal; make that removal fail.
    h.undeletable.insert(entry_name(1, 0));
    put(&mut h, &key_entry(1, 8)).unwrap();
    assert!(h.secrets.contains_key(&entry_name(1, 0)));
    assert_eq!(gc_names(&h), vec![entry_name(1, 0)]);
    // Still failing: still listed.
    let mut s = Store::open(&mut h, P).unwrap();
    s.process_gc();
    drop(s);
    assert!(!gc_names(&h).is_empty());
    // The host recovers: the next call removes it and clears the list.
    h.undeletable.clear();
    let mut s = Store::open(&mut h, P).unwrap();
    s.process_gc();
    drop(s);
    assert!(!h.secrets.contains_key(&entry_name(1, 0)));
    assert!(gc_names(&h).is_empty());
    assert_eq!(read(&mut h, 1), Read::Ok(key_entry(1, 8)));
}

/// An entry copy written and not committed (a crash between the two) is named
/// in `vault:gc` before it is written, so the next call removes it (item 7).
#[test]
fn an_interrupted_entry_write_is_reachable_by_gc() {
    let mut h = MemHost::new();
    put(&mut h, &key_entry(1, 9)).unwrap();
    // Die right after the new copy lands: both gc list copies (2) + entry (1).
    h.crash_after(3);
    let _ = put(&mut h, &key_entry(1, 8));
    assert!(h.secrets.contains_key(&entry_name(1, 1)));
    let mut h = h.restart();
    let mut s = Store::open(&mut h, P).unwrap();
    s.process_gc();
    drop(s);
    assert!(!h.secrets.contains_key(&entry_name(1, 1)));
    assert_eq!(read(&mut h, 1), Read::Ok(key_entry(1, 9)));
    assert!(gc_names(&h).is_empty());
}

/// A gc list that fails to read must not lose pending removals (copy two
/// still has them), and writing it again keeps them.
#[test]
fn the_gc_list_survives_one_copy_not_reading() {
    let mut h = MemHost::new();
    put(&mut h, &key_entry(1, 9)).unwrap();
    // An undeletable stray copy is pending.
    let stray = entry_name(3, 0);
    h.secrets.insert(stray.clone(), vec![7]);
    h.undeletable.insert(stray.clone());
    set_gc(&mut h, std::slice::from_ref(&stray));
    // Copy one stops reading; another operation adds its own names.
    h.hidden.insert(names::gc(&P));
    put(&mut h, &key_entry(1, 8)).unwrap();
    assert!(gc_names_both(&h).contains(&stray), "pending removal lost");
    // Still retried: once removable, it goes.
    h.hidden.clear();
    h.undeletable.clear();
    let mut s = Store::open(&mut h, P).unwrap();
    s.process_gc();
    drop(s);
    assert!(!h.secrets.contains_key(&stray));
}

fn gc_names_both(h: &MemHost) -> Vec<Vec<u8>> {
    gc_names(h)
}

/// The list is bounded: a write that would exceed it fails and leaves the
/// pending names alone, instead of wrapping its count and erasing itself.
#[test]
fn the_gc_list_is_bounded_and_never_erases_itself() {
    let mut h = MemHost::new();
    put(&mut h, &key_entry(1, 9)).unwrap();
    let prefix = names::entry_prefix(&P);
    let full: Vec<Vec<u8>> = (0..MAX_GC_NAMES)
        .map(|i| [prefix.as_slice(), format!("{i:05}").as_bytes()].concat())
        .collect();
    // Every name is undeletable and present, so none can drain.
    for n in &full {
        h.secrets.insert(n.clone(), vec![1]);
        h.undeletable.insert(n.clone());
    }
    set_gc(&mut h, &full);
    let before = gc_names(&h);
    assert_eq!(before.len(), MAX_GC_NAMES);
    assert_eq!(put(&mut h, &key_entry(1, 8)), Err(PutError::Storage));
    assert_eq!(gc_names(&h), before, "the list was not erased or truncated");
    assert_eq!(read(&mut h, 1), Read::Ok(key_entry(1, 9)));
}

/// A removal that neither succeeds nor reads back (freenet-stdlib answers
/// false for a secret that was never there) is kept for a few passes and then
/// dropped, so names of candidates that never landed do not fill the list. A
/// secret that reads is never dropped, however often removal fails.
#[test]
fn an_unconfirmed_removal_is_bounded_but_a_readable_secret_is_never_dropped() {
    let mut h = MemHost::new();
    put(&mut h, &key_entry(1, 9)).unwrap();
    let never = entry_name(5, 0);
    let stuck = entry_name(6, 0);
    h.secrets.insert(stuck.clone(), vec![3]);
    h.undeletable.insert(stuck.clone());
    set_gc(&mut h, &[never.clone(), stuck.clone()]);
    for pass in 1..=GC_UNCERTAIN_LIMIT {
        let mut s = Store::open(&mut h, P).unwrap();
        s.process_gc();
        drop(s);
        let listed = gc_names(&h);
        assert!(listed.contains(&stuck), "pass {pass}");
        assert_eq!(
            listed.contains(&never),
            pass < GC_UNCERTAIN_LIMIT,
            "pass {pass}"
        );
    }
    h.undeletable.clear();
    let mut s = Store::open(&mut h, P).unwrap();
    s.process_gc();
    drop(s);
    assert!(!h.secrets.contains_key(&stuck));
    assert!(gc_names(&h).is_empty());
}

/// Adding names needs both gc list copies to take, so no name ends up held by
/// one copy only (the state a later read miss would erase). A write that
/// cannot list its names is refused before it touches an entry.
#[test]
fn a_write_whose_names_cannot_reach_both_gc_copies_is_refused() {
    let mut h = MemHost::new();
    put(&mut h, &key_entry(1, 9)).unwrap();
    let gc2 = names::gc2(&P);
    h.set_fault(move |n| {
        if n == gc2.as_slice() {
            WriteFault::Fail
        } else {
            WriteFault::None
        }
    });
    let before_entries = h.names_with_prefix(&names::entry_prefix(&P));
    assert_eq!(put(&mut h, &key_entry(1, 8)), Err(PutError::Storage));
    assert_eq!(
        h.names_with_prefix(&names::entry_prefix(&P)),
        before_entries
    );
    h.clear_fault();
    assert_eq!(read(&mut h, 1), Read::Ok(key_entry(1, 9)));
}

/// A write reported as failed whose follow-up read misses may have landed; its
/// name stays listed so gc can still remove it.
#[test]
fn a_failed_candidate_write_with_a_read_miss_stays_listed() {
    let mut h = MemHost::new();
    put(&mut h, &key_entry(1, 9)).unwrap();
    let cand = entry_name(1, 1);
    let c2 = cand.clone();
    h.set_fault(move |n| {
        if n == c2.as_slice() {
            WriteFault::DurableButFail
        } else {
            WriteFault::None
        }
    });
    h.hidden.insert(cand.clone());
    h.undeletable.insert(cand.clone());
    assert_eq!(put(&mut h, &key_entry(1, 8)), Err(PutError::Storage));
    assert!(
        gc_names(&h).contains(&cand),
        "the landed candidate was forgotten"
    );
    assert!(h.secrets.contains_key(&cand));
}

/// A removal that failed while the follow-up read also fails is not taken as
/// done: the name stays listed (the secret is present, just unreadable now).
#[test]
fn a_failed_removal_with_a_failing_read_is_retried() {
    let mut h = MemHost::new();
    put(&mut h, &key_entry(1, 9)).unwrap();
    let stray = entry_name(3, 0);
    h.secrets.insert(stray.clone(), vec![7]);
    h.undeletable.insert(stray.clone());
    h.hidden.insert(stray.clone());
    set_gc(&mut h, std::slice::from_ref(&stray));
    for _ in 0..1 {
        let mut s = Store::open(&mut h, P).unwrap();
        s.process_gc();
    }
    // One uncertain pass: still listed. Once readable again it is retried.
    assert_eq!(gc_names(&h), vec![stray.clone()]);
    h.hidden.clear();
    h.undeletable.clear();
    let mut s = Store::open(&mut h, P).unwrap();
    s.process_gc();
    drop(s);
    assert!(!h.secrets.contains_key(&stray));
}

/// An index write that fails and leaves something that is neither the old nor
/// the new index: the new entry copy might be the committed one, so it is not
/// removed on that evidence (the `old_intact` guard).
#[test]
fn a_torn_index_write_does_not_remove_the_new_copy() {
    let mut h = MemHost::new();
    put(&mut h, &key_entry(1, 9)).unwrap();
    let idx = names::index(&P);
    h.set_fault(move |name| {
        if name == idx.as_slice() {
            WriteFault::GarbageButFail
        } else {
            WriteFault::None
        }
    });
    assert_eq!(put(&mut h, &key_entry(1, 8)), Err(PutError::Storage));
    assert!(
        h.secrets.contains_key(&entry_name(1, 1)),
        "the new copy was removed although the first index is in an unknown state"
    );
    // The next call: the index is torn, so the store does not open and
    // nothing is removed; both entry copies are still there for Export.
    h.clear_fault();
    let before = h.secrets.clone();
    assert!(Store::open(&mut h, P).is_err());
    assert_eq!(h.secrets, before);
    assert!(h.secrets.contains_key(&entry_name(1, 0)));
    assert!(h.secrets.contains_key(&entry_name(1, 1)));
}

/// Bytes whose digest matches the index are exactly what was written. If this
/// build cannot decode them (a newer format) they are not damage: never
/// dropped, rewritten or counted lost.
#[test]
fn a_digest_valid_entry_this_build_cannot_decode_is_never_dropped() {
    use freenet_vault_common::hash::entry_digest;
    let mut h = MemHost::new();
    put(&mut h, &key_entry(2, 9)).unwrap();
    // A key entry whose content is 31 bytes: a known kind with a length this
    // build refuses.
    let bytes = [
        &[1u8, 0, 0, 32][..],
        &[1u8; 32],
        &[0, 31],
        &[2u8; 31],
        &[0, 0],
    ]
    .concat();
    assert!(Entry::decode(&bytes).is_err());
    let name = entry_name(1, 0);
    h.secrets.insert(name.clone(), bytes.clone());
    let digest = entry_digest(&bytes);
    let mut s = Store::open(&mut h, P).unwrap();
    s.update(|ix| {
        ix.upsert(index::IndexEntry {
            kind: KIND_KEY,
            key: vec![1; 32],
            parity: 0,
            len: bytes.len() as u16,
            digest,
        })
    })
    .unwrap();
    drop(s);
    let before = h.secrets.clone();
    assert_eq!(read(&mut h, 1), Read::Corrupt(None));
    assert_eq!(h.secrets, before, "the entry was rewritten or removed");
    let s = Store::open(&mut h, P).unwrap();
    assert_eq!(s.index.lost_entries, 0);
    assert!(s.index.find(KIND_KEY, &[1; 32]).is_some());
}

/// While sealed nothing is rewritten or removed (protocol 4.3).
#[test]
fn corruption_while_sealed_changes_nothing() {
    let mut h = MemHost::new();
    put(&mut h, &key_entry(1, 9)).unwrap();
    let name = entry_name(1, 0);
    let mut tampered = h.secrets[&name].clone();
    tampered[40] ^= 1;
    h.secrets.insert(name.clone(), tampered);
    h.secrets.insert(entry_name(2, 0), vec![]);
    let before = h.secrets.clone();
    let mut s = Store::open(&mut h, P).unwrap();
    assert!(matches!(
        s.read(KIND_KEY, &[1; 32], true),
        Read::Corrupt(Some(_))
    ));
    drop(s);
    assert_eq!(h.secrets, before);
}

/// A flag that was already set when an entry crosses (eflags is preserved
/// verbatim) answers corrupt even though the digest matches.
#[test]
fn an_entry_written_flagged_reads_corrupt() {
    let mut h = MemHost::new();
    let mut e = key_entry(1, 9);
    e.eflags = EFLAG_CORRUPT;
    put(&mut h, &e).unwrap();
    assert_eq!(read(&mut h, 1), Read::Corrupt(Some(e)));
}

#[test]
fn quotas_per_kind_and_overall() {
    let mut h = MemHost::new();
    for s in 0..4 {
        put(&mut h, &key_entry(s, 1)).unwrap();
    }
    assert_eq!(put(&mut h, &key_entry(4, 1)), Err(PutError::Quota));
    // Replacing at the limit is allowed.
    put(&mut h, &key_entry(3, 2)).unwrap();
    let mark = |k: u8| Entry::new(KIND_CALLER_MARK, vec![k; 40], vec![0; 100]);
    put(&mut h, &mark(1)).unwrap();
    put(&mut h, &mark(2)).unwrap();
    assert_eq!(put(&mut h, &mark(3)), Err(PutError::Quota));
}

#[test]
fn byte_quota_is_the_library_maximum() {
    let mut h = MemHost::new();
    let big = |k: u8| Entry {
        kind: 0x40,
        eflags: 0,
        key: vec![k],
        content: vec![0; 60_000],
        ext: vec![],
    };
    // 17 x 60,009 bytes = 1,020,153 <= 1 MiB; the 18th does not fit.
    for k in 0..17 {
        put(&mut h, &big(k)).unwrap();
    }
    assert_eq!(put(&mut h, &big(17)), Err(PutError::Quota));
}

/// Unknown kinds, unknown eflags bits and extensions are stored byte for byte.
#[test]
fn unknown_kinds_and_extensions_are_stored_verbatim() {
    let mut h = MemHost::new();
    let e = Entry {
        kind: 0x7F,
        eflags: 0b1000_0000,
        key: vec![1, 2, 3],
        content: vec![9; 500],
        ext: vec![8; 33],
    };
    put(&mut h, &e).unwrap();
    let name = names::entry(&P, 0x7F, &[1, 2, 3], 0);
    assert_eq!(h.secrets[&name], e.encode().unwrap());
    let mut s = Store::open(&mut h, P).unwrap();
    assert_eq!(s.read(0x7F, &[1, 2, 3], false), Read::Ok(e));
}

#[test]
fn a_malformed_index_is_never_read_as_none() {
    let mut h = MemHost::new();
    put(&mut h, &key_entry(1, 9)).unwrap();
    let mut b = index_on_disk(&h).unwrap();
    b.push(0);
    h.secrets.insert(names::index(&P), b.clone());
    let _ = b;
    assert!(Store::open(&mut h, P).is_err());
}

/// The library maximums are frozen forever (protocol 8.1): both edges.
#[test]
fn library_maximums_have_both_edges() {
    use index::IndexEntry;
    let big = Quota {
        max_key_slots: usize::MAX,
        max_caller_marks: usize::MAX,
    };
    let reserved = |key: Vec<u8>, content: usize| Entry::new(0x10, key, vec![7; content]);
    // 4096 entries: the 4096th fits, the 4097th does not, a replace does.
    let mut h = MemHost::new();
    {
        let mut s = Store::open(&mut h, P).unwrap();
        s.update(|ix| {
            for i in 0..4095u16 {
                ix.upsert(IndexEntry {
                    kind: 0x10,
                    key: i.to_be_bytes().to_vec(),
                    parity: 0,
                    len: 1,
                    digest: [0; 32],
                });
            }
        })
        .unwrap();
        drop(s);
        set_gc(&mut h, &[]);
        let mut s = Store::open(&mut h, P).unwrap();
        s.put(&reserved(vec![0xFF, 0xFF], 1), &big, |_| {}).unwrap();
        assert_eq!(s.index.entries.len(), 4096);
        assert_eq!(
            s.put(&reserved(vec![0xFF, 0xFE, 0], 1), &big, |_| {}),
            Err(PutError::Quota)
        );
        s.put(&reserved(vec![0xFF, 0xFF], 2), &big, |_| {}).unwrap();
    }
    // 1 MiB of entry bytes: the last byte fits, one more does not, and a
    // smaller replacement of an existing entry always fits.
    let mut h = MemHost::new();
    let mut s = Store::open(&mut h, P).unwrap();
    let max = freenet_vault_common::bounds::MAX_PARTITION_BYTES;
    s.update(|ix| {
        for i in 0..16u8 {
            ix.upsert(IndexEntry {
                kind: 0x10,
                key: vec![i],
                parity: 0,
                len: 65_399,
                digest: [0; 32],
            });
        }
    })
    .unwrap();
    drop(s);
    set_gc(&mut h, &[]);
    let mut s = Store::open(&mut h, P).unwrap();
    let held = s.index.total_bytes();
    assert_eq!(held, 16 * 65_399);
    // An entry with 9 bytes of framing and `n` bytes of content.
    let room = max - held;
    let fit = reserved(vec![0xA0], room - 9);
    assert_eq!(fit.encode().unwrap().len(), room);
    s.put(&fit, &big, |_| {}).unwrap();
    assert_eq!(s.index.total_bytes(), max);
    assert_eq!(
        s.put(&reserved(vec![0xA1], 0), &big, |_| {}),
        Err(PutError::Quota)
    );
    s.put(&reserved(vec![0xA0], 10), &big, |_| {}).unwrap();
}

#[test]
fn parts_list_is_idempotent() {
    let mut h = MemHost::new();
    ensure_part_listed(&mut h, &P).unwrap();
    ensure_part_listed(&mut h, &P).unwrap();
    ensure_part_listed(&mut h, &[1; 32]).unwrap();
    assert_eq!(h.secrets[names::PARTS].len(), 64);
}

/// A `vault:parts` that reads but is malformed is left alone, and listing
/// fails, instead of overwriting what other partitions it may hold.
#[test]
fn a_malformed_parts_list_is_never_overwritten() {
    let mut h = MemHost::new();
    let bad = vec![1u8; 33];
    h.secrets.insert(names::PARTS.to_vec(), bad.clone());
    assert_eq!(ensure_part_listed(&mut h, &P), Err(StorageFailure));
    assert_eq!(h.secrets[names::PARTS], bad);
}

/// `Index::seal` (used by the fuzz target) gives a body the checksum, so the
/// body parser is reached: a sealed valid body decodes, a sealed bad one is
/// refused by the parser and not by the checksum.
#[test]
fn a_sealed_body_reaches_the_index_parser() {
    let mut ix = Index::none();
    ix.state = State::Writer;
    let enc = ix.encode();
    let body = &enc[..enc.len() - 32];
    assert_eq!(Index::decode(&Index::seal(body)).unwrap(), ix);
    let mut bad = body.to_vec();
    bad[5] = 99; // the state byte
    let e = Index::decode(&Index::seal(&bad)).unwrap_err();
    assert!(!e.to_string().contains("checksum"), "{e}");
}

/// A flipped bit that still parses (a digest, a parity, the state) fails the
/// checksum: the store does not open, so nothing is believed, written or
/// removed. Restoring the good bytes opens it again.
#[test]
fn a_bit_flipped_index_is_rejected_and_the_store_stays_read_only() {
    let mut h = MemHost::new();
    put(&mut h, &key_entry(1, 9)).unwrap();
    put(&mut h, &key_entry(2, 8)).unwrap();
    let good = h.secrets[&names::index(&P)].clone();
    for at in 0..good.len() {
        let mut d = h.restart();
        let mut bad = good.clone();
        bad[at] ^= 0x01;
        d.secrets.insert(names::index(&P), bad);
        let before = d.secrets.clone();
        assert!(Store::open(&mut d, P).is_err(), "byte {at}");
        assert_eq!(d.secrets, before, "byte {at}: open wrote");
        d.secrets.insert(names::index(&P), good.clone());
        assert!(Store::open(&mut d, P).is_ok(), "byte {at}");
    }
}

/// An absent index for a partition `vault:parts` lists, a `vault:parts` that
/// reads but is malformed, and a damaged index are all "unknown": open fails
/// and writes nothing. An absent index with `vault:parts` not naming the
/// partition (or absent) is a new partition.
#[test]
fn unknown_index_state_is_read_only_and_only_positive_absence_is_new() {
    let mut h = MemHost::new();
    put(&mut h, &key_entry(1, 9)).unwrap();
    // The partition is listed by the first commit (index first, then parts).
    assert!(h.secrets[names::PARTS].chunks(32).any(|c| c == P));
    let idx = names::index(&P);
    // Primary missing while listed.
    let kept = h.secrets.remove(&idx).unwrap();
    let before = h.secrets.clone();
    assert!(Store::open(&mut h, P).is_err());
    assert_eq!(h.secrets, before, "a miss changed storage");
    // Torn first index while listed.
    h.secrets
        .insert(idx.clone(), kept[..kept.len() - 3].to_vec());
    assert!(Store::open(&mut h, P).is_err());
    // A malformed parts list, index absent.
    h.secrets.remove(&idx);
    h.secrets.insert(names::PARTS.to_vec(), vec![1; 33]);
    assert!(Store::open(&mut h, P).is_err());
    // Not listed and absent: new.
    h.secrets.insert(names::PARTS.to_vec(), vec![9; 32]);
    assert!(!Store::open(&mut h, P).unwrap().has_index());
    let mut fresh = MemHost::new();
    assert!(!Store::open(&mut fresh, P).unwrap().has_index());
}

/// A verified index puts the partition back in `vault:parts` (a crash between
/// the first commit and the listing).
#[test]
fn open_lists_a_partition_whose_index_reads() {
    let mut h = MemHost::new();
    put(&mut h, &key_entry(1, 9)).unwrap();
    h.secrets.remove(names::PARTS);
    assert!(Store::open(&mut h, P).is_ok());
    assert!(h.secrets[names::PARTS].chunks(32).any(|c| c == P));
}

/// An uncertain index commit makes the store read-only for the rest of the
/// call: a second write in the same call is refused and nothing is removed.
#[test]
fn an_uncertain_commit_makes_the_rest_of_the_call_read_only() {
    let mut h = MemHost::new();
    put(&mut h, &key_entry(1, 9)).unwrap();
    let idx = names::index(&P);
    h.set_fault(move |n| {
        if n == idx.as_slice() {
            WriteFault::GarbageButFail
        } else {
            WriteFault::None
        }
    });
    let mut s = Store::open(&mut h, P).unwrap();
    assert_eq!(
        s.put(&key_entry(1, 8), &QUOTA, |_| {}),
        Err(PutError::Storage)
    );
    assert_eq!(s.mode(), Mode::ReadOnly);
    // The host recovers within the call; the store still refuses.
    drop(s);
    h.clear_fault();
    let s = Store::open(&mut h, P);
    // The garbage index is not trusted by the next call either.
    assert!(s.is_err());
    drop(s);
    // A call whose commit fails after a good open stays read-only throughout.
    let mut h2 = MemHost::new();
    put(&mut h2, &key_entry(1, 9)).unwrap();
    let idx = names::index(&P);
    let s = Store::open(&mut h2, P).unwrap();
    // Fail the next index write cleanly, then recover the host mid-call.
    drop(s);
    let i2 = idx.clone();
    h2.set_fault(move |n| {
        if n == i2.as_slice() {
            WriteFault::Fail
        } else {
            WriteFault::None
        }
    });
    let mut s = Store::open(&mut h2, P).unwrap();
    assert!(s.put(&key_entry(1, 8), &QUOTA, |_| {}).is_err());
    assert_eq!(s.mode(), Mode::ReadOnly);
    assert!(s.put(&key_entry(2, 8), &QUOTA, |_| {}).is_err());
    assert_eq!(s.delete(KIND_KEY, &[1; 32]), Err(StorageFailure));
}

/// Both gc list copies reading as nothing while the index names entries is
/// "unreadable": gc does not run and a write that needs to list a name fails,
/// instead of rewriting the list without what it held.
#[test]
fn an_unreadable_gc_list_blocks_gc_and_writes_that_need_it() {
    let mut h = MemHost::new();
    put(&mut h, &key_entry(1, 9)).unwrap();
    let stray = entry_name(3, 0);
    h.secrets.insert(stray.clone(), vec![7]);
    set_gc(&mut h, std::slice::from_ref(&stray));
    h.hidden.insert(names::gc(&P));
    h.hidden.insert(names::gc2(&P));
    let before = h.secrets.clone();
    let mut s = Store::open(&mut h, P).unwrap();
    s.process_gc();
    assert_eq!(
        s.put(&key_entry(1, 8), &QUOTA, |_| {}),
        Err(PutError::Storage)
    );
    assert_eq!(s.delete(KIND_KEY, &[1; 32]), Err(StorageFailure));
    drop(s);
    assert_eq!(h.secrets, before, "nothing was written or removed");
    // Readable again: the stray is collected.
    h.hidden.clear();
    let mut s = Store::open(&mut h, P).unwrap();
    s.process_gc();
    drop(s);
    assert!(!h.secrets.contains_key(&stray));
}

/// A full gc list refuses writes that need a gc entry; no name is dropped to
/// make room.
#[test]
fn a_full_gc_list_refuses_writes_and_drops_nothing() {
    let mut h = MemHost::new();
    put(&mut h, &key_entry(1, 9)).unwrap();
    let prefix = names::entry_prefix(&P);
    let full: Vec<GcName> = (0..MAX_GC_NAMES)
        .map(|i| GcName {
            name: [prefix.as_slice(), format!("{i:05}").as_bytes()].concat(),
            uncertain: 2,
        })
        .collect();
    let b = encode_names(&full).unwrap();
    h.secrets.insert(names::gc(&P), b.clone());
    h.secrets.insert(names::gc2(&P), b);
    for g in &full {
        h.secrets.insert(g.name.clone(), vec![1]);
        h.undeletable.insert(g.name.clone());
    }
    let mut s = Store::open(&mut h, P).unwrap();
    assert_eq!(
        s.put(&key_entry(1, 8), &QUOTA, |_| {}),
        Err(PutError::Storage)
    );
    drop(s);
    assert_eq!(gc_names(&h).len(), MAX_GC_NAMES);
}

/// Export while the index state is unknown: exactly one decodable copy of the
/// slot gives the seed; none or two refuse.
#[test]
fn rescue_export_needs_exactly_one_decodable_copy() {
    let mut h = MemHost::new();
    put(&mut h, &key_entry(1, 9)).unwrap();
    let slot = [1u8; 32];
    assert_eq!(rescue_export_seed(&h, &P, &slot), Some([9; 32]));
    // Two decodable copies: refused.
    let other = key_entry(1, 8).encode().unwrap();
    h.secrets.insert(entry_name(1, 1), other);
    assert_eq!(rescue_export_seed(&h, &P, &slot), None);
    // None decodable.
    h.secrets.insert(entry_name(1, 0), vec![0xFF; 4]);
    h.secrets.insert(entry_name(1, 1), vec![0xFF; 4]);
    assert_eq!(rescue_export_seed(&h, &P, &slot), None);
    // A copy for another slot does not count.
    let wrong = key_entry(2, 5).encode().unwrap();
    h.secrets.insert(entry_name(1, 0), wrong);
    assert_eq!(rescue_export_seed(&h, &P, &slot), None);
}
