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
                if !out.contains(&g) {
                    out.push(g);
                }
            }
        }
    }
    out
}

/// Plants a gc list (both copies), as a crash leaves one.
fn set_gc(host: &mut MemHost, list: &[Vec<u8>]) {
    let b = encode_names(list).unwrap();
    host.secrets.insert(names::gc(&P), b.clone());
    host.secrets.insert(names::gc2(&P), b);
}

fn index_on_disk(host: &MemHost) -> Option<Vec<u8>> {
    host.secrets.get(&names::index(&P)).cloned()
}

#[test]
fn put_writes_entry_then_index_then_the_mirror_and_reads_back() {
    let mut h = MemHost::new();
    let e = key_entry(1, 9);
    put(&mut h, &e).unwrap();
    assert_eq!(read(&mut h, 1), Read::Ok(e.clone()));
    // The named copy at parity 0 and its mirror at parity 1, byte for byte, and
    // no gc left behind (spec 4.2: a change never uses vault:gc).
    assert_eq!(h.secrets[&entry_name(1, 0)], e.encode().unwrap());
    assert_eq!(h.secrets[&entry_name(1, 1)], e.encode().unwrap());
    assert!(gc_names(&h).is_empty());
    let s = Store::open(&mut h, P).unwrap();
    assert_eq!(s.index.state, State::Writer);
    assert_eq!(s.index.entries.len(), 1);
}

#[test]
fn replace_flips_the_named_parity_and_rewrites_the_mirror() {
    let mut h = MemHost::new();
    put(&mut h, &key_entry(1, 9)).unwrap();
    put(&mut h, &key_entry(1, 8)).unwrap();
    assert_eq!(read(&mut h, 1), Read::Ok(key_entry(1, 8)));
    let new = key_entry(1, 8).encode().unwrap();
    // The index names parity 1 now; parity 0 holds its mirror.
    assert_eq!(Store::open(&mut h, P).unwrap().index.entries[0].parity, 1);
    assert_eq!(h.secrets[&entry_name(1, 1)], new);
    assert_eq!(h.secrets[&entry_name(1, 0)], new);
    assert!(gc_names(&h).is_empty());
    put(&mut h, &key_entry(1, 7)).unwrap();
    let newer = key_entry(1, 7).encode().unwrap();
    assert_eq!(h.secrets[&entry_name(1, 0)], newer);
    assert_eq!(h.secrets[&entry_name(1, 1)], newer);
}

#[test]
fn a_failed_entry_write_changes_no_acknowledged_value() {
    let mut h = MemHost::new();
    put(&mut h, &key_entry(1, 9)).unwrap();
    h.set_fault(|name| {
        if name.starts_with(b"vault:e:") {
            WriteFault::DurableButFail
        } else {
            WriteFault::None
        }
    });
    assert_eq!(put(&mut h, &key_entry(1, 8)), Err(PutError::Storage));
    assert_eq!(put(&mut h, &key_entry(2, 8)), Err(PutError::Storage));
    h.clear_fault();
    // The index never moved: the old value is what is served.
    assert_eq!(read(&mut h, 1), Read::Ok(key_entry(1, 9)));
    assert_eq!(read(&mut h, 2), Read::Absent);
}

/// A failed index write with the old index provably on disk: the old value
/// stays served. The candidate sits at the parity the index does not name (the
/// old mirror), so the two copies disagree until the sweep repairs the mirror.
#[test]
fn failed_index_write_leaves_the_old_value_served_and_the_sweep_repairs_the_mirror() {
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
    h.clear_fault();
    assert_eq!(read(&mut h, 1), Read::Ok(key_entry(1, 9)));
    let old = key_entry(1, 9).encode().unwrap();
    assert_eq!(h.secrets[&entry_name(1, 0)], old);
    assert_ne!(h.secrets[&entry_name(1, 1)], old, "the candidate");
    // The sweep rewrites the mirror from the named copy.
    let mut s = Store::open(&mut h, P).unwrap();
    s.mirror_sweep();
    drop(s);
    assert_eq!(h.secrets[&entry_name(1, 1)], old);
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
    h.set_pair(&name, tampered.clone());
    let Read::Corrupt(Some(e)) = read(&mut h, 1) else {
        panic!("expected corrupt")
    };
    assert!(e.is_flagged_corrupt());
    // Rewritten at the other parity, flag set, every other byte verbatim.
    let mut flagged = tampered.clone();
    flagged[1] |= EFLAG_CORRUPT;
    assert_eq!(h.secrets[&entry_name(1, 1)], flagged);
    // The mirror (step 4) holds the same flagged bytes.
    assert_eq!(h.secrets[&name], flagged);
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
    h.set_pair(&entry_name(1, 0), vec![0xFF; 5]);
    // Present bytes that do not parse: dropped and counted.
    assert_eq!(read(&mut h, 1), Read::Absent);
    let s = Store::open(&mut h, P).unwrap();
    assert_eq!(s.index.lost_entries, 1);
    assert_eq!(s.index.entries.len(), 1);
    drop(s);
    assert!(!h.secrets.contains_key(&entry_name(1, 0)));
}

/// An entry the index names whose secret is gone (a wipe or restore of that
/// one secret) is Missing, never corrupt: nothing is deleted, flagged or
/// counted, and it reads again if the secret comes back.
#[test]
fn a_named_entry_whose_secret_is_gone_is_never_destroyed() {
    let mut h = MemHost::new();
    put(&mut h, &key_entry(1, 9)).unwrap();
    let name = entry_name(1, 0);
    let bytes = h.secrets.remove(&name).unwrap();
    let before = h.secrets.clone();
    assert_eq!(read(&mut h, 1), Read::Missing);
    assert_eq!(read(&mut h, 1), Read::Missing);
    assert_eq!(h.secrets, before);
    let s = Store::open(&mut h, P).unwrap();
    assert_eq!(s.index.lost_entries, 0);
    assert_eq!(s.index.problems, 0);
    assert_eq!(s.index.entries.len(), 1);
    drop(s);
    h.secrets.insert(name.clone(), bytes);
    assert_eq!(read(&mut h, 1), Read::Ok(key_entry(1, 9)));
    // Also when sealed.
    h.secrets.remove(&name);
    let mut s = Store::open(&mut h, P).unwrap();
    assert_eq!(s.read(KIND_KEY, &[1; 32], true), Read::Missing);
}

/// The real host (freenet-core #5857): a read that fails poisons the call, so
/// no write or removal follows it. The host model refuses them.
#[test]
fn a_read_fault_poisons_the_call_and_no_write_follows() {
    let mut h = MemHost::new();
    put(&mut h, &key_entry(1, 9)).unwrap();
    h.read_fault.insert(entry_name(1, 0));
    let before = h.secrets.clone();
    let mut s = Store::open(&mut h, P).unwrap();
    assert_eq!(s.read(KIND_KEY, &[1; 32], false), Read::Missing);
    assert_eq!(
        s.put(&key_entry(2, 2), &QUOTA, |_| {}),
        Err(PutError::Storage)
    );
    assert_eq!(s.delete(KIND_KEY, &[1; 32]), Err(StorageFailure));
    drop(s);
    assert!(h.poisoned());
    assert_eq!(
        h.secrets, before,
        "a write or removal followed the failed read"
    );
}

#[test]
fn gc_keeps_names_whose_removal_failed_and_retries() {
    let mut h = MemHost::new();
    put(&mut h, &key_entry(1, 9)).unwrap();
    // A deleted slot's copy that will not remove stays listed.
    let stray = entry_name(5, 0);
    h.secrets.insert(stray.clone(), vec![1]);
    h.undeletable.insert(stray.clone());
    set_gc(&mut h, std::slice::from_ref(&stray));
    let mut s = Store::open(&mut h, P).unwrap();
    s.process_gc();
    drop(s);
    assert_eq!(gc_names(&h), vec![stray.clone()]);
    // The host recovers: the next call removes it and clears the list.
    h.undeletable.clear();
    let mut s = Store::open(&mut h, P).unwrap();
    s.process_gc();
    drop(s);
    assert!(!h.secrets.contains_key(&stray));
    assert!(gc_names(&h).is_empty());
    assert_eq!(read(&mut h, 1), Read::Ok(key_entry(1, 9)));
}

/// A change that dies after writing its candidate and before the index commit
/// leaves the old value served (the candidate sits at the old mirror), and the
/// next call's sweep repairs the mirror.
#[test]
fn an_interrupted_entry_write_leaves_the_old_value_served() {
    let mut h = MemHost::new();
    put(&mut h, &key_entry(1, 9)).unwrap();
    let old = key_entry(1, 9).encode().unwrap();
    // The candidate write is the first mutation.
    h.crash_after(1);
    let _ = put(&mut h, &key_entry(1, 8));
    let mut h = h.restart();
    assert_eq!(read(&mut h, 1), Read::Ok(key_entry(1, 9)));
    let mut s = Store::open(&mut h, P).unwrap();
    s.mirror_sweep();
    drop(s);
    assert_eq!(h.secrets[&entry_name(1, 1)], old);
    assert_eq!(h.secrets[&entry_name(1, 0)], old);
}

/// A gc list copy damaged by a torn write contributes nothing; the other copy
/// still holds every pending name, and the next write repairs the damaged one.
#[test]
fn the_gc_list_survives_one_damaged_copy() {
    let mut h = MemHost::new();
    put(&mut h, &key_entry(1, 9)).unwrap();
    // An undeletable stray copy is pending.
    let stray = entry_name(3, 0);
    h.secrets.insert(stray.clone(), vec![7]);
    h.undeletable.insert(stray.clone());
    set_gc(&mut h, std::slice::from_ref(&stray));
    h.secrets.insert(names::gc(&P), b"torn write".to_vec());
    put(&mut h, &key_entry(1, 8)).unwrap();
    assert!(gc_names(&h).contains(&stray), "pending removal lost");
    // Both copies parse again.
    for n in [names::gc(&P), names::gc2(&P)] {
        assert!(decode_names(&h.secrets[&n]).is_some());
    }
    // Still retried: once removable, it goes.
    h.undeletable.clear();
    let mut s = Store::open(&mut h, P).unwrap();
    s.process_gc();
    drop(s);
    assert!(!h.secrets.contains_key(&stray));
}

/// The list is bounded: a Delete whose names would exceed it fails and leaves
/// the pending names alone, instead of wrapping its count and erasing itself.
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
    let mut s = Store::open(&mut h, P).unwrap();
    assert_eq!(s.delete(KIND_KEY, &[1; 32]), Err(StorageFailure));
    drop(s);
    assert_eq!(gc_names(&h), before, "the list was not erased or truncated");
    assert_eq!(read(&mut h, 1), Read::Ok(key_entry(1, 9)));
}

/// A name leaves the list only when its secret reads as absent after the
/// removal attempt: a removal that fails and leaves the secret keeps the name
/// for ever; one that reports failure but landed, or a name that never existed,
/// is done (reads are truthful in a call that completes).
#[test]
fn a_name_is_dropped_only_when_the_secret_reads_absent() {
    let mut h = MemHost::new();
    put(&mut h, &key_entry(1, 9)).unwrap();
    let never = entry_name(5, 0);
    let stuck = entry_name(6, 0);
    let landed = entry_name(7, 0);
    h.secrets.insert(stuck.clone(), vec![3]);
    h.secrets.insert(landed.clone(), vec![4]);
    h.undeletable.insert(stuck.clone());
    h.remove_lands_but_fails.insert(landed.clone());
    set_gc(&mut h, &[never.clone(), stuck.clone(), landed.clone()]);
    for pass in 1..=5 {
        let mut s = Store::open(&mut h, P).unwrap();
        s.process_gc();
        drop(s);
        assert_eq!(gc_names(&h), vec![stuck.clone()], "pass {pass}");
        assert!(h.secrets.contains_key(&stuck));
    }
    assert!(!h.secrets.contains_key(&landed));
    h.undeletable.clear();
    let mut s = Store::open(&mut h, P).unwrap();
    s.process_gc();
    drop(s);
    assert!(!h.secrets.contains_key(&stuck));
    assert!(gc_names(&h).is_empty());
}

/// A Delete lists both names in `vault:gc` first, and both copies must take: a
/// Delete that cannot list is refused before it touches an entry.
#[test]
fn a_delete_whose_names_cannot_reach_both_gc_copies_is_refused() {
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
    let before = h.names_with_prefix(&names::entry_prefix(&P));
    let mut s = Store::open(&mut h, P).unwrap();
    assert_eq!(s.delete(KIND_KEY, &[1; 32]), Err(StorageFailure));
    drop(s);
    assert_eq!(h.names_with_prefix(&names::entry_prefix(&P)), before);
    h.clear_fault();
    assert_eq!(read(&mut h, 1), Read::Ok(key_entry(1, 9)));
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
    h.set_pair(&name, tampered);
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

/// Unknown kinds, unknown eflags bits and extensions are stored byte for byte,
/// and never served: a read answers "cannot use" (Corrupt(None)) without
/// dropping or rewriting the bytes (spec 11).
#[test]
fn unknown_kinds_and_extensions_are_stored_verbatim_and_never_served() {
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
    assert_eq!(s.read(0x7F, &[1, 2, 3], false), Read::Corrupt(None));
    drop(s);
    assert_eq!(h.secrets[&name], e.encode().unwrap(), "bytes changed");
    // A known kind with an unknown flag bit is not served either, and a
    // direct read (no index) skips it.
    let mut k = key_entry(1, 9);
    k.eflags = 0b0100_0000;
    put(&mut h, &k).unwrap();
    assert_eq!(read(&mut h, 1), Read::Corrupt(None));
    assert_eq!(rescue_export_seed(&h, &P, &[1; 32]), None);
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

/// A `vault:parts` that reads but is malformed is overwritten by a list naming
/// the partition being listed (revision 10.2); other partitions' valid indexes
/// are listed again by their own catch-all.
#[test]
fn a_malformed_parts_list_is_overwritten_by_the_listing() {
    let mut h = MemHost::new();
    h.secrets.insert(names::PARTS.to_vec(), vec![1u8; 33]);
    ensure_part_listed(&mut h, &P).unwrap();
    assert_eq!(h.secrets[names::PARTS], P.to_vec());
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

/// The catch-all (spec 4.2): a valid WRITER index for an unlisted partition is
/// listed, and read back, before anything else; `open` itself lists nothing.
#[test]
fn the_catch_all_lists_a_writer_index_and_open_does_not() {
    let mut h = MemHost::new();
    put(&mut h, &key_entry(1, 9)).unwrap();
    h.secrets.remove(names::PARTS);
    assert!(Store::open(&mut h, P).is_ok());
    assert!(!h.secrets.contains_key(names::PARTS), "open listed");
    ensure_listed(&mut h, &P).unwrap();
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

/// Export while the index state is unknown: exactly one decodable copy of the
/// slot gives the seed; none or two refuse.
#[test]
fn rescue_export_needs_exactly_one_decodable_copy() {
    let mut h = MemHost::new();
    put(&mut h, &key_entry(1, 9)).unwrap();
    let slot = [1u8; 32];
    assert_eq!(rescue_export_seed(&h, &P, &slot), Some([9; 32]));
    // Two identical copies are one value.
    let same = h.secrets[&entry_name(1, 0)].clone();
    h.secrets.insert(entry_name(1, 1), same);
    assert_eq!(rescue_export_seed(&h, &P, &slot), Some([9; 32]));
    // Two that differ: refused.
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

/// Step 1 of a change to a new identity removes both parity names first, so a
/// stale copy left at either parity never pairs with the new value.
#[test]
fn a_new_identity_clears_a_stale_copy_at_the_other_parity_first() {
    let mut h = MemHost::new();
    put(&mut h, &key_entry(1, 9)).unwrap();
    let mut s = Store::open(&mut h, P).unwrap();
    s.update(|ix| ix.entries.clear()).unwrap();
    drop(s);
    let stale = Entry::new(KIND_KEY, vec![1; 32], vec![0x77; 32])
        .encode()
        .unwrap();
    h.secrets.insert(entry_name(1, 1), stale);
    put(&mut h, &key_entry(1, 8)).unwrap();
    let new = key_entry(1, 8).encode().unwrap();
    assert_eq!(h.secrets[&entry_name(1, 0)], new);
    assert_eq!(h.secrets[&entry_name(1, 1)], new, "the stale copy stayed");
    assert_eq!(read(&mut h, 1), Read::Ok(key_entry(1, 8)));
}

// ---- revision 10.1: the mirror, Delete, direct read, listing ----------------

/// What direct read would serve for slot `slot`, against what the committed
/// index names: direct read may only ever serve the committed value.
fn assert_direct_read_is_committed(h: &mut MemHost, slot: u8, what: &str) {
    let served = rescue_export_seed(h, &P, &[slot; 32]);
    let committed = match Store::open(h, P) {
        Ok(mut s) => match s.read(KIND_KEY, &[slot; 32], true) {
            Read::Ok(e) => Some(<[u8; 32]>::try_from(e.content.as_slice()).unwrap()),
            _ => None,
        },
        Err(_) => None,
    };
    if let Some(seed) = served {
        assert_eq!(
            Some(seed),
            committed,
            "{what}: direct read served a value the index does not name"
        );
    }
}

/// A crash at every mutation point of a replace, a new identity and a Delete:
/// direct read never serves anything but the committed value (spec 4.2, F13).
#[test]
fn a_crash_at_every_step_never_lets_direct_read_serve_an_uncommitted_value() {
    type Act = fn(&mut MemHost);
    let cases: [(&str, Act); 3] = [
        ("replace", |h| {
            let _ = put(h, &key_entry(1, 8));
        }),
        ("new identity", |h| {
            let _ = put(h, &key_entry(2, 7));
        }),
        ("delete", |h| {
            let mut s = Store::open(h, P).unwrap();
            let _ = s.delete(KIND_KEY, &[1; 32]);
        }),
    ];
    for (name, act) in cases {
        let mut base = MemHost::new();
        put(&mut base, &key_entry(1, 9)).unwrap();
        let start = base.mutations;
        let mut dry = base.restart();
        dry.mutations = 0;
        act(&mut dry);
        let total = dry.mutations;
        assert!(total >= 3, "{name}: {total}");
        let _ = start;
        for n in 0..=total {
            let mut h = base.restart();
            h.crash_after(n);
            act(&mut h);
            let mut h = h.restart();
            for slot in [1, 2] {
                assert_direct_read_is_committed(&mut h, slot, &format!("{name}, crash {n}"));
            }
            // And after the next call's sweep and gc too.
            let mut s = Store::open(&mut h, P).unwrap();
            s.process_gc();
            s.mirror_sweep();
            drop(s);
            for slot in [1, 2] {
                assert_direct_read_is_committed(
                    &mut h,
                    slot,
                    &format!("{name}, crash {n}, recovered"),
                );
            }
        }
    }
}

/// Step 1: a leftover copy that will not clear refuses the change, so it can
/// never pair with the new value. Here a Delete's named copy would not remove.
#[test]
fn step_one_refuses_a_new_identity_whose_leftover_will_not_clear() {
    let mut h = MemHost::new();
    put(&mut h, &key_entry(1, 9)).unwrap();
    // The named copy of slot 1 (parity 0) will not remove.
    h.undeletable.insert(entry_name(1, 0));
    let mut s = Store::open(&mut h, P).unwrap();
    s.delete(KIND_KEY, &[1; 32]).unwrap();
    drop(s);
    assert_eq!(read(&mut h, 1), Read::Absent);
    // Re-creating the slot with the same seed: step 1 cannot clear parity 0.
    assert_eq!(put(&mut h, &key_entry(1, 9)), Err(PutError::Storage));
    assert_eq!(read(&mut h, 1), Read::Absent);
    assert_eq!(
        rescue_export_seed(&h, &P, &[1; 32]),
        None,
        "a deleted key was served"
    );
    // Once the host recovers the change goes through.
    h.undeletable.clear();
    put(&mut h, &key_entry(1, 9)).unwrap();
    assert_eq!(read(&mut h, 1), Read::Ok(key_entry(1, 9)));
}

/// Delete step 2: the mirror must read back as absent before the commit. If it
/// will not clear the Delete is refused and the slot stays readable.
#[test]
fn a_delete_whose_mirror_will_not_clear_is_refused_and_the_slot_stays() {
    let mut h = MemHost::new();
    put(&mut h, &key_entry(1, 9)).unwrap();
    // Parity 0 is named, so parity 1 is the mirror.
    h.undeletable.insert(entry_name(1, 1));
    let mut s = Store::open(&mut h, P).unwrap();
    assert_eq!(s.delete(KIND_KEY, &[1; 32]), Err(StorageFailure));
    drop(s);
    assert_eq!(read(&mut h, 1), Read::Ok(key_entry(1, 9)));
    assert_eq!(Store::open(&mut h, P).unwrap().index.entries.len(), 1);
}

/// A Delete removes the mirror before the commit, so after any outcome of the
/// commit there is at most one copy: a pair never survives a Delete.
#[test]
fn a_delete_leaves_no_pair_whatever_happens_to_its_commit() {
    for fault in [WriteFault::Fail, WriteFault::DurableButFail] {
        let mut h = MemHost::new();
        put(&mut h, &key_entry(1, 9)).unwrap();
        let idx = names::index(&P);
        h.set_fault(move |n| {
            if n == idx.as_slice() {
                fault
            } else {
                WriteFault::None
            }
        });
        let mut s = Store::open(&mut h, P).unwrap();
        let _ = s.delete(KIND_KEY, &[1; 32]);
        drop(s);
        h.clear_fault();
        let both =
            h.secrets.contains_key(&entry_name(1, 0)) && h.secrets.contains_key(&entry_name(1, 1));
        assert!(!both, "{fault:?}: a pair survived the Delete");
        assert_eq!(rescue_export_seed(&h, &P, &[1; 32]), None, "{fault:?}");
    }
}

/// gc works by identity: both parity names of an identity the committed index
/// names are in use, so a gc list naming either (or both) removes neither.
#[test]
fn gc_never_removes_a_name_whose_identity_the_index_names() {
    let mut h = MemHost::new();
    put(&mut h, &key_entry(1, 9)).unwrap();
    set_gc(&mut h, &[entry_name(1, 0), entry_name(1, 1)]);
    let mut s = Store::open(&mut h, P).unwrap();
    s.process_gc();
    drop(s);
    assert!(h.secrets.contains_key(&entry_name(1, 0)));
    assert!(h.secrets.contains_key(&entry_name(1, 1)));
    assert!(gc_names(&h).is_empty(), "the named names stay listed");
    assert_eq!(rescue_export_seed(&h, &P, &[1; 32]), Some([9; 32]));
}

/// The mirror sweep writes a missing or different mirror from the named copy,
/// but only after the named copy passes the index digest, never while sealed.
#[test]
fn the_mirror_sweep_checks_the_digest_and_does_not_run_while_sealed() {
    let mut h = MemHost::new();
    put(&mut h, &key_entry(1, 9)).unwrap();
    put(&mut h, &key_entry(2, 8)).unwrap();
    let good1 = h.secrets[&entry_name(1, 0)].clone();
    // Slot 1: the mirror is missing. Slot 2: the named copy (parity 0) is
    // corrupt (fails the digest) and the mirror differs.
    h.secrets.remove(&entry_name(1, 1));
    let mut bad = h.secrets[&entry_name(2, 0)].clone();
    bad[40] ^= 1;
    h.secrets.insert(entry_name(2, 0), bad.clone());
    h.secrets.insert(entry_name(2, 1), vec![5; 3]);
    // Sealed: nothing is written.
    let mut s = Store::open(&mut h, P).unwrap();
    s.update(|ix| ix.state = State::Sealed).unwrap();
    let before = h.secrets.clone();
    let mut s = Store::open(&mut h, P).unwrap();
    s.mirror_sweep();
    drop(s);
    assert_eq!(h.secrets, before, "a sealed build swept");
    // Writer: slot 1's mirror is written; slot 2's corrupt copy is not copied.
    let mut s = Store::open(&mut h, P).unwrap();
    s.update(|ix| ix.state = State::Writer).unwrap();
    s.mirror_sweep();
    drop(s);
    assert_eq!(h.secrets[&entry_name(1, 1)], good1);
    assert_eq!(
        h.secrets[&entry_name(2, 1)],
        vec![5; 3],
        "swept a copy that fails the digest"
    );
    assert_eq!(h.secrets[&entry_name(2, 0)], bad);
}

/// Direct read (spec 4.5): both parity copies must authenticate and be
/// byte-identical. Every other case is unavailable, and vault:gc is not read.
#[test]
fn direct_read_needs_two_authenticating_identical_copies() {
    let slot = [1u8; 32];
    let good = key_entry(1, 9).encode().unwrap();
    let with = |c0: Option<Vec<u8>>, c1: Option<Vec<u8>>| {
        let mut h = MemHost::new();
        if let Some(c) = c0 {
            h.secrets.insert(entry_name(1, 0), c);
        }
        if let Some(c) = c1 {
            h.secrets.insert(entry_name(1, 1), c);
        }
        h
    };
    let served = |h: &MemHost| rescue_export_seed(h, &P, &slot);
    assert_eq!(
        served(&with(Some(good.clone()), Some(good.clone()))),
        Some([9; 32])
    );
    // One copy, two different copies, none.
    assert_eq!(served(&with(Some(good.clone()), None)), None);
    assert_eq!(served(&with(None, Some(good.clone()))), None);
    let other = key_entry(1, 8).encode().unwrap();
    assert_eq!(served(&with(Some(good.clone()), Some(other))), None);
    assert_eq!(served(&with(None, None)), None);
    // Same bytes but a flag set (integrity flag, reserved bit), or an extension
    // that differs, or another slot's entry under this slot's names.
    for flags in [EFLAG_CORRUPT, 0x80, 0x03] {
        let mut e = key_entry(1, 9);
        e.eflags = flags;
        let b = e.encode().unwrap();
        assert_eq!(
            served(&with(Some(b.clone()), Some(b))),
            None,
            "eflags {flags:#x}"
        );
    }
    let mut ext = key_entry(1, 9);
    ext.ext = vec![1, 2];
    let (a, b) = (ext.encode().unwrap(), good.clone());
    assert_eq!(served(&with(Some(a), Some(b))), None, "extension differs");
    let wrong = key_entry(2, 9).encode().unwrap();
    assert_eq!(
        served(&with(Some(wrong.clone()), Some(wrong))),
        None,
        "another slot's key"
    );
    // A kind that is not a key, a short seed, trailing bytes.
    let mark = Entry::new(KIND_CALLER_MARK, slot.to_vec(), vec![1; 100])
        .encode()
        .unwrap();
    assert_eq!(served(&with(Some(mark.clone()), Some(mark))), None);
    let mut trailing = good.clone();
    trailing.push(0);
    assert_eq!(served(&with(Some(trailing.clone()), Some(trailing))), None);
    // vault:gc is never consulted: listing both names changes nothing.
    let mut h = with(Some(good.clone()), Some(good));
    set_gc(&mut h, &[entry_name(1, 0), entry_name(1, 1)]);
    assert_eq!(served(&h), Some([9; 32]));
}

/// Only a WRITER or SEALED index is listed; the first WRITER index is listed
/// after it reads back; a NONE, RECEIVING or RETIRED index never is.
#[test]
fn only_a_writer_or_sealed_index_is_listed() {
    let listed = |h: &MemHost| {
        h.secrets
            .get(names::PARTS)
            .is_some_and(|l| l.chunks(32).any(|c| c == P))
    };
    for (state, expect) in [
        (State::None, false),
        (State::Receiving, false),
        (State::Retired, false),
        (State::Writer, true),
        (State::Sealed, true),
    ] {
        let mut h = MemHost::new();
        let mut s = Store::open(&mut h, P).unwrap();
        s.update(|ix| ix.state = state).unwrap();
        drop(s);
        assert_eq!(listed(&h), expect, "{state:?}");
    }
    // An armed NONE index is not listed either.
    let mut h = MemHost::new();
    let mut s = Store::open(&mut h, P).unwrap();
    s.update(|ix| ix.armed = Some([7; 100])).unwrap();
    drop(s);
    assert!(!listed(&h));
}

/// A WRITER index whose listing fails: the change answers storage failure, no
/// dependent answer leaves, and the next call's catch-all lists it.
#[test]
fn a_failed_listing_refuses_the_creating_change_and_the_catch_all_lists_it() {
    let mut h = MemHost::new();
    h.set_fault(|n| {
        if n == names::PARTS {
            WriteFault::Fail
        } else {
            WriteFault::None
        }
    });
    assert_eq!(put(&mut h, &key_entry(1, 9)), Err(PutError::Storage));
    assert!(!h.secrets.contains_key(names::PARTS));
    // The index is a valid WRITER index that is not listed.
    h.clear_fault();
    assert_eq!(
        Store::open(&mut h.restart(), P).unwrap().index.state,
        State::Writer
    );
    ensure_listed(&mut h, &P).unwrap();
    assert!(h.secrets[names::PARTS].chunks(32).any(|c| c == P));
    // And a catch-all whose write fails reports it (the call answers nothing).
    let mut h2 = MemHost::new();
    h2.set_fault(|n| {
        if n == names::PARTS {
            WriteFault::Fail
        } else {
            WriteFault::None
        }
    });
    let _ = put(&mut h2, &key_entry(1, 9));
    assert!(ensure_listed(&mut h2, &P).is_err());
}

/// A malformed index counts as index loss only while `vault:parts` lists the
/// partition or is not a valid list. An absent list is a valid empty list.
#[test]
fn a_malformed_index_is_loss_only_while_listed_or_with_a_malformed_list() {
    let torn = |h: &mut MemHost| {
        let b = h.secrets[&names::index(&P)].clone();
        h.secrets
            .insert(names::index(&P), b[..b.len() - 3].to_vec());
    };
    let mut h = MemHost::new();
    put(&mut h, &key_entry(1, 9)).unwrap();
    torn(&mut h);
    // Listed: loss.
    assert!(Store::fault(&h, &P).is_some());
    // Absent list: NONE, exactly as for an absent index.
    h.secrets.remove(names::PARTS);
    assert!(Store::fault(&h, &P).is_none());
    assert!(!Store::open(&mut h, P).unwrap().has_index());
    // A valid list that does not name it: NONE.
    h.secrets.insert(names::PARTS.to_vec(), vec![9; 32]);
    assert!(Store::fault(&h, &P).is_none());
    // A malformed list: loss.
    h.secrets.insert(names::PARTS.to_vec(), vec![9; 33]);
    assert!(Store::fault(&h, &P).is_some());
    // An absent index: loss only when listed or the list is malformed.
    h.secrets.remove(&names::index(&P));
    assert!(Store::fault(&h, &P).is_some());
    h.secrets.insert(names::PARTS.to_vec(), vec![9; 32]);
    assert!(Store::fault(&h, &P).is_none());
    h.secrets.insert(names::PARTS.to_vec(), P.to_vec());
    assert!(Store::fault(&h, &P).is_some());
}

/// Receivers never mirror: a change to a RECEIVING index writes one copy.
#[test]
fn a_receiving_build_writes_single_copies() {
    let mut h = MemHost::new();
    let mut s = Store::open(&mut h, P).unwrap();
    s.update(|ix| ix.state = State::Receiving).unwrap();
    s.put(&key_entry(1, 9), &QUOTA, |_| {}).unwrap();
    drop(s);
    assert!(h.secrets.contains_key(&entry_name(1, 0)));
    assert!(
        !h.secrets.contains_key(&entry_name(1, 1)),
        "a receiver mirrored"
    );
    assert!(
        !h.secrets.contains_key(names::PARTS),
        "a receiver was listed"
    );
}

/// The index of an unlisted partition is written with remove before write: an
/// undecryptable blob there (it reads as absent) does not block the creation.
#[test]
fn the_index_of_an_unlisted_partition_is_written_with_remove_before_write() {
    let mut h = MemHost::new();
    put(&mut h, &key_entry(1, 9)).unwrap();
    // Unlist the partition and make the old index an undecryptable blob.
    h.secrets.remove(names::PARTS);
    h.undecryptable.insert(names::index(&P));
    // It reads as absent and unlisted: NONE. A creation writes a fresh index.
    assert!(Store::fault(&h, &P).is_none());
    put(&mut h, &key_entry(2, 8)).unwrap();
    assert_eq!(read(&mut h, 2), Read::Ok(key_entry(2, 8)));
}

// ---- round 9 ---------------------------------------------------------------

/// 4.3 repair, mirror first (revision 10.2): a named copy restored to an older
/// valid entry (parses, fails the digest) with an intact mirror is rewritten
/// from the mirror and the committed value is served; so is an unparseable
/// named copy. While sealed the mirror is served and nothing is rewritten. A
/// mirror that fails the digest does not help.
#[test]
fn a_damaged_named_copy_is_restored_from_an_intact_mirror() {
    let committed = key_entry(1, 9).encode().unwrap();
    let older = key_entry(1, 7).encode().unwrap();
    for (label, damage) in [
        ("older valid entry", older.clone()),
        ("unparseable", vec![0xFF; 5]),
    ] {
        let mut h = MemHost::new();
        put(&mut h, &key_entry(1, 9)).unwrap();
        h.secrets.insert(entry_name(1, 0), damage.clone());
        assert_eq!(read(&mut h, 1), Read::Ok(key_entry(1, 9)), "{label}");
        assert_eq!(
            h.secrets[&entry_name(1, 0)],
            committed,
            "{label}: not rewritten"
        );
        let s = Store::open(&mut h, P).unwrap();
        assert_eq!(s.index.lost_entries, 0, "{label}: dropped");
        assert_eq!(s.index.entries.len(), 1, "{label}");
        drop(s);
        // Sealed: served, not rewritten.
        let mut h = MemHost::new();
        put(&mut h, &key_entry(1, 9)).unwrap();
        let mut s = Store::open(&mut h, P).unwrap();
        s.update(|ix| ix.state = State::Sealed).unwrap();
        drop(s);
        h.secrets.insert(entry_name(1, 0), damage.clone());
        let mut s = Store::open(&mut h, P).unwrap();
        assert_eq!(
            s.read(KIND_KEY, &[1; 32], true),
            Read::Ok(key_entry(1, 9)),
            "{label} sealed"
        );
        drop(s);
        assert_eq!(
            h.secrets[&entry_name(1, 0)],
            damage,
            "{label}: rewritten while sealed"
        );
    }
    // The mirror fails the digest too: the old behaviour (flag, or drop).
    let mut h = MemHost::new();
    put(&mut h, &key_entry(1, 9)).unwrap();
    h.secrets.insert(entry_name(1, 0), older.clone());
    h.secrets.insert(entry_name(1, 1), older);
    assert!(matches!(read(&mut h, 1), Read::Corrupt(Some(_))));
}

/// A named entry that reads as absent is Missing, not dropped, and is reported
/// (revision 10.2) without inflating `lost_entries`, which counts dropped
/// entries only.
#[test]
fn a_missing_named_entry_is_reported_but_not_counted_as_dropped() {
    let mut h = MemHost::new();
    put(&mut h, &key_entry(1, 9)).unwrap();
    h.secrets.remove(&entry_name(1, 0));
    let mut s = Store::open(&mut h, P).unwrap();
    assert!(!s.saw_missing());
    assert_eq!(s.read(KIND_KEY, &[1; 32], false), Read::Missing);
    assert!(s.saw_missing());
    assert_eq!(s.index.lost_entries, 0);
    assert_eq!(s.index.entries.len(), 1);
    drop(s);
    // The sweep sees it too.
    let mut s = Store::open(&mut h, P).unwrap();
    s.mirror_sweep();
    assert!(s.saw_missing());
}

/// Step 1 with the key at parity 1: replace once (the index then names parity
/// 1), Delete with the named copy stuck, re-create with the same seed.
#[test]
fn step_one_with_a_parity_one_leftover() {
    let mut h = MemHost::new();
    put(&mut h, &key_entry(1, 9)).unwrap();
    put(&mut h, &key_entry(1, 8)).unwrap();
    assert_eq!(Store::open(&mut h, P).unwrap().index.entries[0].parity, 1);
    h.undeletable.insert(entry_name(1, 1));
    let mut s = Store::open(&mut h, P).unwrap();
    s.delete(KIND_KEY, &[1; 32]).unwrap();
    drop(s);
    assert_eq!(put(&mut h, &key_entry(1, 8)), Err(PutError::Storage));
    assert_eq!(
        rescue_export_seed(&h, &P, &[1; 32]),
        None,
        "a deleted key was served"
    );
    h.undeletable.clear();
    put(&mut h, &key_entry(1, 8)).unwrap();
    assert_eq!(read(&mut h, 1), Read::Ok(key_entry(1, 8)));
}

/// The catch-all never lists a NONE, RECEIVING or RETIRED index on a later call.
#[test]
fn the_catch_all_never_lists_a_non_writer_index() {
    for state in [State::None, State::Receiving, State::Retired] {
        let mut h = MemHost::new();
        let mut s = Store::open(&mut h, P).unwrap();
        s.update(|ix| ix.state = state).unwrap();
        drop(s);
        ensure_listed(&mut h, &P).unwrap();
        assert!(
            !h.secrets.contains_key(names::PARTS),
            "{state:?} was listed"
        );
    }
    // Sealed and Writer are.
    for state in [State::Sealed, State::Writer] {
        let mut h = MemHost::new();
        let mut s = Store::open(&mut h, P).unwrap();
        s.update(|ix| ix.state = state).unwrap();
        drop(s);
        h.secrets.remove(names::PARTS);
        ensure_listed(&mut h, &P).unwrap();
        assert!(
            h.secrets[names::PARTS].chunks(32).any(|c| c == P),
            "{state:?}"
        );
    }
}

/// Remove before write at every site that writes a secret which may hold an
/// undecryptable blob (core #6323 refuses a write over one).
#[test]
fn remove_before_write_at_every_site() {
    // vault:parts at the first listing.
    let mut h = MemHost::new();
    h.undecryptable.insert(names::PARTS.to_vec());
    put(&mut h, &key_entry(1, 9)).unwrap();
    assert!(h.secrets[names::PARTS].chunks(32).any(|c| c == P), "parts");
    // Each gc list copy, at a Delete.
    for which in [names::gc(&P), names::gc2(&P)] {
        let mut h = MemHost::new();
        put(&mut h, &key_entry(1, 9)).unwrap();
        h.secrets.insert(which.clone(), b"x".to_vec());
        h.undecryptable.insert(which.clone());
        let mut s = Store::open(&mut h, P).unwrap();
        s.delete(KIND_KEY, &[1; 32]).unwrap();
        drop(s);
        assert_eq!(read(&mut h, 1), Read::Absent);
    }
    // An entry at step 2 (the unnamed parity) and at step 4 (the mirror).
    for parity in [0u8, 1u8] {
        let mut h = MemHost::new();
        put(&mut h, &key_entry(1, 9)).unwrap();
        // Parity 0 is named: parity 1 is step 2's target and parity 0 step 4's.
        h.secrets.insert(entry_name(1, parity), b"x".to_vec());
        h.undecryptable.insert(entry_name(1, parity));
        put(&mut h, &key_entry(1, 8)).unwrap();
        let new = key_entry(1, 8).encode().unwrap();
        assert_eq!(h.secrets[&entry_name(1, 0)], new, "parity {parity}");
        assert_eq!(h.secrets[&entry_name(1, 1)], new, "parity {parity}");
    }
    // A new identity's candidate (step 1 sees an absent-reading name).
    let mut h = MemHost::new();
    put(&mut h, &key_entry(1, 9)).unwrap();
    h.secrets.insert(entry_name(2, 0), b"x".to_vec());
    h.undecryptable.insert(entry_name(2, 0));
    put(&mut h, &key_entry(2, 7)).unwrap();
    assert_eq!(read(&mut h, 2), Read::Ok(key_entry(2, 7)));
    // The sweep's mirror write.
    let mut h = MemHost::new();
    put(&mut h, &key_entry(1, 9)).unwrap();
    h.secrets.insert(entry_name(1, 1), b"x".to_vec());
    h.undecryptable.insert(entry_name(1, 1));
    let mut s = Store::open(&mut h, P).unwrap();
    s.mirror_sweep();
    drop(s);
    assert_eq!(
        h.secrets[&entry_name(1, 1)],
        key_entry(1, 9).encode().unwrap(),
        "sweep"
    );
}

/// Delete edge cases: the mirror already absent; the mirror's removal landed
/// but reported an error.
#[test]
fn a_delete_whose_mirror_is_absent_or_whose_remove_errored_still_works() {
    let mut h = MemHost::new();
    put(&mut h, &key_entry(1, 9)).unwrap();
    h.secrets.remove(&entry_name(1, 1));
    let mut s = Store::open(&mut h, P).unwrap();
    s.delete(KIND_KEY, &[1; 32]).unwrap();
    drop(s);
    assert_eq!(read(&mut h, 1), Read::Absent);
    let mut h = MemHost::new();
    put(&mut h, &key_entry(2, 9)).unwrap();
    h.remove_lands_but_fails.insert(entry_name(2, 1));
    let mut s = Store::open(&mut h, P).unwrap();
    s.delete(KIND_KEY, &[2; 32]).unwrap();
    drop(s);
    assert_eq!(read(&mut h, 2), Read::Absent);
    assert!(!h.secrets.contains_key(&entry_name(2, 1)));
}

/// A mirror write that fails on its own (step 4) is not an error: the change
/// is committed and served from the index; direct read is unavailable until
/// the sweep. An index write that lands but reports an error during a replace
/// is committed and mirrored.
#[test]
fn step_four_failure_and_a_landed_index_write_during_a_replace() {
    let mut h = MemHost::new();
    put(&mut h, &key_entry(1, 9)).unwrap();
    let mirror = entry_name(1, 0); // parity 1 is named after the replace
    h.set_fault(move |n| {
        if n == mirror.as_slice() {
            WriteFault::Fail
        } else {
            WriteFault::None
        }
    });
    put(&mut h, &key_entry(1, 8)).unwrap();
    h.clear_fault();
    assert_eq!(read(&mut h, 1), Read::Ok(key_entry(1, 8)));
    assert_eq!(rescue_export_seed(&h, &P, &[1; 32]), None);
    let mut s = Store::open(&mut h, P).unwrap();
    s.mirror_sweep();
    drop(s);
    assert_eq!(rescue_export_seed(&h, &P, &[1; 32]), Some([8; 32]));
    // The index write lands but reports an error: the read-back confirms it.
    let mut h = MemHost::new();
    put(&mut h, &key_entry(1, 9)).unwrap();
    let idx = names::index(&P);
    h.set_fault(move |n| {
        if n == idx.as_slice() {
            WriteFault::DurableButFail
        } else {
            WriteFault::None
        }
    });
    put(&mut h, &key_entry(1, 8)).unwrap();
    h.clear_fault();
    assert_eq!(read(&mut h, 1), Read::Ok(key_entry(1, 8)));
}

/// gc needs a verified index, and the sweep stops after an uncertain commit.
#[test]
fn gc_needs_a_verified_index_and_the_sweep_stops_after_an_uncertain_commit() {
    // An unverified (fresh) store removes nothing.
    let mut h = MemHost::new();
    let stray = entry_name(5, 0);
    h.secrets.insert(stray.clone(), vec![1]);
    set_gc(&mut h, std::slice::from_ref(&stray));
    let mut s = Store::open(&mut h, P).unwrap();
    s.process_gc();
    drop(s);
    assert!(
        h.secrets.contains_key(&stray),
        "gc ran on an unverified index"
    );
    // After an uncertain commit the sweep writes nothing.
    let mut h = MemHost::new();
    put(&mut h, &key_entry(1, 9)).unwrap();
    h.secrets.remove(&entry_name(1, 1));
    let idx = names::index(&P);
    h.set_fault(move |n| {
        if n == idx.as_slice() {
            WriteFault::GarbageButFail
        } else {
            WriteFault::None
        }
    });
    let mut s = Store::open(&mut h, P).unwrap();
    assert!(s.update(|ix| ix.problems = 1).is_err());
    s.mirror_sweep();
    drop(s);
    assert!(
        !h.secrets.contains_key(&entry_name(1, 1)),
        "swept after an uncertain commit"
    );
}
