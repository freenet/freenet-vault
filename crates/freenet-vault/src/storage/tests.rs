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
    assert!(!h.secrets.contains_key(&names::gc(&P)));
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
    assert!(!h.secrets.contains_key(&names::gc(&P)));
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
    assert!(!h.secrets.contains_key(&entry_name(1, 1)));
    // gc ran at once: the new copy is gone, the old one (still referenced) was
    // skipped, and the list is cleared.
    assert!(!h.secrets.contains_key(&names::gc(&P)));
    assert_eq!(read(&mut h, 1), Read::Ok(key_entry(1, 9)));
    // The same state as after a crash: a gc list naming both copies.
    h.clear_fault();
    set_gc(&mut h, &[entry_name(1, 0), entry_name(1, 1)]);
    for _ in 0..2 {
        // The second name never existed: uncertain once, then dropped.
        let mut s = Store::open(&mut h, P).unwrap();
        s.process_gc();
    }
    assert!(!h.secrets.contains_key(&names::gc(&P)));
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
    assert!(!h.secrets.contains_key(&names::gc(&P)));
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
    assert!(!h.secrets.contains_key(&names::gc(&P)));
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
    assert!(h.secrets.contains_key(&names::gc(&P)));
    // The host recovers: the next call removes it and clears the list.
    h.undeletable.clear();
    let mut s = Store::open(&mut h, P).unwrap();
    s.process_gc();
    drop(s);
    assert!(!h.secrets.contains_key(&entry_name(1, 0)));
    assert!(!h.secrets.contains_key(&names::gc(&P)));
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
    assert!(!h.secrets.contains_key(&names::gc(&P)));
}

/// The second index copy (item 9): a lost or damaged first copy falls back to
/// the second; both damaged is an error; a lost partition is still NONE.
#[test]
fn the_second_index_copy_covers_a_lost_or_damaged_first() {
    let mut h = MemHost::new();
    put(&mut h, &key_entry(1, 9)).unwrap();
    put(&mut h, &key_entry(2, 9)).unwrap();
    assert_eq!(h.secrets[&names::index(&P)], h.secrets[&names::index2(&P)]);
    // First copy absent.
    let first = h.secrets.remove(&names::index(&P)).unwrap();
    assert_eq!(read(&mut h, 1), Read::Ok(key_entry(1, 9)));
    assert!(Store::open(&mut h, P).unwrap().has_index());
    // First copy damaged.
    let mut bad = first.clone();
    bad.push(0);
    h.secrets.insert(names::index(&P), bad);
    assert_eq!(read(&mut h, 2), Read::Ok(key_entry(2, 9)));
    // A commit heals both copies.
    put(&mut h, &key_entry(3, 9)).unwrap();
    assert_eq!(h.secrets[&names::index(&P)], h.secrets[&names::index2(&P)]);
    // Both damaged: an error, never NONE.
    let mut bad2 = h.secrets[&names::index2(&P)].clone();
    bad2.push(0);
    h.secrets.insert(names::index2(&P), bad2.clone());
    let mut bad1 = bad2.clone();
    bad1.push(1);
    h.secrets.insert(names::index(&P), bad1);
    assert!(Store::open(&mut h, P).is_err());
    // First damaged and second absent: an error.
    h.secrets.remove(&names::index2(&P));
    assert!(Store::open(&mut h, P).is_err());
    // Neither present: NONE.
    h.secrets.remove(&names::index(&P));
    let s = Store::open(&mut h, P).unwrap();
    assert!(!s.has_index());
    assert!(s.index.entries.is_empty());
}

/// A crash between the two index writes leaves the second one commit behind,
/// and with the first copy then lost the older state is consistent: its
/// entries are all still there.
#[test]
fn a_crash_between_the_two_index_writes_leaves_a_consistent_older_state() {
    let mut h = MemHost::new();
    put(&mut h, &key_entry(1, 9)).unwrap();
    // Replace: gc lists (2), entry write, index 1, [crash before index 2].
    h.crash_after(4);
    let _ = put(&mut h, &key_entry(1, 8));
    let mut h = h.restart();
    assert_ne!(h.secrets[&names::index(&P)], h.secrets[&names::index2(&P)]);
    // First copy lost: the second (older) serves the old value, intact.
    h.secrets.remove(&names::index(&P));
    assert_eq!(read(&mut h, 1), Read::Ok(key_entry(1, 9)));
}

/// The round-2 failure: after a crash between the two index writes, the next
/// call runs gc. It must not remove the copy the OLDER index still names, so
/// the first index can then be lost with no harm. (`open` brings the second
/// copy in line before gc is allowed to run.)
#[test]
fn gc_after_a_crash_between_index_writes_never_orphans_the_other_index() {
    let mut h = MemHost::new();
    put(&mut h, &key_entry(1, 9)).unwrap();
    h.crash_after(4);
    let _ = put(&mut h, &key_entry(1, 8));
    for lose_first in [true, false] {
        let mut d = h.restart();
        // The next call: open reconciles, then gc.
        let mut s = Store::open(&mut d, P).unwrap();
        assert_eq!(s.mode(), Mode::Clean);
        s.process_gc();
        drop(s);
        assert_eq!(d.secrets[&names::index(&P)], d.secrets[&names::index2(&P)]);
        // Lose either index copy: the other names a copy that still exists.
        d.secrets.remove(&if lose_first {
            names::index(&P)
        } else {
            names::index2(&P)
        });
        let value = read(&mut d, 1);
        assert!(
            matches!(value, Read::Ok(_)),
            "lose_first={lose_first}: {value:?}"
        );
    }
}

/// A flipped bit that still parses (a digest, a parity, the state) fails the
/// checksum, so the good copy wins instead of the flip being believed.
#[test]
fn a_bit_flipped_index_that_still_parses_is_rejected() {
    let mut h = MemHost::new();
    put(&mut h, &key_entry(1, 9)).unwrap();
    put(&mut h, &key_entry(2, 8)).unwrap();
    let good = h.secrets[&names::index(&P)].clone();
    for at in 0..good.len() {
        for second in [false, true] {
            let mut d = h.restart();
            let name = if second {
                names::index2(&P)
            } else {
                names::index(&P)
            };
            let mut bad = good.clone();
            bad[at] ^= 0x01;
            d.secrets.insert(name, bad);
            let mut s = Store::open(&mut d, P).unwrap_or_else(|_| panic!("byte {at}"));
            assert_eq!(s.mode(), Mode::Clean, "byte {at}");
            assert_eq!(s.read(KIND_KEY, &[1; 32], false), Read::Ok(key_entry(1, 9)));
            assert_eq!(s.read(KIND_KEY, &[2; 32], false), Read::Ok(key_entry(2, 8)));
            drop(s);
            // Both copies are the good one again.
            assert_eq!(d.secrets[&names::index(&P)], good, "byte {at}");
            assert_eq!(d.secrets[&names::index2(&P)], good, "byte {at}");
        }
    }
}

/// gc waits while the second copy cannot be written, and runs once it can.
#[test]
fn gc_does_not_run_while_the_second_index_copy_is_unwritten() {
    let mut h = MemHost::new();
    put(&mut h, &key_entry(1, 9)).unwrap();
    let idx2 = names::index2(&P);
    h.set_fault(move |name| {
        if name == idx2.as_slice() {
            WriteFault::Fail
        } else {
            WriteFault::None
        }
    });
    put(&mut h, &key_entry(1, 8)).unwrap();
    // The old copy is still there, because the second index names it.
    assert!(h.secrets.contains_key(&entry_name(1, 0)));
    assert!(!gc_names(&h).is_empty());
    // Still failing on the next call: still no gc.
    let mut s = Store::open(&mut h, P).unwrap();
    assert_eq!(s.mode(), Mode::Unsynced);
    s.process_gc();
    drop(s);
    assert!(h.secrets.contains_key(&entry_name(1, 0)));
    // The host recovers: open writes the second copy, then gc removes it.
    h.clear_fault();
    let mut s = Store::open(&mut h, P).unwrap();
    assert_eq!(s.mode(), Mode::Clean);
    s.process_gc();
    drop(s);
    assert!(!h.secrets.contains_key(&entry_name(1, 0)));
    assert!(gc_names(&h).is_empty());
    assert_eq!(read(&mut h, 1), Read::Ok(key_entry(1, 8)));
}

/// A first index copy that reads as absent is ambiguous (lost, or a transient
/// miss), so the store is read-only: nothing is written, rewritten or removed.
#[test]
fn an_absent_first_index_makes_the_store_read_only() {
    let mut h = MemHost::new();
    put(&mut h, &key_entry(1, 9)).unwrap();
    // A pending removal that must not run on this evidence.
    set_gc(&mut h, &[entry_name(1, 1)]);
    h.secrets.insert(entry_name(1, 1), vec![1]);
    h.hidden.insert(names::index(&P));
    let before = h.secrets.clone();
    let mut s = Store::open(&mut h, P).unwrap();
    assert_eq!(s.mode(), Mode::ReadOnly);
    assert_eq!(s.read(KIND_KEY, &[1; 32], false), Read::Ok(key_entry(1, 9)));
    s.process_gc();
    assert_eq!(
        s.put(&key_entry(2, 2), &QUOTA, |_| {}),
        Err(PutError::Storage)
    );
    assert_eq!(s.delete(KIND_KEY, &[1; 32]), Err(StorageFailure));
    assert_eq!(s.update(|ix| ix.problems = 1), Err(StorageFailure));
    drop(s);
    assert_eq!(h.secrets, before, "nothing changed");
}

/// An absent index for a partition `vault:parts` lists is an error, never a
/// fresh partition (a transient miss of both copies must not orphan entries).
#[test]
fn a_listed_partition_with_no_index_is_an_error_not_none() {
    let mut h = MemHost::new();
    put(&mut h, &key_entry(1, 9)).unwrap();
    ensure_part_listed(&mut h, &P).unwrap();
    h.hidden.insert(names::index(&P));
    h.hidden.insert(names::index2(&P));
    assert!(Store::open(&mut h, P).is_err());
    // An unlisted partition with no index is simply new.
    let mut fresh = MemHost::new();
    assert!(!Store::open(&mut fresh, P).unwrap().has_index());
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

/// A removal that neither succeeds nor reads back is retried, then dropped:
/// a name that never existed does not stay listed for ever.
#[test]
fn an_uncertain_removal_is_retried_then_dropped() {
    let mut h = MemHost::new();
    put(&mut h, &key_entry(1, 9)).unwrap();
    set_gc(&mut h, &[entry_name(5, 0)]);
    let mut s = Store::open(&mut h, P).unwrap();
    s.process_gc();
    drop(s);
    assert_eq!(gc_names(&h), vec![entry_name(5, 0)], "kept for one retry");
    let mut s = Store::open(&mut h, P).unwrap();
    s.process_gc();
    drop(s);
    assert!(gc_names(&h).is_empty());
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
    // The next call: the first index is damaged, the second is the old one.
    h.clear_fault();
    let mut s = Store::open(&mut h, P).unwrap();
    s.process_gc();
    drop(s);
    assert_eq!(read(&mut h, 1), Read::Ok(key_entry(1, 9)));
    assert!(!h.secrets.contains_key(&entry_name(1, 1)));
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
    h.secrets.insert(names::index2(&P), b);
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
