//! Every frozen constant pinned by value, with the numbers copied from the
//! protocol text (section 12), not from the code: a renumbering fails here.

use freenet_vault_common::bounds::*;
use freenet_vault_common::entry::{EFLAG_CORRUPT, KIND_CALLER_MARK, KIND_KEY};
use freenet_vault_common::frame::{types, HEADER_LEN};
use freenet_vault_common::status::*;

#[test]
fn frozen_constants_by_value() {
    // 12.4 Refused reasons: 9 and 13 are unassigned.
    assert_eq!(refused::ORIGIN_REQUIRED, 1);
    assert_eq!(refused::CALLER_NOT_AUTHORIZED, 2);
    assert_eq!(refused::QUOTA, 3);
    assert_eq!(refused::SLOT_OCCUPIED, 4);
    assert_eq!(refused::MALFORMED, 5);
    assert_eq!(refused::CONSENT_DENIED, 6);
    assert_eq!(refused::STORED_RECORD_MALFORMED, 7);
    assert_eq!(refused::OPERATION_NOT_ALLOWED, 8);
    assert_eq!(refused::UNKNOWN_FRAME, 10);
    assert_eq!(refused::FORBIDDEN_SIGNING_DOMAIN, 11);
    assert_eq!(refused::STORAGE_FAILURE, 12);
    assert_eq!(refused::PUBLIC_KEY_MISMATCH, 14);
    // Unusable reasons.
    assert_eq!(unusable::PUBLISHER_KEY, 1);
    assert_eq!(unusable::CORRUPT, 2);
    // HandoverStatus fields.
    assert_eq!(partition_state::NONE, 0);
    assert_eq!(partition_state::WRITER, 1);
    assert_eq!(partition_state::SEALED, 2);
    assert_eq!(partition_state::RECEIVING, 3);
    assert_eq!(partition_state::RETIRED, 4);
    assert_eq!(partition_state::NONE_ARMED, 5);
    assert_eq!(partition_state::WRITER_AWAITING, 6);
    assert_eq!(partition_state::UNKNOWN_INDEX_LOST, 7);
    assert_eq!(record_state::NONE, 0);
    assert_eq!(record_state::SUCCESSOR, 1);
    assert_eq!(record_state::STOPPED, 2);
    assert_eq!(record_state::STORED_MALFORMED, 3);
    assert_eq!(step_result::NOTHING, 0);
    assert_eq!(step_result::MESSAGES_SENT, 1);
    assert_eq!(step_result::RECORD_ACCEPTED, 2);
    assert_eq!(step_result::NOT_NEWER, 3);
    assert_eq!(step_result::EQUIVOCATION, 4);
    assert_eq!(step_result::INVALID, 5);
    // problems bits 0 to 5.
    assert_eq!(problems::STORAGE_FAILURE, 0x01);
    assert_eq!(problems::CORRUPT_OR_LOST, 0x02);
    assert_eq!(problems::ANOTHER_WRITER, 0x04);
    assert_eq!(problems::STAGING_FULL, 0x08);
    assert_eq!(problems::COPYING_PAUSED, 0x10);
    assert_eq!(problems::RECEIVER_HIGHER_BUILD, 0x20);
    assert_eq!(problems::INDEX_LOST, 0x40);
    // Poke flags: bits 0, 1 and 4.
    assert_eq!(poke_flags::PAUSE_COPYING, 0x01);
    assert_eq!(poke_flags::ARM, 0x02);

    // Frame types.
    assert_eq!(HEADER_LEN, 10);
    for (got, want) in [
        (types::CHUNK, 0x01),
        (types::ACK, 0x02),
        (types::COMPLETE, 0x03),
        (types::COMPLETE_ACK, 0x04),
        (types::ABORT, 0x05),
        (types::RETIRED, 0x06),
        (types::QUERY, 0x07),
        (types::POKE, 0x20),
        (types::SUBMIT_RECORD, 0x21),
        (types::MOVED, 0x40),
        (types::NOT_HERE, 0x41),
        (types::HANDOVER_STATUS, 0x42),
        (types::ABSENT, 0x43),
        (types::BUSY, 0x44),
        (types::UNUSABLE, 0x45),
        (types::REFUSED, 0x46),
        (types::GENERATE, 0x80),
        (types::IMPORT, 0x81),
        (types::DELETE, 0x82),
        (types::PUBLIC_KEY, 0x83),
        (types::LIST, 0x84),
        (types::BATCH, 0x85),
        (types::EXPORT, 0x86),
        (types::KEY_RESULT, 0xA0),
        (types::OK, 0xA1),
        (types::LIST_RESULT, 0xA2),
        (types::BATCH_RESULT, 0xA3),
        (types::EXPORT_RESULT, 0xA4),
    ] {
        assert_eq!(got, want);
    }

    // Entry kinds and flags.
    assert_eq!(KIND_KEY, 1);
    assert_eq!(KIND_CALLER_MARK, 2);
    assert_eq!(EFLAG_CORRUPT, 1);

    // Bounds.
    assert_eq!(MAX_REPLY, 65_536);
    assert_eq!(MAX_FRAME_BODY, 16 * 1024 * 1024);
    assert_eq!(MAX_REQUEST_BODY, 1024 * 1024);
    assert_eq!(MAX_ENTRY, 65_399);
    assert_eq!(MAX_KEY, 256);
    assert_eq!(MAX_SLOT, 64);
    assert_eq!(MAX_APP_ID, 64);
    assert_eq!(MAX_BATCH_ITEMS, 256);
    assert_eq!(MAX_ITEM_DATA, 65_536);
    assert_eq!(MAX_DERIVE_CONTEXT, 256);
    assert_eq!(MAX_LIST, 256);
    assert_eq!(MAX_LIST_AFTER, 64);
    assert_eq!(MAX_PARTITION_ENTRIES, 4096);
    assert_eq!(MAX_PARTITION_BYTES, 1024 * 1024);
    assert_eq!(FORBIDDEN_SIGNING_PREFIX, b"freenet-pointer/");
}
