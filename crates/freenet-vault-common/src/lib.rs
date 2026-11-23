//! v1 formats of the freenet-vault key vault.
//!
//! This crate holds the byte layouts that a vault build and the apps calling
//! it share: the frame envelope, the entry encoding, the operation requests and
//! results, the status frames and the pointer record. Layout references are to
//! the handover protocol document, section 12. Those layouts are frozen once a
//! vault is published: new data goes into new entry kinds, extensions and
//! reserved flag bits, never into a changed layout (protocol section 11).
//!
//! NOT YET PUBLISHED. Until the first River vault release is signed the
//! formats can still change, and `DESIGN-NOTES.md` lists the open points.
//!
//! The vault-to-vault handover frames (Chunk, Ack, Complete, CompleteAck,
//! Abort, Retired, Query) are deliberately absent: their design is still
//! being decided. Only their frame-type numbers are reserved here.

pub mod codec;
pub mod entry;
pub mod frame;
pub mod hash;
pub mod ops;
pub mod record;
pub mod status;

pub use codec::Malformed;

/// Frozen bounds (protocol 11) and library maximums (protocol 8.1).
pub mod bounds {
    /// A frame body.
    pub const MAX_FRAME_BODY: usize = 16 * 1024 * 1024;
    /// An operation request's frame body.
    pub const MAX_REQUEST_BODY: usize = 1024 * 1024;
    /// One stored entry, kind through ext.
    pub const MAX_ENTRY: usize = 65_399;
    /// An entry key.
    pub const MAX_KEY: usize = 256;
    /// A slot as named by an operation frame (`slot_len` is 1..=64).
    pub const MAX_SLOT: usize = 64;
    /// `app_id` in a caller proof or SubmitRecord.
    pub const MAX_APP_ID: usize = 64;
    /// Items in one Batch.
    pub const MAX_BATCH_ITEMS: usize = 256;
    /// Data signed by one Sign item, and data of one Derive item.
    pub const MAX_ITEM_DATA: usize = 65_536;
    /// A Derive context, in bytes of UTF-8.
    pub const MAX_DERIVE_CONTEXT: usize = 256;
    /// Slots returned by one List.
    pub const MAX_LIST: usize = 256;
    /// `after` in a List request.
    pub const MAX_LIST_AFTER: usize = 64;
    /// Entries per partition, frozen forever (8.1).
    pub const MAX_PARTITION_ENTRIES: usize = 4096;
    /// Entry bytes per partition, frozen forever (8.1).
    pub const MAX_PARTITION_BYTES: usize = 1024 * 1024;
    /// Signing data starting with this prefix is refused item by item.
    pub const FORBIDDEN_SIGNING_PREFIX: &[u8] = b"freenet-pointer/";
}
