//! Status frames (protocol 12.4): Moved, NotHere, HandoverStatus, Absent,
//! Busy, Unusable, Refused; and the caller frame Poke.
//!
//! HandoverStatus and Poke belong to the handover protocol, whose design is
//! still open. This crate encodes them as revision 6 lays them out so the
//! operation path can create a partition (Poke flag bit 1) and report its
//! state, and DESIGN-NOTES.md marks both layouts provisional.

use crate::codec::{Malformed, Reader, Result, Writer};
use crate::frame::{self, types};

/// Refused reasons (protocol 12.4).
pub mod refused {
    pub const ORIGIN_REQUIRED: u8 = 1;
    pub const CALLER_NOT_AUTHORIZED: u8 = 2;
    pub const QUOTA: u8 = 3;
    pub const SLOT_OCCUPIED: u8 = 4;
    pub const MALFORMED: u8 = 5;
    pub const CONSENT_DENIED: u8 = 6;
    pub const STORED_RECORD_MALFORMED: u8 = 7;
    pub const OPERATION_NOT_ALLOWED: u8 = 8;
    pub const UNKNOWN_FRAME: u8 = 10;
    pub const FORBIDDEN_SIGNING_DOMAIN: u8 = 11;
    pub const STORAGE_FAILURE: u8 = 12;
    pub const NOT_PERMITTED_IN_STATE: u8 = 13;
    /// Batch's `expected_public_key` differs from the key the slot holds.
    /// New in this implementation; not yet in the documents (DESIGN-NOTES.md).
    pub const PUBLIC_KEY_MISMATCH: u8 = 14;
}

/// Unusable reasons.
pub mod unusable {
    pub const PUBLISHER_KEY: u8 = 1;
    pub const CORRUPT: u8 = 2;
}

/// HandoverStatus `partition_state`.
pub mod partition_state {
    pub const NONE: u8 = 0;
    pub const WRITER: u8 = 1;
    pub const SEALED: u8 = 2;
    pub const RECEIVING: u8 = 3;
    pub const RETIRED: u8 = 4;
    pub const NONE_ARMED: u8 = 5;
    pub const WRITER_AWAITING: u8 = 6;
}

/// HandoverStatus `record_state`.
pub mod record_state {
    pub const NONE: u8 = 0;
    pub const SUCCESSOR: u8 = 1;
    pub const STOPPED: u8 = 2;
    pub const STORED_MALFORMED: u8 = 3;
}

/// HandoverStatus `step_result`.
pub mod step_result {
    pub const NOTHING: u8 = 0;
    pub const MESSAGES_SENT: u8 = 1;
    pub const RECORD_ACCEPTED: u8 = 2;
    pub const NOT_NEWER: u8 = 3;
    pub const EQUIVOCATION: u8 = 4;
    pub const INVALID: u8 = 5;
}

/// HandoverStatus `problems` bits.
pub mod problems {
    pub const STORAGE_FAILURE: u8 = 1 << 0;
    pub const CORRUPT_OR_LOST: u8 = 1 << 1;
    pub const ANOTHER_WRITER: u8 = 1 << 2;
    pub const STAGING_FULL: u8 = 1 << 3;
    pub const COPYING_PAUSED: u8 = 1 << 4;
}

/// Poke flag bits. Only bit 1 is acted on by this implementation; the others
/// belong to the deferred handover.
pub mod poke_flags {
    pub const PAUSE_COPYING: u8 = 1 << 0;
    pub const ARM: u8 = 1 << 1;
    pub const REDELIVER: u8 = 1 << 2;
    pub const TARGET_DID_NOT_TAKE_OVER: u8 = 1 << 3;
    pub const DISCARD_PARTIAL: u8 = 1 << 4;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandoverStatus {
    pub request_id: u64,
    pub own_version: u32,
    pub floor_version: u32,
    pub record_state: u8,
    pub step_result: u8,
    pub partition_state: u8,
    pub peer_record: [u8; 100],
    pub taken_over_from: u32,
    pub taken_over_attempt: u32,
    pub taken_over_manifest: [u8; 32],
    pub attempt: u32,
    pub manifest_digest: [u8; 32],
    pub problems: u8,
    pub lost_entries: u16,
}

impl HandoverStatus {
    /// The fields after `step_result` go only to the domain's own pages;
    /// others get zeros (protocol 12.4).
    pub fn redacted(&self) -> Self {
        Self {
            request_id: self.request_id,
            own_version: self.own_version,
            floor_version: self.floor_version,
            record_state: self.record_state,
            step_result: self.step_result,
            partition_state: 0,
            peer_record: [0; 100],
            taken_over_from: 0,
            taken_over_attempt: 0,
            taken_over_manifest: [0; 32],
            attempt: 0,
            manifest_digest: [0; 32],
            problems: 0,
            lost_entries: 0,
        }
    }
}

/// A status frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    Moved {
        request_id: u64,
        partition: [u8; 32],
        record: [u8; 100],
    },
    NotHere {
        request_id: u64,
        partition: [u8; 32],
    },
    Handover(HandoverStatus),
    Absent {
        request_id: u64,
        partition: [u8; 32],
        slot: Vec<u8>,
    },
    Busy {
        request_id: u64,
        partition: [u8; 32],
    },
    Unusable {
        request_id: u64,
        partition: [u8; 32],
        slot: Vec<u8>,
        reason: u8,
    },
    Refused {
        request_id: u64,
        reason: u8,
    },
}

fn read_slot(r: &mut Reader) -> Result<Vec<u8>> {
    let len = r.u8("slot_len")? as usize;
    if len == 0 || len > crate::bounds::MAX_SLOT {
        return Err(Malformed("slot_len"));
    }
    Ok(r.take(len, "slot")?.to_vec())
}

impl Status {
    pub fn frame_type(&self) -> u8 {
        match self {
            Self::Moved { .. } => types::MOVED,
            Self::NotHere { .. } => types::NOT_HERE,
            Self::Handover(_) => types::HANDOVER_STATUS,
            Self::Absent { .. } => types::ABSENT,
            Self::Busy { .. } => types::BUSY,
            Self::Unusable { .. } => types::UNUSABLE,
            Self::Refused { .. } => types::REFUSED,
        }
    }

    pub fn request_id(&self) -> u64 {
        match self {
            Self::Moved { request_id, .. }
            | Self::NotHere { request_id, .. }
            | Self::Absent { request_id, .. }
            | Self::Busy { request_id, .. }
            | Self::Unusable { request_id, .. }
            | Self::Refused { request_id, .. } => *request_id,
            Self::Handover(h) => h.request_id,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u64(self.request_id());
        match self {
            Self::Moved {
                partition, record, ..
            } => {
                w.bytes(partition).bytes(record);
            }
            Self::NotHere { partition, .. } | Self::Busy { partition, .. } => {
                w.bytes(partition);
            }
            Self::Handover(h) => {
                w.u32(h.own_version)
                    .u32(h.floor_version)
                    .u8(h.record_state)
                    .u8(h.step_result)
                    .u8(h.partition_state)
                    .bytes(&h.peer_record)
                    .u32(h.taken_over_from)
                    .u32(h.taken_over_attempt)
                    .bytes(&h.taken_over_manifest)
                    .u32(h.attempt)
                    .bytes(&h.manifest_digest)
                    .u8(h.problems)
                    .u16(h.lost_entries);
            }
            Self::Absent {
                partition, slot, ..
            } => {
                w.bytes(partition).u8(slot.len() as u8).bytes(slot);
            }
            Self::Unusable {
                partition,
                slot,
                reason,
                ..
            } => {
                w.bytes(partition)
                    .u8(slot.len() as u8)
                    .bytes(slot)
                    .u8(*reason);
            }
            Self::Refused { reason, .. } => {
                w.u8(*reason);
            }
        }
        w.ext(&[]);
        frame::encode(self.frame_type(), &w.into_vec())
    }

    pub fn decode(frame_type: u8, body: &[u8]) -> Result<Self> {
        let mut r = Reader::new(body);
        let request_id = r.u64("request_id")?;
        let s = match frame_type {
            types::MOVED => Self::Moved {
                request_id,
                partition: r.array("partition")?,
                record: r.array("record")?,
            },
            types::NOT_HERE => Self::NotHere {
                request_id,
                partition: r.array("partition")?,
            },
            types::HANDOVER_STATUS => Self::Handover(HandoverStatus {
                request_id,
                own_version: r.u32("own_version")?,
                floor_version: r.u32("floor_version")?,
                record_state: r.u8("record_state")?,
                step_result: r.u8("step_result")?,
                partition_state: r.u8("partition_state")?,
                peer_record: r.array("peer_record")?,
                taken_over_from: r.u32("taken_over_from")?,
                taken_over_attempt: r.u32("taken_over_attempt")?,
                taken_over_manifest: r.array("taken_over_manifest")?,
                attempt: r.u32("attempt")?,
                manifest_digest: r.array("manifest_digest")?,
                problems: r.u8("problems")?,
                lost_entries: r.u16("lost_entries")?,
            }),
            types::ABSENT => Self::Absent {
                request_id,
                partition: r.array("partition")?,
                slot: read_slot(&mut r)?,
            },
            types::BUSY => Self::Busy {
                request_id,
                partition: r.array("partition")?,
            },
            types::UNUSABLE => Self::Unusable {
                request_id,
                partition: r.array("partition")?,
                slot: read_slot(&mut r)?,
                reason: r.u8("reason")?,
            },
            types::REFUSED => Self::Refused {
                request_id,
                reason: r.u8("reason")?,
            },
            _ => return Err(Malformed("not a status frame")),
        };
        r.ext()?;
        r.finish()?;
        Ok(s)
    }
}

/// Poke (0x20): `flags 1 ; partition 32 ; record_present 1 ; record 100 (or zero bytes) ; ext`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Poke {
    pub flags: u8,
    pub partition: [u8; 32],
    pub record: Option<[u8; 100]>,
    pub ext: Vec<u8>,
}

impl Poke {
    pub fn decode(body: &[u8]) -> Result<Self> {
        let mut r = Reader::new(body);
        let flags = r.u8("flags")?;
        let partition = r.array("partition")?;
        let present = r.bool("record_present")?;
        let bytes: [u8; 100] = r.array("record")?;
        // "or zero bytes" means zero-filled (protocol 11).
        if !present && bytes != [0u8; 100] {
            return Err(Malformed("absent record not zero-filled"));
        }
        let ext = r.ext()?;
        r.finish()?;
        Ok(Self {
            flags,
            partition,
            record: present.then_some(bytes),
            ext,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(self.flags)
            .bytes(&self.partition)
            .u8(self.record.is_some() as u8)
            .bytes(&self.record.unwrap_or([0; 100]))
            .ext(&self.ext);
        frame::encode(types::POKE, &w.into_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::Frame;

    #[test]
    fn status_frames_round_trip() {
        let p = [7u8; 32];
        let cases = vec![
            Status::Moved {
                request_id: 1,
                partition: p,
                record: [3; 100],
            },
            Status::NotHere {
                request_id: 0,
                partition: p,
            },
            Status::Absent {
                request_id: 2,
                partition: p,
                slot: vec![1; 32],
            },
            Status::Busy {
                request_id: 3,
                partition: p,
            },
            Status::Unusable {
                request_id: 4,
                partition: p,
                slot: vec![2; 32],
                reason: unusable::CORRUPT,
            },
            Status::Refused {
                request_id: 5,
                reason: refused::QUOTA,
            },
            Status::Handover(HandoverStatus {
                request_id: 6,
                own_version: 1,
                floor_version: 2,
                record_state: record_state::SUCCESSOR,
                step_result: step_result::RECORD_ACCEPTED,
                partition_state: partition_state::WRITER,
                peer_record: [9; 100],
                taken_over_from: 0,
                taken_over_attempt: 0,
                taken_over_manifest: [0; 32],
                attempt: 0,
                manifest_digest: [0; 32],
                problems: problems::CORRUPT_OR_LOST,
                lost_entries: 2,
            }),
        ];
        for c in cases {
            let bytes = c.encode();
            let f = Frame::decode(&bytes).unwrap();
            assert_eq!(Status::decode(f.frame_type, f.body).unwrap(), c);
        }
    }

    #[test]
    fn status_vectors() {
        let r = Status::Refused {
            request_id: 9,
            reason: refused::ORIGIN_REQUIRED,
        }
        .encode();
        assert_eq!(
            r,
            [b'F', b'V', b'L', b'T', 1, 0x46, 0, 0, 0, 11, 0, 0, 0, 0, 0, 0, 0, 9, 1, 0, 0]
        );
        // HandoverStatus body: 8 + 4 + 4 + 1 + 1 + 1 + 100 + 4 + 4 + 32 + 4 + 32 + 1 + 2 + 2.
        let h = Status::Handover(HandoverStatus {
            request_id: 0,
            own_version: 0,
            floor_version: 0,
            record_state: 0,
            step_result: 0,
            partition_state: 0,
            peer_record: [0; 100],
            taken_over_from: 0,
            taken_over_attempt: 0,
            taken_over_manifest: [0; 32],
            attempt: 0,
            manifest_digest: [0; 32],
            problems: 0,
            lost_entries: 0,
        })
        .encode();
        assert_eq!(h.len(), 10 + 200);
    }

    #[test]
    fn poke_round_trip_and_malformed() {
        for record in [None, Some([5u8; 100])] {
            let p = Poke {
                flags: poke_flags::ARM,
                partition: [1; 32],
                record,
                ext: vec![],
            };
            let bytes = p.encode();
            let f = Frame::decode(&bytes).unwrap();
            assert_eq!(f.frame_type, types::POKE);
            assert_eq!(Poke::decode(f.body).unwrap(), p);
        }
        // record_present 0 with non-zero record bytes; record_present 2.
        let mut b = vec![0u8];
        b.extend_from_slice(&[1; 32]);
        b.push(0);
        let mut rec = [0u8; 100];
        rec[50] = 1;
        b.extend_from_slice(&rec);
        b.extend_from_slice(&[0, 0]);
        assert!(Poke::decode(&b).is_err());
        b[33] = 2;
        assert!(Poke::decode(&b).is_err());
    }
}
