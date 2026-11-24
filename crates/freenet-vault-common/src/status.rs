//! Status frames (protocol 12.4): Moved, NotHere, HandoverStatus, Absent,
//! Busy, Unusable, Refused; and the caller frame Poke.
//!
//! HandoverStatus and Poke follow handover protocol revision 7, section 12.4.
//! The operation path uses them to create a partition (Poke flag bit 1) and to
//! report its state; the handover itself is not built.

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
    /// Batch's `expected_public_key` differs from the key the slot holds
    /// (protocol 12.4, reason 14).
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
    /// The index is lost: read-only, state unknown (protocol 4.5, 12.4).
    pub const UNKNOWN_INDEX_LOST: u8 = 7;
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
    pub const RECEIVER_HIGHER_BUILD: u8 = 1 << 5;
    /// The index is absent while listed, or malformed: read-only (protocol 4.5).
    pub const INDEX_LOST: u8 = 1 << 6;
}

/// Poke flag bits. Only bit 1 is acted on by this implementation; bits 2 and 3
/// are reserved and not used in v1 (revision 7), so they have no names here.
pub mod poke_flags {
    pub const PAUSE_COPYING: u8 = 1 << 0;
    pub const ARM: u8 = 1 << 1;
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
    /// The sender's version while receiving, else 0.
    pub receiving_from: u32,
    pub taken_over_from: u32,
    pub taken_over_manifest: [u8; 32],
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
            receiving_from: 0,
            taken_over_from: 0,
            taken_over_manifest: [0; 32],
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

fn write_slot(w: &mut Writer, slot: &[u8]) {
    w.require(
        (1..=crate::bounds::MAX_SLOT).contains(&slot.len()),
        "slot_len",
    )
    .len_u8(slot.len(), "slot_len")
    .bytes(slot);
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

    pub fn encode(&self) -> Result<Vec<u8>> {
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
                    .u32(h.receiving_from)
                    .u32(h.taken_over_from)
                    .bytes(&h.taken_over_manifest)
                    .bytes(&h.manifest_digest)
                    .u8(h.problems)
                    .u16(h.lost_entries);
            }
            Self::Absent {
                partition, slot, ..
            } => {
                w.bytes(partition);
                write_slot(&mut w, slot);
            }
            Self::Unusable {
                partition,
                slot,
                reason,
                ..
            } => {
                w.bytes(partition);
                write_slot(&mut w, slot);
                w.u8(*reason);
            }
            Self::Refused { reason, .. } => {
                w.u8(*reason);
            }
        }
        w.ext(&[]);
        frame::encode_reply(self.frame_type(), &w.finish()?)
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
                receiving_from: r.u32("receiving_from")?,
                taken_over_from: r.u32("taken_over_from")?,
                taken_over_manifest: r.array("taken_over_manifest")?,
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

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut w = Writer::new();
        w.u8(self.flags)
            .bytes(&self.partition)
            .u8(self.record.is_some() as u8)
            .bytes(&self.record.unwrap_or([0; 100]))
            .ext(&self.ext);
        frame::encode(types::POKE, &w.finish()?)
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
                receiving_from: 3,
                taken_over_from: 4,
                taken_over_manifest: [5; 32],
                manifest_digest: [6; 32],
                problems: problems::CORRUPT_OR_LOST,
                lost_entries: 2,
            }),
        ];
        for c in cases {
            let bytes = c.encode().unwrap();
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
        .encode()
        .unwrap();
        assert_eq!(
            r,
            [b'F', b'V', b'L', b'T', 1, 0x46, 0, 0, 0, 11, 0, 0, 0, 0, 0, 0, 0, 9, 1, 0, 0]
        );
        // HandoverStatus, written out from revision 7 section 12.4 and not
        // from the encoder: request_id 8, own_version 4, floor_version 4,
        // record_state 1, step_result 1, partition_state 1, peer_record 100,
        // receiving_from 4, taken_over_from 4, taken_over_manifest 32,
        // manifest_digest 32, problems 1, lost_entries 2, ext_len 2.
        let h = Status::Handover(HandoverStatus {
            request_id: 0x0102030405060708,
            own_version: 0x11,
            floor_version: 0x12,
            record_state: 1,
            step_result: 2,
            partition_state: 6,
            peer_record: [0xAA; 100],
            receiving_from: 0x13,
            taken_over_from: 0x14,
            taken_over_manifest: [0xBB; 32],
            manifest_digest: [0xCC; 32],
            problems: 0b10_0001,
            lost_entries: 0x0102,
        })
        .encode()
        .unwrap();
        let mut want = vec![b'F', b'V', b'L', b'T', 1, 0x42, 0, 0, 0, 196];
        want.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        want.extend_from_slice(&[0, 0, 0, 0x11, 0, 0, 0, 0x12]);
        want.extend_from_slice(&[1, 2, 6]);
        want.extend_from_slice(&[0xAA; 100]);
        want.extend_from_slice(&[0, 0, 0, 0x13, 0, 0, 0, 0x14]);
        want.extend_from_slice(&[0xBB; 32]);
        want.extend_from_slice(&[0xCC; 32]);
        want.extend_from_slice(&[0b10_0001, 1, 2]);
        want.extend_from_slice(&[0, 0]);
        assert_eq!(h, want);
    }

    /// Every other status frame, written out byte by byte.
    #[test]
    fn status_golden_vectors() {
        let p = [0x07u8; 32];
        let head = |ty: u8, body_len: u8| vec![b'F', b'V', b'L', b'T', 1, ty, 0, 0, 0, body_len];
        let rid = [0, 0, 0, 0, 0, 0, 0, 5u8];

        let mut w = head(0x40, 8 + 32 + 100 + 2);
        w.extend_from_slice(&rid);
        w.extend_from_slice(&p);
        w.extend_from_slice(&[0x09; 100]);
        w.extend_from_slice(&[0, 0]);
        let moved = Status::Moved {
            request_id: 5,
            partition: p,
            record: [9; 100],
        };
        assert_eq!(moved.encode().unwrap(), w);

        let mut w = head(0x41, 8 + 32 + 2);
        w.extend_from_slice(&rid);
        w.extend_from_slice(&p);
        w.extend_from_slice(&[0, 0]);
        let not_here = Status::NotHere {
            request_id: 5,
            partition: p,
        };
        assert_eq!(not_here.encode().unwrap(), w);

        let mut w = head(0x43, 8 + 32 + 1 + 2 + 2);
        w.extend_from_slice(&rid);
        w.extend_from_slice(&p);
        w.extend_from_slice(&[2, 0xEE, 0xEF]);
        w.extend_from_slice(&[0, 0]);
        let absent = Status::Absent {
            request_id: 5,
            partition: p,
            slot: vec![0xEE, 0xEF],
        };
        assert_eq!(absent.encode().unwrap(), w);

        let mut w = head(0x44, 8 + 32 + 2);
        w.extend_from_slice(&rid);
        w.extend_from_slice(&p);
        w.extend_from_slice(&[0, 0]);
        let busy = Status::Busy {
            request_id: 5,
            partition: p,
        };
        assert_eq!(busy.encode().unwrap(), w);

        let mut w = head(0x45, 8 + 32 + 1 + 1 + 1 + 2);
        w.extend_from_slice(&rid);
        w.extend_from_slice(&p);
        w.extend_from_slice(&[1, 0xEE, 2]);
        w.extend_from_slice(&[0, 0]);
        let unusable = Status::Unusable {
            request_id: 5,
            partition: p,
            slot: vec![0xEE],
            reason: unusable::CORRUPT,
        };
        assert_eq!(unusable.encode().unwrap(), w);
    }

    #[test]
    fn poke_golden_vector() {
        let p = Poke {
            flags: poke_flags::ARM,
            partition: [0x33; 32],
            record: Some([0x44; 100]),
            ext: vec![],
        };
        let mut w = vec![
            b'F',
            b'V',
            b'L',
            b'T',
            1,
            0x20,
            0,
            0,
            0,
            1 + 32 + 1 + 100 + 2,
        ];
        w.push(0b10);
        w.extend_from_slice(&[0x33; 32]);
        w.push(1);
        w.extend_from_slice(&[0x44; 100]);
        w.extend_from_slice(&[0, 0]);
        assert_eq!(p.encode().unwrap(), w);
    }

    #[test]
    fn status_encoders_enforce_bounds() {
        let p = [0u8; 32];
        for len in [0usize, 65, 300] {
            assert!(Status::Absent {
                request_id: 0,
                partition: p,
                slot: vec![1; len],
            }
            .encode()
            .is_err());
        }
        assert!(Status::Absent {
            request_id: 0,
            partition: p,
            slot: vec![1; 64],
        }
        .encode()
        .is_ok());
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
            let bytes = p.encode().unwrap();
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
