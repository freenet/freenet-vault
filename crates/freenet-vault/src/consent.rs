//! The consent prompt for Export (spec 6).
//!
//! Export emits `RequestUserInput`; the node shows the prompt and calls the
//! vault again with `UserResponse` in the same run, under the same origin,
//! while the lane is held (at most 60 s). The pending request rides in the
//! delegate context, not in secrets, so Export still works when storage is
//! full (spec 11). It is bound to a random prompt id and to the page's
//! origin; an answer matching neither is refused.
//!
//! Context layout (build-private):
//! `"FVPC" 4 ; prompt_id 4 ; origin 32 ; request_id 8 ; slot_len 1 ; slot ;
//! reset 1`.

use freenet_vault_common::codec::{Reader, Writer};

pub const ALLOW: &[u8] = b"Allow";
pub const DENY: &[u8] = b"Deny";

/// The prompt for ResetPartition (protocol 4.5).
pub const RESET_PROMPT: &str = "Repair the key vault? Its index is damaged. The vault will start a fresh index; keys you do not re-import afterwards can no longer be used.";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pending {
    pub prompt_id: u32,
    pub origin: [u8; 32],
    pub request_id: u64,
    pub slot: Vec<u8>,
    /// ResetPartition (true) or Export (false).
    pub reset: bool,
}

impl Pending {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(b"FVPC")
            .u32(self.prompt_id)
            .bytes(&self.origin)
            .u64(self.request_id)
            .len_u8(self.slot.len(), "slot_len")
            .bytes(&self.slot)
            .u8(self.reset as u8);
        w.into_vec()
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        let mut r = Reader::new(b);
        if r.take(4, "magic").ok()? != b"FVPC" {
            return None;
        }
        let prompt_id = r.u32("prompt_id").ok()?;
        let origin = r.array("origin").ok()?;
        let request_id = r.u64("request_id").ok()?;
        let len = r.u8("slot_len").ok()? as usize;
        let slot = r.take(len, "slot").ok()?.to_vec();
        let reset = r.bool("reset").ok()?;
        r.finish().ok()?;
        Some(Self {
            prompt_id,
            origin,
            request_id,
            slot,
            reset,
        })
    }
}
