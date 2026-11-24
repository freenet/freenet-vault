//! The delegate context: what the vault keeps between calls without writing
//! it to storage.
//!
//! The node keeps a delegate's context across its calls (per delegate, pruned
//! after a time; freenet-stdlib `WakeupFired` docs), and a restart loses it.
//! That is exactly the "volatile" state of the handover protocol (7.1, 7.7):
//! the in-flight marks, and whether the mirror sweep has finished since the
//! build started or took over. Losing it is always safe: in-flight entries are
//! sent again and the sweep runs again. It also carries a pending Export
//! prompt (spec 6) to its answer.
//!
//! Layout (build-private):
//! ```text
//! "FVCT" 4 ; pending_len 2 ; pending (consent::Pending) ;
//! flags 1 (bit 0 swept, bit 1 complete_in_flight, bit 2 cursor present) ;
//! [cursor: kind 1 ; key_len 2 ; key] ;
//! in_flight_count 2 ; in_flight_count x { kind 1 ; key_len 2 ; key }
//! ```
//! A bare `"FVPC"` context (a pending prompt written before this layout) is
//! read as that prompt alone.

use crate::consent::Pending;
use crate::host::Host;
use freenet_vault_common::codec::{Reader, Writer};
use std::collections::BTreeSet;

/// An entry identity (protocol 2).
pub type Ident = (u8, Vec<u8>);

/// The handover's volatile state (7.1, 7.7).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Vol {
    /// Entries sent in the current step and not yet answered.
    pub in_flight: BTreeSet<Ident>,
    /// A Complete was sent in the current step and not yet answered.
    pub complete_in_flight: bool,
    /// The mirror sweep has finished since this build started or took over.
    pub swept: bool,
    /// Where an unfinished sweep continues: the last identity it examined.
    pub sweep_cursor: Option<Ident>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ctx {
    pub pending: Option<Pending>,
    pub vol: Vol,
}

fn ident(r: &mut Reader) -> Option<Ident> {
    let kind = r.u8("kind").ok()?;
    let n = r.u16("key_len").ok()? as usize;
    Some((kind, r.take(n, "key").ok()?.to_vec()))
}

impl Ctx {
    pub fn load<H: Host>(host: &H) -> Self {
        Self::decode(&host.read_context()).unwrap_or_default()
    }

    /// Writes the context back if it changed from `before`.
    pub fn store<H: Host>(&self, host: &mut H, before: &Ctx) -> bool {
        if self == before {
            return true;
        }
        host.write_context(&self.encode())
    }

    pub fn encode(&self) -> Vec<u8> {
        if self == &Self::default() {
            return Vec::new();
        }
        let p = self.pending.as_ref().map(|p| p.encode()).unwrap_or_default();
        let v = &self.vol;
        let mut w = Writer::new();
        w.bytes(b"FVCT").len_u16(p.len(), "pending").bytes(&p);
        let flags = (v.swept as u8)
            | ((v.complete_in_flight as u8) << 1)
            | ((v.sweep_cursor.is_some() as u8) << 2);
        w.u8(flags);
        if let Some((k, key)) = &v.sweep_cursor {
            w.u8(*k).len_u16(key.len(), "key").bytes(key);
        }
        w.len_u16(v.in_flight.len(), "in_flight");
        for (k, key) in &v.in_flight {
            w.u8(*k).len_u16(key.len(), "key").bytes(key);
        }
        w.into_vec()
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.is_empty() {
            return Some(Self::default());
        }
        if b.starts_with(b"FVPC") {
            return Some(Self {
                pending: Some(Pending::decode(b)?),
                vol: Vol::default(),
            });
        }
        let mut r = Reader::new(b);
        if r.take(4, "magic").ok()? != b"FVCT" {
            return None;
        }
        let n = r.u16("pending").ok()? as usize;
        let p = r.take(n, "pending").ok()?;
        let pending = if p.is_empty() {
            None
        } else {
            Some(Pending::decode(p)?)
        };
        let flags = r.u8("flags").ok()?;
        let sweep_cursor = if flags & 4 != 0 {
            Some(ident(&mut r)?)
        } else {
            None
        };
        let n = r.u16("in_flight").ok()? as usize;
        let mut in_flight = BTreeSet::new();
        for _ in 0..n {
            in_flight.insert(ident(&mut r)?);
        }
        r.finish().ok()?;
        Some(Self {
            pending,
            vol: Vol {
                in_flight,
                complete_in_flight: flags & 2 != 0,
                swept: flags & 1 != 0,
                sweep_cursor,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ctx_round_trips() {
        let mut c = Ctx::default();
        assert_eq!(Ctx::decode(&c.encode()), Some(c.clone()));
        c.vol.swept = true;
        c.vol.in_flight.insert((1, vec![1, 2]));
        c.vol.sweep_cursor = Some((2, vec![3]));
        c.pending = Some(Pending {
            prompt_id: 7,
            origin: [1; 32],
            request_id: 9,
            slot: vec![4; 32],
        });
        assert_eq!(Ctx::decode(&c.encode()), Some(c.clone()));
        let old = c.pending.clone().unwrap().encode();
        assert_eq!(Ctx::decode(&old).unwrap().pending, c.pending);
    }
}
