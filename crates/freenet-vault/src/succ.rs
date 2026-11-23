//! The domain's own records, `vault:succ` (protocol 3).
//!
//! A build stores `current` (the highest non-withdrawal record) and the
//! highest withdrawal; its floor is the highest of OWN_VERSION and both.
//! Build-private layout:
//! `"FVSU" 4 ; format 1 ; current_present 1 ; current 100 ; withdrawal_present 1 ; withdrawal 100`.

use crate::domain::Domain;
use crate::host::Host;
use crate::storage::names;
use freenet_vault_common::codec::{Malformed, Reader, Writer};
use freenet_vault_common::record::PointerRecord;
use freenet_vault_common::status::{record_state, step_result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Succ {
    pub current: Option<[u8; 100]>,
    pub withdrawal: Option<[u8; 100]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoredSuccMalformed;

fn version(r: &[u8; 100]) -> u32 {
    PointerRecord::decode(r).version
}

impl Succ {
    pub fn load<H: Host>(host: &H) -> Result<Self, StoredSuccMalformed> {
        match host.get_secret(names::SUCC) {
            None => Ok(Self::default()),
            Some(b) => Self::decode(&b).map_err(|_| StoredSuccMalformed),
        }
    }

    fn decode(b: &[u8]) -> Result<Self, Malformed> {
        let mut r = Reader::new(b);
        if r.take(4, "magic")? != b"FVSU" || r.u8("format")? != 1 {
            return Err(Malformed("succ header"));
        }
        let cp = r.bool("current_present")?;
        let c: [u8; 100] = r.array("current")?;
        let wp = r.bool("withdrawal_present")?;
        let w: [u8; 100] = r.array("withdrawal")?;
        r.finish()?;
        Ok(Self {
            current: cp.then_some(c),
            withdrawal: wp.then_some(w),
        })
    }

    fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(b"FVSU")
            .u8(1)
            .u8(self.current.is_some() as u8)
            .bytes(&self.current.unwrap_or([0; 100]))
            .u8(self.withdrawal.is_some() as u8)
            .bytes(&self.withdrawal.unwrap_or([0; 100]));
        w.into_vec()
    }

    pub fn floor(&self, own_version: u32) -> u32 {
        own_version
            .max(self.current.as_ref().map(version).unwrap_or(0))
            .max(self.withdrawal.as_ref().map(version).unwrap_or(0))
    }

    /// Stopped: a stored withdrawal above `current`, or a withdrawal and no
    /// `current`.
    pub fn stopped(&self) -> bool {
        match (&self.withdrawal, &self.current) {
            (Some(w), Some(c)) => version(w) > version(c),
            (Some(_), None) => true,
            _ => false,
        }
    }

    pub fn record_state(&self) -> u8 {
        if self.stopped() {
            record_state::STOPPED
        } else if self.current.is_some() {
            record_state::SUCCESSOR
        } else {
            record_state::NONE
        }
    }

    /// A known non-withdrawn record above OWN_VERSION. Every stored `current`
    /// is above the floor it was accepted at, so above OWN_VERSION.
    pub fn successor(&self) -> Option<[u8; 100]> {
        self.current
    }
}

/// The outcome of offering a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Accepted {
    pub step_result: u8,
    pub storage_failure: bool,
}

/// Protocol 3: accept a candidate domain record.
pub fn accept_record<H: Host>(
    domain: &Domain,
    host: &mut H,
    succ: &mut Succ,
    bytes: &[u8; 100],
) -> Accepted {
    let r = PointerRecord::decode(bytes);
    let done = |step_result| Accepted {
        step_result,
        storage_failure: false,
    };
    if r.verify(&domain.author_vk, domain.app_id).is_err() {
        return done(step_result::INVALID);
    }
    let floor = succ.floor(domain.own_version);
    if r.version < floor || r.version == domain.own_version {
        return done(step_result::NOT_NEWER);
    }
    if r.version == floor {
        let same = [succ.current, succ.withdrawal]
            .iter()
            .flatten()
            .any(|s| s == bytes);
        // Byte-identical at the floor: the record is already held ("retry").
        return done(if same {
            step_result::RECORD_ACCEPTED
        } else {
            step_result::EQUIVOCATION
        });
    }
    let mut next = *succ;
    if r.is_withdrawal() {
        next.withdrawal = Some(*bytes);
    } else {
        next.current = Some(*bytes);
    }
    let enc = next.encode();
    if host.set_secret(names::SUCC, &enc)
        || host.get_secret(names::SUCC).as_deref() == Some(enc.as_slice())
    {
        *succ = next;
        done(step_result::RECORD_ACCEPTED)
    } else {
        Accepted {
            step_result: step_result::NOTHING,
            storage_failure: true,
        }
    }
}
