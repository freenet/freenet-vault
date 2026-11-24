//! Who may call the vault (spec 5). The vault trusts nothing beyond the
//! node's origin stamp and, for a delegate, the pointer record it attaches.

use crate::domain::Domain;
use freenet_vault_common::hash::delegate_key_empty_params;
use freenet_vault_common::ops::RequestHeader;
use freenet_vault_common::record::PointerRecord;
use freenet_vault_common::status::refused;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Caller {
    /// One of the domain's own pages (or a native app's grant).
    Page { id: [u8; 32] },
    /// A delegate whose pointer record verified and names its stamped key.
    Delegate {
        key: [u8; 32],
        author_vk: [u8; 32],
        app_id: Vec<u8>,
        record: [u8; 100],
    },
}

impl Caller {
    /// The caller-mark entry key: `author_vk || app_id`.
    pub fn mark_key(&self) -> Option<Vec<u8>> {
        match self {
            Caller::Delegate {
                author_vk, app_id, ..
            } => Some([author_vk.as_slice(), app_id].concat()),
            Caller::Page { .. } => None,
        }
    }
}

/// A page: its origin must be one of the domain's pages, and it sends no
/// caller proof. Otherwise `Refused(2)`.
pub fn page(domain: &Domain, id: &[u8; 32], header: &RequestHeader) -> Result<Caller, u8> {
    if !domain.is_own_page(id) || header.proof.is_some() {
        return Err(refused::CALLER_NOT_AUTHORIZED);
    }
    Ok(Caller::Page { id: *id })
}

/// A delegate: it must attach the pointer record of an accepted caller,
/// which verifies, is not a withdrawal, and names the stamped key under
/// empty parameters (D3). The version floor (caller mark) is checked later,
/// against storage. Otherwise `Refused(2)`.
pub fn delegate(domain: &Domain, key: &[u8; 32], header: &RequestHeader) -> Result<Caller, u8> {
    let deny = Err(refused::CALLER_NOT_AUTHORIZED);
    let Some(proof) = &header.proof else {
        return deny;
    };
    // Records under the domain's own author key are never caller records.
    if proof.author_vk == domain.author_vk {
        return deny;
    }
    let Some(accepted) = domain.caller_delegate(&proof.author_vk, &proof.app_id) else {
        return deny;
    };
    let record = PointerRecord::decode(&proof.record);
    if record.verify(&proof.author_vk, &proof.app_id).is_err() || record.is_withdrawal() {
        return deny;
    }
    // The compiled-in floor holds even when no caller mark is stored.
    if record.version < accepted.min_version {
        return deny;
    }
    if &delegate_key_empty_params(&record.code_hash) != key {
        return deny;
    }
    Ok(Caller::Delegate {
        key: *key,
        author_vk: proof.author_vk,
        app_id: proof.app_id.clone(),
        record: proof.record,
    })
}
