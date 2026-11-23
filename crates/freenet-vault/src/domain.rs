//! A domain's compiled-in constants (spec 4, decision D1).
//!
//! Each domain is a small crate that builds the library into its own WASM
//! with one `Domain` value. The library never exposes a seed to domain code:
//! a domain supplies only constants and prompt wording.

use freenet_vault_common::bounds::{MAX_PARTITION_ENTRIES, MAX_SLOT};
use freenet_vault_common::hash;

/// A web container whose pages may call the vault: its code hash and the
/// publisher key it is parameterized with. The page's origin is
/// `WebApp(BLAKE3(code_hash || publisher_vk))`.
#[derive(Debug, Clone, Copy)]
pub struct PageContainer {
    pub code_hash: [u8; 32],
    pub publisher_vk: [u8; 32],
}

impl PageContainer {
    pub fn instance_id(&self) -> [u8; 32] {
        hash::contract_instance_id(&self.code_hash, &self.publisher_vk)
    }
}

/// A delegate that may call the vault, named by the pointer record that
/// identifies its current build: `(author_vk, app_id)`.
#[derive(Debug, Clone, Copy)]
pub struct CallerDelegate {
    pub author_vk: [u8; 32],
    pub app_id: &'static [u8],
}

#[derive(Debug, Clone, Copy)]
pub struct Domain {
    /// The domain's offline author key, which signs the vault's own records.
    pub author_vk: [u8; 32],
    /// The domain's app id (River: `river.vault`).
    pub app_id: &'static [u8],
    /// This build's version.
    pub own_version: u32,
    /// Every signed non-withdrawal version below `own_version`, as
    /// `(version, delegate key)`. Unused until the handover is built.
    pub predecessors: &'static [(u32, [u8; 32])],
    /// Containers whose pages are the domain's own pages.
    pub page_containers: &'static [PageContainer],
    /// Further accepted `WebApp` origins given as raw instance ids (a native
    /// app's grant).
    pub extra_page_ids: &'static [[u8; 32]],
    /// Delegates that may call the vault.
    pub caller_delegates: &'static [CallerDelegate],
    /// Frame types a delegate caller may send.
    pub delegate_frames: &'static [u8],
    /// Keys never served: the domain author key is always included by the
    /// library; these are the domain's other publisher keys.
    pub publisher_keys: &'static [[u8; 32]],
    /// Required slot length, if the domain fixes one (River: 32).
    pub slot_len: Option<usize>,
    /// Local quotas, at or below the library maximums.
    pub max_key_slots: usize,
    pub max_caller_marks: usize,
    /// The consent prompt's text for Export of `slot`.
    pub export_prompt: fn(slot: &[u8]) -> String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainError {
    QuotaAboveLibraryMaximum,
    SlotLenOutOfRange,
    ZeroVersion,
    EmptyAppId,
}

impl Domain {
    /// Checks the constants against the library's frozen bounds. Domain
    /// crates call this from a unit test.
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.max_key_slots + self.max_caller_marks > MAX_PARTITION_ENTRIES {
            return Err(DomainError::QuotaAboveLibraryMaximum);
        }
        if let Some(n) = self.slot_len {
            if n == 0 || n > MAX_SLOT {
                return Err(DomainError::SlotLenOutOfRange);
            }
        }
        if self.own_version == 0 {
            return Err(DomainError::ZeroVersion);
        }
        if self.app_id.is_empty() {
            return Err(DomainError::EmptyAppId);
        }
        Ok(())
    }

    pub fn partition(&self) -> [u8; 32] {
        hash::partition_id(&self.author_vk, self.app_id)
    }

    pub fn is_own_page(&self, instance_id: &[u8; 32]) -> bool {
        self.page_containers
            .iter()
            .any(|c| &c.instance_id() == instance_id)
            || self.extra_page_ids.contains(instance_id)
    }

    pub fn caller_delegate(&self, author_vk: &[u8; 32], app_id: &[u8]) -> Option<&CallerDelegate> {
        self.caller_delegates
            .iter()
            .find(|c| &c.author_vk == author_vk && c.app_id == app_id)
    }

    /// The domain author key and every compiled-in publisher key.
    pub fn is_publisher_key(&self, public_key: &[u8; 32]) -> bool {
        public_key == &self.author_vk || self.publisher_keys.contains(public_key)
    }

    pub fn slot_ok(&self, slot: &[u8]) -> bool {
        match self.slot_len {
            Some(n) => slot.len() == n,
            None => !slot.is_empty() && slot.len() <= MAX_SLOT,
        }
    }
}
