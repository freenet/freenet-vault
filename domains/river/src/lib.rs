//! The River vault (spec 7): the freenet-vault library with River's domain
//! constants compiled in. Registered with empty parameters.

use freenet_stdlib::prelude::*;
use freenet_vault::{CallerDelegate, Domain, PageContainer};
use freenet_vault_common::frame::types;

#[cfg(feature = "release")]
compile_error!(
    "RIVER_VAULT_AUTHOR_VK is a placeholder. A release needs the offline River vault author key \
     (DESIGN-NOTES.md, \"River constants\")."
);

/// PLACEHOLDER: the River vault's offline author key does not exist yet.
/// This is the public key of the seed `[0x52; 32]`, which anyone can sign
/// with, so the `release` feature refuses to build while it is here.
pub const RIVER_VAULT_AUTHOR_VK: [u8; 32] = [
    0x20, 0x12, 0xcb, 0x90, 0xca, 0x60, 0xe8, 0xe5, 0xd8, 0xda, 0xf6, 0x6e, 0x22, 0x72, 0xd2, 0x23,
    0x3e, 0x04, 0x86, 0xd5, 0x57, 0xe8, 0xc6, 0x61, 0x41, 0xed, 0x89, 0x20, 0x17, 0x7d, 0x7e, 0xb7,
];

/// River's online publishing key: it parameterizes River's web container and
/// signs River's pointer records (river `published-contract/webapp.parameters`
/// and `pointer-records.toml`, origin/main 4d137e66).
pub const RIVER_PUBLISHER_VK: [u8; 32] = [
    0x7a, 0x59, 0x7a, 0xb5, 0x35, 0x3d, 0x99, 0xb2, 0x2f, 0x1f, 0x9d, 0x36, 0x65, 0x36, 0x58, 0x4f,
    0xa4, 0x44, 0x23, 0x3c, 0x7f, 0xa0, 0xb0, 0xad, 0xad, 0x6b, 0xcd, 0x55, 0xc9, 0x73, 0xd6, 0x83,
];

/// BLAKE3 of River's committed web container WASM
/// (`published-contract/web_container_contract.wasm`, origin/main 4d137e66).
/// freenet-core #6310 will change it once; the vault release accepting the
/// new id lists both.
pub const RIVER_WEB_CONTAINER_CODE_HASH: [u8; 32] = [
    0x7c, 0x9d, 0x7d, 0xbe, 0xcf, 0x0c, 0x90, 0x40, 0x96, 0xca, 0x8b, 0x9d, 0x25, 0xd7, 0xd3, 0x99,
    0x2e, 0xe6, 0xae, 0xe3, 0x41, 0xb3, 0x1d, 0x52, 0xfe, 0x79, 0xfe, 0x09, 0xce, 0x17, 0xb8, 0x28,
];

pub const RIVER_PAGE_CONTAINERS: &[PageContainer] = &[PageContainer {
    code_hash: RIVER_WEB_CONTAINER_CODE_HASH,
    publisher_vk: RIVER_PUBLISHER_VK,
}];

pub const RIVER_CALLER_DELEGATES: &[CallerDelegate] = &[CallerDelegate {
    author_vk: RIVER_PUBLISHER_VK,
    app_id: b"river.chat-delegate",
}];

fn export_prompt(slot: &[u8]) -> String {
    let short: String = slot.iter().take(4).map(|b| format!("{b:02x}")).collect();
    format!(
        "River asks to export your private key for the room {short}…. \
         Anyone holding it can act as you in that room. \
         Allow only if you asked River to export it."
    )
}

pub const RIVER: Domain = Domain {
    author_vk: RIVER_VAULT_AUTHOR_VK,
    app_id: b"river.vault",
    own_version: 1,
    predecessors: &[],
    page_containers: RIVER_PAGE_CONTAINERS,
    // Native River's app grant (#6130) is not yet defined as an origin.
    extra_page_ids: &[],
    caller_delegates: RIVER_CALLER_DELEGATES,
    delegate_frames: &[types::BATCH, types::PUBLIC_KEY, types::SUBMIT_RECORD],
    publisher_keys: &[RIVER_PUBLISHER_VK],
    slot_len: Some(32),
    max_key_slots: 1024,
    max_caller_marks: 64,
    export_prompt,
};

pub struct RiverVault;

#[delegate]
impl DelegateInterface for RiverVault {
    fn process(
        ctx: &mut DelegateCtx,
        parameters: Parameters<'static>,
        origin: Option<MessageOrigin>,
        message: InboundDelegateMsg,
    ) -> Result<Vec<OutboundDelegateMsg>, DelegateError> {
        #[cfg(target_family = "wasm")]
        {
            let mut host = freenet_vault::host::CtxHost(ctx);
            freenet_vault::process(
                &RIVER,
                &mut host,
                parameters.as_ref(),
                origin.as_ref(),
                message,
            )
        }
        // DelegateCtx is inert off wasm32; native tests call
        // `freenet_vault::process` with a test host instead.
        #[cfg(not(target_family = "wasm"))]
        {
            let _ = (ctx, parameters, origin, message);
            Err(DelegateError::Other("the vault runs only as WASM".into()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn river_domain_is_within_library_bounds() {
        assert_eq!(RIVER.validate(), Ok(()));
    }

    #[test]
    fn placeholder_author_key_is_what_it_claims() {
        let vk = ed25519_dalek::SigningKey::from_bytes(&[0x52; 32]).verifying_key();
        assert_eq!(
            vk.to_bytes(),
            RIVER_VAULT_AUTHOR_VK,
            "{:02x?}",
            vk.to_bytes()
        );
    }

    /// The page origin the vault accepts is River's published web container
    /// id (`published-contract/contract-id.txt`).
    #[test]
    fn page_container_is_rivers_published_web_container() {
        let id = bs58::decode("raAqMhMG7KUpXBU2SxgCQ3Vh4PYjttxdSWd9ftV7RLv")
            .into_vec()
            .unwrap();
        assert_eq!(
            RIVER_PAGE_CONTAINERS[0].instance_id().as_slice(),
            id.as_slice()
        );
        assert!(RIVER.is_own_page(&RIVER_PAGE_CONTAINERS[0].instance_id()));
    }
}
