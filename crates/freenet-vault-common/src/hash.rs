//! Domain-tagged hashes (protocol 12.1). Tags are raw ASCII with no length or
//! terminator.

pub const TAG_TRANSFER: &[u8] = b"freenet-vault/transfer/v1";
pub const TAG_ENTRY: &[u8] = b"freenet-vault/entry/v1";
pub const TAG_MANIFEST: &[u8] = b"freenet-vault/manifest/v1";
pub const TAG_CHUNK: &[u8] = b"freenet-vault/chunk/v1";
pub const TAG_KEY: &[u8] = b"freenet-vault/key/v1";
pub const TAG_PARTITION: &[u8] = b"freenet-vault/partition/v1";
pub const TAG_RESET: &[u8] = b"freenet-vault/reset/v1";

fn tagged(tag: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(tag);
    for p in parts {
        h.update(p);
    }
    // UFCS: always blake3's inherent finalize, whatever traits are in scope.
    *blake3::Hasher::finalize(&h).as_bytes()
}

/// `BLAKE3("freenet-vault/entry/v1" || the entry's bytes as stored)`.
pub fn entry_digest(entry_bytes: &[u8]) -> [u8; 32] {
    tagged(TAG_ENTRY, &[entry_bytes])
}

/// `BLAKE3("freenet-vault/key/v1" || kind || key)`.
pub fn key_hash(kind: u8, key: &[u8]) -> [u8; 32] {
    tagged(TAG_KEY, &[&[kind], key])
}

/// `BLAKE3("freenet-vault/partition/v1" || DOMAIN_AUTHOR_VK || DOMAIN_APP_ID)`.
pub fn partition_id(domain_author_vk: &[u8; 32], domain_app_id: &[u8]) -> [u8; 32] {
    tagged(TAG_PARTITION, &[domain_author_vk, domain_app_id])
}

/// `BLAKE3("freenet-vault/reset/v1" || partition)`: the `confirm` field of
/// ResetPartition (protocol 12.5).
pub fn reset_confirm(partition: &[u8; 32]) -> [u8; 32] {
    tagged(TAG_RESET, &[partition])
}

/// `BLAKE3("freenet-vault/manifest/v1" || sorted digests)`. The caller sorts.
pub fn manifest_digest(sorted_digests: &[[u8; 32]]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(TAG_MANIFEST);
    for d in sorted_digests {
        h.update(d);
    }
    *blake3::Hasher::finalize(&h).as_bytes()
}

/// `BLAKE3("freenet-vault/chunk/v1" || chunk body)`.
pub fn chunk_digest(chunk_body: &[u8]) -> [u8; 32] {
    tagged(TAG_CHUNK, &[chunk_body])
}

/// `BLAKE3("freenet-vault/transfer/v1" || DOMAIN_AUTHOR_VK || pred_version u32 || record 100)`.
pub fn transfer_id(domain_author_vk: &[u8; 32], pred_version: u32, record: &[u8; 100]) -> [u8; 32] {
    tagged(
        TAG_TRANSFER,
        &[domain_author_vk, &pred_version.to_be_bytes(), record],
    )
}

/// The key of a delegate registered with empty parameters, from its code
/// hash: `BLAKE3(code_hash || [])`. Spec 5 / protocol 2 call this S(R).
pub fn delegate_key_empty_params(code_hash: &[u8; 32]) -> [u8; 32] {
    *blake3::hash(code_hash).as_bytes()
}

/// A contract instance id: `BLAKE3(code_hash || params)`.
pub fn contract_instance_id(code_hash: &[u8; 32], params: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(code_hash);
    h.update(params);
    *blake3::Hasher::finalize(&h).as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// Expected values computed outside this crate by `b3sum` over the
    /// concatenation written in each comment (protocol 12.1), so a changed tag,
    /// operand or operand order fails here.
    #[test]
    fn golden_hashes() {
        let vk = [0x11u8; 32];
        // "freenet-vault/entry/v1" 01 02 03
        assert_eq!(
            hex(&entry_digest(&[1, 2, 3])),
            "7ac0d5a484afd301f2ff597931c2908f39fd23368838d76cb57393742d1c8555"
        );
        // "freenet-vault/key/v1" kind(01) key(07 07 07 07)
        assert_eq!(
            hex(&key_hash(1, &[7; 4])),
            "5e8110c67abedc06302fc72aca719e211930e0328d7a39d719102ba1918d1799"
        );
        // "freenet-vault/partition/v1" author_vk app_id
        assert_eq!(
            hex(&partition_id(&vk, b"river.vault")),
            "326b8f0cb6dce1695ee2c50df3891f3cb292ebf118d88d3aa008cd56fa8c5fe9"
        );
        // "freenet-vault/manifest/v1" digest(01*32) digest(02*32)
        assert_eq!(
            hex(&manifest_digest(&[[1; 32], [2; 32]])),
            "fd3b9d06c9552de8c636dadf237643a769ddf8b00bf3f28bf6ff24d424f40942"
        );
        // "freenet-vault/chunk/v1" "chunk"
        assert_eq!(
            hex(&chunk_digest(b"chunk")),
            "166b5df3da581acc08373483c5b2ba9b1e96e67ca0095dbd67df64f96bcb077a"
        );
        // "freenet-vault/transfer/v1" author_vk version(01 02 03 04) record(22*100)
        assert_eq!(
            hex(&transfer_id(&vk, 0x01020304, &[0x22; 100])),
            "d3452a7b042501654a5cd11c33ff584a1e9e9e6e1fadbc5d1240cd114aff812f"
        );
        // code_hash(03*32) alone, and followed by "params"
        assert_eq!(
            hex(&delegate_key_empty_params(&[3; 32])),
            "1fb5fbf7762cd146e8d15a1c322c338f2a69bee4fc2398b160e5b90099fd3942"
        );
        assert_eq!(
            hex(&contract_instance_id(&[3; 32], b"params")),
            "be72caa7b30ae308b01b84fd62d1a8b085f1ff65bad9d512c49e6706fedb357c"
        );
    }

    #[test]
    fn operand_order_matters() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert_ne!(manifest_digest(&[a, b]), manifest_digest(&[b, a]));
        assert_ne!(partition_id(&a, &b), partition_id(&b, &a));
        assert_ne!(transfer_id(&a, 1, &[0; 100]), transfer_id(&a, 2, &[0; 100]));
        assert_ne!(key_hash(1, b"k"), key_hash(2, b"k"));
    }
}
