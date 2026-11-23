//! Domain-tagged hashes (protocol 12.1). Tags are raw ASCII with no length or
//! terminator.

pub const TAG_TRANSFER: &[u8] = b"freenet-vault/transfer/v1";
pub const TAG_ENTRY: &[u8] = b"freenet-vault/entry/v1";
pub const TAG_MANIFEST: &[u8] = b"freenet-vault/manifest/v1";
pub const TAG_CHUNK: &[u8] = b"freenet-vault/chunk/v1";
pub const TAG_KEY: &[u8] = b"freenet-vault/key/v1";
pub const TAG_PARTITION: &[u8] = b"freenet-vault/partition/v1";

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
