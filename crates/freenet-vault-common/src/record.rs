//! The pointer record (freenet-migrate's pointer contract state).
//!
//! `version u32 BE || code_hash 32 || signature 64`, signed over
//! `"freenet-pointer/state-v1" || author_vk || app_id || version_be || code_hash`.
//! A zero code hash is a withdrawal. This mirrors
//! `freenet-migrate/contracts/pointer-contract/src/lib.rs` byte for byte; the
//! tests check it against a record River has published.

use ed25519_dalek::{Signature, VerifyingKey};

pub const RECORD_LEN: usize = 100;
pub const SIGNING_DOMAIN: &[u8] = b"freenet-pointer/state-v1";
pub const MAX_VERSION: u32 = u32::MAX - 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PointerRecord {
    pub version: u32,
    pub code_hash: [u8; 32],
    pub signature: [u8; 64],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordError {
    ZeroVersion,
    ReservedVersion,
    SignatureUnset,
    BadSignature,
    BadAuthorKey,
}

/// The message a record's signature covers.
pub fn signing_message(
    author_vk: &[u8; 32],
    app_id: &[u8],
    version: u32,
    code_hash: &[u8; 32],
) -> Vec<u8> {
    let mut m = Vec::with_capacity(SIGNING_DOMAIN.len() + 32 + app_id.len() + 4 + 32);
    m.extend_from_slice(SIGNING_DOMAIN);
    m.extend_from_slice(author_vk);
    m.extend_from_slice(app_id);
    m.extend_from_slice(&version.to_be_bytes());
    m.extend_from_slice(code_hash);
    m
}

impl PointerRecord {
    pub fn decode(bytes: &[u8; RECORD_LEN]) -> Self {
        let mut version = [0u8; 4];
        version.copy_from_slice(&bytes[..4]);
        let mut code_hash = [0u8; 32];
        code_hash.copy_from_slice(&bytes[4..36]);
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&bytes[36..]);
        Self {
            version: u32::from_be_bytes(version),
            code_hash,
            signature,
        }
    }

    pub fn encode(&self) -> [u8; RECORD_LEN] {
        let mut out = [0u8; RECORD_LEN];
        out[..4].copy_from_slice(&self.version.to_be_bytes());
        out[4..36].copy_from_slice(&self.code_hash);
        out[36..].copy_from_slice(&self.signature);
        out
    }

    pub fn is_withdrawal(&self) -> bool {
        self.code_hash == [0u8; 32]
    }

    /// Checks the record is signed by `author_vk` for `app_id`. Same checks,
    /// in the same order, as the pointer contract's `PointerRecord::verify`.
    pub fn verify(&self, author_vk: &[u8; 32], app_id: &[u8]) -> Result<(), RecordError> {
        if self.version == 0 {
            return Err(RecordError::ZeroVersion);
        }
        if self.version > MAX_VERSION {
            return Err(RecordError::ReservedVersion);
        }
        if self.signature == [0u8; 64] {
            return Err(RecordError::SignatureUnset);
        }
        let vk = VerifyingKey::from_bytes(author_vk).map_err(|_| RecordError::BadAuthorKey)?;
        if vk.is_weak() {
            return Err(RecordError::BadAuthorKey);
        }
        let msg = signing_message(author_vk, app_id, self.version, &self.code_hash);
        vk.verify_strict(&msg, &Signature::from_bytes(&self.signature))
            .map_err(|_| RecordError::BadSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex32(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }

    fn hex_vec(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    /// River's author key (`published-contract/webapp.parameters`, river
    /// origin/main 4d137e66) and the `river.chat-delegate` record it signed
    /// (`pointer-records.toml`, version 11). A record the real signer
    /// produced, so a drift in the message layout fails here.
    const RIVER_AUTHOR_VK: &str =
        "7a597ab5353d99b22f1f9d366536584fa444233c7fa0b0adad6bcd55c973d683";
    const CHAT_DELEGATE_V11: &str = "0000000b4fbc0f3a4940d1dace00415337d3cfae7ea3eceac03a8877a2b62fc9455bf4c4749cc8eb4b8e1305ed5857f4be5a8491c4a4713cb5f5be6f9a4eb88494ef8bf8ce10a1ee5c31234f4bd01d4453eb4ee8f51341f8f1656a563bda067fc424f50b";

    #[test]
    fn verifies_a_record_river_published() {
        let vk = hex32(RIVER_AUTHOR_VK);
        let bytes: [u8; 100] = hex_vec(CHAT_DELEGATE_V11).try_into().unwrap();
        let r = PointerRecord::decode(&bytes);
        assert_eq!(r.version, 11);
        assert_eq!(r.encode(), bytes);
        assert_eq!(r.verify(&vk, b"river.chat-delegate"), Ok(()));
        // Bound to the app id and to every field.
        assert_eq!(
            r.verify(&vk, b"river.room-contract"),
            Err(RecordError::BadSignature)
        );
        let mut v = r;
        v.version = 12;
        assert_eq!(
            v.verify(&vk, b"river.chat-delegate"),
            Err(RecordError::BadSignature)
        );
        let mut h = r;
        h.code_hash[0] ^= 1;
        assert_eq!(
            h.verify(&vk, b"river.chat-delegate"),
            Err(RecordError::BadSignature)
        );
    }

    #[test]
    fn refuses_reserved_forms() {
        let vk = hex32(RIVER_AUTHOR_VK);
        let bytes: [u8; 100] = hex_vec(CHAT_DELEGATE_V11).try_into().unwrap();
        let r = PointerRecord::decode(&bytes);
        let mut z = r;
        z.version = 0;
        assert_eq!(z.verify(&vk, b"x"), Err(RecordError::ZeroVersion));
        let mut m = r;
        m.version = u32::MAX;
        assert_eq!(m.verify(&vk, b"x"), Err(RecordError::ReservedVersion));
        let mut s = r;
        s.signature = [0; 64];
        assert_eq!(s.verify(&vk, b"x"), Err(RecordError::SignatureUnset));
    }
}
