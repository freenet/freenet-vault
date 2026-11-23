//! The key operations (spec 6). ed25519 only. Seeds never leave this module
//! except through Export.

use ed25519_dalek::{Signer, SigningKey};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};
use zeroize::Zeroizing;

pub fn public_key(seed: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

/// Plain ed25519 over `data`.
pub fn sign(seed: &[u8; 32], data: &[u8]) -> [u8; 64] {
    SigningKey::from_bytes(seed).sign(data).to_bytes()
}

/// The stored key converted to X25519 (SHA-512 of the seed, first 32 bytes,
/// clamped), then X25519 with `peer`. Returns the raw output, zeros included
/// for a low-order peer.
pub fn key_agreement(seed: &[u8; 32], peer: &[u8; 32]) -> [u8; 32] {
    use sha2::Digest;
    let mut h = Zeroizing::new([0u8; 64]);
    h.copy_from_slice(&sha2::Sha512::digest(seed));
    let mut k = Zeroizing::new([0u8; 32]);
    k.copy_from_slice(&h[..32]);
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
    let secret = StaticSecret::from(*k);
    secret.diffie_hellman(&X25519Public::from(*peer)).to_bytes()
}

/// `blake3_keyed(blake3::derive_key(context, seed), data)`.
pub fn derive(seed: &[u8; 32], context: &str, data: &[u8]) -> [u8; 32] {
    let root = Zeroizing::new(blake3::derive_key(context, seed));
    *blake3::keyed_hash(&root, data).as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_verifies() {
        let seed = [7u8; 32];
        let sig = sign(&seed, b"hello");
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&public_key(&seed)).unwrap();
        vk.verify_strict(b"hello", &ed25519_dalek::Signature::from_bytes(&sig))
            .unwrap();
    }

    /// X25519(a, B) == X25519(b, A), with A and B the X25519 public keys of
    /// the converted scalars. (Byte identity with River's conversion is
    /// tested against river-core in `tests/river_cross.rs`.)
    #[test]
    fn key_agreement_is_symmetric() {
        use sha2::Digest;
        let x_public = |seed: &[u8; 32]| {
            let h = sha2::Sha512::digest(seed);
            let mut k = [0u8; 32];
            k.copy_from_slice(&h[..32]);
            X25519Public::from(&StaticSecret::from(k)).to_bytes()
        };
        let (a, b) = ([1u8; 32], [2u8; 32]);
        let ab = key_agreement(&a, &x_public(&b));
        assert_eq!(ab, key_agreement(&b, &x_public(&a)));
        assert_ne!(ab, [0u8; 32]);
    }

    #[test]
    fn low_order_peer_gives_zeros() {
        assert_eq!(key_agreement(&[3u8; 32], &[0u8; 32]), [0u8; 32]);
        // u = 1 is a low-order point as well.
        let mut one = [0u8; 32];
        one[0] = 1;
        assert_eq!(key_agreement(&[3u8; 32], &one), [0u8; 32]);
    }
}
