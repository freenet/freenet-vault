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

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 8032 section 7.1, test vectors 1 to 3 (seed, public key, message,
    /// signature). The vault signs with plain ed25519, so Sign must equal
    /// these byte for byte; the three were also reproduced with an
    /// independent implementation before being written here.
    #[test]
    fn sign_matches_rfc_8032_vectors() {
        let vectors = [
            (
                "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                "",
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
            ),
            (
                "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
                "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
                "72",
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
            ),
            (
                "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
                "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
                "af82",
                "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
            ),
        ];
        for (seed, public, msg, sig) in vectors {
            let seed: [u8; 32] = unhex(seed).try_into().unwrap();
            assert_eq!(public_key(&seed).to_vec(), unhex(public));
            assert_eq!(sign(&seed, &unhex(msg)).to_vec(), unhex(sig));
        }
    }

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
