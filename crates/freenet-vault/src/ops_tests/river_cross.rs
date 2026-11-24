//! Byte-identical cross tests against River's crypto (spec 7.1 and 15),
//! river-core at origin/main 4d137e66.
//!
//! Each test runs the vault operation through `process` (Import the member's
//! seed, then Batch) and checks the result against river-core's own
//! function on the same inputs. KeyAgreement is checked through River's
//! decryption: an AES-GCM tag verifies only under the identical key, so
//! decrypting River's ciphertext with `SHA-256(vault output)` proves the
//! vault's X25519 output equals River's shared secret byte for byte.

use super::*;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use river_core::ecies;
use river_core::key_derivation::derive_room_secret;
use sha2::Digest;

/// River's `ROOT_CONTEXT` (private in river-core; pinned here by River's own
/// known-answer vectors below).
const RIVER_ROOT_CONTEXT: &str = "river-rotate v1 2026-04 room-secret-root";

/// Runs one Batch on a vault holding `seed`, returning each item's bytes.
fn vault_batch(seed: [u8; 32], items: Vec<BatchItem>) -> Vec<ItemResult> {
    let mut h = MemHost::new();
    arm(&mut h);
    let slot = vec![0x5A; 32];
    page(
        &mut h,
        op(
            1,
            Operation::Import {
                slot: slot.clone(),
                seed,
                replace: false,
            },
        ),
    );
    match page(
        &mut h,
        op(2, batch(2, &slot, crypto::public_key(&seed), items)),
    ) {
        Reply::Op(2, OpResult::Batch(r)) => {
            assert!(r.iter().all(|i| i.status == ITEM_OK), "{r:?}");
            r
        }
        other => panic!("{other:?}"),
    }
}

fn vault_key_agreement(seed: [u8; 32], peer: [u8; 32]) -> [u8; 32] {
    vault_batch(seed, vec![BatchItem::KeyAgreement(peer)])[0]
        .bytes
        .clone()
        .try_into()
        .unwrap()
}

fn aes_open(shared: &[u8; 32], nonce: &[u8; 12], ct: &[u8]) -> Result<Vec<u8>, aes_gcm::Error> {
    let key = sha2::Sha256::digest(shared);
    Aes256Gcm::new_from_slice(&key)
        .unwrap()
        .decrypt(&Nonce::from(*nonce), ct)
}

const SEEDS: [[u8; 32]; 4] = [[3; 32], [7; 32], [0xFF; 32], [0x11; 32]];

/// `decrypt_secret_from_member_blob_raw` == KeyAgreement, then River's
/// SHA-256 and AES-GCM (spec 7.1, first row).
#[test]
fn key_agreement_opens_rivers_member_secret_blobs() {
    for (i, member_seed) in SEEDS.into_iter().enumerate() {
        let member = ed25519_dalek::SigningKey::from_bytes(&member_seed);
        let secret = [i as u8 + 40; 32];
        let (ct, nonce, eph) = ecies::encrypt_secret_for_member(&secret, &member.verifying_key());
        let shared = vault_key_agreement(member_seed, eph.to_bytes());
        let opened = aes_open(&shared, &nonce, &ct).expect("same key as River's");
        assert_eq!(opened, secret);
        assert_eq!(
            ecies::decrypt_secret_from_member_blob_raw(&ct, &nonce, &eph.to_bytes(), &member)
                .unwrap(),
            <[u8; 32]>::try_from(opened.as_slice()).unwrap()
        );
    }
}

/// River's own known-answer blob (`encrypt_secret_for_member_known_answer`):
/// member seed [3; 32], secret [42; 32].
#[test]
fn key_agreement_opens_rivers_known_answer_blob() {
    let ct = hex("ae3a2f82fc8982c6014649b76c19ea0920d0eaf9bf8f2690ddf7dd70bda39bc54d829d924dc0afb8621639430515c78d");
    let eph: [u8; 32] = hex("19f806d18ca5b14914ebd6831cf896369030b1e9c8c36ae60f7156317021aa12")
        .try_into()
        .unwrap();
    let shared = vault_key_agreement([3; 32], eph);
    assert_eq!(aes_open(&shared, &[0; 12], &ct).unwrap(), vec![42u8; 32]);
}

/// `unseal_dm_from_sender` == KeyAgreement on the envelope's ephemeral key,
/// then River's SHA-256 and AES-GCM.
#[test]
fn key_agreement_opens_rivers_direct_messages() {
    for member_seed in SEEDS {
        let member = ed25519_dalek::SigningKey::from_bytes(&member_seed);
        let body = b"a direct message body".to_vec();
        let env = ecies::seal_dm_for_recipient(&member.verifying_key(), &body);
        let eph: [u8; 32] = env[..32].try_into().unwrap();
        let nonce: [u8; 12] = env[32..44].try_into().unwrap();
        let shared = vault_key_agreement(member_seed, eph);
        assert_eq!(aes_open(&shared, &nonce, &env[44..]).unwrap(), body);
        assert_eq!(ecies::unseal_dm_from_sender(&member, &env).unwrap(), body);
    }
}

/// A low-order ephemeral key: the vault returns zeros, and River computes the
/// same zero shared secret (its decryption under SHA-256(zeros) succeeds).
#[test]
fn key_agreement_with_a_low_order_peer_matches_river() {
    let member_seed = [9u8; 32];
    let member = ed25519_dalek::SigningKey::from_bytes(&member_seed);
    let mut one = [0u8; 32];
    one[0] = 1;
    for low in [[0u8; 32], one] {
        let shared = vault_key_agreement(member_seed, low);
        assert_eq!(shared, [0u8; 32]);
        let secret = [77u8; 32];
        let key = sha2::Sha256::digest([0u8; 32]);
        let nonce = [5u8; 12];
        let ct = Aes256Gcm::new_from_slice(&key)
            .unwrap()
            .encrypt(&Nonce::from(nonce), secret.as_slice())
            .unwrap();
        assert_eq!(
            ecies::try_decrypt_secret_from_member_blob_raw(&ct, &nonce, &low, &member),
            Ok(secret)
        );
    }
}

/// `derive_room_secret` == Derive with ROOT_CONTEXT, data = owner_vk ||
/// version (LE) (spec 7.1, second row).
#[test]
fn derive_matches_derive_room_secret() {
    for seed in SEEDS.into_iter().chain([[0u8; 32]]) {
        for owner_seed in [[1u8; 32], [2u8; 32]] {
            let owner_vk = ed25519_dalek::SigningKey::from_bytes(&owner_seed).verifying_key();
            let versions = [0u32, 1, 2, 0x01020304, u32::MAX];
            let items = versions
                .iter()
                .map(|v| BatchItem::Derive {
                    context: RIVER_ROOT_CONTEXT.into(),
                    data: [owner_vk.as_bytes().as_slice(), &v.to_le_bytes()].concat(),
                })
                .collect();
            let got = vault_batch(seed, items);
            for (v, r) in versions.iter().zip(got) {
                assert_eq!(
                    r.bytes,
                    derive_room_secret(&seed, &owner_vk, *v).to_vec(),
                    "seed {seed:?} v {v}"
                );
            }
        }
    }
}

/// River's known-answer vector `derive_known_answer_v1_zero_seed_zero_version`.
#[test]
fn derive_reproduces_rivers_known_answer() {
    let owner_vk = ed25519_dalek::SigningKey::from_bytes(&[1; 32]).verifying_key();
    let r = vault_batch(
        [0; 32],
        vec![BatchItem::Derive {
            context: RIVER_ROOT_CONTEXT.into(),
            data: [owner_vk.as_bytes().as_slice(), &0u32.to_le_bytes()].concat(),
        }],
    );
    assert_eq!(
        r[0].bytes,
        hex("dd189cce079374856eb7a201618e5886a1e9e5598b33340843002cbb9091e1a9")
    );
}

/// River signs with ed25519-dalek's `SigningKey::sign`; the vault's Sign is
/// byte-identical (ed25519 is deterministic) and verifies under River's
/// member key.
#[test]
fn sign_matches_rivers_signing() {
    use ed25519_dalek::Signer;
    for seed in SEEDS {
        let data = format!("member payload {}", seed[0]).into_bytes();
        let r = vault_batch(seed, vec![BatchItem::Sign(data.clone())]);
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        assert_eq!(r[0].bytes, sk.sign(&data).to_bytes().to_vec());
    }
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}
