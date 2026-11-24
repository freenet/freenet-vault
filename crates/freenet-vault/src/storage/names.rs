//! Secret names (protocol 4.1). Binary parts are lower-case hex.

use freenet_vault_common::hash::key_hash;

pub const SUCC: &[u8] = b"vault:succ";
pub const PARTS: &[u8] = b"vault:parts";

pub fn hex(bytes: &[u8]) -> String {
    const D: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(D[(b >> 4) as usize] as char);
        s.push(D[(b & 15) as usize] as char);
    }
    s
}

pub fn index(partition: &[u8; 32]) -> Vec<u8> {
    format!("vault:idx:{}", hex(partition)).into_bytes()
}

/// The second copy of the index, written after the first (protocol 4.2).
pub fn index2(partition: &[u8; 32]) -> Vec<u8> {
    format!("vault:idx2:{}", hex(partition)).into_bytes()
}

pub fn gc(partition: &[u8; 32]) -> Vec<u8> {
    format!("vault:gc:{}", hex(partition)).into_bytes()
}

/// The second copy of the gc list, written with the first. A read takes the
/// union, so one copy that fails to read does not lose a pending removal.
pub fn gc2(partition: &[u8; 32]) -> Vec<u8> {
    format!("vault:gc2:{}", hex(partition)).into_bytes()
}

/// Set when the first index copy read as absent while the second was valid. A
/// second sighting on a later call turns "ambiguous" into "lost" and the first
/// copy is rewritten from the second.
pub fn index_miss(partition: &[u8; 32]) -> Vec<u8> {
    format!("vault:idxmiss:{}", hex(partition)).into_bytes()
}

/// `vault:e:<P>:<key hash>:<p>`.
pub fn entry(partition: &[u8; 32], kind: u8, key: &[u8], parity: u8) -> Vec<u8> {
    format!(
        "vault:e:{}:{}:{}",
        hex(partition),
        hex(&key_hash(kind, key)),
        parity & 1
    )
    .into_bytes()
}

/// The prefix every entry secret of a partition starts with.
pub fn entry_prefix(partition: &[u8; 32]) -> Vec<u8> {
    format!("vault:e:{}:", hex(partition)).into_bytes()
}
