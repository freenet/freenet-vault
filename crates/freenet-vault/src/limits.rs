//! The library maximums and the handover's windows (protocol 7.7, 8, 11).
//!
//! Real builds always use [`V1`]. Builds with the `testing` feature can lower
//! them for one thread, so that the conformance harness reaches staging full,
//! multi-chunk copies, window limits and hop caps with the simulation model's
//! scaled-down constants. None of the protocol rules depends on the absolute
//! sizes; the frozen bounds are never raised.

use freenet_vault_common::bounds::{MAX_PARTITION_BYTES, MAX_PARTITION_ENTRIES};
use freenet_vault_common::handover::{MAX_CHUNK_ENTRIES, MAX_MISSING};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Entries per partition (8).
    pub max_entries: usize,
    /// Entry bytes per partition (8).
    pub max_bytes: usize,
    /// Entries per chunk (11).
    pub chunk_max: usize,
    /// Messages per step on a poke (7.7).
    pub window_poke: usize,
    /// Messages per step on a wake-up (7.7).
    pub window_wakeup: usize,
    /// Digests in a "missing" answer (11).
    pub missing_max: usize,
    /// Identities the mirror sweep examines per message of the window (7.7):
    /// a step examines at most `window * sweep_per_message` identities, and
    /// the next step continues where it stopped.
    pub sweep_per_message: usize,
}

pub const V1: Limits = Limits {
    max_entries: MAX_PARTITION_ENTRIES,
    max_bytes: MAX_PARTITION_BYTES,
    chunk_max: MAX_CHUNK_ENTRIES,
    window_poke: 32,
    window_wakeup: 8,
    missing_max: MAX_MISSING,
    sweep_per_message: 4,
};

#[cfg(any(test, feature = "testing"))]
thread_local! {
    static OVERRIDE: std::cell::Cell<Option<Limits>> = const { std::cell::Cell::new(None) };
}

/// Lowers the limits for this thread (testing builds only). The values must
/// be at or below [`V1`].
#[cfg(any(test, feature = "testing"))]
pub fn set_for_tests(l: Option<Limits>) {
    if let Some(l) = &l {
        assert!(l.max_entries <= V1.max_entries && l.chunk_max <= V1.chunk_max);
        assert!(l.missing_max <= V1.missing_max && l.max_bytes <= V1.max_bytes);
    }
    OVERRIDE.with(|c| c.set(l));
}

pub fn get() -> Limits {
    #[cfg(any(test, feature = "testing"))]
    if let Some(l) = OVERRIDE.with(|c| c.get()) {
        return l;
    }
    V1
}
