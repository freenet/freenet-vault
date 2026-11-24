//! What the vault needs from the node, behind a trait.
//!
//! `DelegateCtx`'s methods are inert off wasm32 (every read misses, every
//! write is refused), so code taking it directly cannot be tested natively.
//! The library takes `impl Host`; the delegate entry point wraps the real
//! context in [`CtxHost`], and tests use `testing::MemHost`.

/// Secrets, the per-run context, and randomness.
pub trait Host {
    fn get_secret(&self, key: &[u8]) -> Option<Vec<u8>>;
    /// `false` means the write failed. For a first-time secret the value may
    /// still be durable and readable (protocol 1), so a caller that depends
    /// on the outcome reads back.
    fn set_secret(&mut self, key: &[u8], value: &[u8]) -> bool;
    /// `true` means the secret was removed. `false` means it was not there
    /// (freenet-stdlib's answer) or the removal failed; the two cannot be told
    /// apart, so the caller reads back and keeps its record of the name.
    fn remove_secret(&mut self, key: &[u8]) -> bool;
    /// The delegate context, which the runtime keeps across the calls of one
    /// run (used to carry a pending consent prompt to its answer).
    fn read_context(&self) -> Vec<u8>;
    fn write_context(&mut self, data: &[u8]) -> bool;
    /// Fills `out` from the node's random source.
    fn random_bytes(&mut self, out: &mut [u8]);
}

/// The real host: a delegate's `DelegateCtx` and the node's random source.
#[cfg(target_family = "wasm")]
pub struct CtxHost<'a>(pub &'a mut freenet_stdlib::prelude::DelegateCtx);

#[cfg(target_family = "wasm")]
impl Host for CtxHost<'_> {
    fn get_secret(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.0.get_secret(key)
    }
    fn set_secret(&mut self, key: &[u8], value: &[u8]) -> bool {
        self.0.set_secret(key, value)
    }
    fn remove_secret(&mut self, key: &[u8]) -> bool {
        self.0.remove_secret(key)
    }
    fn read_context(&self) -> Vec<u8> {
        self.0.read()
    }
    fn write_context(&mut self, data: &[u8]) -> bool {
        if data.is_empty() {
            self.0.clear();
            true
        } else {
            self.0.write(data)
        }
    }
    fn random_bytes(&mut self, out: &mut [u8]) {
        let bytes = freenet_stdlib::rand::rand_bytes(out.len() as u32);
        out.copy_from_slice(&bytes);
    }
}
