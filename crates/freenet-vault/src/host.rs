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
    /// Every write and removal is refused for the rest of this call (a write
    /// failed earlier in it). A `Store` opened later in the call reports
    /// read-only, so reads and signing still take the read-only path.
    fn writes_refused(&self) -> bool {
        false
    }
}

/// Wraps the host for one call: after a `set_secret` that reports failure the
/// call is read-only (every later `set_secret` and `remove_secret` is refused),
/// because that write may or may not have landed and nothing later in the call
/// may build on either outcome. This holds across every `Store` the call opens.
/// A failed removal does not latch: the name stays listed and the next call
/// retries it.
pub struct WriteLatch<'a, H: Host> {
    inner: &'a mut H,
    failed: bool,
}

impl<'a, H: Host> WriteLatch<'a, H> {
    pub fn new(inner: &'a mut H) -> Self {
        Self {
            inner,
            failed: false,
        }
    }
}

impl<H: Host> Host for WriteLatch<'_, H> {
    fn get_secret(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.inner.get_secret(key)
    }
    fn set_secret(&mut self, key: &[u8], value: &[u8]) -> bool {
        if self.failed {
            return false;
        }
        let ok = self.inner.set_secret(key, value);
        self.failed |= !ok;
        ok
    }
    fn remove_secret(&mut self, key: &[u8]) -> bool {
        !self.failed && self.inner.remove_secret(key)
    }
    fn read_context(&self) -> Vec<u8> {
        self.inner.read_context()
    }
    fn write_context(&mut self, data: &[u8]) -> bool {
        self.inner.write_context(data)
    }
    fn random_bytes(&mut self, out: &mut [u8]) {
        self.inner.random_bytes(out)
    }
    fn writes_refused(&self) -> bool {
        self.failed || self.inner.writes_refused()
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{MemHost, WriteFault};

    /// After a failed `set_secret` every later write and removal in the call is
    /// refused, whichever store asks; a failed removal does not latch.
    #[test]
    fn a_failed_write_makes_the_rest_of_the_call_read_only() {
        let mut m = MemHost::new();
        m.secrets.insert(b"x".to_vec(), vec![1]);
        m.set_fault(|n| {
            if n == b"bad" {
                WriteFault::Fail
            } else {
                WriteFault::None
            }
        });
        let mut l = WriteLatch::new(&mut m);
        assert!(l.set_secret(b"a", &[1]));
        assert!(!l.set_secret(b"bad", &[1]));
        assert!(!l.set_secret(b"b", &[2]), "a later write was let through");
        assert!(!l.remove_secret(b"x"), "a later removal was let through");
        assert_eq!(l.get_secret(b"a"), Some(vec![1]));
        assert!(m.secrets.contains_key(b"x".as_slice()));
        assert!(!m.secrets.contains_key(b"b".as_slice()));
        // A failed removal does not latch.
        let mut m = MemHost::new();
        m.undeletable.insert(b"u".to_vec());
        m.secrets.insert(b"u".to_vec(), vec![1]);
        let mut l = WriteLatch::new(&mut m);
        assert!(!l.remove_secret(b"u"));
        assert!(l.set_secret(b"a", &[1]));
    }
}
