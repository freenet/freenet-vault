//! freenet-vault: a key-vault delegate library.
//!
//! A domain crate (for example `domains/river`) supplies a [`Domain`] and
//! calls [`process`] from its delegate's `process`. The library owns storage
//! (protocol 4), caller checks (spec 5), and the operations (spec 6,
//! protocol 12.5). The handover between builds (protocol 7) is not built
//! yet; `handover` marks where it attaches.
//!
//! NOT YET PUBLISHED; see the repository README.

pub mod domain;
pub mod host;
pub mod storage;
#[cfg(any(test, feature = "testing"))]
pub mod testing;

pub use domain::{CallerDelegate, Domain, PageContainer};
pub use host::Host;
