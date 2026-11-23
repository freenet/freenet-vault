//! Abstract simulation model of the freenet-vault handover protocol.
//!
//! Step 1 of the acceptance gate in the handover protocol document
//! (revision 7, section 15): an executable model written from the document
//! alone, independently of the library's handover code. Each build is a pure
//! state machine over an explicit durable store; a seeded scheduler drives
//! clients, wake-ups, the publisher and the operator through the fault model
//! of 15.3, and invariants I1 to I8 are checked after every step.
//!
//! A violation is a finding against the document, not something to patch
//! here: the document is fixed first, then the model.

pub mod build;
pub mod cov;
pub mod gen;
pub mod store;
pub mod types;
pub mod world;

#[cfg(test)]
mod tests_76;
