# freenet-vault

**Design in progress, not for use.** Nothing here is published, signed or
registered on any node. The formats may still change.

A key-vault delegate library for Freenet apps, and the River vault built from
it.

- `crates/freenet-vault-common`: frame and entry formats, shared by the vault
  and the apps that call it. Few dependencies.
- `crates/freenet-vault`: the delegate library: storage, caller checks and the
  vault operations.
- `domains/river`: the River vault, which compiles River's domain constants
  into the library.

`river-vault` refuses to compile while its author key is the placeholder, so
tests and development builds name the feature that allows it:

    cargo test --workspace --features river-vault/placeholder-key

`fuzz/` holds cargo-fuzz targets (nightly, outside the workspace).

`DESIGN-NOTES.md` records where the implementation had to choose between
readings of the design documents.
