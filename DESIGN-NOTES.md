# Design notes

Where the implementation had to choose between readings of the design
documents (`freenet-vault-spec.html` revision 6 and
`freenet-vault-handover-protocol.html` revision 6, both 2026-11-23), or adds
something they do not yet say. Each entry names the choice and why. The
documents should be updated to match, or the code changed.

## Changes not yet in the documents

- **Batch carries `expected_public_key`** (approved 2026-11-23). Layout:
  `slot_len 1 ; slot ; expected_public_key 32 ; count 2 ; items`. The vault
  refuses the whole Batch when the slot's public key differs, with a new
  Refused reason **14, public key mismatch**. The documents name neither the
  field's position nor the refusal reason.

## Scope of this build

- The handover (copy, seal, take-over, retire; Chunk, Ack, Complete,
  CompleteAck, Abort, Retired, Query; attempt numbers; recovery and RetireTo)
  is not implemented. Its frame-type numbers are reserved in
  `freenet-vault-common::frame::types` and nothing else. A handover frame from
  a delegate is ignored, as protocol 6 says for frames a build does not
  handle. RetireTo (0x87) from a page answers Refused(10), which callers treat
  as "retry after the handover" (protocol 5.2).
- The partition index has an opaque `handover` field and the states SEALED,
  RECEIVING and RETIRED, so the operation path already answers as protocol
  5.1 says for those states. Nothing in this build enters them.

## River constants

- `RIVER_VAULT_AUTHOR_VK` is a placeholder (the public key of seed
  `[0x52; 32]`). The `release` feature of `river-vault` refuses to compile
  until it is replaced by the offline River vault author key.
- Native River's app grant (#6130) has no defined origin yet, so
  `extra_page_ids` is empty: native River cannot call this build.
