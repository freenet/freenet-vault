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

## Readings chosen where the documents are silent or ambiguous

Storage and formats:

- **Entry kind 0x00** is not assigned by protocol 7.1 (0x01, 0x02 defined,
  0x03 to 0xFF reserved). Read as malformed.
- **The partition index and `vault:succ` are build-private.** Builds exchange
  entries, never indexes (a different build is a different secret namespace),
  so their layouts are not frozen formats. Both carry a magic and a format
  byte so a build refuses bytes it did not write.
- **gc never deletes a referenced entry.** Protocol 4.2 writes `vault:gc`
  before the index. If that index write then fails, `vault:gc` names a copy
  the index still references; processing it as written would delete a live
  key. gc therefore removes only names under the partition's entry prefix
  that the current index does not reference.
- **A malformed index** is never read as NONE (protocol 3's rule for records,
  applied to the index): operations answer Refused(12).

Records and routing:

- **Section 3, "equal to the floor and byte-identical: retry"** answers
  step_result 2 (record accepted): the record is already held.
- **Clearing creation arming** is a second write, because `vault:succ` and the
  index are separate secrets. If it fails, the creation-time re-check (no
  non-withdrawn record above OWN_VERSION) still prevents creation, and a test
  covers that case.
- **Poke from any page** is processed for its record (records verify
  themselves); its flags are honoured only from the domain's own pages, and
  the status is redacted for other pages and for delegates (12.4).
- **Poke naming another partition** answers Refused(5).
- **SubmitRecord replies with HandoverStatus** for both domain records and
  caller records; `step_result` gives the outcome (2 accepted, 3 not newer,
  4 equivocation, 5 invalid). A SubmitRecord for a domain record while
  `vault:succ` is malformed answers Refused(7).

Caller marks:

- **Equal version, different record**: spec 5 says a caller is accepted when
  "its version is at least the stored caller mark". At an equal version the
  vault accepts only the byte-identical record and refuses a different one,
  as protocol 3 treats equivocation.
- **A stored caller withdrawal at version W** blocks every caller record up to
  and including W.
- **A mark that is lost, corrupt beyond parsing, or no longer verifies**
  imposes no floor and is rewritten by the next raise. The alternative,
  refusing the caller forever, would make one corrupted entry disable River's
  background signing. Accepted residual (team lead, 2026-11-23): storage
  corruption of a mark removes rollback protection for that caller until its
  next raise.

Operations:

- **Delete of an absent slot** answers Ok. Leaving a room is idempotent.
- **PublicKey of a publisher key** answers Unusable(1), like every other use.
  Delete of it is allowed.
- **Import over a corrupt slot**: "same key" compares with the flagged bytes.
  The original seed, if the corruption changed it, is a different key and
  needs `replace`.
- **Generate when the node's random source returns all zeros** (twice) answers
  Refused(12). No reason code fits better.
- **Export from a delegate** is refused (8) even if a domain lists it.
- **The consent prompt** keeps the pending request in the delegate context, not
  in secrets, so Export still works when storage is full (spec 11). It is
  bound to a random prompt id and the page's origin. Responses are `Allow`
  and `Deny`; anything else, including the node's empty answer on a timeout,
  is a denial (Refused(6)). An answer that matches no pending prompt fails the
  call.
- **Bytes from a page that are not a vault frame** answer Refused(5) (River has
  no domain decoder, protocol 12.1).
- **A reply to a delegate** is a `SendDelegateMessage` addressed to the caller.
  Its `sender` field carries the caller's key as a placeholder; the core
  overwrites it (freenet-core #6340).

## Cross tests against River

`crates/freenet-vault/src/ops_tests/river_cross.rs` runs each operation through
`process` and compares with river-core at 4d137e66 (a dev-dependency only).
River's X25519 shared secret is private to river-core, so KeyAgreement is
checked by decrypting River's own ciphertexts with `SHA-256(vault output)`:
the AES-GCM tag verifies only under the identical key. Derive and Sign are
compared byte for byte. Mutating the KeyAgreement clamp is not detectable,
because x25519-dalek clamps the scalar again itself; the clamp is kept to
match River's code line for line.

## River constants

- `RIVER_VAULT_AUTHOR_VK` is a placeholder (the public key of seed
  `[0x52; 32]`). The `release` feature of `river-vault` refuses to compile
  until it is replaced by the offline River vault author key.
- Native River needs no origin of its own: under freenet-core #6130 a native
  app with a user-approved grant connects with the same origin as River's
  page, `WebApp(<River container instance id>)`, so the container-id check
  accepts it. `extra_page_ids` stays empty.

## Pending alignment with revision 7 (after review)

- HandoverStatus and Poke still follow revision 6. Revision 7 drops attempt
  numbers (no attempt field), adds `receiving_from` and a "receiver at a
  higher build" problem bit, and reserves Poke bits 2 and 3.
- Export on a slot flagged corrupt must be allowed (revision 7), so the page
  can repair it. This build still answers Unusable(2).
