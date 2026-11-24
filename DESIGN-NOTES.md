# Design notes

Where the implementation had to choose between readings of the design
documents (`freenet-vault-spec.html` and `freenet-vault-handover-protocol.html`,
revision 7, 2026-11-23), or adds something they do not yet say. Each entry
names the choice and why. The documents should be updated to match, or the
code changed.

## Decided 2026-11-23 by the design session, now in the spec

Taken after the first review round. All four are in the code and in the
protocol document (sections 9 and 11, added 2026-11-23).

- **Entry kind 0x00 is reserved.** Decoders treat it as malformed (protocol
  7.1 and section 11 say nothing about 0x00; 0x03 to 0xFF stay carried
  verbatim). The partition index applies the same rule.
- **KeyAgreement returns the raw X25519 output, zeros included**, for a
  low-order peer. It matches River's own code, so there is no new status.
  The spec should say so.
- **Each domain compiles in a minimum version per caller app**
  (`CallerDelegate::min_version`). A request whose record is below it is
  refused (Refused 2) whether or not a mark is stored, so a fresh vault, or
  one that lost its mark, still refuses a known-bad old caller. River uses
  the chat delegate's current pointer version at build time, 11 (river
  `pointer-records.toml` at 4d137e66); raise it when the vault is released.
- **Caller-mark rules go into spec 4.4.** A record at the mark's version is
  accepted only if byte-identical; a different record at that version is
  refused (spec 5 says "at least"). A stored caller withdrawal at version W
  blocks every caller record up to and including W. A mark that is lost,
  corrupt beyond parsing, or no longer verifies imposes no floor beyond
  `min_version`, and the next raise rewrites it. Storage corruption of a mark
  therefore removes rollback protection for that caller above `min_version`
  until its next raise (accepted residual, team lead, 2026-11-23).

## Layouts as revision 7 has them

- **Batch carries `expected_public_key`** (protocol 12.5): `slot_len 1 ; slot ;
  expected_public_key 32 ; count 2 ; items`. The vault refuses the whole Batch
  when the slot's public key differs, with Refused **14, public key mismatch**.
- **HandoverStatus follows revision 7**: `receiving_from` after `peer_record`,
  no attempt fields (body 196 bytes), problems bit 5 "receiver at a higher
  build". Poke flag bits 2 and 3 are reserved and have no names; Refused 13
  and the `RETIRE_TO` frame name are gone (0x87 is reserved).
- **Encoders enforce the decoders' bounds.** Every encoder returns an error
  where a decoder would refuse (slot 1..=64, app_id 1..=64, `after` at most 64,
  List max 1..=256, Batch 1..=256 items, Derive context 1..=256, data at most
  65,536, an extension at most 65,535, a request body at most 1 MiB), and a
  reply frame is limited to 65,536 bytes in total. Nothing truncates or
  panics. A reply that would break a bound is answered Refused(12).

## Scope of this build

- The handover (copy, seal, take-over, retire; Chunk, Ack, Complete,
  CompleteAck, Abort, Retired, Query) is not implemented. Its frame-type
  numbers are reserved in `freenet-vault-common::frame::types` and nothing
  else (protocol 12.3 has the layouts). A handover frame from a delegate is
  ignored, as protocol 6 says for frames a build does not handle. A handover
  frame, or the reserved 0x87 (RetireTo was removed in revision 7), from a page
  answers Refused(10), which callers treat as "retry after the handover"
  (protocol 5.2).
- The partition index has an opaque `handover` field and the states SEALED,
  RECEIVING and RETIRED, so the operation path already answers as protocol
  5.1 says for those states. Nothing in this build enters them.
- Not implemented here, so not tested: the handover frames, and the
  WASM entry point's `CtxHost`. CI compiles and lints `CtxHost` (wasm32
  build and clippy) but no test runs a WASM module; every behaviour is
  tested through `process` over the in-memory host.

## Readings chosen where the documents are silent or ambiguous

Storage and formats:

- **Entry kind 0x00** is not assigned by protocol 7.1 (0x01, 0x02 defined,
  0x03 to 0xFF reserved). Read as malformed.
- **The partition index and `vault:succ` are build-private.** Builds exchange
  entries, never indexes (a different build is a different secret namespace),
  so their layouts are not frozen formats. Both carry a magic and a format
  byte so a build refuses bytes it did not write. The index decoder enforces
  the frozen bounds (at most 4096 entries, kind not 0, key 1..=256, entry
  length at most 65,399).
- **One index copy, with a BLAKE3 checksum** (`vault:idx:<P>`), is the commit
  point (decided 2026-11-24; the backup copy was removed after four review
  rounds). Protocol revision 10.1 (the v1 read-only base) now states the
  index-loss rules; the code follows 4.5 as written. An absent `vault:parts` is
  a valid empty list. A valid index is never an index loss. An absent index is a
  loss while `vault:parts` lists the partition or is present but not a valid
  list. A malformed index is a loss only while `vault:parts` lists the partition
  or is not a valid list; with a valid list that does not name it the build is
  NONE for the partition, exactly as for an absent index. In a loss the call is
  read-only (no write, no gc, no creation, no arming), HandoverStatus reports
  problems bit 6 and `partition_state` 7, and the build keeps signing by direct
  read. Rev 10.1 G2 and G2b: with `vault:parts` malformed and the index absent
  or malformed, a build whose `vault:succ` holds a non-withdrawal record above
  OWN_VERSION answers every read and change Moved(that record) and never
  direct-reads (also at the consent answer of a pending Export). After a failed
  write the rest of the call is read-only (the `WriteLatch`).
  **Direct read** (4.5): a slot is served only when BOTH parity copies
  authenticate (present, parse exactly as an entry, expected kind, eflags 0, the
  requested key, content length 32 for a key and 100 for a caller mark) and are
  byte-identical, extension included. Anything else, including one copy, two
  different copies and no copy, answers storage failure for that slot; it never
  answers Absent and never reads `vault:gc`. Export by the same rule, behind
  consent every time. A slot that answers storage failure cannot be exported in
  v1. **ResetPartition was removed** (0x88 is reserved for Reindex in v1.1); no
  state offers a repair, and the index is never rebuilt in v1.
- **The host fault model (freenet-core #5857), and the defences it made
  unnecessary.** (Statements below about Reset, the orphan-slot probe and the
  "one distinct value" direct read are superseded by the revision 10.1 entries
  above and at the end of this section.) A secret read that fails with an I/O error POISONS THE CALL in
  core: every later `set_secret`, `remove_secret` and `create_delegate` in that
  call is refused and the call's result is discarded and retried. So in a call
  that completes, a `None` read means the secret really is absent, and a
  "transient miss that looks like absence" can never lead to a write, a removal
  or a reply. `MemHost` models exactly this (`read_fault` poisons the call;
  a write or removal fault reports failure and may or may not have landed;
  crashes at any write boundary). What the vault still defends against: a
  write or removal that reports failure and may have landed, bytes that are
  present but corrupt (checksums and digests), crashes between host calls, and
  restores or wipes of the store. Removed as moot: the "both gc list copies
  read as nothing while the index names entries means unreadable" test and the
  untrusted-list state (an absent list is absent); the drop-after-3-passes rule
  and the per-name uncertainty counter in the gc list (a name now leaves the
  list when its secret reads as absent after a removal attempt, whatever the
  removal reported, and stays for ever while it still reads); the stated
  residual that index and `vault:parts` both missing "looks like a new
  partition" as a transient (it is really absent); the tests that hid a secret
  from reads (they now wipe it, or poison the call). Kept: read-only mode for
  index bytes that are present but damaged, `vault:parts` that is present but
  malformed, and for the rest of a call after a failed write, which is now one
  latch for the whole call (`WriteLatch` around the host in `process`), not per
  store: a failed `set_secret` refuses every later write and removal however
  many stores the call opens (a failed removal does not latch; its name stays
  listed). gc list copies are written one after the other and the write stops
  at the first failure, so a torn write damages at most one copy.
  **Correction (freenet-core #6323, still open):** a blob that cannot be
  decrypted (corrupt bytes on disk) reads as ABSENT without poisoning the call,
  so "absent" can also mean corrupt. `MemHost::undecryptable` models it. The
  vault takes no destructive action on the absence of a secret that a sibling
  record says should exist: index absent while `vault:parts` lists the
  partition is read-only, not new (so an undecryptable index never leads to a
  fresh index); an entry or caller mark the index names but that reads absent
  is Missing (never dropped, a mark is served at the floor and not overwritten
  by an operation); absent gc lists remove nothing (the next write rebuilds
  them; names held only by corrupt lists are leaked, bounded by the 4096-name
  cap on the list, and a deleted key's bytes can outlive the delete in that
  case). Double-corruption residual: if the index AND `vault:parts` are both
  undecryptable at once the partition looks new, and a creation or ARM then
  writes a fresh index over it and orphans the keys. They stay on disk and
  Export by direct read finds each slot the UI asks for (pinned by a test).
  Fixing core #6323 (poison, or a distinct code) closes it. Direct read can also
  return a stale copy if the newer copy is undecryptable and the older one was
  never removed. Revision 8 (4.5): a build whose index is lost reports
  `partition_state` 7 (unknown: index lost) with problems bit 6, answers no
  handover frame (none are built) and ignores Poke flags (it cannot write); the
  courier never counts it as NONE.
  Round-5 findings against this model: moot (they need a present secret to read
  as absent in a completed call): blind arming over a transient miss (also the
  skeptical lens's S1: index and `vault:parts` both missing in a completed call
  means they are really absent, so the partition really is new), `vault:parts`
  rewritten after a miss, direct-read mode meeting a stale or uncommitted copy
  because the other copy read as absent, the empty-index exception and the
  3-pass forgetting in gc, both gc lists unreadable. Fixed: Reset clears both gc
  lists first and requires them to take; the failed-write latch is per call;
  both gc copies unparseable no longer blocks writes (the lists are rebuilt by the
  next write, and ResetPartition also rewrites both, so no state stays read-only
  without bit 6); a malformed `vault:parts`
  with no index can be reset; a Reset is refused when a newer build is known;
  both parity names are always listed for gc so a stale copy left at the other
  parity is collected. Stated residuals: direct-read mode has no content
  integrity check on an entry (an entry has no checksum; Batch is guarded by
  `expected_public_key`, Export by the UI's check); a deleted key whose copies
  could not be removed is served by direct read if the index is later lost; names
  whose removal keeps failing accumulate to 4096, after which writes that need a
  gc entry fail.
- **Round 6 (before the freeze).** (1) An entry with an unknown `eflags` bit is
  kept byte for byte and never served (Unusable); a direct read skips it. (2) A
  Batch item result is 64 or 32 bytes when OK and empty otherwise, enforced in
  both the encoder and the decoder; the A3 golden vector uses a legal payload.
  No valid result reaches the 65,536-byte reply bound, so its decoder-edge test
  uses an Export result with a long extension. (3) Poke bit 4 is reserved
  (revision 8 keeps a partial copy); its name is gone. (4) `Host::writes_refused`
  makes every `Store` opened after a failed write report read-only, so an
  authorised delegate is still served on the read-only path. (5) A malformed
  `vault:parts` with a verified index stays writable and is never overwritten
  except by Reset's repair; the spec's 4.5 trigger list should say "malformed
  `vault:parts` with the index absent". (6) A corrupt mark imposes no floor above
  `min_version` (spec 9); a mark whose secret is gone is written again by the
  first valid request above `min_version`, and a request at the minimum writes
  nothing. (7) With no index and no `vault:parts` listing, a request naming a slot
  whose entry is on disk takes the read-only path: PublicKey, Batch and Export read
  it directly, and Import, Generate of that slot and Delete are refused, so
  nothing is created over it. ARM itself cannot probe (it names no slot).
  (8) Under the agreed core #6323 rule a `set_secret` over an undecryptable blob
  is refused and `remove_secret` is always allowed; `MemHost` models it. Every
  rewrite of a secret that may be undecryptable removes it first
  (`replace_secret`: gc lists, `vault:parts`, entry candidates, `vault:succ`); Reset
  removes the gc lists, a damaged `vault:parts` and the index before writing them,
  and lists the partition before the index is replaced so a crash between the
  two leaves the index absent while listed, never new. (9) Reset re-checks the
  index loss and "no known newer build" at the consent ANSWER; the prompt says
  it also clears the pending cleanup list and every caller version mark. That no
  other lineage build is WRITER or SEALED is the courier's check (the library
  cannot see other builds). Spec 4.3: an absent entry the index names answers
  Missing and is not dropped, which the code already does.
- **Round 7.** Unknown `eflags` bits are rejected on every serving path,
  including an entry whose bytes parse but fail the index digest (it answers
  Unusable, is not flagged or rewritten, and Export cannot return it). Direct
  read checks disagreement BEFORE filtering flags: two different decodable
  copies are a storage failure whatever their flags. Presence is separate from
  choosing a value: if any parity copy of the requested slot decodes the slot is
  present, so with no index and no parts listing PublicKey answers storage
  failure (never NotHere) on ambiguity and nothing is created over it. Reset
  overwrites a READABLE malformed `vault:parts` in place; it removes a list
  first only when it reads as absent (possibly undecryptable), and then only
  while the damaged index still reads, so a crash leaves a damaged index and
  never a partition that looks new (a sweep checks every crash point).
- **Revision 10.1 alignment (supersedes the Reset, orphan-probe and
  one-distinct-value notes above).**
  *The mirror (4.2).* A change to a WRITER follows four steps: (1) for an
  identity the index does not name, remove both parity names and read them back
  as absent, refusing the change if one will not clear; (2) write the new value
  to the parity the index does not name; (3) commit the index, which the answer
  depends on; (4) write the same bytes to the other parity. A failed step 4 is
  not an error: the slot is served from the index and is unavailable to direct
  read until the sweep or the slot's next change. A 4.3 flag rewrite and the
  read-drop of an unparseable entry follow the same steps. A change never uses
  `vault:gc`. Receivers (index state RECEIVING) write single copies.
  *Delete (4.2).* List both parity names in `vault:gc`; remove the mirror and
  read it back as absent, refusing if it is still there; commit the index
  without the slot; gc removes the other copy. gc works by identity: a name whose
  identity the committed index names is never removed (it is dropped from the
  list).
  *Mirror sweep (7.7).* `Store::mirror_sweep` writes a missing or different
  mirror from the named copy after checking that copy against the index digest;
  it does not run while sealed, in read-only mode, or without a verified index.
  It runs on every Poke (the courier pokes on each load). The library keeps no
  progress, so nothing is ever marked finished and a call that fails marks
  nothing; the spec's "after start and after take-over" is the poke here.
  *Listing (4.2).* Only a WRITER or SEALED index is listed, and the commit that
  makes an index WRITER reads it back and lists the partition (and reads the
  listing back) before the change answers; if either fails the change answers
  Refused(12) and the call is read-only. An armed NONE index is never listed.
  The catch-all in `process` lists a valid WRITER or SEALED index first and
  answers nothing if that write or its read-back fails (G3). A malformed
  `vault:parts` is left untouched. `open` no longer lists anything.
  *Remove before write.* `replace_secret` is used for `vault:parts`, the gc
  lists, `vault:succ`, every entry name and the index of an unlisted partition;
  the index of a listed partition is never written while it reads as absent.
  `vault:x` and `vault:rx` belong to the handover and are not built.
  *Residuals, accepted for v1 (spec 4.4, 4.5):* I2-two-index-lost (the index and
  `vault:parts` both lost or undecryptable make the partition look NONE, and a
  creation or ARM can then write a fresh index; the keys stay on disk but a slot
  is served only if both its copies still pair, and a slot whose copies were not
  mirrored is unavailable); I7-retired-still-listed (a retired build that
  crashed between its RETIRED index write and unlisting stays listed; liveness
  only, handover); I7-sealed-predecessor-index-lost, label G4 (a SEALED, listed
  predecessor whose index is lost reports state 7 and never answers Query, so
  its successor stays awaiting retirement: reads work, changes are Busy on that
  node; one fault, in the v1.1 repair scope); the restore class (restores of an
  index with the entry it names, of `vault:succ`, or of one entry are
  consistent and undetectable); and an unavailable slot after a double fault (a
  slot whose last change or Delete had not finished, or whose mirror was not yet
  written, answers storage failure under index loss: an accepted availability
  loss, never a wrong key).

- **Round 9 (revision 10.2 alignment).** (1) A stopped domain (a withdrawal
  above `current`) neither arms nor creates, checked at arming and at creation
  whenever the arming happened; existing writers keep serving. (2) A creation
  commits an EMPTY WRITER index first, lists it and reads the listing back, and
  only then commits the first entry, so a refused listing never leaves a
  committed key; a creating change that answers Refused(12) therefore means the
  key does not exist. (3) A listing write that REPORTS failure makes the call
  answer nothing even if it landed (G3, the model's rule), on both the catch-all
  and the creating-change path. (4) Listing a WRITER or SEALED index overwrites a
  malformed `vault:parts` with a list naming the partition; other partitions'
  valid indexes are listed again by their own catch-all. A malformed
  `vault:parts` with the index absent or malformed keeps the G2/G2b handling.
  (5) In index loss Poke and SubmitRecord store no record, including the repair
  of a malformed `vault:succ` (spec 4.5: no writes, no record storage). (6) 4.3
  repair reads the mirror first: if the other parity parses and matches the
  index digest, the named copy is rewritten from it and served (nothing is
  rewritten while sealed or read-only); only then is a copy flagged or an
  identity dropped. (7) A named entry that reads as absent is not dropped and is
  reported as problems bit 1 by any call whose read or sweep sees it;
  `lost_entries` counts dropped entries only. (8) A Delete of an absent slot
  answers Absent (the page treats Absent as done); Import over a Missing named
  slot without `replace` is refused. (9) The write latch does not cover failed
  removals on purpose: a removal only touches a name whose identity the index
  does not name (gc, retried next call) or the mirror in a Delete, which is read
  back as absent before the commit. Notes for later: the sweep runs on every Poke
  without a bound (the handover step's scheduler must bound it); gc uses the
  in-memory index, which is correct within one call; direct read of caller marks
  is an extension the protocol model does not cover (marks are read by the same
  both-copies rule, kind 2, content length 100).
- **A secret that is gone is Missing, never corrupt.** When the index
  names an entry but `get_secret` returns nothing (a wipe or restore of that
  secret), the vault changes and
  deletes nothing, and answers storage failure (Refused 12). List shows the
  slot as corrupt with a zero key; Import without `replace` is refused, and
  with `replace` overwrites it; Delete works. Only bytes that are present and
  do not parse are dropped and counted. Residual: an entry whose secret is
  gone for good stays Missing until the page imports over it.
- **gc is durable and bounded.** Every entry copy is listed in the gc list
  before it is written, so a crash leaves a name the next call removes. The
  list is kept twice (`vault:gc`, `vault:gc2`, read as a union; a copy that does
  not parse contributes nothing) and written one copy at a time, stopping at
  the first failure. Names are added only when both copies take. A name leaves
  the list when its secret reads as absent after a removal attempt (a removal
  that reports failure may still have landed; reads are truthful in a completed
  call). The list holds at most 4096 names; when full, writes that need a gc
  entry fail with storage failure and no name is dropped to make room.
- **Stored successor records are verified on load.** `vault:succ` whose
  `current` or withdrawal no longer verifies under the domain key, is in the
  wrong role, or has `current` at or below OWN_VERSION is read as malformed:
  Poke reports `STORED_MALFORMED`, Moved is never returned with an invalid
  record, and record handling is refused (Refused 7). It is not permanent: a
  submitted or poked record that verifies and is newer than this build replaces
  it. Whatever the unreadable store held is lost, so the floor it carried is
  too (corruption already cost that knowledge).
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

- **Equal version, different record, withdrawals, lost marks**: decided; see
  "Decided 2026-11-23" above.
- **A mark whose secret is gone** (a wipe or restore of that secret) is served
  at the compiled-in `min_version` and is never overwritten by an operation.
  While it lasts, a caller below the stored mark but at or above `min_version`
  is served. A SubmitRecord of a caller record at or above `min_version`
  replaces it (it lowers the floor to that version), so a
  mark lost for good is not stuck for ever. Accepted residual: nothing else
  stores the lost mark's version (the index holds a digest, the gc list holds
  names), so the replacement cannot be required to reach the highest version
  seen before; a caller record between `min_version` and the lost mark's
  version is accepted until the next raise.
- **SubmitRecord from a delegate is held to its caller mark** exactly like an
  operation: a stale caller is refused (Refused 2), a newer one raises its
  mark (Busy while sealed or awaiting retirement, Refused 3 or 12 if the raise
  cannot be written), one needing no raise is served. A vault that is not
  serving (NONE, RECEIVING, RETIRED) has nowhere to keep a raised mark, so a
  delegate whose request would need a raise gets the same NotHere or Moved
  an operation gets; one needing none is served. Pages are not held to marks.

Operations:

- **Delete of an absent slot** answers Ok. Leaving a room is idempotent. On a
  partition that is NONE and unarmed it answers NotHere (the route runs first).
- **PublicKey of a publisher key** answers Unusable(1), like every other use.
  Delete of it is allowed.
- **A digest-valid entry this build cannot decode** (kind 0, a defined kind
  with the wrong content length, a newer format) is Corrupt without a parse: it
  is never dropped, rewritten or counted lost, and no operation can use it.
- **Export's lookup never changes storage**: an unparseable slot is not
  dropped when Export asks about it, so a user who answers Deny loses nothing.
- **Import over a corrupt slot**: "same key" compares with the flagged bytes.
  The original seed, if the corruption changed it, is a different key and
  needs `replace`. The repair path is Export (allowed on a corrupt slot whose
  bytes still parse as a 32-byte seed), compare the derived key with the
  expected identity, then Import the right seed with `replace`.
- **Generate when the node's random source returns all zeros** (twice) answers
  Refused(12). No reason code fits better.
- **Export from a delegate** is refused (8) even if a domain lists it.
- **The consent prompt** keeps the pending request in the delegate context, not
  in secrets, so Export still works when storage is full (spec 11). The answer
  reads the slot again: what is there when the user answers is what is
  exported (Absent if it was deleted, the new key if replaced, the flagged
  bytes' seed if it went corrupt; a slot that no longer parses is Unusable 2).
  It is bound to a random prompt id and the page's origin. Responses are `Allow`
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
  `[0x52; 32]`). `river-vault` refuses to compile in every profile while the
  key is the placeholder, unless the `placeholder-key` feature is named: the
  guard is a const assertion on the key's value, so replacing the key with the
  offline River vault author key lifts it with no other change. (The first
  version of the guard sat behind a `release` feature, so a plain release
  build shipped a key anyone can sign with.) Tests, clippy and development
  builds pass `--features river-vault/placeholder-key`; CI builds the default
  profile and fails if it succeeds (the `placeholder-guard` job).
- Native River needs no origin of its own: under freenet-core #6130 a native
  app with a user-approved grant connects with the same origin as River's
  page, `WebApp(<River container instance id>)`, so the container-id check
  accepts it. `extra_page_ids` stays empty.
