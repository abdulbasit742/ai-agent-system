# Security audit: audit trust receiver state

## Security properties

- The state and policy must be consumer-owned and outside the handoff directory.
- Creation accepts only a fully verified and admitted snapshot handoff.
- Advancement accepts only a fully verified and admitted transition whose retained checkpoint, retained trust-state ID, and retained entry count equal the receiver head.
- Every entry and the complete state use domain-separated SHA-256 identifiers.
- Externally retained `state_id` values detect stale or rolled-back receiver files.
- Handoff, checkpoint, and candidate trust-state identities cannot repeat.
- Trust entry count and generation must increase; segment count cannot decrease.
- Advisory locking, symlink rejection, mode-0600 temporary files, fsync, and atomic replacement protect updates.
- Denied and invalid operations leave the original bytes unchanged.

## Diagnostics

`ATR001` covers unsafe files and outputs; `ATR002` schema, canonicalization, and hash failures; `ATR003` external pin failures; `ATR004` policy denial; `ATR005` wrong snapshot/transition role; `ATR006` receiver-head mismatch; `ATR007` replayed identity; `ATR008` non-advancing history; `ATR009` consumer-ownership boundary; and `ATR010` lock or I/O failure.

## Trust boundary

The receiver state is unsigned. It proves local append-only acceptance relative to consumer-retained state IDs and verified handoff evidence. It does not claim signer identity, trusted time, witness quorum, or global log consensus.
