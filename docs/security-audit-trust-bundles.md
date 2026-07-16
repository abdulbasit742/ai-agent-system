# Security audit: portable audit trust handoff bundles

## Security objective

Task 25 prevents loose-file mix-and-match during offline audit-trust transfer. One domain-separated bundle ID commits the candidate checkpoint, optional previous checkpoint, transition consistency reference, selected inclusion-proof identities, exact file roles, digests, and sizes.

## Creation preconditions

Creation fails before publishing output unless:

- every checkpoint is canonical and matches its externally retained checkpoint ID;
- every inclusion proof reconstructs the candidate checkpoint root;
- exactly one proof authenticates the candidate checkpoint head;
- transition inputs are supplied as a complete previous-checkpoint/pin/consistency set;
- transition consistency is `right-descendant` and binds the exact previous and candidate checkpoints;
- proof sequences, bundle IDs, proof IDs, and canonical paths are unique;
- the destination does not already exist and neither it nor its evidence inputs are symlinks.

Evidence is assembled in a mode-0700 staging directory, independently verified, fsynced, and renamed only after verification succeeds.

## Verification controls

Verification requires an externally retained handoff bundle ID and candidate checkpoint ID. Transition verification additionally requires the previous checkpoint ID. It rejects:

- missing, extra, renamed, duplicate, symlinked, or non-regular files;
- checksum-boundary, digest, size, manifest, or bundle-ID drift;
- checkpoint substitution or stale pins;
- inclusion proofs that reference another checkpoint;
- missing or duplicated candidate-head proofs;
- same/rollback/fork evidence presented as a transition;
- consistency proofs that do not bind both manifest checkpoints;
- non-canonical JSON and unsafe relative paths.

## Data minimization

Handoffs contain checkpoint summaries, compact proofs, selected trust entries already present in inclusion proofs, hashes, counts, generations, stable roles, and diagnostics. They do not contain audit records, source files, raw paths, commands, environment values, credentials, admission policy bodies, signing keys, or complete trust-state histories.

## Stable diagnostics

- `ATB001`: unsafe path, symlink, or non-regular filesystem input;
- `ATB002`: schema, type, ordering, or canonicalization failure;
- `ATB003`: bundle/checkpoint external pin or bundle-ID failure;
- `ATB004`: checkpoint or inclusion-proof binding failure;
- `ATB005`: transition composition or consistency-reference failure;
- `ATB006`: non-descendant transition relation;
- `ATB007`: duplicate evidence identity;
- `ATB008`: file or checksum boundary mismatch;
- `ATB009`: reserved for incompatible selected-entry composition;
- `ATB010`: reviewed count or byte limit exceeded;
- `ATB011`: output overwrite or publication race;
- `ATB012`: missing or inconsistent candidate-head proof.

## Explicit non-goals

These bundles remain unsigned. They provide integrity and portability, not signer authentication, authorization, trusted timestamps, public transparency publication, witness consensus, or non-repudiation. Freshness still depends on externally retained bundle and checkpoint IDs.
