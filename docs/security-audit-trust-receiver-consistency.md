# Security audit: audit trust receiver consistency proofs

## Scope

This audit covers `agent_audit_trust_receiver_consistency.py`, its source and installed-package workflows, and the proof artifacts it creates. The module provides compact append-only verification between pinned receiver checkpoints. It does not sign evidence, publish artifacts, manage keys, or modify receiver states.

## Reused compact-range core

The implementation loads the reviewed audit-trust compact-range engine into a private module namespace and then binds receiver-specific state/checkpoint validators, Merkle functions, errors, hash domains, lineage, and boundary validation. The public `agent_audit_trust_consistency` module is not mutated. Regression coverage explicitly checks namespace isolation.

This reduces duplicate Merkle code while preserving domain separation:

- proof ID domain: `audit-trust-receiver-consistency-proof-v1`;
- denial decision domain: `audit-trust-receiver-consistency-decision-v1`;
- diagnostics: `ARR001`–`ARR011`.

## Verified inputs

Proof creation requires:

- a canonical retained receiver state and external `state_id` pin;
- its exact canonical receiver checkpoint and external checkpoint pin;
- a canonical candidate receiver state and external `state_id` pin;
- its exact canonical receiver checkpoint and external checkpoint pin.

Both checkpoints are regenerated from their complete states before proof material is emitted. Rollback and fork relations are denied before output publication.

Proof verification requires strict canonical proof JSON and two externally pinned canonical checkpoints. Complete states are not required.

## Merkle integrity

Receiver entries use RFC 6962-style leaves `SHA-256(0x00 || canonical-entry)` and internal nodes `SHA-256(0x01 || left || right)`. The retained prefix and appended suffix use canonical aligned power-of-two covers. Layout changes, missing or extra segments, nonalignment, reordering, or rehashed subtree changes are rejected.

The verifier reconstructs both checkpoint roots and compares them with the exact checkpoint references committed by the proof.

## Receiver transition binding

The first appended leaf is exposed and parsed as a complete receiver entry. The verifier requires:

- transition kind and exact next receiver sequence;
- previous receiver entry hash equals the retained head;
- previous trust checkpoint ID equals the retained head checkpoint;
- previous trust state ID equals the retained head state;
- trust-entry-count delta is positive and exact;
- generation delta is positive and exact;
- candidate head entry count and generation advance;
- candidate segment count does not decrease;
- the boundary entry leaf equals the first append-frontier hash.

This receiver-specific binding prevents an attacker from supplying a Merkle-consistent append whose predecessor trust evidence does not match the consumer's retained receiver head.

## Filesystem controls

Proof creation:

- rejects existing or symlink outputs;
- verifies the nearest existing output parent is a regular directory;
- creates missing directories only under that verified parent;
- writes a mode-`0600` same-directory temporary file;
- flushes and fsyncs file contents;
- publishes with a no-overwrite hard link;
- fsyncs the containing directory;
- removes the temporary file.

Denied rollback/fork operations and invalid inputs do not create proof files.

## Failure semantics

- `ARR001`: unsafe path or non-regular proof input/output;
- `ARR002`: malformed, noncanonical, unsupported, or out-of-bound evidence;
- `ARR003`: stale or malformed external pin;
- `ARR004`: state/checkpoint or proof/checkpoint mismatch;
- `ARR005`: invalid compact-range layout;
- `ARR006`: reconstructed Merkle root mismatch;
- `ARR007`: consistency ID mismatch;
- `ARR008`: immutable output violation;
- `ARR009`: rollback;
- `ARR010`: fork or same-size checkpoint substitution;
- `ARR011`: invalid first-transition receiver boundary.

CLI exit `1` represents valid evidence denied by freshness or lineage policy. Exit `2` represents malformed, unsafe, or unverifiable input.

## Residual trust assumptions

The artifacts are unsigned. A consumer must retain checkpoint IDs independently and obtain checkpoints from an authenticated channel. A proof establishes integrity and append-only relationship only for the committed receiver entries; it does not establish who produced the states or whether the original handoff admission policy was appropriate.
