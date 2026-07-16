# Security audit: receiver acceptance consistency proofs

## Scope

Task 34 adds portable compact append-only proofs between pinned receiver-acceptance checkpoints. The implementation loads the reviewed receiver-consistency adapter in a private module namespace and binds its nested compact-range engine directly to acceptance-state schemas, acceptance-checkpoint validation, acceptance hash domains, and `ASR` diagnostics. The public receiver-consistency module is not mutated.

## Integrity properties

- Both complete states and both checkpoints are fully validated before proof creation.
- Checkpoints must equal the canonical checkpoints regenerated from their states.
- The previous and append frontiers use one deterministic aligned power-of-two layout.
- Verification independently reconstructs the retained and candidate Merkle roots.
- The consistency identifier is domain-separated from catalog, trust, receiver, and acceptance-checkpoint identifiers.
- Strict canonical JSON rejects duplicate keys, non-finite numbers, alternate encodings, and reserialized payloads.
- External checkpoint pins prevent silent checkpoint substitution and stale-evidence acceptance.

## Transition-boundary checks

A descendant proof exposes the first appended acceptance entry. Verification requires exact sequence, transition kind, previous entry hash, previous receiver checkpoint/state identifiers, receiver entry delta, underlying trust entry delta, and generation delta. The first append-frontier segment must be the canonical leaf hash of that entry. Candidate heads must advance receiver and trust entry counts and generation, and may not reduce segment count.

These checks prevent a prover from presenting valid Merkle roots while omitting, replacing, or weakening the semantic transition at the retained boundary.

## Filesystem boundary

Proof output uses the reviewed immutable writer:

- existing paths and symlinks are rejected;
- temporary bytes are written in the destination directory;
- files use mode `0600`;
- file and directory data are fsynced;
- publication uses a no-overwrite hard-link operation;
- rollback/fork denials produce no artifact.

## Diagnostics

- `ASR001`: unsafe path or unavailable reviewed engine.
- `ASR002`: malformed schema, strict JSON, canonicalization, or unsupported version.
- `ASR003`: stale or malformed external pin.
- `ASR004`: state/checkpoint/proof reference mismatch.
- `ASR005`: invalid compact-range layout.
- `ASR006`: reconstructed root mismatch.
- `ASR007`: consistency identifier mismatch.
- `ASR008`: immutable output violation.
- `ASR009`: rollback.
- `ASR010`: fork or same-size checkpoint substitution.
- `ASR011`: invalid authenticated acceptance-transition boundary.

Exit `0` is success, exit `1` is a verified continuity denial, and exit `2` is malformed, unsafe, stale-pinned, or unverifiable input.

## Trust boundary

The evidence is unsigned. Hashes prove integrity and append-only relationship only. They do not authenticate the producer, establish wall-clock freshness, or replace consumer-owned checkpoint retention and signing policy.