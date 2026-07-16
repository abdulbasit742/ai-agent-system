# Security audit: audit bundle trust checkpoints

## Reviewed objective

Task 23 adds portable integrity evidence for consumer-owned audit bundle trust states. It does not add a server, key store, signer, network lookup, or publication service.

## Evidence construction

- The complete trust state is strictly validated before checkpoint or proof creation.
- Every checkpoint is bound to an externally supplied `state_id`.
- Merkle leaves commit the complete canonical trust entry, including bundle, checkpoint, catalog, generation, segment count, Merkle root, admission decision, policy hash, and transition predecessor evidence.
- Leaf and internal-node domains are separated with RFC 6962-compatible `0x00` and `0x01` prefixes.
- Largest-power-of-two splitting is deterministic and odd leaves are not duplicated.
- Checkpoint and proof identifiers use separate domain strings.

## Verification order

1. Reject unsafe, symlinked, oversized, non-regular, non-UTF-8, duplicate-key, or noncanonical files.
2. Validate exact schemas and scalar types.
3. Recompute entry hashes inherited from the trust-state format.
4. Reconstruct the Merkle root from the authenticated entry and complete audit path.
5. Bind the proof reference to the supplied checkpoint.
6. Compare the checkpoint with the externally retained checkpoint ID.
7. When `--bundle` is supplied, fully verify that portable bundle using identities authenticated by the proof and compare all trust evidence.

A matching `proof_id` or `checkpoint_id` alone is never sufficient when the corresponding external pin or Merkle reconstruction fails.

## Rollback and fork handling

Lineage comparison requires externally retained IDs for both complete states. Only identical and exact right-descendant histories are accepted. A shorter candidate is `ATC010`; divergent histories are `ATC011`. The implementation never selects a branch, repairs a history, or merges a fork.

## Filesystem boundary

- Inputs must be regular non-symlink files.
- Missing output parents are created only beneath a verified regular ancestor.
- Checkpoint and proof outputs are mode `0600`.
- Outputs use same-directory temporary files, flush, `fsync`, hard-link no-overwrite publication, and parent-directory `fsync`.
- Existing outputs and symlink paths fail closed.

## Data minimization

Trust entries contain hashes, counts, generations, fixed type markers, and admission identifiers. They do not contain audit records, source contents, raw commands, raw paths, credentials, environment values, or policy bodies. Optional bundle verification reads portable evidence but does not copy it into the proof.

## Limits

- checkpoint file: 1 MB
- proof file: 2 MB
- proof audit path: at most 64 hashes
- trust-state limits remain 5 MB and 10,000 entries

## Explicit non-goals

These checkpoints and proofs are unsigned. They do not provide:

- signer authentication
- witness consensus
- public transparency-log publication
- trusted timestamps
- non-repudiation
- automatic fork resolution

Freshness depends on consumer-retained `state_id` and `checkpoint_id` values. A self-consistent file without those pins is not rollback protection.
