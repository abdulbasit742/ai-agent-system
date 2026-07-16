# Security audit: compact release consistency proofs

## Scope

This review covers `scripts/release_consistency.py`, its generated proof format, CLI exit semantics, immutable output handling, and the read-only GitHub Actions workflow.

## Trust assumptions

The consumer independently retains:

- the previous checkpoint ID
- the candidate checkpoint ID
- both checkpoint files, or trustworthy copies of them

Proof generation additionally requires both complete trust states and their externally retained state IDs. Verification does not require either trust-state file.

## Controls

### Complete upstream validation

Before proof creation:

1. both trust states are loaded through canonical trust-state validation;
2. both checkpoints are loaded through canonical checkpoint validation;
3. each checkpoint is regenerated from and compared with its trust state;
4. full-history lineage establishes `same`, descendant, rollback, or fork.

### Compact-range schema

Every frontier segment contains exactly:

- `start`
- `size`
- `hash`

The verifier enforces a canonical maximal aligned power-of-two cover. It rejects gaps, overlaps, duplicate coverage, reordering, non-power-of-two sizes, bad alignment, extra segments, and excessive segment counts.

### Independent root reconstruction

The verifier does not trust `consistency_id` or frontier hashes by themselves. It reconstructs:

- the previous Merkle root from the previous frontier;
- the candidate Merkle root after binary-carry merging the append frontier.

Both reconstructed roots must match their pinned checkpoint references.

### Domain separation

The implementation reuses the checkpoint tree's reviewed domains:

- leaf: `0x00`
- node: `0x01`

Changing domains or tree construction would invalidate existing checkpoint roots and is prohibited without an explicit version transition.

### Immutable outputs

Proof files use the checkpoint module's atomic no-overwrite writer. Existing files and symlinks are rejected without changing their bytes or targets.

### Pinned identities

Creation requires exact previous/candidate state IDs and checkpoint IDs. Verification requires both checkpoint IDs. Self-consistent evidence without these external pins is rejected as insufficient.

## Denial and error semantics

- `0`: identical or append-only consistency was proven or verified
- `1`: valid evidence indicates rollback (`CNS010`) or fork (`CNS011`)
- `2`: malformed, stale, unsafe, non-canonical, or unverifiable input

A denied proof operation does not create an output file.

## Data minimization

Proofs contain only checkpoint references and subtree hashes. They exclude:

- trust entries
- release source contents
- transition IDs and policy details
- bundle files
- credentials
- environment secrets

## Attacks tested

Regression coverage includes:

- modified previous frontier with recalculated proof ID
- modified append frontier with recalculated proof ID
- non-canonical range layout with recalculated proof ID
- same-size different-checkpoint claims
- wrong state and checkpoint pins
- non-canonical JSON
- overwrite and symlink targets
- rollback and fork proof requests
- proof verification against another checkpoint
- compactness across uneven and larger histories

## CI boundary

The workflow uses `contents: read`, creates only temporary synthetic trust states and proof evidence, and uploads read-only artifacts. It does not publish packages, create releases, request OIDC credentials, use signing keys, or read registry secrets.

## Residual risks

SHA-256 collision or second-preimage resistance is assumed. A compact proof is not a digital signature and does not establish the identity of a checkpoint producer. Compromise of the consumer's independently retained checkpoint IDs can defeat freshness and origin expectations.
