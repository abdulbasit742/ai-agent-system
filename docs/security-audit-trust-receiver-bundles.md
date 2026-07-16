# Security audit: audit trust receiver checkpoint bundles

## Security objective

A consumer must be able to transfer one pinned receiver checkpoint generation, selected accepted-handoff proofs, and optional append-only transition evidence without allowing loose-file substitution, path traversal, rollback, or silent omission of the candidate head.

## Verified controls

- Creation verifies all checkpoints, inclusion proofs, and consistency evidence before copying bytes.
- Every inclusion proof is bound to the candidate checkpoint.
- Exactly one selected proof must authenticate the candidate receiver head.
- Transition bundles require all three retained inputs: previous checkpoint, its external pin, and a right-descendant consistency proof.
- The consistency proof must bind the exact retained and candidate checkpoint IDs.
- The manifest has an exact reviewed schema, canonical ordering, bounded counts/sizes, and a domain-separated bundle ID.
- `SHA256SUMS` and manifest file records independently bind every evidence file.
- Verification requires external bundle and candidate-checkpoint pins; transition verification also requires the retained-checkpoint pin.
- The directory walker rejects symlinks, nonregular files, unsafe names, traversal components, missing files, and extra files.
- Staging uses restrictive modes, file and directory fsync, independent verification, and no-overwrite publication.
- Complete receiver states and original loose evidence are unnecessary after publication.

## Threat analysis

### Checkpoint or proof substitution

A substituted checkpoint changes its externally pinned ID or manifest reference. A substituted inclusion proof fails checkpoint binding. A substituted consistency proof fails both checkpoint references or the right-descendant relation.

### Omitted candidate head

Historical proofs alone are insufficient for a current handoff. Creation and manifest validation require exactly one proof whose sequence equals the candidate checkpoint entry count.

### Filesystem attacks

Output and bundle roots must be regular non-symlink directories. Internal symlinks, nonregular objects, unsafe relative paths, duplicate paths, and files not declared by the manifest are rejected.

### Rehashed manifest attack

Changing file records or selected entries changes the domain-separated bundle ID. A caller retaining the prior bundle ID rejects the replacement even if an attacker recomputes local checksums.

### Rollback and fork

Transition creation accepts only a receiver consistency proof that verifies as `right-descendant` between the exact retained and candidate checkpoints. Independent external checkpoint pins prevent replacement with another internally consistent history.

## Residual trust boundary

The bundle is unsigned. Hashes prove integrity, selection, and checkpoint relationship, not producer identity or wall-clock freshness. Consumers must retain and authenticate bundle/checkpoint IDs independently. Host compromise before evidence creation, compromised trusted software, and denial of service remain outside this control.

## Diagnostics

`ARB001`–`ARB012` provide stable machine-readable failures. Exit `1` represents valid but denied pinned evidence; exit `2` represents malformed, unsafe, or unverifiable input.
