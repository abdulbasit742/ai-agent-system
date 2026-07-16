# Audit catalog consistency proofs

`agent_audit_consistency.py` creates compact append-only evidence between two canonical audit catalog checkpoints. The proof allows a consumer to verify that a candidate checkpoint retains every segment committed by a previously retained checkpoint without distributing either full catalog.

## What the proof establishes

A valid proof establishes all of the following:

- both checkpoint files are canonical and match externally retained checkpoint IDs;
- both checkpoint catalog IDs match externally retained catalog IDs;
- the previous catalog segment entries are an exact prefix of the candidate entries;
- canonical compact-range hashes reconstruct the previous Merkle root;
- appending the candidate frontier reconstructs the candidate Merkle root;
- candidate generation increases when the segment count increases;
- a direct next-generation candidate retains the previous catalog ID.

A proof with a generation gap greater than one establishes append-only segment continuity. It does not authenticate omitted intermediate catalog checkpoints or their predecessor links.

## Relations

The lineage gate returns one of these relations:

- `same`: checkpoint and catalog identities are identical;
- `right-descendant`: the candidate retains the previous entries as an exact prefix and adds segments;
- `rollback`: the candidate is an older exact prefix;
- `fork`: histories diverge or same-size catalogs carry different identities;
- `generation-regression`: the candidate adds segments without increasing catalog generation.

Only `same` and `right-descendant` can produce a consistency proof.

## Create a proof

Both catalogs must remain available with their listed sealed segment directories. Extra later segments in the same archive root are allowed for a retained historical catalog, but every segment listed by each catalog is independently verified.

```bash
basit-agent-catalog-consistency prove \
  retained/segments/catalog.json \
  retained-checkpoint.json \
  candidate/segments/catalog.json \
  candidate-checkpoint.json \
  catalog-consistency.json \
  --expected-previous-catalog-id "$RETAINED_CATALOG_ID" \
  --expected-previous-checkpoint-id "$RETAINED_CHECKPOINT_ID" \
  --expected-candidate-catalog-id "$CANDIDATE_CATALOG_ID" \
  --expected-candidate-checkpoint-id "$CANDIDATE_CHECKPOINT_ID" \
  --candidate-active candidate/active.jsonl \
  --format json
```

The output path must not already exist. The file is written as canonical JSON through an atomic no-overwrite operation.

## Verify without catalogs

After creation, verification requires only the proof, both checkpoint files, and the four retained identities:

```bash
agent-audit-catalog-consistency verify \
  catalog-consistency.json \
  retained-checkpoint.json \
  candidate-checkpoint.json \
  --expected-previous-catalog-id "$RETAINED_CATALOG_ID" \
  --expected-previous-checkpoint-id "$RETAINED_CHECKPOINT_ID" \
  --expected-candidate-catalog-id "$CANDIDATE_CATALOG_ID" \
  --expected-candidate-checkpoint-id "$CANDIDATE_CHECKPOINT_ID" \
  --format json
```

The verifier does not trust `consistency_id` alone. It validates the canonical compact-range layout and reconstructs both Merkle roots.

## Inspect lineage before creating evidence

```bash
basit-agent-catalog-consistency lineage \
  retained/segments/catalog.json \
  retained-checkpoint.json \
  candidate/segments/catalog.json \
  candidate-checkpoint.json \
  --expected-previous-catalog-id "$RETAINED_CATALOG_ID" \
  --expected-previous-checkpoint-id "$RETAINED_CHECKPOINT_ID" \
  --expected-candidate-catalog-id "$CANDIDATE_CATALOG_ID" \
  --expected-candidate-checkpoint-id "$CANDIDATE_CHECKPOINT_ID" \
  --format json
```

`lineage` does not create a proof file. It is useful for diagnosing rollback, fork, or generation failures.

## Compact frontier format

The proof contains:

- a complete reference to each checkpoint identity and catalog summary;
- `previous_frontier`, the canonical maximal aligned power-of-two cover of the retained prefix;
- `append_frontier`, the corresponding cover of only the appended candidate entries;
- relation and direct-predecessor status;
- a domain-separated `consistency_id`.

The number of frontier hashes grows logarithmically with catalog size. Full catalog entries, audit records, source contents, raw paths, and command arguments are not stored in the proof.

## Exit codes

- `0`: identical or valid right-descendant continuity;
- `1`: valid evidence was denied because of a stale pin, rollback, fork, generation regression, or checkpoint/catalog mismatch;
- `2`: malformed, unsafe, noncanonical, oversized, or cryptographically unverifiable input.

Stable relation rules are:

- `AUK009`: rollback;
- `AUK010`: fork or direct predecessor mismatch;
- `AUK011`: generation regression.

Other `AUK001` through `AUK008` rules cover paths, schemas, identifiers, checkpoint binding, compact layouts, root reconstruction, stale pins, and overwrite protection.

## Operational retention

Retain these values outside the archive being verified:

- previous catalog ID;
- previous checkpoint ID;
- candidate catalog ID;
- candidate checkpoint ID.

After accepting the candidate, promote its catalog and checkpoint IDs to the retained trust position. A self-consistent proof without external pins is not rollback protection.

## Trust boundary

Catalog consistency proofs are unsigned integrity commitments. They do not authenticate the operator, provide witness consensus, establish non-repudiation, or prove publication in a public transparency log.
