# Audit evidence bundle admission

Portable audit evidence bundles prove integrity. Admission adds a separate consumer-owned authorization decision.

The evaluator always verifies the complete bundle first. Policy rules are applied only after exact file-boundary, checksum, checkpoint, proof, optional consistency, optional sealed-segment, and external-pin verification succeeds.

## Commands

Create the default policy without overwriting an existing path:

```bash
basit-agent-audit-admission init audit-admission.json
```

Validate a policy and display its canonical SHA-256:

```bash
agent-audit-admission validate audit-admission.json --format json
```

Evaluate a snapshot bundle:

```bash
basit-agent-audit-admission evaluate audit-handoff \
  --policy audit-admission.json \
  --expected-bundle-id "$BUNDLE_ID" \
  --expected-candidate-checkpoint-id "$CHECKPOINT_ID" \
  --format json
```

Evaluate a transition bundle:

```bash
basit-agent-audit-admission evaluate transition-handoff \
  --policy audit-admission.json \
  --expected-bundle-id "$BUNDLE_ID" \
  --expected-candidate-checkpoint-id "$CANDIDATE_CHECKPOINT_ID" \
  --expected-previous-checkpoint-id "$PREVIOUS_CHECKPOINT_ID" \
  --format json
```

## Policy schema

The version-1 policy contains five exact top-level fields:

- `version`
- `bundle`
- `candidate`
- `selection`
- `transition`

Unknown or missing fields fail closed.

### Bundle controls

`bundle.allowed_types` permits `snapshot`, `transition`, or both.

`bundle.max_files` and `bundle.max_bytes` bound the verified bundle report.

`bundle.min_proofs` and `bundle.max_proofs` constrain selected inclusion proofs.

`bundle.sealed_segments` accepts one of:

- `forbidden`: no selected segment may include sealed bytes
- `optional`: sealed bytes may be absent or present
- `required-all`: every selected proof must carry its sealed segment directory

### Candidate controls

The candidate checkpoint may be constrained by:

- minimum and maximum catalog generation
- minimum and maximum total segment count
- an optional exact catalog-ID allowlist

An empty catalog allowlist means no additional catalog-ID restriction. Exact external checkpoint and bundle pins are still mandatory.

### Segment-selection controls

Policies may require or allowlist exact segment indexes and exact segment IDs.

Empty allowed arrays mean unrestricted selection. When an allowed array is non-empty, every selected item must appear in it. Required items must also be included in the corresponding allowed array when that allowlist is non-empty.

### Transition controls

For transition bundles, policies may constrain:

- allowed consistency relations: `same` or `right-descendant`
- whether direct predecessor verification is mandatory
- minimum and maximum candidate-generation delta
- an optional exact previous-catalog-ID allowlist

Transition controls do not turn a snapshot into a transition. Bundle type is decided by the verified bundle manifest.

## Decision report

A successful evaluation emits:

- `admitted`
- canonical `policy_sha256`
- deterministic `decision_id`
- pinned bundle/checkpoint/catalog identities
- file, byte, proof, and sealed-segment counts
- selected segment indexes and IDs
- candidate generation and total segment count
- transition generation delta when applicable
- stable sorted violations

The report omits audit record contents, raw paths, command arrays, credentials, source files, and policy secrets.

## Exit codes

- `0`: the fully verified bundle is admitted
- `1`: the fully verified bundle is denied by policy
- `2`: policy, arguments, external pins, paths, or bundle evidence are malformed or unverifiable

This separation prevents invalid evidence from being mistaken for an ordinary policy denial.

## External trust requirements

The policy must be supplied by the consumer and must remain outside the bundle directory. Loading a policy from inside the evidence being evaluated fails with `AUA016`.

Retain the expected bundle ID and candidate checkpoint ID independently. Retain the previous checkpoint ID as well for transition bundles.

The policy hash and decision ID are integrity commitments. They are not signatures, authenticated operator identities, witness consensus, transparency-log publication, or non-repudiation.

## Stable policy rules

- `AUA001`: bundle type
- `AUA002`: file or byte limits
- `AUA003`: proof-count limits
- `AUA004`: sealed-segment mode
- `AUA005`: candidate generation
- `AUA006`: candidate total segment count
- `AUA007`: candidate catalog allowlist
- `AUA008`: missing required segment indexes
- `AUA009`: selected indexes outside allowlist
- `AUA010`: missing required segment IDs
- `AUA011`: selected IDs outside allowlist
- `AUA012`: transition relation
- `AUA013`: direct predecessor requirement
- `AUA014`: transition generation delta
- `AUA015`: previous catalog allowlist
- `AUA016`: policy loaded from inside bundle

Malformed policy or unverifiable bundle input uses the invalid-input `AUA000` boundary and exits with status `2`.
