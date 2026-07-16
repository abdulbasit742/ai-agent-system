# Security audit: audit evidence bundle admission

Task 21 separates evidence verification from consumer authorization for portable audit bundles.

## Security objective

A self-consistent bundle is not automatically acceptable for every consumer. Admission must answer a second question: does this already verified bundle satisfy the consumer's exact operational policy?

The implementation therefore follows this order:

1. validate the consumer-owned policy
2. verify the complete bundle using externally retained identities
3. load the already verified canonical manifest
4. evaluate deterministic authorization rules
5. emit an admitted or denied decision

Policy rules never run against unverified bundle metadata.

## Consumer-owned policy boundary

The policy is supplied separately from the bundle. The CLI rejects a policy whose resolved path is inside the bundle directory with `AUA016`.

This prevents the producer from choosing the rules under which its own evidence is admitted.

Policy initialization is no-overwrite. Existing files and symlinks are rejected. Policy parsing uses strict UTF-8 JSON, duplicate-key rejection, non-finite-number rejection, exact schemas, strict types, sorted unique arrays, and reviewed numeric ranges.

## Identity boundary

Evaluation requires:

- exact expected bundle ID
- exact expected candidate checkpoint ID
- exact expected previous checkpoint ID for transitions

The underlying bundle verifier checks exact file boundaries, canonical manifest integrity, checksums, file metadata, inclusion proofs, optional consistency proof, and optional sealed segment bytes before admission starts.

A pin mismatch or unverifiable bundle is invalid input with exit status `2`, not a normal policy denial.

## Authorization controls

Stable rules cover:

- allowed snapshot/transition types
- maximum files and bytes
- minimum and maximum proof counts
- forbidden, optional, or required-all sealed evidence
- candidate generation bounds
- candidate total segment-count bounds
- exact candidate catalog allowlists
- required and allowed selected segment indexes
- required and allowed selected segment IDs
- allowed consistency relations
- direct-predecessor requirements
- generation-delta bounds
- exact previous catalog allowlists

Empty catalog, segment-index, or segment-ID allowlists mean no additional allowlist restriction. They do not remove mandatory external bundle and checkpoint pins.

## Determinism

Policies are normalized before hashing. `policy_sha256` is SHA-256 over canonical normalized JSON.

Violations are sorted by stable rule ID and canonical context. `decision_id` is domain-separated from other repository hashes and covers:

- admitted state
- policy hash
- bundle/checkpoint/catalog identities
- evidence counts and selected segment identities
- generation information
- complete sorted violations

Repeated evaluation of identical evidence, pins, and policy produces the same decision.

## Data minimization

Admission reports contain identities, hashes, counts, segment indexes, segment IDs, generations, and rule diagnostics.

They do not contain:

- audit JSON Lines records
- sealed segment contents
- raw filesystem paths from audited operations
- command arrays
- Git refs
- source files
- credentials
- environment variables
- policy secrets

The policy format contains no executable expressions, imports, shell fragments, or callbacks.

## Filesystem boundary

The admission engine reads the bundle through the existing exact-boundary verifier. Symlinks and non-regular evidence files are rejected there.

Policy files must be regular non-symlink files. New default policies use exclusive creation and flush their bytes before returning.

Admission does not mutate the bundle or policy. It emits the decision to stdout only; CI may redirect that report to a consumer-controlled path.

## Exit semantics

- `0`: verified and admitted
- `1`: verified but denied by policy
- `2`: malformed policy, unsafe path, missing external pin, or unverifiable evidence

This distinction is tested at the API and CLI layers.

## Unsigned boundary

The following are unsigned integrity values:

- bundle ID
- checkpoint IDs
- catalog IDs
- policy SHA-256
- decision ID

They do not authenticate a producer or consumer and do not provide non-repudiation, public transparency, witness consensus, or key ownership. Authentication may be layered externally without changing the canonical policy and decision formats.

## CI boundary

The admission workflows use `contents: read` only. They:

- run the 20 admission scenarios on Python 3.11 and 3.12
- build a real typed audit segment and portable bundle
- prove admission, policy denial, invalid tamper handling, and internal-policy rejection
- build and validate the dependency-free wheel
- install and exercise both admission aliases outside the source checkout
- upload only temporary decisions and diagnostics

They do not publish packages, create releases, request OIDC credentials, use signing keys, or read registry secrets.

## Residual risks

- An external pin can be lost or replaced outside this repository.
- An unsigned policy hash does not prove who selected the policy.
- Allowlist configuration can be too broad even when structurally valid.
- A consumer must retain decisions and pins according to its own retention and authentication requirements.
- Multi-generation catalog consistency proves append-only segment continuity but does not authenticate omitted intermediate checkpoints.

These limits are explicit and are not represented as stronger guarantees.
