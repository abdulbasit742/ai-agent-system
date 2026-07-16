# Security audit: receiver-acceptance checkpoint bundles

## Scope

Task 35 reuses the reviewed receiver bundle engine through a deterministic isolated source adapter. The original receiver bundle module is never imported into a mutable shared namespace and its globals remain unchanged.

## Threats addressed

- loose checkpoint or proof substitution during handoff;
- omission of the candidate-head inclusion proof;
- rollback to a stale candidate or previous checkpoint;
- mixing a consistency proof with unrelated checkpoints;
- path traversal, unsafe components, symlink entries, and non-regular files;
- checksum or manifest tampering;
- undeclared, missing, renamed, or extra bundle files;
- duplicate proof identities or selected acceptance entries;
- output overwrite and partial publication.

## Adapter boundary

`agent_audit_trust_receiver_acceptance_bundle.py` reads the packaged reviewed receiver bundle source and applies a fixed token map before compiling it into a private module namespace. The map replaces only:

- checkpoint and consistency imports;
- error classes and `AAB` rule IDs;
- manifest/file names and file roles;
- proof paths and bundle hash domain;
- user-facing acceptance terminology.

Loading fails closed if any expected source token is missing or any receiver-specific boundary token remains after adaptation. Regression tests confirm the original `ARB` namespace and manifest name are unchanged.

The repository scanner correctly reports the adapter's single local compilation call as `BAS013`. `.agent-system-policy.json` suppresses only that exact fingerprint and path, assigns ownership to `repository-security`, records the local-reviewed-source rationale, and expires on `2027-07-16`. Any source movement, evidence change, second dynamic-execution site, wildcard path, or expired policy becomes active again. External or caller-provided source is never compiled.

## Stable diagnostics

- `AAB001`: unsafe path, symlink, or non-regular filesystem object;
- `AAB002`: malformed, noncanonical, or unsupported schema;
- `AAB003`: bundle/checkpoint pin or bundle-ID mismatch;
- `AAB004`: checkpoint or inclusion-proof binding failure;
- `AAB005`: incomplete or inconsistent snapshot/transition composition;
- `AAB006`: non-descendant transition evidence;
- `AAB007`: duplicate selected evidence;
- `AAB008`: exact file/checksum boundary or metadata mismatch;
- `AAB009`: reserved compatibility boundary;
- `AAB010`: reviewed file, byte, or proof limit exceeded;
- `AAB011`: immutable output already exists or appeared during publication;
- `AAB012`: candidate-head proof missing or inconsistent.

## Publication safety

Creation validates all source evidence first, writes mode-restricted files into a same-parent staging directory, fsyncs file and directory data, independently verifies the staged bundle, and only then atomically renames it to the final path. Existing paths and symlinks are never overwritten.

## Trust boundary

The bundle is unsigned. SHA-256 IDs and exact external pins provide integrity and freshness only when the pins are retained independently. They do not authenticate the producer or authorize the contents.
