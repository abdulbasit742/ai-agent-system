# Repository Agent Guidance

- Keep the root control plane dependency-free, local-first, and dry-run-first.
- Never commit secrets, populated `.env` files, private data, generated reports, audit logs, segment archives, segment catalogs, catalog checkpoints, catalog inclusion proofs, or catalog consistency proofs.
- Do not copy, fetch, vendor, or include `Dicklesworthstone/destructive_command_guard`; its current license restricts OpenAI and related parties.
- Preserve licenses and reviewed commits in `integrations.lock.json`.
- Add stable rule IDs and regression tests for scanner or command-guard changes.
- Require explicit `--approve` for integration execution; publishing must never be the default.
- Execute the numbered 1-to-400 workflow in order. Preserve completed work and update `development-progress.json` after every verified step.
- The `core` scanner pack and rules `BAS000` through `BAS003` are mandatory and must never be configurable off.
- Baselines may match only exact scanner fingerprints, must omit finding evidence, and must fail closed when their integrity or control scope changes.
- Git change scopes must use read-only argument-array commands, resolved commit SHAs, merge-base semantics, NUL-delimited path parsing, and repository-bound path validation.
- Changed-scope baseline resolution must never classify unrelated baseline paths as resolved.
- Added-line gates must filter current findings with new-side ranges and baseline resolutions with old-side ranges; never reuse one coordinate system for both.
- Pure renames must remain silent in added-line mode unless content hunks exist. Added/copied files are full new-file scope and deleted files are full old-file resolution scope.
- GitHub Action values must enter through environment variables and validated argument arrays, never through shell interpolation.
- Action-controlled input paths must remain beneath `GITHUB_WORKSPACE`; generated report and SARIF paths must remain beneath `.agent-system/`, be distinct, and resist symlink escape.
- Stale generated reports must be deleted before execution only after the output boundary validates.
- Workflow annotations, job summaries, and generated SARIF must never contain scanner preview evidence.
- Recommended pull-request workflows must remain read-only and must not use `pull_request_target` for untrusted code.
- `agent_version.py` is the only package version source; do not duplicate a static version in `pyproject.toml`, validators, or CLI wrappers.
- The public wheel must remain runtime-dependency-free and contain only the reviewed fifteen-module allowlist.
- Tests, docs, action internals, integration locks, external repositories, environment files, baselines, reports, audit-log data, segment archives, segment catalogs, catalog checkpoints, catalog proofs, and catalog consistency proofs must never enter the wheel.
- Installed-wheel `doctor` and integration `run` commands must fail closed rather than silently vendoring or changing pinned integrations.
- Audit logs must use strict UTF-8 canonical JSON Lines, exact legacy/versioned schemas, UTC timestamps, printable events, object details, lowercase SHA-256 links, and versioned physical-line sequences.
- Every audit append must hold the sidecar advisory lock and verify the complete existing chain before deriving the next sequence and previous hash. Invalid chains must never be extended.
- Audited commands must preflight the selected log. Malformed JSON, duplicate keys, blank records, partial final writes, schema drift, non-canonical lines, hash breaks, and symlinks must fail closed with stable `AUDxxx` diagnostics.
- New audit events must pass typed admission before append. Reserved events require exact fields; generic events must use bounded safe JSON and lowercase hyphenated names.
- Audit paths, command arrays, and Git refs must be stored only as domain-separated SHA-256 references and counts/kinds, never alongside their raw values.
- Credential-bearing generic field names and credential-shaped free-form values must fail with `AUD023`; typed schema/canonicalization drift must fail with `AUD022`.
- Pre-schema audit records remain verifiable for append-only compatibility but must be reported as untyped. Consumers may require complete typed coverage with `AUD024` only after retaining a migration checkpoint.
- Audit rollback or replay protection requires externally retained record-count and head-hash pins. A self-consistent file alone does not prove freshness.
- Audit recovery must copy only the verified byte prefix to a new immutable atomic no-overwrite path, never mutate the source, and never treat external-pin or typed-coverage mismatch as safely recoverable.
- Audit rotation may seal only a non-empty, fully typed, completely verified active log while holding the same sidecar lock used by append operations.
- Segment archives must be new atomic directories containing exact `segment.jsonl` bytes and a strict canonical `manifest.json`; existing outputs and symlinks must fail closed with stable `AUSxxx` diagnostics.
- A segment manifest must bind its index, previous segment ID, byte count, record count, typed coverage, audit head, content SHA-256, event schema, and domain-separated segment ID.
- The archive directory must independently verify before the active log is atomically replaced. Failure ordering must preserve the original active bytes rather than truncate them.
- Every non-initial archived segment and the active log must begin with an exact typed continuity record for the immediately preceding segment. Never infer, sort, skip, repair, or merge segment history automatically.
- Complete segment-chain verification must begin at index one and should require an independently retained latest segment ID. Unsigned segment manifests are integrity commitments, not signer authentication.
- Audit segment catalogs must live in a dedicated archive root, auto-discover only regular immediate-child segment directories, and bind safe relative directory names plus manifest/data digests and audit metadata.
- Catalog verification must compare stored entries with independently discovered sealed evidence exactly; missing, renamed, replaced, reordered, extra, or forked segments must fail with stable `AUCxxx` diagnostics.
- Catalog synchronization must require the latest externally retained `catalog_id`, retain the current catalog as an exact prefix, append only right-descendant segments, and preserve bytes on stale pins, forks, or active-log mismatch.
- Catalog creation must be no-overwrite; synchronization must be lock-coordinated and same-directory atomic. A verified no-op sync must not rewrite bytes or change the catalog ID.
- Catalog IDs and predecessor links are unsigned integrity commitments. They do not authenticate the operator, and forks must never be repaired or merged automatically.
- Audit catalog checkpoints may be created only from a fully verified catalog bound to an externally retained `catalog_id`; stored catalog summaries alone are insufficient.
- Catalog checkpoint leaves and nodes must retain separate `0x00` and `0x01` SHA-256 domains and RFC 6962 largest-power-of-two splitting. Never duplicate odd leaves or silently change tree construction.
- Catalog proof verification must require an externally retained `checkpoint_id`, reconstruct the exact Merkle root, reject missing or extra sibling hashes, and optionally bind the proof entry to independently verified sealed segment bytes.
- Catalog checkpoint and proof outputs must be canonical, bounded, immutable, symlink-safe, and atomic no-overwrite files. Proof-only verification may omit the full catalog but never the pinned checkpoint identity.
- Catalog checkpoints and proofs are unsigned integrity commitments, not authenticated operator statements, signatures, witness consensus, or public transparency-log evidence.
- Catalog consistency-proof creation must verify both catalogs and checkpoints against exact external pins and accept only identical or exact segment-prefix right-descendant histories.
- Catalog consistency proofs must reconstruct both checkpoint roots from canonical maximal aligned power-of-two frontiers; a matching `consistency_id` alone is insufficient.
- Direct next-generation catalogs must retain the previous `catalog_id`. Multi-generation proofs establish append-only segment continuity but do not authenticate omitted intermediate catalog checkpoints.
- Rollback, fork, and non-increasing-generation requests must retain stable `AUK009`, `AUK010`, and `AUK011` denials and must not create proof files.
- Catalog consistency outputs must be canonical, bounded, immutable, symlink-safe, atomic no-overwrite files and must exclude audit records, source contents, credentials, and raw command/path data.
- Release bundles must use exact commit SHAs and `SOURCE_DATE_EPOCH`; never include wall-clock build time, runner identity, or mutable branch names.
- Release output directories must be new or empty. Never delete or overwrite existing release content.
- Release verification must check the exact file boundary, canonical manifest integrity, wheel metadata, evidence metadata, sizes, SHA-256 checksums, and byte-for-byte reproducibility.
- Each wheel must have a deterministic SPDX 2.3 JSON SBOM and an unsigned in-toto Statement v1 / SLSA provenance v1 evidence file.
- SBOMs must describe only the reviewed wheel modules, carry MIT package/file conclusions, and bind each module to SHA-1 and SHA-256 checksums.
- Provenance must bind the exact wheel digest, source commit, source epoch, package identity, module list, console commands, and zero-runtime-dependency boundary.
- Evidence verification must regenerate expected SBOM and provenance objects from the bundled wheel; matching manifest hashes alone are insufficient.
- Never describe unsigned provenance as signed, authenticated, transparency-logged, or non-repudiable.
- Release admission policies are consumer-owned inputs and must never be loaded from inside a release bundle.
- Admission must verify the complete bundle before applying policy and must distinguish policy denial (`1`) from malformed or unverifiable input (`2`).
- Admission reports must include the canonical policy SHA-256 and stable `ADMxxx` rules without source previews or environment secrets.
- Exact expected source commit and version are mandatory for admission; an expected release ID should be supplied when one reviewed manifest is known.
- Release-transition policies and trusted previous bundles are consumer-owned inputs; never choose a previous trust anchor automatically or load policy from either bundle.
- Transition gates must fully verify both bundles before comparison and must bind the previous release ID plus candidate commit/version before authorization.
- Numeric rollback, exact replay, same-version mutation, source epoch/commit reuse, module/command removal, dependency increase, and license drift must remain explicit `TRNxxx` controls.
- Transition reports may contain identities, hashes, filenames, commands, counts, and license IDs, but never source contents, scanner previews, credentials, or environment secrets.
- Release trust states are consumer-owned, canonical, hash-chained files and must never be embedded in release bundles or committed as generated repository source.
- Every trust-state verify or advance must require the latest externally retained `state_id`; an internally valid state without that pin is not rollback or fork protection.
- Trust-state mutation must verify both bundles, require the previous bundle to equal the current head, reject duplicate release IDs, and append only accepted transition IDs and policy hashes.
- Trust-state writes must remain symlink-safe, lock-coordinated, same-directory atomic replacements; denied or stale-pin operations must leave state bytes unchanged.
- Release checkpoints must bind the exact pinned state ID, head, entry count, and a domain-separated SHA-256 Merkle root over canonical trust entries.
- Checkpoint and inclusion-proof verification must require an externally retained checkpoint ID; self-consistent unsigned files alone are not freshness or signer authentication.
- Merkle leaves and nodes must retain separate `0x00` and `0x01` domains and RFC 6962 largest-power-of-two splitting; never duplicate odd leaves or silently change tree construction.
- Checkpoint and proof outputs must be immutable, symlink-safe, canonical, and atomic no-overwrite creations. Rehashed proof changes must still reconstruct the pinned root.
- Trust-state lineage gates must accept only identical or right-descendant histories and retain stable `CHK010` rollback and `CHK011` fork denials; never merge forks automatically.
- Compact consistency proofs must reconstruct both pinned checkpoint roots from canonical maximal aligned power-of-two ranges; a matching `consistency_id` alone is insufficient.
- Consistency-proof creation may accept only identical or right-descendant histories. Rollback and fork requests must retain stable `CNS010` and `CNS011` denials and must not create proof files.
- Previous and candidate checkpoint IDs must be externally pinned for consistency verification; proof files do not authenticate checkpoint producers.
- Consistency proof outputs must remain immutable, canonical, symlink-safe, atomic no-overwrite files and must exclude trust entries, source contents, credentials, and transition-policy details.
- Ordinary CI may build, verify, admit, compare, exercise temporary audit logs, typed-event gates, segment rotations, segment catalogs, catalog checkpoints, catalog inclusion and consistency proofs, trust states, release checkpoints, and release consistency proofs, and upload evidence decisions but must never publish a package, create a release, request OIDC credentials, use signing keys, or read registry secrets.

Verification:

```bash
python -m unittest discover -s tests -v
python -m compileall -q agent_audit.py agent_audit_events.py agent_audit_segments.py agent_audit_catalog.py agent_audit_checkpoint.py agent_audit_consistency.py agent_system.py agent_system_legacy.py agent_policy.py agent_config.py agent_baseline.py agent_git.py agent_changed_lines.py agent_cli.py agent_version.py tests scripts
python agent_system.py config .agent-system.example.json
python agent_system.py policy .agent-system-policy.example.json
python agent_system.py audit-events --format json
python agent_system.py --audit-log /tmp/agent-audit.jsonl baseline /tmp/agent-baseline.json --create --scan-path .
python agent_system.py --audit-log /tmp/agent-audit.jsonl scan . --new-only --baseline /tmp/agent-baseline.json --format json --fail-on high
python agent_system.py audit --path /tmp/agent-audit.jsonl --require-typed --format json
python agent_changed_lines.py . --changed-from HEAD --format json --audit-log /tmp/agent-line-audit.jsonl
python agent_system.py audit --path /tmp/agent-line-audit.jsonl --require-typed --format json
python -m unittest discover -s tests -p "test_agent_audit.py" -v
python -m unittest discover -s tests -p "test_audit_event_admission.py" -v
python -m unittest discover -s tests -p "test_audit_segments.py" -v
python -m unittest discover -s tests -p "test_audit_catalog.py" -v
python -m unittest discover -s tests -p "test_audit_catalog_checkpoint.py" -v
python -m unittest discover -s tests -p "test_audit_catalog_consistency.py" -v
python -m unittest discover -s tests -p "test_github_action.py" -v
python -m unittest discover -s tests -p "test_action_entrypoint.py" -v
python -m unittest discover -s tests -p "test_packaging.py" -v
python -m unittest discover -s tests -p "test_wheel_validator.py" -v
python -m unittest discover -s tests -p "test_release_bundle.py" -v
python -m unittest discover -s tests -p "test_supply_chain_evidence.py" -v
python -m unittest discover -s tests -p "test_release_admission.py" -v
python -m unittest discover -s tests -p "test_release_transition.py" -v
python -m unittest discover -s tests -p "test_release_trust.py" -v
python -m unittest discover -s tests -p "test_release_checkpoint.py" -v
python -m unittest discover -s tests -p "test_release_consistency.py" -v
python -m pip wheel . --no-deps --wheel-dir dist
python scripts/validate_wheel.py dist/*.whl
python scripts/release_bundle.py create --wheel dist/*.whl --output-dir release --source-commit "$(git rev-parse HEAD)" --source-date-epoch "$(git show -s --format=%ct HEAD)"
python scripts/release_bundle.py verify release
python scripts/release_admission.py evaluate release --policy .release-admission.example.json --expected-source-commit "$(git rev-parse HEAD)" --expected-version "0.1.0"
python scripts/release_transition.py policy .release-transition.example.json
python agent_system.py scan . --format json --fail-on high
```
