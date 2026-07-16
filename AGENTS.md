# Repository Agent Guidance

- Keep the root control plane dependency-free, local-first, and dry-run-first.
- Never commit secrets, populated `.env` files, private data, generated reports, or audit logs.
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
- The public wheel must remain runtime-dependency-free and contain only the reviewed eight-module allowlist.
- Tests, docs, action internals, integration locks, external repositories, environment files, baselines, reports, and audit logs must never enter the wheel.
- Installed-wheel `doctor` and integration `run` commands must fail closed rather than silently vendoring or changing pinned integrations.
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
- Ordinary CI may build, verify, admit, compare, exercise temporary trust states and checkpoints, and upload evidence decisions but must never publish a package, create a release, request OIDC credentials, use signing keys, or read registry secrets.

Verification:

```bash
python -m unittest discover -s tests -v
python -m compileall -q agent_system.py agent_policy.py agent_config.py agent_baseline.py agent_git.py agent_changed_lines.py agent_cli.py agent_version.py tests scripts
python agent_system.py config .agent-system.example.json
python agent_system.py policy .agent-system-policy.example.json
python agent_system.py --audit-log /tmp/agent-audit.jsonl baseline /tmp/agent-baseline.json --create --scan-path .
python agent_system.py --audit-log /tmp/agent-audit.jsonl scan . --new-only --baseline /tmp/agent-baseline.json --format json --fail-on high
python agent_changed_lines.py . --changed-from HEAD --format json --audit-log /tmp/agent-line-audit.jsonl
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
python -m pip wheel . --no-deps --wheel-dir dist
python scripts/validate_wheel.py dist/*.whl
python scripts/release_bundle.py create --wheel dist/*.whl --output-dir release --source-commit "$(git rev-parse HEAD)" --source-date-epoch "$(git show -s --format=%ct HEAD)"
python scripts/release_bundle.py verify release
python scripts/release_admission.py evaluate release --policy .release-admission.example.json --expected-source-commit "$(git rev-parse HEAD)" --expected-version "0.1.0"
python scripts/release_transition.py policy .release-transition.example.json
python agent_system.py scan . --format json --fail-on high
```
