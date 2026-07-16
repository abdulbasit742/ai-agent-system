# Security audit: strict audit-log integrity

## Scope

This review covers `agent_audit.py`, the `agent_system.py` compatibility wrapper, the retained `agent_system_legacy.py` control-plane implementation, package-boundary changes, and the read-only audit-integrity workflow.

## Threat model

The audit log is local consumer evidence. An attacker or interrupted process may try to:

- alter one record while preserving valid JSON;
- rewrite a record and recalculate only its own hash;
- break or replace a previous-hash link;
- truncate the file to an older valid prefix;
- replay a different valid chain;
- append malformed, duplicate-key, non-canonical, or partial JSON;
- introduce blank lines or CRLF ambiguity;
- use a symlink to redirect reads, appends, locks, or recovery output;
- race two appenders so both trust the same previous head;
- cause a verifier traceback that is mistaken for a successful check;
- overwrite the damaged source while attempting recovery;
- place secrets or complete audit details in diagnostics or CI artifacts.

## Controls

### Complete-chain verification

Every append validates the full existing chain while holding a persistent sidecar advisory lock. The next `sequence` and `previous_hash` are derived only from the verified report. A corrupt chain is never extended.

### Strict parsing and canonical encoding

The parser rejects invalid UTF-8, duplicate keys, non-finite numbers, blank lines, missing final newlines, CRLF records, unsupported schemas, invalid timestamps, unsafe event strings, non-object details, malformed hashes, chain breaks, and non-canonical serialization.

The first failure is returned as a stable `AUDxxx` rule with physical line and byte offset. Verification failures are data, not uncaught JSON or key exceptions.

### Backward-compatible migration

Exact legacy records remain verifiable. New appends use schema version 1 and a physical-line sequence. Mixed legacy/versioned chains remain cryptographically continuous without silently rewriting historical bytes.

### External freshness pins

A valid hash chain alone cannot detect deliberate truncation to an older valid prefix. Optional externally retained record-count and head-hash pins provide that freshness check. Pin mismatches are marked non-recoverable to avoid treating rollback as an interrupted write.

### Atomic append and concurrency

A sidecar advisory lock serializes appenders. The final canonical line is written through one `O_APPEND` descriptor operation and synchronized. A short write is treated as an error.

The lock is a coordination mechanism, not an authentication mechanism. Processes that ignore the lock can still damage the file; strict verification then detects that damage.

### Recovery boundaries

Recovery never mutates the source. It writes only the byte prefix covered by fully verified records to a new path using a same-directory temporary file, restrictive permissions, a hard-link no-overwrite commit, and independent post-write verification.

Existing or symlink outputs are rejected. External-pin mismatches cannot produce a recovery copy.

### Command preflight

The wrapper verifies the selected audit log before scan, guard, scrub, baseline creation, or integration dispatch. Known corruption therefore blocks audited work with exit code `2` and a concise stable diagnostic instead of a traceback.

### Data minimization

Verification reports contain counts, hashes, offsets, paths, schema counters, and rule messages. They do not include record detail objects, source previews, credentials, environment values, or event payload contents. The CI artifact contains only synthetic audit evidence created during the workflow.

## Residual risks

- The chain is unsigned. It proves internal continuity, not who produced a record.
- A privileged attacker who controls both the file and every external pin can replace the complete history.
- Advisory locks cannot coordinate malicious writers that deliberately ignore them.
- Filesystem or hardware behavior can still fail after `fsync`; external backups remain necessary.
- The compatibility wrapper retains the pre-task control-plane module unchanged to minimize behavioral drift. A later reviewed refactor may fold that implementation back into one module.

## Verification requirements

```bash
python -m unittest discover -s tests -p "test_agent_audit.py" -v
python -m unittest discover -s tests -p "test_agent_system.py" -v
python -m unittest discover -s tests -p "test_packaging.py" -v
python -m unittest discover -s tests -p "test_wheel_validator.py" -v
python -m compileall -q agent_audit.py agent_system.py agent_system_legacy.py tests scripts
python agent_system.py audit --path .agent-system/audit.jsonl --format json
python agent_system.py scan . --format json --fail-on high
python agent_system.py guard python -m unittest discover -s tests
```

The dedicated workflow must additionally prove exact head/count pinning, partial-write recovery, stale-pin rejection, corrupt-log preflight, immutable recovery output, Python 3.11/3.12 compatibility, and read-only artifact preservation.
