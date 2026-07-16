# Audit segment catalogs

Audit segments preserve large typed audit histories across rotation. A catalog makes that history discoverable and verifiable without requiring callers to manually order every archive directory on each check.

## Archive layout

Use one dedicated directory for sealed segments and the catalog:

```text
segments/
  0001/
    manifest.json
    segment.jsonl
  0002/
    manifest.json
    segment.jsonl
  catalog.json
  catalog.json.lock
```

The active audit log should normally remain outside this directory. The catalog discovers immediate child directories, verifies each segment independently, then sorts them by the segment index committed in each manifest. Directory names do not determine history order.

The archive root must not contain symlinks or unrelated directories. Regular files such as the catalog and its lock file are allowed.

## Initialize a catalog

After at least one segment has been sealed:

```bash
python agent_audit_catalog.py init segments/catalog.json \
  --active .agent-system/audit.jsonl \
  --format json
```

Initialization:

- discovers every immediate sealed segment directory;
- verifies exact segment bytes and canonical manifests;
- verifies a complete segment chain beginning at index 1;
- verifies the optional active log continues from the latest segment;
- writes a new canonical catalog without overwriting an existing path;
- returns the new `catalog_id`.

Retain the returned `catalog_id` outside the archive directory. A self-consistent catalog alone does not prove freshness.

## Verify a catalog

```bash
python agent_audit_catalog.py verify segments/catalog.json \
  --expected-catalog-id "$EXPECTED_CATALOG_ID" \
  --active .agent-system/audit.jsonl \
  --format json
```

Verification checks:

- strict UTF-8 JSON and canonical serialization;
- exact catalog schema, summaries, generation, and predecessor ID;
- the domain-separated catalog ID;
- safe immediate-child directory names;
- exact manifest and segment digests;
- record counts, byte counts, audit heads, and segment IDs;
- complete discovery, so missing or unindexed segment directories fail;
- archived continuity records and the optional active-log link;
- the externally retained catalog ID.

## Synchronize newly rotated segments

Rotation creates new immutable segment directories but does not silently modify the catalog. Synchronize explicitly:

```bash
python agent_audit_catalog.py sync segments/catalog.json \
  --expected-catalog-id "$EXPECTED_CATALOG_ID" \
  --active .agent-system/audit.jsonl \
  --format json
```

`sync` first verifies the pinned current catalog and every cataloged segment. It then discovers the archive root again. An update is accepted only when the old catalog entries are an exact prefix of the newly discovered complete chain.

A successful update:

- increments `generation`;
- stores the previous catalog ID;
- appends all newly discovered right-descendant segments;
- atomically replaces the catalog under a sidecar advisory lock;
- independently verifies the new catalog and optional active log;
- returns the new `catalog_id`.

When no new segments exist, synchronization is a verified no-op and preserves the catalog bytes and ID.

After every successful update, replace the externally retained catalog ID with the returned value.

## Exit codes

- `0`: catalog created, verified, synchronized, or confirmed unchanged;
- `1`: valid evidence conflicts with the retained trust state, such as a stale pin, missing segment, fork, or active-log mismatch;
- `2`: malformed input, unsafe paths, invalid segment data, or an operational error.

## Stable diagnostics

- `AUC001`: unsafe filesystem object or archive layout
- `AUC002`: malformed, unsupported, or noncanonical catalog
- `AUC003`: catalog metadata, summary, or ID mismatch
- `AUC004`: indexed segment evidence mismatch
- `AUC005`: incomplete, replaced, reordered, or forked segment history
- `AUC006`: active audit log does not continue from the catalog head
- `AUC007`: external catalog or latest-segment pin mismatch
- `AUC008`: unsafe create or atomic-update target
- `AUC010`: no sealed segment available for initialization

## Trust boundary

Catalogs and segment manifests are unsigned integrity commitments. They do not authenticate an operator or provide non-repudiation. Freshness and rollback protection require an independently retained `catalog_id`. Stronger deployment can sign or transparency-log the catalog externally without changing the canonical catalog bytes.

Do not commit generated segment archives, active audit logs, catalog files, lock files, or verification reports to the repository.
