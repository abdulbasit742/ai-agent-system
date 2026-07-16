# Security audit: receiver-acceptance bundle admission

## Scope

Task 36 authorizes already verified receiver-acceptance checkpoint bundles. It does not weaken bundle verification and does not treat a valid bundle as automatically acceptable.

## Verify-before-authorize ordering

Evaluation first calls the acceptance-bundle verifier with externally supplied bundle and checkpoint pins. Authorization rules run only after exact file-boundary, checksum, checkpoint, inclusion-proof, and consistency-proof verification succeeds. Invalid evidence returns exit `2`; it is never converted into a policy denial.

The manifest is reloaded after verification and its canonical bundle ID must equal the verified report. This closes the reviewed post-verification manifest-replacement window.

## Consumer-owned inputs

The policy and freshness pins remain outside the bundle. The CLI rejects a policy path located inside the bundle directory. Empty allowlists are deliberately unrestricted; non-empty allowlists are exact lowercase SHA-256 identity sets.

## Policy integrity

The parser rejects duplicate JSON keys, non-finite numbers, unknown or missing fields, booleans used as integers, unsorted/duplicate lists, inverted ranges, invalid IDs, and noncanonical serialization. The canonical policy bytes produce `policy_sha256`. The complete normalized decision produces a domain-separated deterministic `decision_id`.

## Authorization surface

Stable `ABA001`–`ABA016` controls cover:

- bundle type, size, and proof count;
- acceptance, receiver, and trust entry bounds;
- generation and segment bounds;
- candidate acceptance and downstream receiver/trust identity allowlists;
- selected acceptance sequences and receiver-bundle IDs;
- anchor/head proof requirements;
- transition relation and all reviewed deltas;
- previous acceptance/receiver/trust identities;
- optional single-step acceptance advancement.

Multiple violations are reported together in deterministic order.

## Filesystem and package boundary

Policy creation uses exclusive mode-`0600` creation and fsync. Symlink policies and unsafe parents are rejected. Generated policies and decision reports are data, not package source. The wheel remains dependency-free and contains only reviewed runtime modules and console aliases.

## Residual boundary

Hashes authenticate content integrity and deterministic decisions, not producer identity or freshness by themselves. Consumers must retain bundle/checkpoint IDs independently and protect their policy through an external trust channel. This repository contains no signing key, witness service, OIDC request, or registry credential.
