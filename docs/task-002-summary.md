# Task 2 summary

Task 2 adds exact-fingerprint security baselines and a new-findings-only CI gate.

Implemented components:

- strict versioned baseline schema
- baseline content integrity hash
- control-scope hash for rule packs and suppressions
- exact new, existing, and resolved classification
- baseline creation and validation CLI
- automatic baseline discovery
- JSON, text, SARIF, and audit integration
- regression tests and CI smoke coverage

The baseline stores no matched evidence, previews, fixes, or source contents.
