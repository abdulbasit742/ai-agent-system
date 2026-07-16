from pathlib import Path

from agent_audit_trust_admission import default_policy, evaluate_handoff
from agent_audit_trust_bundle import verify_bundle
from agent_audit_trust_receiver import append_transition, create_state
from test_audit_trust_admission import make_bundle
from test_audit_trust_consistency import advance, anchor


def admitted(root, candidate, previous=None, sequences=None, name="bundle", policy=None):
    inputs, manifest, bundle = make_bundle(root, candidate, previous, sequences, name)
    previous_id = (inputs.get("previous") or {}).get("checkpoint_id")
    report = evaluate_handoff(
        bundle,
        policy or default_policy(),
        expected_bundle_id=manifest["bundle_id"],
        expected_candidate_checkpoint_id=inputs["candidate"]["checkpoint_id"],
        expected_previous_checkpoint_id=previous_id,
    )
    verified = verify_bundle(
        bundle,
        expected_bundle_id=manifest["bundle_id"],
        expected_candidate_checkpoint_id=inputs["candidate"]["checkpoint_id"],
        expected_previous_checkpoint_id=previous_id,
    )
    return report, verified, inputs, manifest, bundle


def receiver_history(root: Path):
    retained = anchor()
    candidate = advance(retained)
    snapshot = admitted(root / "snapshot", retained)
    transition = admitted(root / "transition", candidate, retained)
    state = create_state(snapshot[0], snapshot[1])
    updated = append_transition(state, transition[0], transition[1])
    return state, updated, snapshot, transition
