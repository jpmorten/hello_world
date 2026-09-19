import hashlib

import pytest

from schema.validate import SchemaValidationError, validate_attack_scenario, validate_event


def _fingerprint(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


@pytest.fixture
def valid_scenario() -> dict:
    f1 = _fingerprint("supply-chain", "CVE-2024-12345", "svc-checkout", "repo:stibo/checkout")
    f2 = _fingerprint("red-team-recon", "title:Wildcard certificate in use", "red-team-example", "domain:example.com")
    return {
        "scenario_id": _fingerprint("run-1", f"{f1},{f2}", "Chain A into B"),
        "run_id": "run-1",
        "title": "Chain A into B",
        "attacker_goal": "Reach the data lake",
        "narrative": "An attacker would first do X, then use it to do Y.",
        "attack_path": [
            {"step": 1, "description": "Exploit finding A", "based_on_finding_id": f1},
            {"step": 2, "description": "Pivot using the result", "based_on_finding_id": None},
        ],
        "chained_finding_ids": [f1, f2],
        "likelihood": "medium",
        "confidence": 0.6,
        "potential_impact": "Exposure of customer PII.",
        "mitre_attack_techniques": ["T1590", "T1078.001"],
        "status": "predicted",
        "evidence_ref": [f"sbom://{f1}"],
    }


def test_valid_scenario_passes(valid_scenario):
    validate_attack_scenario(valid_scenario)  # must not raise


def test_missing_required_field_rejected(valid_scenario):
    del valid_scenario["narrative"]
    with pytest.raises(SchemaValidationError):
        validate_attack_scenario(valid_scenario)


def test_additional_property_rejected(valid_scenario):
    valid_scenario["exploit_result"] = "succeeded"
    with pytest.raises(SchemaValidationError):
        validate_attack_scenario(valid_scenario)


def test_status_confirmed_rejected(valid_scenario):
    valid_scenario["status"] = "confirmed"
    with pytest.raises(SchemaValidationError):
        validate_attack_scenario(valid_scenario)


def test_status_exploited_rejected(valid_scenario):
    valid_scenario["status"] = "exploited"
    with pytest.raises(SchemaValidationError):
        validate_attack_scenario(valid_scenario)


def test_single_chained_finding_rejected(valid_scenario):
    valid_scenario["chained_finding_ids"] = [valid_scenario["chained_finding_ids"][0]]
    with pytest.raises(SchemaValidationError):
        validate_attack_scenario(valid_scenario)


def test_bad_finding_id_pattern_rejected(valid_scenario):
    valid_scenario["chained_finding_ids"] = ["not-a-real-hash", valid_scenario["chained_finding_ids"][1]]
    with pytest.raises(SchemaValidationError):
        validate_attack_scenario(valid_scenario)


def test_bad_likelihood_rejected(valid_scenario):
    valid_scenario["likelihood"] = "certain"
    with pytest.raises(SchemaValidationError):
        validate_attack_scenario(valid_scenario)


def test_confidence_out_of_range_rejected(valid_scenario):
    valid_scenario["confidence"] = 1.5
    with pytest.raises(SchemaValidationError):
        validate_attack_scenario(valid_scenario)


def test_bad_mitre_technique_pattern_rejected(valid_scenario):
    valid_scenario["mitre_attack_techniques"] = ["not-a-technique-id"]
    with pytest.raises(SchemaValidationError):
        validate_attack_scenario(valid_scenario)


def test_empty_mitre_techniques_allowed(valid_scenario):
    valid_scenario["mitre_attack_techniques"] = []
    validate_attack_scenario(valid_scenario)  # must not raise


def test_attack_scenario_event_requires_details():
    event = {
        "timestamp": "2026-09-19T08:00:00Z",
        "run_id": "run-1",
        "agent_id": "attack-scenario-analysis-1",
        "agent_role": "attack-scenario-analyst",
        "tier": 1,
        "parent_agent_id": "fleet-orchestrator",
        "span_id": "span-1",
        "parent_span_id": "root",
        "event_type": "attack_scenario",
        "severity": "notice",
        "entity": None,
        "asset_id": None,
        "scope_ref": None,
        "authorization_ref": None,
        "message": "Predicted attack scenario: Chain A into B",
        "evidence_ref": [],
        "integrity_hash": "a" * 64,
    }
    with pytest.raises(SchemaValidationError):
        validate_event(event)


def test_attack_scenario_event_with_valid_details_passes(valid_scenario):
    event = {
        "timestamp": "2026-09-19T08:00:00Z",
        "run_id": "run-1",
        "agent_id": "attack-scenario-analysis-1",
        "agent_role": "attack-scenario-analyst",
        "tier": 1,
        "parent_agent_id": "fleet-orchestrator",
        "span_id": "span-1",
        "parent_span_id": "root",
        "event_type": "attack_scenario",
        "severity": "notice",
        "entity": None,
        "asset_id": None,
        "scope_ref": None,
        "authorization_ref": None,
        "message": "Predicted attack scenario: Chain A into B",
        "evidence_ref": [],
        "details": valid_scenario,
        "integrity_hash": "a" * 64,
    }
    validate_event(event)  # must not raise
