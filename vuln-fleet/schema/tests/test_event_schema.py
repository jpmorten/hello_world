import hashlib

import pytest

from schema.validate import SchemaValidationError, validate_event


GENESIS_HASH = "0" * 64


def _chain(prev_hash: str, event_without_hash: dict) -> str:
    import json

    canonical = json.dumps(event_without_hash, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256((prev_hash + canonical).encode("utf-8")).hexdigest()


@pytest.fixture
def valid_event() -> dict:
    body = {
        "timestamp": "2026-09-18T08:00:00Z",
        "run_id": "run-2026-09-18-0001",
        "agent_id": "fleet-orchestrator",
        "agent_role": "fleet-orchestrator",
        "tier": 0,
        "parent_agent_id": None,
        "span_id": "span-0001",
        "parent_span_id": None,
        "event_type": "run_start",
        "severity": "info",
        "entity": None,
        "asset_id": None,
        "scope_ref": None,
        "authorization_ref": None,
        "message": "Full sweep started.",
        "evidence_ref": [],
    }
    body["integrity_hash"] = _chain(GENESIS_HASH, body)
    return body


def test_valid_event_passes(valid_event):
    validate_event(valid_event)  # must not raise


def test_missing_required_field_rejected(valid_event):
    del valid_event["integrity_hash"]
    with pytest.raises(SchemaValidationError):
        validate_event(valid_event)


def test_unknown_event_type_rejected(valid_event):
    valid_event["event_type"] = "totally_made_up"
    with pytest.raises(SchemaValidationError):
        validate_event(valid_event)


def test_bad_tier_rejected(valid_event):
    valid_event["tier"] = 3
    with pytest.raises(SchemaValidationError):
        validate_event(valid_event)


def test_malformed_integrity_hash_rejected(valid_event):
    valid_event["integrity_hash"] = "not-a-hash"
    with pytest.raises(SchemaValidationError):
        validate_event(valid_event)


def test_finding_event_requires_details(valid_event):
    valid_event["event_type"] = "finding"
    valid_event.pop("details", None)
    with pytest.raises(SchemaValidationError):
        validate_event(valid_event)


def test_additional_property_rejected(valid_event):
    valid_event["raw_credential"] = "should-never-appear"
    with pytest.raises(SchemaValidationError):
        validate_event(valid_event)
