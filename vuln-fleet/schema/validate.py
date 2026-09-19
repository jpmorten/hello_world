"""Schema validation helpers for findings and events.

Deterministic, plain-code validation only — no model judgement involved,
per the governance requirement that arithmetic/matching/schema checks are
unit-tested code, not agent output.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

_SCHEMA_DIR = Path(__file__).parent


def _load_schema(name: str) -> dict[str, Any]:
    with open(_SCHEMA_DIR / name, encoding="utf-8") as f:
        return json.load(f)


FINDING_SCHEMA = _load_schema("finding.schema.json")
EVENT_SCHEMA = _load_schema("event.schema.json")
ATTACK_SCENARIO_SCHEMA = _load_schema("attack_scenario.schema.json")
GOVERNANCE_REPORT_SCHEMA = _load_schema("governance_report.schema.json")

_finding_validator = Draft202012Validator(FINDING_SCHEMA)
_event_validator = Draft202012Validator(EVENT_SCHEMA)
_attack_scenario_validator = Draft202012Validator(ATTACK_SCENARIO_SCHEMA)
_governance_report_validator = Draft202012Validator(GOVERNANCE_REPORT_SCHEMA)


class SchemaValidationError(Exception):
    """Raised with all violations collected, not just the first."""

    def __init__(self, errors: list[str]):
        self.errors = errors
        super().__init__("; ".join(errors))


def validate_finding(finding: dict[str, Any]) -> None:
    errors = sorted(
        f"{'/'.join(str(p) for p in e.path) or '<root>'}: {e.message}"
        for e in _finding_validator.iter_errors(finding)
    )
    if errors:
        raise SchemaValidationError(errors)


def validate_attack_scenario(scenario: dict[str, Any]) -> None:
    errors = sorted(
        f"{'/'.join(str(p) for p in e.path) or '<root>'}: {e.message}"
        for e in _attack_scenario_validator.iter_errors(scenario)
    )
    if errors:
        raise SchemaValidationError(errors)


def validate_governance_report(report: dict[str, Any]) -> None:
    errors = sorted(
        f"{'/'.join(str(p) for p in e.path) or '<root>'}: {e.message}"
        for e in _governance_report_validator.iter_errors(report)
    )
    if errors:
        raise SchemaValidationError(errors)


def validate_event(event: dict[str, Any]) -> None:
    errors = sorted(
        f"{'/'.join(str(p) for p in e.path) or '<root>'}: {e.message}"
        for e in _event_validator.iter_errors(event)
    )
    if errors:
        raise SchemaValidationError(errors)
    if event["event_type"] == "finding":
        details = event.get("details")
        if details is None:
            raise SchemaValidationError(["details: required when event_type=finding"])
        validate_finding(details)
    if event["event_type"] == "attack_scenario":
        details = event.get("details")
        if details is None:
            raise SchemaValidationError(["details: required when event_type=attack_scenario"])
        validate_attack_scenario(details)
    if event["event_type"] == "governance_report":
        details = event.get("details")
        if details is None:
            raise SchemaValidationError(["details: required when event_type=governance_report"])
        validate_governance_report(details)
