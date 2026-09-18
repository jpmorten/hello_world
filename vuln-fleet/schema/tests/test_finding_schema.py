import copy
import hashlib

import pytest

from schema.validate import SchemaValidationError, validate_finding


def _fingerprint(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


@pytest.fixture
def valid_finding() -> dict:
    return {
        "finding_id": _fingerprint("supply-chain", "CVE-2024-12345", "svc-checkout", "repo:stibo/checkout"),
        "run_id": "run-2026-09-18-0001",
        "domain": "supply-chain",
        "title": "Vulnerable transitive dependency: lodash@4.17.15",
        "description": "SBOM scan found lodash 4.17.15 pulled in transitively via express-legacy.",
        "entity": "Stibo Systems",
        "asset": {
            "asset_id": "svc-checkout",
            "type": "service",
            "owner_team": "checkout-platform",
            "criticality": "high",
        },
        "technology": "node.js",
        "location": {"kind": "repo", "ref": "repo:stibo/checkout"},
        "identifiers": {"cve": ["CVE-2024-12345"], "cwe": ["CWE-1321"], "ghsa": []},
        "cvss_v4": {"base": 7.5, "environmental": None},
        "epss": 0.12,
        "kev_listed": False,
        "exploitation_status": "poc_public",
        "first_seen": "2026-09-18T08:00:00Z",
        "last_seen": "2026-09-18T08:00:00Z",
        "evidence_ref": ["sbom://run-2026-09-18-0001/checkout/component/lodash"],
        "confidence": 0.9,
        "false_positive_likelihood": 0.05,
        "regulatory_tags": ["NIS2"],
        "suggested_remediation": "Upgrade lodash to >=4.17.21 or drop express-legacy.",
        "status": "new",
        "scope_ref": "assets.yaml#svc-checkout",
        "authorization_ref": None,
    }


def test_valid_finding_passes(valid_finding):
    validate_finding(valid_finding)  # must not raise


def test_missing_required_field_rejected(valid_finding):
    del valid_finding["cvss_v4"]
    with pytest.raises(SchemaValidationError):
        validate_finding(valid_finding)


def test_additional_property_rejected(valid_finding):
    valid_finding["exploit_payload"] = "rm -rf /"
    with pytest.raises(SchemaValidationError):
        validate_finding(valid_finding)


def test_bad_cve_pattern_rejected(valid_finding):
    valid_finding["identifiers"]["cve"] = ["not-a-cve"]
    with pytest.raises(SchemaValidationError):
        validate_finding(valid_finding)


def test_confidence_out_of_range_rejected(valid_finding):
    valid_finding["confidence"] = 1.5
    with pytest.raises(SchemaValidationError):
        validate_finding(valid_finding)


def test_unknown_domain_rejected(valid_finding):
    valid_finding["domain"] = "not-a-real-domain"
    with pytest.raises(SchemaValidationError):
        validate_finding(valid_finding)


def test_kev_listed_requires_known_exploited_status(valid_finding):
    valid_finding["kev_listed"] = True
    valid_finding["exploitation_status"] = "poc_public"
    with pytest.raises(SchemaValidationError):
        validate_finding(valid_finding)


def test_kev_listed_with_known_exploited_passes(valid_finding):
    valid_finding["kev_listed"] = True
    valid_finding["exploitation_status"] = "known_exploited"
    validate_finding(valid_finding)  # must not raise


def test_active_scan_finding_requires_authorization_ref_field_present(valid_finding):
    finding = copy.deepcopy(valid_finding)
    finding["domain"] = "infra-network"
    finding["authorization_ref"] = "authorized-active.yaml#nsg-sweep-2026-09"
    validate_finding(finding)  # must not raise; field is present, non-null is allowed
