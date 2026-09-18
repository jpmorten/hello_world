"""Mock api-surface adapter for the step-5 end-to-end proof.

Same interface contract as adapters/mock/supply_chain.py; see that
module's docstring. This adapter's findings have no CVE, exercising the
title-based fallback in engine/dedupe.py.compute_finding_id.
"""
from __future__ import annotations

from engine.scope import ScopeResolution

_FINDINGS_BY_TARGET: dict[str, list[dict]] = {
    "endpoint:https://login.example-stibo.com": [
        {
            "title": "Deprecated API version v1 still live",
            "description": "OpenAPI diff shows /v1/auth is marked deprecated but still serving traffic with no sunset enforced.",
            "technology": "REST API",
            "location": {"kind": "endpoint", "ref": "endpoint:https://login.example-stibo.com"},
            "identifiers": {"cve": [], "cwe": ["CWE-1059"], "ghsa": []},
            "cvss_v4": {"base": 5.3, "environmental": None},
            "epss": 0.0,
            "kev_listed": False,
            "exploitation_status": "no_known_exploitation",
            "evidence_ref": ["openapi-diff://login.example-stibo.com/v1/auth"],
            "confidence": 0.8,
            "false_positive_likelihood": 0.1,
            "regulatory_tags": ["ISO27001"],
            "suggested_remediation": "Sunset /v1/auth or apply the same authn/rate-limit controls as v2.",
        }
    ],
}


def scan(target_ref: str, resolution: ScopeResolution) -> list[dict]:
    return [dict(finding) for finding in _FINDINGS_BY_TARGET.get(target_ref, [])]
