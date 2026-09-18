"""Mock api-surface adapter.

Same interface contract as adapters/mock/supply_chain.py; see that
module's docstring. These findings have no CVE, exercising the
title-based fallback in engine/dedupe.py.compute_finding_id.

The api-surface registry entry (engine/domains.py) decomposes to
`service`-typed assets' `endpoint:` targets, i.e. cms-edge's; the
login.example-stibo.com entry below is only reachable directly, kept for
the step-5 test that predates the registry and still exercises this
adapter with an explicit target list.
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
    "endpoint:https://cms-edge.example-stibodx.com": [
        {
            "title": "Undocumented /internal/preview endpoint reachable without authentication",
            "description": "Spec-vs-reality diff found /internal/preview live on cms-edge with no entry in the published OpenAPI spec and no authn/authz check.",
            "technology": "REST API",
            "location": {"kind": "endpoint", "ref": "endpoint:https://cms-edge.example-stibodx.com"},
            "identifiers": {"cve": [], "cwe": ["CWE-284"], "ghsa": []},
            "cvss_v4": {"base": 7.1, "environmental": None},
            "epss": 0.0,
            "kev_listed": False,
            "exploitation_status": "no_known_exploitation",
            "evidence_ref": ["openapi-diff://cms-edge.example-stibodx.com/internal/preview"],
            "confidence": 0.85,
            "false_positive_likelihood": 0.08,
            "regulatory_tags": ["ISO27001"],
            "suggested_remediation": "Remove the endpoint if unused, or document it and add authn/authz consistent with the rest of the API.",
        }
    ],
}


def scan(target_ref: str, resolution: ScopeResolution) -> list[dict]:
    return [dict(finding) for finding in _FINDINGS_BY_TARGET.get(target_ref, [])]
