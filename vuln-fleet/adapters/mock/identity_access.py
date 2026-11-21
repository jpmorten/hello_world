"""Mock identity-access adapter. Same interface contract as
adapters/mock/supply_chain.py."""
from __future__ import annotations

from engine.scope import ScopeResolution

_FINDINGS_BY_TARGET: dict[str, list[dict]] = {
    "endpoint:https://login.example-stibo.com": [
        {
            "title": "Stale service principal retains Owner role after 400 days idle",
            "description": "The 'legacy-etl-svc' service principal has not authenticated in 400 days but still holds Owner-level access.",
            "technology": "identity provider",
            "location": {"kind": "identity", "ref": "endpoint:https://login.example-stibo.com"},
            "identifiers": {"cve": [], "cwe": ["CWE-284"], "ghsa": []},
            "cvss_v4": {"base": 6.5, "environmental": None},
            "epss": 0.0,
            "kev_listed": False,
            "exploitation_status": "no_known_exploitation",
            "evidence_ref": ["idp-audit://corp-idp/service-principal/legacy-etl-svc"],
            "confidence": 0.9,
            "false_positive_likelihood": 0.05,
            "regulatory_tags": ["ISO27001", "NIS2"],
            "suggested_remediation": "Disable the principal or scope it down to least privilege; require re-justification for any Owner-role grant.",
        }
    ],
}


def scan(target_ref: str, resolution: ScopeResolution) -> list[dict]:
    return [dict(finding) for finding in _FINDINGS_BY_TARGET.get(target_ref, [])]
