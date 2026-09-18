"""Mock data-exposure adapter. Same interface contract as
adapters/mock/supply_chain.py."""
from __future__ import annotations

from engine.scope import ScopeResolution

_FINDINGS_BY_TARGET: dict[str, list[dict]] = {
    "host:analytics-lake-01.example-stibo.internal": [
        {
            "title": "Analytics data lake stores customer PII unencrypted at rest",
            "description": "The analytics data lake's raw ingestion zone stores customer PII fields without at-rest encryption enabled.",
            "technology": "data lake",
            "location": {"kind": "host", "ref": "host:analytics-lake-01.example-stibo.internal"},
            "identifiers": {"cve": [], "cwe": ["CWE-311"], "ghsa": []},
            "cvss_v4": {"base": 6.9, "environmental": None},
            "epss": 0.0,
            "kev_listed": False,
            "exploitation_status": "no_known_exploitation",
            "evidence_ref": ["data-posture://analytics-lake/raw-zone/encryption-at-rest"],
            "confidence": 0.85,
            "false_positive_likelihood": 0.08,
            "regulatory_tags": ["GDPR", "ISO27001"],
            "suggested_remediation": "Enable at-rest encryption on the raw ingestion zone and re-key existing data.",
        }
    ],
}


def scan(target_ref: str, resolution: ScopeResolution) -> list[dict]:
    return [dict(finding) for finding in _FINDINGS_BY_TARGET.get(target_ref, [])]
