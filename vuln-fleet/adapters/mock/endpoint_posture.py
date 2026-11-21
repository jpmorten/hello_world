"""Mock endpoint-posture adapter. Same interface contract as
adapters/mock/supply_chain.py."""
from __future__ import annotations

from engine.scope import ScopeResolution

_FINDINGS_BY_TARGET: dict[str, list[dict]] = {
    "host:checkout-prod-01.example-stibo.internal": [
        {
            "title": "EDR agent silent for 30 days on production host",
            "description": "checkout-prod-01 has not reported EDR telemetry in 30 days; the agent may be disabled, crashed, or uninstalled.",
            "technology": "endpoint",
            "location": {"kind": "host", "ref": "host:checkout-prod-01.example-stibo.internal"},
            "identifiers": {"cve": [], "cwe": ["CWE-693"], "ghsa": []},
            "cvss_v4": {"base": 5.9, "environmental": None},
            "epss": 0.0,
            "kev_listed": False,
            "exploitation_status": "no_known_exploitation",
            "evidence_ref": ["edr-console://checkout-prod-01/last-checkin"],
            "confidence": 0.8,
            "false_positive_likelihood": 0.1,
            "regulatory_tags": ["ISO27001"],
            "suggested_remediation": "Investigate and restore EDR coverage on checkout-prod-01; treat as a potential compromise indicator until explained.",
        }
    ],
}


def scan(target_ref: str, resolution: ScopeResolution) -> list[dict]:
    return [dict(finding) for finding in _FINDINGS_BY_TARGET.get(target_ref, [])]
