"""Mock firmware-hardware adapter. Same interface contract as
adapters/mock/supply_chain.py."""
from __future__ import annotations

from engine.scope import ScopeResolution

_FINDINGS_BY_TARGET: dict[str, list[dict]] = {
    "host:idrac-mdm-01.example-stibo.internal": [
        {
            "title": "iDRAC firmware end-of-life with a KEV-listed remote auth bypass",
            "description": "idrac-mdm-01 runs an iDRAC firmware version that has not received vendor security patches since 2022 and is affected by a KEV-listed authentication bypass.",
            "technology": "BMC firmware",
            "location": {"kind": "firmware_image", "ref": "host:idrac-mdm-01.example-stibo.internal"},
            "identifiers": {"cve": ["CVE-2022-88888"], "cwe": ["CWE-287"], "ghsa": []},
            "cvss_v4": {"base": 9.1, "environmental": None},
            "epss": 0.88,
            "kev_listed": True,
            "exploitation_status": "known_exploited",
            "evidence_ref": ["firmware-inventory://idrac-mdm-01/version"],
            "confidence": 0.9,
            "false_positive_likelihood": 0.05,
            "regulatory_tags": ["CRA", "NIS2"],
            "suggested_remediation": "Apply the vendor's current iDRAC firmware immediately; KEV-listed.",
        }
    ],
}


def scan(target_ref: str, resolution: ScopeResolution) -> list[dict]:
    return [dict(finding) for finding in _FINDINGS_BY_TARGET.get(target_ref, [])]
