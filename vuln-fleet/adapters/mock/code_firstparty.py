"""Mock code-firstparty adapter. Deliberately targets the same repos
supply-chain does — SAST and SBOM scanning the same repository is
realistic, and the two domains' findings never collide because
finding_id and spawn dedup are both fingerprinted per-domain. Same
interface contract as adapters/mock/supply_chain.py.
"""
from __future__ import annotations

from engine.scope import ScopeResolution

_FINDINGS_BY_TARGET: dict[str, list[dict]] = {
    "repo:stibo/checkout": [
        {
            "title": "Hardcoded AWS access key in commit history",
            "description": "SAST + secret-history scan found a live-format AWS access key committed to checkout two years ago; it was never rotated.",
            "technology": "node.js",
            "location": {"kind": "repo", "ref": "repo:stibo/checkout"},
            "identifiers": {"cve": [], "cwe": ["CWE-798"], "ghsa": []},
            "cvss_v4": {"base": 8.6, "environmental": None},
            "epss": 0.0,
            "kev_listed": False,
            "exploitation_status": "no_known_exploitation",
            "evidence_ref": ["sast://repo:stibo/checkout/secret-history/finding-1"],
            "confidence": 0.85,
            "false_positive_likelihood": 0.1,
            "regulatory_tags": ["ISO27001", "GDPR"],
            "suggested_remediation": "Rotate the key immediately and purge it from git history.",
        }
    ],
}


def scan(target_ref: str, resolution: ScopeResolution) -> list[dict]:
    return [dict(finding) for finding in _FINDINGS_BY_TARGET.get(target_ref, [])]
