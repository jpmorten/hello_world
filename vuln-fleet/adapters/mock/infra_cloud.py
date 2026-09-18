"""Mock infra-cloud adapter. Same interface contract as
adapters/mock/supply_chain.py."""
from __future__ import annotations

from engine.scope import ScopeResolution

_FINDINGS_BY_TARGET: dict[str, list[dict]] = {
    "endpoint:https://public-bucket.example-stibo-storage.com": [
        {
            "title": "Public read access on storage bucket exposes build artifacts",
            "description": "The bucket backing DX build artifacts allows anonymous public read, including artifacts from private repositories.",
            "technology": "object storage",
            "location": {
                "kind": "cloud_resource",
                "ref": "endpoint:https://public-bucket.example-stibo-storage.com",
            },
            "identifiers": {"cve": [], "cwe": ["CWE-284"], "ghsa": []},
            "cvss_v4": {"base": 7.5, "environmental": None},
            "epss": 0.0,
            "kev_listed": False,
            "exploitation_status": "no_known_exploitation",
            "evidence_ref": ["cloud-posture://public-assets-bucket/acl/public-read"],
            "confidence": 0.95,
            "false_positive_likelihood": 0.02,
            "regulatory_tags": ["NIS2", "GDPR"],
            "suggested_remediation": "Remove public read ACL; front the bucket with a signed-URL CDN if public access is genuinely needed.",
        }
    ],
}


def scan(target_ref: str, resolution: ScopeResolution) -> list[dict]:
    return [dict(finding) for finding in _FINDINGS_BY_TARGET.get(target_ref, [])]
