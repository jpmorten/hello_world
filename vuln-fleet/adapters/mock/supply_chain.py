"""Mock supply-chain adapter for the step-5 end-to-end proof.

Returns synthetic SBOM-derived findings for a fixed set of known target
refs, and nothing for anything else. This is what step 7 replaces with a
real CycloneDX-consuming adapter; the interface it must keep is
`scan(target_ref, resolution) -> list[dict]`, where each dict carries
every Finding field except the ones the orchestrator fills in from run/
scope context (finding_id, run_id, entity, asset, first_seen, last_seen,
status, scope_ref, authorization_ref).
"""
from __future__ import annotations

from engine.scope import ScopeResolution

_FINDINGS_BY_TARGET: dict[str, list[dict]] = {
    "repo:stibo/checkout": [
        {
            "title": "Vulnerable transitive dependency: lodash@4.17.15",
            "description": "SBOM scan found lodash 4.17.15 pulled in transitively via express-legacy.",
            "technology": "node.js",
            "location": {"kind": "repo", "ref": "repo:stibo/checkout"},
            "identifiers": {"cve": ["CVE-2024-12345"], "cwe": ["CWE-1321"], "ghsa": []},
            "cvss_v4": {"base": 7.5, "environmental": None},
            "epss": 0.12,
            "kev_listed": False,
            "exploitation_status": "poc_public",
            "evidence_ref": ["sbom://repo:stibo/checkout/component/lodash"],
            "confidence": 0.9,
            "false_positive_likelihood": 0.05,
            "regulatory_tags": ["NIS2"],
            "suggested_remediation": "Upgrade lodash to >=4.17.21 or drop express-legacy.",
        }
    ],
    "repo:stibo/mdm-core": [
        {
            "title": "Actively exploited deserialization flaw in log-ingest@2.3.0",
            "description": "SBOM scan found log-ingest 2.3.0, affected by a KEV-listed unsafe deserialization CVE.",
            "technology": "java",
            "location": {"kind": "repo", "ref": "repo:stibo/mdm-core"},
            "identifiers": {"cve": ["CVE-2023-99999"], "cwe": ["CWE-502"], "ghsa": []},
            "cvss_v4": {"base": 9.8, "environmental": None},
            "epss": 0.94,
            "kev_listed": True,
            "exploitation_status": "known_exploited",
            "evidence_ref": ["sbom://repo:stibo/mdm-core/component/log-ingest"],
            "confidence": 0.95,
            "false_positive_likelihood": 0.02,
            "regulatory_tags": ["NIS2", "CRA"],
            "suggested_remediation": "Upgrade log-ingest to >=2.4.1 immediately; KEV-listed.",
        }
    ],
}


def scan(target_ref: str, resolution: ScopeResolution) -> list[dict]:
    return [dict(finding) for finding in _FINDINGS_BY_TARGET.get(target_ref, [])]
