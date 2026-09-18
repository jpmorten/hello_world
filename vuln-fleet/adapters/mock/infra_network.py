"""Mock infra-network adapter. Two decomposition axes feed this same
function: `cidr:` targets (one worker per subnet) and targets on
`network_device`-typed assets (one worker per firewall platform) — see
engine/domains.py. Same interface contract as
adapters/mock/supply_chain.py.
"""
from __future__ import annotations

from engine.scope import ScopeResolution

_FINDINGS_BY_TARGET: dict[str, list[dict]] = {
    "cidr:10.20.0.0/24": [
        {
            "title": "Flat network segment: mdm-core has no internal segmentation",
            "description": "10.20.0.0/24 carries mdm-core's database, application, and management traffic on one flat segment with no internal ACLs.",
            "technology": "network",
            "location": {"kind": "network_segment", "ref": "cidr:10.20.0.0/24"},
            "identifiers": {"cve": [], "cwe": ["CWE-284"], "ghsa": []},
            "cvss_v4": {"base": 6.5, "environmental": None},
            "epss": 0.0,
            "kev_listed": False,
            "exploitation_status": "no_known_exploitation",
            "evidence_ref": ["netmap://cidr:10.20.0.0/24/segmentation-scan"],
            "confidence": 0.75,
            "false_positive_likelihood": 0.15,
            "regulatory_tags": ["NIS2", "ISO27001"],
            "suggested_remediation": "Split management, app, and data-tier traffic into separate segments with default-deny ACLs between them.",
        }
    ],
    "endpoint:https://fw-mgmt.example-stibo.internal": [
        {
            "title": "Permissive any-any inbound rule on firewall management plane",
            "description": "The firewall's own management interface accepts inbound connections from any source on its administrative port.",
            "technology": "firewall",
            "location": {"kind": "endpoint", "ref": "endpoint:https://fw-mgmt.example-stibo.internal"},
            "identifiers": {"cve": [], "cwe": ["CWE-284"], "ghsa": []},
            "cvss_v4": {"base": 8.1, "environmental": None},
            "epss": 0.0,
            "kev_listed": False,
            "exploitation_status": "no_known_exploitation",
            "evidence_ref": ["fw-config://fw-mgmt/rule/mgmt-any-any"],
            "confidence": 0.9,
            "false_positive_likelihood": 0.05,
            "regulatory_tags": ["NIS2"],
            "suggested_remediation": "Restrict the management interface to a dedicated admin jump-host source range.",
        }
    ],
}


def scan(target_ref: str, resolution: ScopeResolution) -> list[dict]:
    return [dict(finding) for finding in _FINDINGS_BY_TARGET.get(target_ref, [])]
