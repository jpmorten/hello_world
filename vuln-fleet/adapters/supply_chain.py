"""Real supply-chain adapter: real dependency vulnerability data from
OSV.dev, real exploitability intelligence from adapters/cve_intel.py.
Replaces adapters/mock/supply_chain.py in engine/domains.py's registry
(the mock module stays in the repo — it's still what
engine/tests/test_orchestrator.py's step-5 test exercises directly).

What's *not* real yet: the inventory of which packages are in which
repo. `_SBOM_BY_TARGET` below is a placeholder standing in for a real
SBOM store / CMDB integration (a genuinely future adapter) — for now it
only knows about one package, deliberately, so this module's value is
obviously the vulnerability *lookup*, not a fabricated inventory. A
target with no entry here returns [] (nothing scanned, not "nothing
found") rather than pretending it was assessed.
"""
from __future__ import annotations

from typing import Optional

from adapters import cve_intel, osv
from engine.scope import ScopeResolution

_SBOM_BY_TARGET: dict[str, list[dict]] = {
    "repo:stibo/checkout": [
        {"ecosystem": "npm", "name": "lodash", "version": "4.17.15"},
    ],
}

# OSV.dev reports a qualitative severity (sourced from the advisory
# itself) even when no CVE/NVD numeric CVSS is available. This maps that
# real, sourced rating to a representative CVSS-scale band — coarser than
# a true CVSS vector calculation, but grounded in the advisory's own
# assessment rather than invented. Used only when NVD has nothing (i.e.
# there's no CVE alias, or NVD hasn't scored it).
_SEVERITY_TO_CVSS_BASE = {"CRITICAL": 9.5, "HIGH": 7.5, "MODERATE": 5.5, "MEDIUM": 5.5, "LOW": 3.0}
_DEFAULT_CVSS_BASE = 5.0


def _severity_to_cvss_base(severity: Optional[str]) -> float:
    return _SEVERITY_TO_CVSS_BASE.get((severity or "").upper(), _DEFAULT_CVSS_BASE)


def _build_finding(target_ref: str, package: dict, vuln: dict) -> dict:
    cve_id = osv.extract_cve(vuln)
    if cve_id:
        intel = cve_intel.enrich_cve(cve_id)
        kev_listed, epss, exploitation_status = intel["kev_listed"], intel["epss"], intel["exploitation_status"]
        cvss_base = intel["cvss_v4_base"]
    else:
        kev_listed, epss, exploitation_status, cvss_base = False, 0.0, "no_known_exploitation", None

    if cvss_base is None:
        cvss_base = _severity_to_cvss_base(vuln.get("database_specific", {}).get("severity"))

    fixed_version = osv.extract_fixed_version(vuln)
    remediation = (
        f"Upgrade {package['name']} to {fixed_version} or later."
        if fixed_version
        else f"See {vuln['id']} for remediation guidance; OSV reports no fixed version yet."
    )

    return {
        "title": f"Vulnerable dependency: {package['name']}@{package['version']} ({vuln['id']})",
        "description": vuln.get("summary") or (vuln.get("details") or "")[:500] or vuln["id"],
        "technology": package["ecosystem"],
        "location": {"kind": "repo", "ref": target_ref},
        "identifiers": {
            "cve": [cve_id] if cve_id else [],
            "cwe": vuln.get("database_specific", {}).get("cwe_ids") or [],
            "ghsa": [vuln["id"]] if vuln["id"].startswith("GHSA") else [],
        },
        "cvss_v4": {"base": cvss_base, "environmental": None},
        "epss": epss,
        "kev_listed": kev_listed,
        "exploitation_status": exploitation_status,
        "evidence_ref": [f"osv://{vuln['id']}"],
        "confidence": 0.9,
        "false_positive_likelihood": 0.05,
        "regulatory_tags": ["NIS2"],
        "suggested_remediation": remediation,
    }


def scan(target_ref: str, resolution: ScopeResolution) -> list[dict]:
    findings = []
    for package in _SBOM_BY_TARGET.get(target_ref, []):
        for vuln in osv.query_package(package["ecosystem"], package["name"], package["version"]):
            findings.append(_build_finding(target_ref, package, vuln))
    return findings
