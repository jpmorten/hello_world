"""Unit tests for adapters/supply_chain.py: the real OSV.dev + KEV/EPSS/
NVD pipeline, exercised hermetically via the two underlying HTTP seams
(adapters.osv._http_post_json, adapters.cve_intel._http_get_json).
"""
import pytest

from adapters import cve_intel, osv, supply_chain
from engine.scope import ScopeResolution
from schema.validate import validate_finding

LODASH_VULN_FIXTURE = {
    "vulns": [
        {
            "id": "GHSA-29mw-wpgm-hmr9",
            "summary": "Regular Expression Denial of Service (ReDoS) in lodash",
            "aliases": ["CVE-2020-28500"],
            "database_specific": {"severity": "MODERATE", "cwe_ids": ["CWE-1333", "CWE-400"]},
            "affected": [{"ranges": [{"events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}],
        }
    ]
}

GHSA_ONLY_VULN_FIXTURE = {
    "vulns": [
        {
            "id": "GHSA-aaaa-bbbb-cccc",
            "summary": "Prototype pollution in some-package",
            "aliases": [],
            "database_specific": {"severity": "HIGH", "cwe_ids": ["CWE-1321"]},
            "affected": [{"ranges": [{"events": [{"introduced": "0"}]}]}],
        }
    ]
}

KEV_NOT_LISTED = {"vulnerabilities": []}
EPSS_SOME_SCORE = {"data": [{"cve": "CVE-2020-28500", "epss": "0.04"}]}
NVD_NO_RESULT = {"vulnerabilities": []}


def _resolution() -> ScopeResolution:
    return ScopeResolution(
        target_ref="repo:stibo/checkout",
        asset_id="svc-checkout",
        entity="Stibo Systems",
        asset_type="service",
        criticality="high",
        owner_team="checkout-platform",
        scope_ref="assets.yaml#svc-checkout",
    )


@pytest.fixture(autouse=True)
def _reset_kev_cache():
    cve_intel.reset_cache()
    yield
    cve_intel.reset_cache()


def _patch_no_cve_id_intel(monkeypatch):
    """cve_intel is only reached when a CVE alias exists; when it is,
    stub it to avoid needing KEV/EPSS/NVD fixtures for every test."""
    monkeypatch.setattr(cve_intel, "_http_get_json", lambda url, timeout=15.0: (
        KEV_NOT_LISTED if "cisa.gov" in url else EPSS_SOME_SCORE if "first.org" in url else NVD_NO_RESULT
    ))


def test_scan_unknown_target_returns_empty_list():
    assert supply_chain.scan("repo:no-such-repo", _resolution()) == []


def test_scan_returns_valid_finding_for_known_target(monkeypatch):
    monkeypatch.setattr(osv, "_http_post_json", lambda url, payload, timeout=15.0: LODASH_VULN_FIXTURE)
    _patch_no_cve_id_intel(monkeypatch)

    findings = supply_chain.scan("repo:stibo/checkout", _resolution())

    assert len(findings) == 1
    finding = findings[0]
    assert finding["identifiers"]["cve"] == ["CVE-2020-28500"]
    assert finding["identifiers"]["ghsa"] == ["GHSA-29mw-wpgm-hmr9"]
    assert finding["identifiers"]["cwe"] == ["CWE-1333", "CWE-400"]
    assert finding["kev_listed"] is False
    assert finding["epss"] == pytest.approx(0.04)
    assert "4.17.21" in finding["suggested_remediation"]
    assert finding["evidence_ref"] == ["osv://GHSA-29mw-wpgm-hmr9"]


def test_scan_finding_is_schema_valid(monkeypatch):
    monkeypatch.setattr(osv, "_http_post_json", lambda url, payload, timeout=15.0: LODASH_VULN_FIXTURE)
    _patch_no_cve_id_intel(monkeypatch)

    findings = supply_chain.scan("repo:stibo/checkout", _resolution())

    # validate_finding requires the full envelope; supply just what a real
    # orchestrator finalization step would add on top of the adapter's output.
    finding = dict(findings[0])
    finding.update(
        finding_id="a" * 64,
        run_id="run-test",
        domain="supply-chain",
        entity="Stibo Systems",
        asset={"asset_id": "svc-checkout", "type": "service", "owner_team": "checkout-platform", "criticality": "high"},
        first_seen="2026-09-18T00:00:00Z",
        last_seen="2026-09-18T00:00:00Z",
        status="new",
        scope_ref="assets.yaml#svc-checkout",
        authorization_ref=None,
    )
    validate_finding(finding)  # must not raise


def test_scan_kev_listed_vuln_flagged_known_exploited(monkeypatch):
    monkeypatch.setattr(osv, "_http_post_json", lambda url, payload, timeout=15.0: LODASH_VULN_FIXTURE)
    monkeypatch.setattr(
        cve_intel,
        "_http_get_json",
        lambda url, timeout=15.0: (
            {"vulnerabilities": [{"cveID": "CVE-2020-28500"}]}
            if "cisa.gov" in url
            else EPSS_SOME_SCORE if "first.org" in url else NVD_NO_RESULT
        ),
    )

    finding = supply_chain.scan("repo:stibo/checkout", _resolution())[0]

    assert finding["kev_listed"] is True
    assert finding["exploitation_status"] == "known_exploited"


def test_scan_ghsa_only_vuln_falls_back_to_severity_based_cvss(monkeypatch):
    monkeypatch.setattr(supply_chain, "_SBOM_BY_TARGET", {"repo:stibo/checkout": [{"ecosystem": "npm", "name": "some-package", "version": "1.0.0"}]})
    monkeypatch.setattr(osv, "_http_post_json", lambda url, payload, timeout=15.0: GHSA_ONLY_VULN_FIXTURE)

    finding = supply_chain.scan("repo:stibo/checkout", _resolution())[0]

    assert finding["identifiers"]["cve"] == []
    assert finding["kev_listed"] is False
    assert finding["exploitation_status"] == "no_known_exploitation"
    assert finding["cvss_v4"]["base"] == 7.5  # HIGH -> representative band, no NVD/CVE lookup needed
    assert "no fixed version" in finding["suggested_remediation"]


def test_severity_to_cvss_base_known_and_unknown_bands():
    assert supply_chain._severity_to_cvss_base("CRITICAL") == 9.5
    assert supply_chain._severity_to_cvss_base("low") == 3.0  # case-insensitive
    assert supply_chain._severity_to_cvss_base(None) == supply_chain._DEFAULT_CVSS_BASE
    assert supply_chain._severity_to_cvss_base("unrecognized") == supply_chain._DEFAULT_CVSS_BASE
