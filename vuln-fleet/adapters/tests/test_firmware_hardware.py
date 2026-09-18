"""Unit tests for adapters/firmware_hardware.py: real NVD keyword search
+ KEV/EPSS/NVD enrichment, exercised hermetically via the underlying HTTP
seam (adapters.cve_intel._http_get_json).
"""
import pytest

from adapters import cve_intel, firmware_hardware
from engine.scope import ScopeResolution
from schema.validate import validate_finding

KEYWORD_SEARCH_FIXTURE = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2013-4783",
                "descriptions": [{"lang": "en", "value": "The Dell iDRAC6 allows remote attackers to bypass authentication via cipher zero."}],
                "weaknesses": [{"description": [{"lang": "en", "value": "CWE-287"}]}],
                "metrics": {"cvssMetricV2": [{"cvssData": {"baseScore": 10.0}}]},
            }
        },
        {
            "cve": {
                "id": "CVE-2016-5685",
                "descriptions": [{"lang": "en", "value": "Dell iDRAC7 and iDRAC8 devices allow authenticated users to gain access."}],
                "weaknesses": [],
                "metrics": {},
            }
        },
    ]
}

KEV_NOT_LISTED = {"vulnerabilities": []}
EPSS_EMPTY = {"data": []}
NVD_NO_RESULT = {"vulnerabilities": []}


def _resolution() -> ScopeResolution:
    return ScopeResolution(
        target_ref="host:idrac-mdm-01.example-stibo.internal",
        asset_id="idrac-mdm-01",
        entity="Stibo Systems",
        asset_type="firmware",
        criticality="high",
        owner_team="mdm-platform",
        scope_ref="assets.yaml#idrac-mdm-01",
    )


@pytest.fixture(autouse=True)
def _reset_kev_cache():
    cve_intel.reset_cache()
    yield
    cve_intel.reset_cache()


def _patch_enrichment(monkeypatch, kev_ids=frozenset()):
    def fake_get(url, timeout=15.0):
        if "cisa.gov" in url:
            return {"vulnerabilities": [{"cveID": cve_id} for cve_id in kev_ids]}
        if "first.org" in url:
            return EPSS_EMPTY
        return NVD_NO_RESULT

    monkeypatch.setattr(cve_intel, "_http_get_json", fake_get)


def test_scan_unknown_target_returns_empty_list_without_network(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("should not touch the network for an unmapped target")

    monkeypatch.setattr(cve_intel, "_http_get_json", boom)

    assert firmware_hardware.scan("host:no-such-device.example.internal", _resolution()) == []


def test_scan_returns_one_finding_per_keyword_match(monkeypatch):
    monkeypatch.setattr(cve_intel, "search_nvd_by_keyword", lambda keyword, results_limit=5: KEYWORD_SEARCH_FIXTURE["vulnerabilities"])
    _patch_enrichment(monkeypatch)

    findings = firmware_hardware.scan("host:idrac-mdm-01.example-stibo.internal", _resolution())

    assert len(findings) == 2
    cve_ids = {f["identifiers"]["cve"][0] for f in findings}
    assert cve_ids == {"CVE-2013-4783", "CVE-2016-5685"}


def test_finding_discloses_unversioned_match_and_low_confidence(monkeypatch):
    monkeypatch.setattr(cve_intel, "search_nvd_by_keyword", lambda keyword, results_limit=5: KEYWORD_SEARCH_FIXTURE["vulnerabilities"])
    _patch_enrichment(monkeypatch)

    finding = firmware_hardware.scan("host:idrac-mdm-01.example-stibo.internal", _resolution())[0]

    assert "Unversioned NVD keyword match" in finding["description"]
    assert finding["confidence"] < 0.5
    assert finding["false_positive_likelihood"] > 0.3
    assert "Confirm the installed" in finding["suggested_remediation"]


def test_finding_uses_cvss_from_entry_when_nvd_lookup_has_none(monkeypatch):
    monkeypatch.setattr(cve_intel, "search_nvd_by_keyword", lambda keyword, results_limit=5: KEYWORD_SEARCH_FIXTURE["vulnerabilities"])
    _patch_enrichment(monkeypatch)

    finding = firmware_hardware.scan("host:idrac-mdm-01.example-stibo.internal", _resolution())[0]

    # enrich_cve's own NVD-by-id lookup is empty (NVD_NO_RESULT), so the
    # adapter must fall back to the CVSS already present on the keyword
    # search entry itself rather than losing it or defaulting silently.
    assert finding["cvss_v4"]["base"] == 10.0


def test_finding_falls_back_to_default_cvss_when_none_available(monkeypatch):
    fixture = [KEYWORD_SEARCH_FIXTURE["vulnerabilities"][1]]  # CVE-2016-5685: empty metrics
    monkeypatch.setattr(cve_intel, "search_nvd_by_keyword", lambda keyword, results_limit=5: fixture)
    _patch_enrichment(monkeypatch)

    finding = firmware_hardware.scan("host:idrac-mdm-01.example-stibo.internal", _resolution())[0]

    assert finding["cvss_v4"]["base"] == 5.0


def test_kev_listed_match_flagged_known_exploited(monkeypatch):
    monkeypatch.setattr(cve_intel, "search_nvd_by_keyword", lambda keyword, results_limit=5: [KEYWORD_SEARCH_FIXTURE["vulnerabilities"][0]])
    _patch_enrichment(monkeypatch, kev_ids={"CVE-2013-4783"})

    finding = firmware_hardware.scan("host:idrac-mdm-01.example-stibo.internal", _resolution())[0]

    assert finding["kev_listed"] is True
    assert finding["exploitation_status"] == "known_exploited"


def test_finding_is_schema_valid(monkeypatch):
    monkeypatch.setattr(cve_intel, "search_nvd_by_keyword", lambda keyword, results_limit=5: [KEYWORD_SEARCH_FIXTURE["vulnerabilities"][0]])
    _patch_enrichment(monkeypatch)

    raw = firmware_hardware.scan("host:idrac-mdm-01.example-stibo.internal", _resolution())[0]
    finding = dict(raw)
    finding.update(
        finding_id="a" * 64,
        run_id="run-test",
        domain="firmware-hardware",
        entity="Stibo Systems",
        asset={"asset_id": "idrac-mdm-01", "type": "firmware", "owner_team": "mdm-platform", "criticality": "high"},
        first_seen="2026-09-18T00:00:00Z",
        last_seen="2026-09-18T00:00:00Z",
        status="new",
        scope_ref="assets.yaml#idrac-mdm-01",
        authorization_ref=None,
    )
    validate_finding(finding)  # must not raise


def test_cwe_ids_extracted_and_empty_when_absent(monkeypatch):
    monkeypatch.setattr(cve_intel, "search_nvd_by_keyword", lambda keyword, results_limit=5: KEYWORD_SEARCH_FIXTURE["vulnerabilities"])
    _patch_enrichment(monkeypatch)

    findings = firmware_hardware.scan("host:idrac-mdm-01.example-stibo.internal", _resolution())

    by_cve = {f["identifiers"]["cve"][0]: f for f in findings}
    assert by_cve["CVE-2013-4783"]["identifiers"]["cwe"] == ["CWE-287"]
    assert by_cve["CVE-2016-5685"]["identifiers"]["cwe"] == []
