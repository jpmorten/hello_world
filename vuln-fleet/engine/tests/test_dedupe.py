import pytest

from engine.dedupe import compute_finding_id, correlate_findings, dedupe_findings


def _finding(**overrides) -> dict:
    finding = {
        "finding_id": "id-1",
        "domain": "supply-chain",
        "identifiers": {"cve": ["CVE-2024-12345"], "cwe": [], "ghsa": []},
        "asset": {"asset_id": "svc-checkout", "criticality": "high"},
        "evidence_ref": ["ev-1"],
        "first_seen": "2026-09-18T00:00:00Z",
        "last_seen": "2026-09-18T00:00:00Z",
        "kev_listed": False,
        "cvss_v4": {"base": 7.5},
        "epss": 0.1,
        "risk_score": 50.0,
    }
    finding.update(overrides)
    return finding


# -- compute_finding_id --------------------------------------------------------


def test_finding_id_deterministic_for_same_inputs():
    a = compute_finding_id(domain="supply-chain", identifiers={"cve": ["CVE-2024-12345"]}, asset_id="svc-checkout", location_ref="repo:x")
    b = compute_finding_id(domain="supply-chain", identifiers={"cve": ["CVE-2024-12345"]}, asset_id="svc-checkout", location_ref="repo:x")

    assert a == b


def test_finding_id_ignores_cve_order():
    a = compute_finding_id(domain="d", identifiers={"cve": ["CVE-1", "CVE-2"]}, asset_id="a", location_ref="r")
    b = compute_finding_id(domain="d", identifiers={"cve": ["CVE-2", "CVE-1"]}, asset_id="a", location_ref="r")

    assert a == b


def test_finding_id_falls_back_to_title_when_no_cve():
    a = compute_finding_id(domain="d", identifiers={}, asset_id="a", location_ref="r", title="Same title")
    b = compute_finding_id(domain="d", identifiers={}, asset_id="a", location_ref="r", title="Same title")
    c = compute_finding_id(domain="d", identifiers={}, asset_id="a", location_ref="r", title="Different title")

    assert a == b
    assert a != c


def test_finding_id_differs_across_domains_for_same_everything_else():
    a = compute_finding_id(domain="supply-chain", identifiers={"cve": ["CVE-1"]}, asset_id="a", location_ref="r")
    b = compute_finding_id(domain="code-firstparty", identifiers={"cve": ["CVE-1"]}, asset_id="a", location_ref="r")

    assert a != b


# -- dedupe_findings ------------------------------------------------------------


def test_dedupe_collapses_identical_finding_ids():
    findings = [_finding(finding_id="x", evidence_ref=["a"]), _finding(finding_id="x", evidence_ref=["b"])]

    result = dedupe_findings(findings)

    assert len(result) == 1
    assert result[0]["evidence_ref"] == ["a", "b"]


def test_dedupe_widens_first_last_seen_window():
    findings = [
        _finding(finding_id="x", first_seen="2026-09-10T00:00:00Z", last_seen="2026-09-10T00:00:00Z"),
        _finding(finding_id="x", first_seen="2026-09-01T00:00:00Z", last_seen="2026-09-15T00:00:00Z"),
    ]

    result = dedupe_findings(findings)[0]

    assert result["first_seen"] == "2026-09-01T00:00:00Z"
    assert result["last_seen"] == "2026-09-15T00:00:00Z"


def test_dedupe_preserves_distinct_findings():
    findings = [_finding(finding_id="x"), _finding(finding_id="y")]

    assert len(dedupe_findings(findings)) == 2


# -- correlate_findings ---------------------------------------------------------


def test_correlate_groups_shared_cve_across_domains():
    findings = [
        _finding(finding_id="f1", domain="supply-chain", identifiers={"cve": ["CVE-X"]}, asset={"asset_id": "a1", "criticality": "high"}),
        _finding(finding_id="f2", domain="firmware-hardware", identifiers={"cve": ["CVE-X"]}, asset={"asset_id": "a2", "criticality": "critical"}),
    ]

    issues = correlate_findings(findings)

    assert len(issues) == 1
    issue = issues[0]
    assert issue["issue_id"] == "CVE-X"
    assert set(issue["finding_ids"]) == {"f1", "f2"}
    assert issue["domains"] == ["firmware-hardware", "supply-chain"]
    assert issue["asset_ids"] == ["a1", "a2"]
    assert issue["exposure_count"] == 2


def test_correlate_no_cve_findings_become_standalone_issues():
    findings = [_finding(finding_id="f1", identifiers={"cve": []}), _finding(finding_id="f2", identifiers={"cve": []})]

    issues = correlate_findings(findings)

    assert len(issues) == 2
    assert {i["issue_id"] for i in issues} == {"f1", "f2"}
    assert all(i["cve"] is None for i in issues)
    assert all(i["exposure_count"] == 1 for i in issues)


def test_correlate_every_finding_appears_in_exactly_one_issue():
    findings = [
        _finding(finding_id="f1", identifiers={"cve": ["CVE-X"]}),
        _finding(finding_id="f2", identifiers={"cve": ["CVE-X"]}),
        _finding(finding_id="f3", identifiers={"cve": []}),
    ]

    issues = correlate_findings(findings)
    all_finding_ids = [fid for issue in issues for fid in issue["finding_ids"]]

    assert sorted(all_finding_ids) == ["f1", "f2", "f3"]


def test_correlate_issue_kev_listed_true_if_any_member_is():
    findings = [
        _finding(finding_id="f1", identifiers={"cve": ["CVE-X"]}, kev_listed=False),
        _finding(finding_id="f2", identifiers={"cve": ["CVE-X"]}, kev_listed=True),
    ]

    issue = correlate_findings(findings)[0]

    assert issue["kev_listed"] is True


def test_correlate_issue_risk_score_uses_score_issue(monkeypatch):
    from engine import dedupe

    monkeypatch.setattr(dedupe, "score_issue", lambda members: 42.0)
    findings = [_finding(finding_id="f1", identifiers={"cve": ["CVE-X"]})]

    issue = correlate_findings(findings)[0]

    assert issue["risk_score"] == 42.0


def test_correlate_different_ghsa_no_cve_are_not_merged():
    findings = [
        _finding(finding_id="f1", identifiers={"cve": [], "ghsa": ["GHSA-aaaa-aaaa-aaaa"]}, title="A"),
        _finding(finding_id="f2", identifiers={"cve": [], "ghsa": ["GHSA-bbbb-bbbb-bbbb"]}, title="B"),
    ]

    issues = correlate_findings(findings)

    assert len(issues) == 2
