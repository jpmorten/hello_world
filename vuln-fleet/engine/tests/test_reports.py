import json
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from engine import reports


@dataclass
class _FakeRollup:
    targets_attempted: list
    targets_failed: dict = field(default_factory=dict)
    findings: list = field(default_factory=list)


def _finding(**overrides) -> dict:
    finding = {
        "finding_id": "f1",
        "title": "Vulnerable dependency: lodash@4.17.15",
        "domain": "supply-chain",
        "asset": {"asset_id": "svc-checkout", "owner_team": "checkout-platform", "criticality": "high"},
        "location": {"kind": "repo", "ref": "repo:stibo/checkout"},
        "risk_score": 60.0,
        "regulatory_tags": ["NIS2"],
        "kev_listed": False,
        "status": "new",
    }
    finding.update(overrides)
    return finding


def _issue(**overrides) -> dict:
    issue = {
        "issue_id": "CVE-2024-12345",
        "cve": "CVE-2024-12345",
        "finding_ids": ["f1"],
        "domains": ["supply-chain"],
        "asset_ids": ["svc-checkout"],
        "exposure_count": 1,
        "kev_listed": False,
        "risk_score": 60.0,
    }
    issue.update(overrides)
    return issue


# -- severity_band ------------------------------------------------------------


@pytest.mark.parametrize(
    "score,expected_band,expected_sla",
    [(95.0, "Critical", 15), (90.0, "Critical", 15), (89.9, "High", 30), (70.0, "High", 30), (69.9, "Medium", 90), (40.0, "Medium", 90), (0.0, "Low", 180)],
)
def test_severity_band_thresholds(score, expected_band, expected_sla):
    assert reports.severity_band(score) == (expected_band, expected_sla)


# -- write_reports: file set ----------------------------------------------------


def test_write_reports_creates_all_six_files(tmp_path):
    findings = [_finding()]
    issues = [_issue()]
    rollups = {"supply-chain": _FakeRollup(targets_attempted=["repo:stibo/checkout"], findings=findings)}
    delta = {"new": ["f1"], "recurring": [], "resolved": [], "regressed": []}

    paths = reports.write_reports(tmp_path, "run-1", findings, issues, rollups, delta, previous_run_id=None)

    assert set(paths) == {"findings_json", "issues_json", "posture_md", "by_domain_md", "remediation_board_md", "compliance_view_md"}
    for path_str in paths.values():
        assert Path(path_str).exists()


def test_write_reports_findings_json_roundtrips(tmp_path):
    findings = [_finding()]
    rollups = {"supply-chain": _FakeRollup(targets_attempted=["repo:stibo/checkout"], findings=findings)}

    paths = reports.write_reports(tmp_path, "run-1", findings, [_issue()], rollups, {"new": [], "recurring": [], "resolved": [], "regressed": []}, None)

    on_disk = json.loads((tmp_path / "findings.json").read_text())
    assert on_disk == findings


# -- posture.md -----------------------------------------------------------------


def test_posture_clean_when_no_findings(tmp_path):
    rollups = {"supply-chain": _FakeRollup(targets_attempted=[])}
    paths = reports.write_reports(tmp_path, "run-1", [], [], rollups, {"new": [], "recurring": [], "resolved": [], "regressed": []}, None)

    text = (tmp_path / "posture.md").read_text()
    assert "**CLEAN**" in text
    assert "No findings this run." in text


def test_posture_critical_label_when_top_issue_is_critical():
    findings = [_finding(risk_score=95.0)]
    issues = [_issue(risk_score=95.0)]
    rollups = {"supply-chain": _FakeRollup(targets_attempted=["repo:x"], findings=findings)}
    text = _posture_text(rollups, findings, issues)

    assert "**CRITICAL**" in text
    assert "highest single issue risk: 95.0" in text


def test_posture_lists_top_10_issues_ranked_by_risk():
    issues = [_issue(issue_id=f"CVE-{i}", risk_score=float(i)) for i in range(15)]
    rollups = {"supply-chain": _FakeRollup(targets_attempted=[])}
    text = _posture_text(rollups, [], issues)

    assert "1. **CVE-14**" in text  # highest risk_score (14) ranked first
    assert "CVE-0" not in text  # only top 10 shown


def test_posture_coverage_gap_named_with_target_and_reason():
    rollups = {"supply-chain": _FakeRollup(targets_attempted=["repo:a", "repo:b"], targets_failed={"repo:b": "scope_violation: excluded"})}
    text = _posture_text(rollups, [], [])

    assert "1/2 target(s) assessed" in text
    assert "`repo:b` — scope_violation: excluded" in text


def test_posture_no_previous_run_says_so_explicitly():
    rollups = {"supply-chain": _FakeRollup(targets_attempted=[])}
    text = _posture_text(rollups, [], [], previous_run_id=None)

    assert "No previous run to compare against" in text


def test_posture_delta_with_previous_run_shows_counts_and_regressed_titles():
    findings = [_finding(finding_id="f1", title="Something bad came back")]
    rollups = {"supply-chain": _FakeRollup(targets_attempted=[])}
    delta = {"new": [], "recurring": [], "resolved": [], "regressed": ["f1"]}
    text = _posture_text(rollups, findings, [], delta=delta, previous_run_id="run-0")

    assert "Compared against `run-0`" in text
    assert "Regressed: 1" in text
    assert "Something bad came back" in text


def _posture_text(rollups, findings, issues, delta=None, previous_run_id=None) -> str:
    delta = delta or {"new": [], "recurring": [], "resolved": [], "regressed": []}
    return reports._render_posture("run-1", findings, issues, rollups, delta, previous_run_id)


# -- by-domain.md -----------------------------------------------------------------


def test_by_domain_has_one_section_per_domain():
    rollups = {
        "supply-chain": _FakeRollup(targets_attempted=["repo:a"], findings=[_finding()]),
        "api-surface": _FakeRollup(targets_attempted=["endpoint:b"]),
    }

    text = reports._render_by_domain(rollups)

    assert "## supply-chain" in text
    assert "## api-surface" in text
    assert "No findings." in text  # api-surface has none


def test_by_domain_findings_sorted_by_risk_descending():
    findings = [_finding(finding_id="low", title="Low risk", risk_score=10.0), _finding(finding_id="high", title="High risk", risk_score=90.0)]
    rollups = {"supply-chain": _FakeRollup(targets_attempted=["repo:a"], findings=findings)}

    text = reports._render_by_domain(rollups)

    assert text.index("High risk") < text.index("Low risk")


def test_by_domain_lists_coverage_gaps():
    rollups = {"supply-chain": _FakeRollup(targets_attempted=["repo:a"], targets_failed={"repo:a": "adapter_error: boom"})}

    text = reports._render_by_domain(rollups)

    assert "`repo:a`: adapter_error: boom" in text


# -- remediation-board.md -----------------------------------------------------------


def test_remediation_board_empty_when_no_issues():
    text = reports._render_remediation_board([], [])

    assert "No open issues." in text


def test_remediation_board_ranks_by_risk_and_shows_owner_and_sla():
    findings = [_finding(finding_id="f1", risk_score=95.0)]
    issues = [_issue(risk_score=95.0)]

    text = reports._render_remediation_board(issues, findings)

    assert "checkout-platform" in text
    assert "Critical" in text
    assert "| 15 |" in text  # SLA days for Critical
    assert "Low (dependency version bump)" in text  # supply-chain effort mapping


def test_remediation_board_unmapped_domain_gets_default_effort():
    findings = [_finding(finding_id="f1", domain="some-future-domain")]
    issues = [_issue(domains=["some-future-domain"])]

    text = reports._render_remediation_board(issues, findings)

    assert reports.DEFAULT_EFFORT_ESTIMATE in text


def test_remediation_board_unassigned_owner_when_no_matching_findings():
    issues = [_issue(finding_ids=["missing-finding-id"])]

    text = reports._render_remediation_board(issues, [])

    assert "unassigned" in text


# -- compliance-view.md --------------------------------------------------------------


def test_compliance_view_always_shows_headline_sections_even_when_empty():
    text = reports._render_compliance_view([])

    for tag in reports.REGULATORY_HEADLINE_TAGS:
        assert f"## {tag}" in text
        assert f"No findings currently tagged {tag}." in text


def test_compliance_view_lists_matching_findings_under_their_tag():
    findings = [_finding(regulatory_tags=["GDPR", "NIS2"])]

    text = reports._render_compliance_view(findings)

    assert "## GDPR" in text
    assert "## NIS2" in text
    assert "1 finding(s):" in text.split("## GDPR")[1]


def test_compliance_view_does_not_claim_annex_a_control_mapping():
    text = reports._render_compliance_view([])

    assert "does NOT map to specific ISO 27001" in text


def test_compliance_view_other_tags_section_for_non_headline_tags():
    findings = [_finding(regulatory_tags=["SOC2"])]

    text = reports._render_compliance_view(findings)

    assert "## Other tags present this run" in text
    assert "**SOC2**: 1 finding(s)" in text


def test_compliance_view_no_other_tags_section_when_none_present():
    findings = [_finding(regulatory_tags=["NIS2"])]

    text = reports._render_compliance_view(findings)

    assert "## Other tags present this run" not in text
