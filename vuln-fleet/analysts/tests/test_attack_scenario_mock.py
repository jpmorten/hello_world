from analysts.mock import attack_scenario


def _finding(finding_id: str, title: str) -> dict:
    return {"finding_id": finding_id, "title": title, "evidence_ref": [f"evidence://{finding_id}"]}


def _issue(issue_id: str, risk_score: float, finding_id: str) -> dict:
    return {"issue_id": issue_id, "risk_score": risk_score, "finding_ids": [finding_id]}


def test_synthesize_returns_empty_with_fewer_than_two_issues():
    findings = [_finding("f1", "Only one finding")]
    issues = [_issue("i1", 50.0, "f1")]

    assert attack_scenario.synthesize(findings, issues) == []


def test_synthesize_chains_top_two_issues_by_risk():
    findings = [_finding("f1", "High risk finding"), _finding("f2", "Medium risk finding"), _finding("f3", "Low risk finding")]
    issues = [_issue("i1", 30.0, "f3"), _issue("i2", 90.0, "f1"), _issue("i3", 60.0, "f2")]

    scenarios = attack_scenario.synthesize(findings, issues)

    assert len(scenarios) == 1
    assert scenarios[0]["chained_finding_ids"] == ["f1", "f2"]  # the two highest-risk, not the lowest


def test_synthesize_output_is_clearly_labeled_as_mock():
    findings = [_finding("f1", "A"), _finding("f2", "B")]
    issues = [_issue("i1", 90.0, "f1"), _issue("i2", 60.0, "f2")]

    scenario = attack_scenario.synthesize(findings, issues)[0]

    assert "MOCK ANALYSIS" in scenario["title"]
    assert "MOCK ANALYSIS" in scenario["narrative"]
    assert "not a real attacker assessment" in scenario["narrative"].lower()


def test_synthesize_never_claims_high_likelihood_or_confidence():
    findings = [_finding("f1", "A"), _finding("f2", "B")]
    issues = [_issue("i1", 90.0, "f1"), _issue("i2", 60.0, "f2")]

    scenario = attack_scenario.synthesize(findings, issues)[0]

    assert scenario["likelihood"] == "low"
    assert scenario["confidence"] < 0.2


def test_synthesize_returns_empty_when_issue_finding_ids_are_unknown():
    findings = [_finding("f1", "A")]  # f2 missing from findings
    issues = [_issue("i1", 90.0, "f1"), _issue("i2", 60.0, "f2")]

    assert attack_scenario.synthesize(findings, issues) == []
