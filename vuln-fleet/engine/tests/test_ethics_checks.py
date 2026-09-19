from engine import ethics_checks


def _finding(**overrides) -> dict:
    finding = {
        "finding_id": "f1",
        "domain": "supply-chain",
        "exploitation_status": "no_known_exploitation",
        "location": {"kind": "repo", "ref": "repo:stibo/checkout"},
        "evidence_ref": ["osv://GHSA-xxxx"],
    }
    finding.update(overrides)
    return finding


def _scenario(**overrides) -> dict:
    scenario = {"scenario_id": "s1", "status": "predicted"}
    scenario.update(overrides)
    return scenario


# -- check_exploitation_status_vocabulary -----------------------------------


def test_exploitation_status_within_vocabulary_produces_no_flag():
    assert ethics_checks.check_exploitation_status_vocabulary([_finding()]) == []


def test_exploitation_status_outside_vocabulary_flagged_critical():
    flags = ethics_checks.check_exploitation_status_vocabulary([_finding(exploitation_status="fleet_exploited_it")])

    assert len(flags) == 1
    assert flags[0].severity == "critical"
    assert flags[0].guardrail == "no_self_exploitation"


# -- check_attack_scenarios_never_confirmed ----------------------------------


def test_predicted_scenario_produces_no_flag():
    assert ethics_checks.check_attack_scenarios_never_confirmed([_scenario()]) == []


def test_non_predicted_status_flagged_critical():
    flags = ethics_checks.check_attack_scenarios_never_confirmed([_scenario(status="confirmed")])

    assert len(flags) == 1
    assert flags[0].severity == "critical"
    assert flags[0].guardrail == "predictions_never_validated"


def test_empty_scenarios_list_produces_no_flags():
    assert ethics_checks.check_attack_scenarios_never_confirmed([]) == []


# -- check_scope_violations_were_actually_refused ----------------------------


def test_no_scope_violations_means_no_flags():
    events = [{"event_type": "finding", "details": {"location": {"ref": "repo:stibo/checkout"}}}]

    assert ethics_checks.check_scope_violations_were_actually_refused(events) == []


def test_scope_violation_with_no_matching_finding_produces_no_flag():
    events = [
        {"event_type": "scope_violation", "details": {"target_ref": "repo:unknown/ghost"}},
        {"event_type": "finding", "details": {"location": {"ref": "repo:stibo/checkout"}}},
    ]

    assert ethics_checks.check_scope_violations_were_actually_refused(events) == []


def test_scope_violation_with_matching_finding_flagged_critical():
    events = [
        {"event_type": "scope_violation", "details": {"target_ref": "repo:unknown/ghost"}},
        {"event_type": "finding", "details": {"location": {"ref": "repo:unknown/ghost"}}},
    ]

    flags = ethics_checks.check_scope_violations_were_actually_refused(events)

    assert len(flags) == 1
    assert flags[0].severity == "critical"
    assert flags[0].guardrail == "refused_targets_produce_no_findings"


# -- check_red_team_no_body_capture ------------------------------------------


def test_red_team_finding_with_normal_evidence_ref_produces_no_flag():
    finding = _finding(domain="red-team-recon", evidence_ref=["dns-header://SPF/missing"])

    assert ethics_checks.check_red_team_no_body_capture([finding]) == []


def test_red_team_finding_with_body_like_ref_flagged_warning():
    finding = _finding(domain="red-team-recon", evidence_ref=["http://example.com/body"])

    flags = ethics_checks.check_red_team_no_body_capture([finding])

    assert len(flags) == 1
    assert flags[0].severity == "warning"
    assert flags[0].guardrail == "red_team_never_captures_content"


def test_red_team_finding_with_overlong_ref_flagged_warning():
    finding = _finding(domain="red-team-recon", evidence_ref=["x" * 600])

    assert len(ethics_checks.check_red_team_no_body_capture([finding])) == 1


def test_non_red_team_finding_never_flagged_by_body_capture_check():
    finding = _finding(domain="supply-chain", evidence_ref=["http://example.com/body"])

    assert ethics_checks.check_red_team_no_body_capture([finding]) == []


# -- run_ethics_checks --------------------------------------------------------


def test_run_ethics_checks_clean_run_produces_no_flags():
    flags = ethics_checks.run_ethics_checks([_finding()], [_scenario()], [])

    assert flags == []


def test_run_ethics_checks_aggregates_every_sub_check():
    findings = [_finding(exploitation_status="bad_value")]
    scenarios = [_scenario(status="confirmed")]

    flags = ethics_checks.run_ethics_checks(findings, scenarios, [])

    guardrails = {f.guardrail for f in flags}
    assert "no_self_exploitation" in guardrails
    assert "predictions_never_validated" in guardrails


def test_run_ethics_checks_handles_none_scenarios():
    assert ethics_checks.run_ethics_checks([_finding()], None, []) == []
