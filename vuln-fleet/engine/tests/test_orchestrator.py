"""Proves the full spawn -> worker -> rollup -> log -> report loop
end-to-end for two domains that need no active scanning, per the
build-order step 5 acceptance criteria: a full sweep produces a valid
hash-chained event stream, every finding traces to an agent/asset/scope
entry/evidence, an out-of-scope target is refused+logged without halting
the run, and re-running with identical input is stable.
"""
import json
from pathlib import Path

import pytest

from adapters.mock import api_surface, supply_chain
from engine.orchestrator import DomainSpec, Orchestrator
from engine.scope import ScopeModel
from schema.validate import validate_event, validate_finding

REPO_SCOPE_DIR = Path(__file__).parent.parent.parent / "scope"


def _domain_specs() -> list[DomainSpec]:
    return [
        DomainSpec(
            domain="supply-chain",
            worker_role="repo-worker",
            targets=["repo:stibo/checkout", "repo:stibo/mdm-core", "repo:unknown/ghost"],
            adapter_fn=supply_chain.scan,
        ),
        DomainSpec(
            domain="api-surface",
            worker_role="endpoint-worker",
            targets=["endpoint:https://login.example-stibo.com", "endpoint:foo.salesforce.com"],
            adapter_fn=api_surface.scan,
        ),
    ]


def _scope_model() -> ScopeModel:
    return ScopeModel(
        REPO_SCOPE_DIR / "assets.yaml",
        REPO_SCOPE_DIR / "exclusions.yaml",
        REPO_SCOPE_DIR / "authorized-active.yaml",
    )


def _run(tmp_path, run_id="e2e-run", previous_run_id=None) -> dict:
    orchestrator = Orchestrator(
        run_id,
        _scope_model(),
        log_dir=tmp_path / "logs",
        report_dir=tmp_path / "reports",
        domain_budgets={"supply-chain": 3, "api-surface": 3},
        previous_run_id=previous_run_id,
    )
    return orchestrator.run(_domain_specs())


def _log_events(tmp_path, run_id="e2e-run") -> list[dict]:
    path = tmp_path / "logs" / f"{run_id}.ndjson"
    return [json.loads(line) for line in path.read_text().strip().splitlines()]


def test_finds_expected_findings_across_both_domains(tmp_path):
    result = _run(tmp_path)

    titles = {f["title"] for f in result["findings"]}
    assert "Vulnerable transitive dependency: lodash@4.17.15" in titles
    assert "Actively exploited deserialization flaw in log-ingest@2.3.0" in titles
    assert "Deprecated API version v1 still live" in titles
    assert len(result["findings"]) == 3


def test_every_finding_is_schema_valid_and_traces_to_scope(tmp_path):
    result = _run(tmp_path)

    for finding in result["findings"]:
        validate_finding(finding)  # must not raise
        assert finding["scope_ref"].startswith("assets.yaml#")
        assert finding["evidence_ref"]


def test_kev_finding_flagged_known_exploited(tmp_path):
    result = _run(tmp_path)

    kev_finding = next(f for f in result["findings"] if f["kev_listed"])
    assert kev_finding["exploitation_status"] == "known_exploited"
    assert kev_finding["asset"]["asset_id"] == "mdm-core"


def test_out_of_scope_target_refused_logged_and_does_not_halt_run(tmp_path):
    result = _run(tmp_path)

    supply_chain_rollup = result["rollups"]["supply-chain"]
    assert "repo:unknown/ghost" in supply_chain_rollup.targets_failed
    assert "scope_violation" in supply_chain_rollup.targets_failed["repo:unknown/ghost"]
    # the run still completed and still produced the other domain's findings
    assert any(f["domain"] == "api-surface" for f in result["findings"])

    events = _log_events(tmp_path)
    violations = [e for e in events if e["event_type"] == "scope_violation"]
    assert len(violations) == 2  # repo:unknown/ghost (out of scope) + the excluded endpoint below
    assert any(v["details"]["target_ref"] == "repo:unknown/ghost" for v in violations)
    assert any(e["event_type"] == "run_complete" for e in events)  # run finished despite the gap


def test_excluded_target_refused_and_logged(tmp_path):
    result = _run(tmp_path)

    api_rollup = result["rollups"]["api-surface"]
    assert "endpoint:foo.salesforce.com" in api_rollup.targets_failed
    assert "excluded" in api_rollup.targets_failed["endpoint:foo.salesforce.com"]


def test_event_stream_is_hash_chained_and_schema_valid(tmp_path):
    _run(tmp_path)

    events = _log_events(tmp_path)
    assert events[0]["event_type"] == "run_start"
    assert events[-1]["event_type"] == "run_complete"
    for event in events:
        validate_event(event)  # must not raise for any event in the stream

    from engine.logbus import GENESIS_HASH, compute_integrity_hash

    prev_hash = GENESIS_HASH
    for event in events:
        stored_hash = event["integrity_hash"]
        recomputed = compute_integrity_hash(prev_hash, {k: v for k, v in event.items() if k != "integrity_hash"})
        assert recomputed == stored_hash
        prev_hash = stored_hash


def test_lifecycle_events_present_for_domain_and_worker_agents(tmp_path):
    _run(tmp_path)

    events = _log_events(tmp_path)
    event_types = [e["event_type"] for e in events]
    for expected in ("agent_spawn", "agent_start", "heartbeat", "finding", "agent_complete", "rollup"):
        assert expected in event_types

    domain_agent_ids = {e["agent_id"] for e in events if e["event_type"] == "rollup"}
    assert len(domain_agent_ids) == 2  # one rollup per domain


def test_scope_check_logged_for_every_successfully_resolved_target(tmp_path):
    """The audit trail should show every scope decision, not just
    refusals — matching .claude/hooks/scope_guard.py's behavior on the
    live-agent path."""
    result = _run(tmp_path)

    events = _log_events(tmp_path)
    scope_checks = [e for e in events if e["event_type"] == "scope_check"]
    resolved_targets = {e["details"]["target_ref"] for e in scope_checks}

    in_scope_targets = {
        target
        for rollup in result["rollups"].values()
        for target in rollup.targets_attempted
        if target not in rollup.targets_failed
    }
    assert resolved_targets == in_scope_targets
    assert len(scope_checks) == len(in_scope_targets)  # exactly one per resolved target, not per finding


def test_report_files_written(tmp_path):
    result = _run(tmp_path)

    findings_path = Path(result["report_paths"]["findings_json"])
    posture_path = Path(result["report_paths"]["posture_md"])
    assert findings_path.exists()
    assert posture_path.exists()

    on_disk_findings = json.loads(findings_path.read_text())
    assert len(on_disk_findings) == len(result["findings"])

    posture_text = posture_path.read_text()
    assert "Coverage gap" in posture_text
    assert "repo:unknown/ghost" in posture_text
    assert "endpoint:foo.salesforce.com" in posture_text


def test_rerun_with_identical_input_is_stable(tmp_path):
    """Same environment, same run -> same findings (by finding_id), i.e.
    a stable baseline for the delta logic step 8 will build on top of."""
    first = _run(tmp_path, run_id="run-a")
    second = _run(tmp_path, run_id="run-b")

    first_ids = {f["finding_id"] for f in first["findings"]}
    second_ids = {f["finding_id"] for f in second["findings"]}
    assert first_ids == second_ids


def test_duplicate_target_across_domains_is_not_treated_as_duplicate_spawn(tmp_path):
    """finding/spawn fingerprints are scoped per-domain, so two different
    domains scanning conceptually-different things never collide even if
    a target string were reused."""
    orchestrator = Orchestrator(
        "shared-target-run",
        _scope_model(),
        log_dir=tmp_path / "logs",
        report_dir=tmp_path / "reports",
        domain_budgets={"supply-chain": 3, "api-surface": 3},
    )
    specs = [
        DomainSpec(
            domain="supply-chain",
            worker_role="repo-worker",
            targets=["repo:stibo/checkout"],
            adapter_fn=supply_chain.scan,
        ),
        DomainSpec(
            domain="api-surface",
            worker_role="endpoint-worker",
            targets=["repo:stibo/checkout"],  # nonsensical for this domain, but must not collide
            adapter_fn=api_surface.scan,
        ),
    ]

    result = orchestrator.run(specs)

    assert "repo:stibo/checkout" not in result["rollups"]["supply-chain"].targets_failed
    assert "repo:stibo/checkout" not in result["rollups"]["api-surface"].targets_failed


# -- step 8: risk scoring, correlation, baseline delta -------------------------


def test_findings_carry_a_risk_score(tmp_path):
    result = _run(tmp_path)

    for finding in result["findings"]:
        assert 0.0 <= finding["risk_score"] <= 100.0
        validate_finding(finding)  # risk_score is optional in the schema; must still validate


def test_issues_json_written_and_covers_every_finding(tmp_path):
    result = _run(tmp_path)

    issues_path = Path(result["report_paths"]["issues_json"])
    assert issues_path.exists()
    issues = json.loads(issues_path.read_text())
    all_finding_ids = {fid for issue in issues for fid in issue["finding_ids"]}
    assert all_finding_ids == {f["finding_id"] for f in result["findings"]}


def test_kev_finding_correlates_into_its_own_high_risk_issue(tmp_path):
    result = _run(tmp_path)

    kev_finding = next(f for f in result["findings"] if f["kev_listed"])
    kev_issue = next(i for i in result["issues"] if kev_finding["finding_id"] in i["finding_ids"])

    assert kev_issue["kev_listed"] is True
    assert kev_issue["risk_score"] > 50.0


def test_posture_md_reports_top_issues_and_delta(tmp_path):
    result = _run(tmp_path)

    posture_text = Path(result["report_paths"]["posture_md"]).read_text()

    assert "## Top 10 issues by business risk" in posture_text
    assert "## Delta vs. previous run" in posture_text
    # first run: no previous run to diff against, so posture.md says so
    # explicitly rather than presenting delta counts against nothing.
    assert "No previous run to compare against" in posture_text
    assert all(f["status"] == "new" for f in result["findings"])


def test_first_run_all_findings_are_new(tmp_path):
    result = _run(tmp_path)

    assert all(f["status"] == "new" for f in result["findings"])
    assert result["delta"]["recurring"] == []
    assert result["delta"]["regressed"] == []


def test_second_run_same_findings_are_recurring(tmp_path):
    first = _run(tmp_path, run_id="run-1")
    second = _run(tmp_path, run_id="run-2", previous_run_id="run-1")

    assert set(second["delta"]["recurring"]) == {f["finding_id"] for f in first["findings"]}
    assert second["delta"]["new"] == []
    assert all(f["status"] == "recurring" for f in second["findings"])


def test_finding_disappearing_between_runs_is_resolved(tmp_path):
    orchestrator1 = Orchestrator(
        "run-1", _scope_model(), log_dir=tmp_path / "logs", report_dir=tmp_path / "reports",
        domain_budgets={"supply-chain": 3, "api-surface": 3},
    )
    orchestrator1.run(_domain_specs())

    # run 2 only sweeps api-surface: everything supply-chain found is now "missing"
    orchestrator2 = Orchestrator(
        "run-2", _scope_model(), log_dir=tmp_path / "logs", report_dir=tmp_path / "reports",
        domain_budgets={"supply-chain": 3, "api-surface": 3}, previous_run_id="run-1",
    )
    api_only_specs = [s for s in _domain_specs() if s.domain == "api-surface"]
    result2 = orchestrator2.run(api_only_specs)

    assert len(result2["delta"]["resolved"]) > 0


# -- kill switch --------------------------------------------------------------


def test_kill_flag_present_before_run_gaps_every_domain(tmp_path):
    kill_flag = tmp_path / "reports" / "e2e-run.kill"
    kill_flag.parent.mkdir(parents=True)
    kill_flag.write_text("kill requested")

    orchestrator = Orchestrator(
        "e2e-run", _scope_model(), log_dir=tmp_path / "logs", report_dir=tmp_path / "reports",
        domain_budgets={"supply-chain": 3, "api-surface": 3},
    )
    result = orchestrator.run(_domain_specs())

    assert result["findings"] == []
    for rollup in result["rollups"].values():
        assert all("kill_switch" in reason for reason in rollup.targets_failed.values())
    assert orchestrator.spawn_manager.kill_switch_active is True


def test_kill_flag_written_mid_run_stops_remaining_targets_and_domains(tmp_path):
    kill_flag = tmp_path / "reports" / "e2e-run.kill"
    calls = {"n": 0}

    def killing_adapter(target_ref, resolution):
        calls["n"] += 1
        if calls["n"] == 1:
            kill_flag.parent.mkdir(parents=True, exist_ok=True)
            kill_flag.write_text("kill requested mid-run")
        return supply_chain.scan(target_ref, resolution)

    specs = [
        DomainSpec(
            domain="supply-chain",
            worker_role="repo-worker",
            targets=["repo:stibo/checkout", "repo:stibo/mdm-core"],
            adapter_fn=killing_adapter,
        ),
        DomainSpec(domain="api-surface", worker_role="endpoint-worker", targets=["endpoint:https://login.example-stibo.com"], adapter_fn=api_surface.scan),
    ]
    orchestrator = Orchestrator(
        "e2e-run", _scope_model(), log_dir=tmp_path / "logs", report_dir=tmp_path / "reports",
        domain_budgets={"supply-chain": 3, "api-surface": 3},
    )

    result = orchestrator.run(specs)

    # first target was already in flight when the flag appeared: it completed normally
    supply_chain_rollup = result["rollups"]["supply-chain"]
    assert len(supply_chain_rollup.findings) > 0
    assert "repo:stibo/checkout" not in supply_chain_rollup.targets_failed
    # second target in the same domain: killed
    assert "kill_switch" in supply_chain_rollup.targets_failed["repo:stibo/mdm-core"]
    # the next domain never even started
    api_rollup = result["rollups"]["api-surface"]
    assert "kill_switch" in api_rollup.targets_failed["endpoint:https://login.example-stibo.com"]
    assert api_rollup.findings == []

    posture_text = Path(result["report_paths"]["posture_md"]).read_text()
    assert "kill_switch" in posture_text


# -- attack-scenario analysis (Tier 0.5) -----------------------------------------


def test_attack_scenario_analysis_disabled_by_default(tmp_path):
    """No attack_scenario_fn passed in -> the stage never runs: no
    attack_scenario events, attack_scenarios is None (not []) in the
    result, and no scenario-analysis agent is spawned."""
    result = _run(tmp_path)

    assert result["attack_scenarios"] is None
    events = _log_events(tmp_path)
    assert not any(e["event_type"] == "attack_scenario" for e in events)
    assert not any(e.get("agent_role") == "attack-scenario-analyst" for e in events)


def test_attack_scenario_fn_wired_produces_scenario_and_event(tmp_path):
    def stub_analyst(findings, issues):
        ids = [f["finding_id"] for f in findings[:2]]
        return [
            {
                "title": "Stub chain",
                "attacker_goal": "Test the wiring",
                "narrative": "An attacker would chain these two findings.",
                "attack_path": [{"step": 1, "description": "Step one", "based_on_finding_id": ids[0]}],
                "chained_finding_ids": ids,
                "likelihood": "medium",
                "confidence": 0.5,
                "potential_impact": "None -- this is a test.",
                "mitre_attack_techniques": [],
                "evidence_ref": [],
            }
        ]

    orchestrator = Orchestrator(
        "e2e-run", _scope_model(), log_dir=tmp_path / "logs", report_dir=tmp_path / "reports",
        domain_budgets={"supply-chain": 3, "api-surface": 3}, attack_scenario_fn=stub_analyst,
    )
    result = orchestrator.run(_domain_specs())

    assert len(result["attack_scenarios"]) == 1
    scenario = result["attack_scenarios"][0]
    assert scenario["title"] == "Stub chain"
    assert scenario["status"] == "predicted"
    assert scenario["run_id"] == "e2e-run"

    events = _log_events(tmp_path)
    scenario_events = [e for e in events if e["event_type"] == "attack_scenario"]
    assert len(scenario_events) == 1
    assert scenario_events[0]["details"]["scenario_id"] == scenario["scenario_id"]
    assert scenario_events[0]["agent_role"] == "attack-scenario-analyst"

    attack_scenarios_text = Path(result["report_paths"]["attack_scenarios_md"]).read_text()
    assert "Stub chain" in attack_scenarios_text


def test_attack_scenario_fn_returning_bad_finding_id_is_rejected_not_crashed(tmp_path):
    def hallucinating_analyst(findings, issues):
        return [
            {
                "title": "Hallucinated chain",
                "attacker_goal": "x",
                "narrative": "x",
                "attack_path": [],
                "chained_finding_ids": ["not-a-real-finding-id", "also-not-real"],
                "likelihood": "low",
                "confidence": 0.1,
                "potential_impact": "x",
                "mitre_attack_techniques": [],
                "evidence_ref": [],
            }
        ]

    orchestrator = Orchestrator(
        "e2e-run", _scope_model(), log_dir=tmp_path / "logs", report_dir=tmp_path / "reports",
        domain_budgets={"supply-chain": 3, "api-surface": 3}, attack_scenario_fn=hallucinating_analyst,
    )
    result = orchestrator.run(_domain_specs())

    assert result["attack_scenarios"] == []  # rejected, not accepted
    events = _log_events(tmp_path)
    assert not any(e["event_type"] == "attack_scenario" for e in events)
    rejection_events = [e for e in events if e["event_type"] == "agent_error" and "rejected" in e["message"]]
    assert len(rejection_events) == 1
    assert "not-a-real-finding-id" in rejection_events[0]["message"]


def test_attack_scenario_fn_raising_does_not_crash_the_run(tmp_path):
    def broken_analyst(findings, issues):
        raise RuntimeError("analyst blew up")

    orchestrator = Orchestrator(
        "e2e-run", _scope_model(), log_dir=tmp_path / "logs", report_dir=tmp_path / "reports",
        domain_budgets={"supply-chain": 3, "api-surface": 3}, attack_scenario_fn=broken_analyst,
    )
    result = orchestrator.run(_domain_specs())  # must not raise

    assert result["attack_scenarios"] == []
    events = _log_events(tmp_path)
    assert any(e["event_type"] == "run_complete" for e in events)  # run still finished


def test_attack_scenario_analysis_skipped_when_kill_switch_already_active(tmp_path):
    """Reproduces a real bug caught by the full suite: spawning the
    analysis agent after a kill switch trip raised SpawnRefused instead
    of being skipped like any other new activity a killed run refuses."""
    def never_called_analyst(findings, issues):
        raise AssertionError("should never be called once the kill switch has tripped")

    kill_flag = tmp_path / "reports" / "e2e-run.kill"

    def killing_adapter(target_ref, resolution):
        kill_flag.parent.mkdir(parents=True, exist_ok=True)
        kill_flag.write_text("kill requested mid-run")
        return supply_chain.scan(target_ref, resolution)

    specs = [
        DomainSpec(domain="supply-chain", worker_role="repo-worker", targets=["repo:stibo/checkout"], adapter_fn=killing_adapter),
    ]
    orchestrator = Orchestrator(
        "e2e-run", _scope_model(), log_dir=tmp_path / "logs", report_dir=tmp_path / "reports",
        domain_budgets={"supply-chain": 3}, attack_scenario_fn=never_called_analyst,
    )

    result = orchestrator.run(specs)  # must not raise

    assert result["attack_scenarios"] == []


def test_attack_scenario_analysis_skipped_with_no_findings(tmp_path):
    def never_called_analyst(findings, issues):
        raise AssertionError("should never be called when there are no findings")

    orchestrator = Orchestrator(
        "e2e-run", _scope_model(), log_dir=tmp_path / "logs", report_dir=tmp_path / "reports",
        domain_budgets={"supply-chain": 3}, attack_scenario_fn=never_called_analyst,
    )
    empty_spec = [DomainSpec(domain="supply-chain", worker_role="repo-worker", targets=[], adapter_fn=lambda t, r: [])]

    result = orchestrator.run(empty_spec)

    assert result["attack_scenarios"] == []
