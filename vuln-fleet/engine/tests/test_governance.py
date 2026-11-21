from datetime import datetime, timezone
from pathlib import Path

import pytest

from engine import governance
from schema.validate import validate_governance_report

FIXED_NOW = lambda: datetime(2026, 1, 1, tzinfo=timezone.utc)  # noqa: E731


def _repo_root(tmp_path, budget_tokens=1000, alert_threshold_pct=20) -> Path:
    """A minimal, synthetic repo tree with no policy/ethics violations,
    so tests can layer in exactly the one thing they want to break."""
    root = tmp_path / "repo"
    (root / ".claude" / "agents").mkdir(parents=True)
    (root / ".claude" / "agents" / "clean-agent.md").write_text(
        "---\nname: clean-agent\ntools: Read, Grep, Glob, Bash\nmodel: sonnet\n---\n\nBody.\n"
    )
    (root / "schema").mkdir(parents=True)
    (root / "schema" / "finding.schema.json").write_text(
        '{"required": ["confidence", "false_positive_likelihood", "regulatory_tags", '
        '"evidence_ref", "suggested_remediation"]}'
    )
    (root / "analysts" / "mock").mkdir(parents=True)
    (root / "analysts" / "mock" / "attack_scenario.py").write_text('TAG = "[MOCK ANALYSIS -- ...]"\n')
    (root / "scope").mkdir(parents=True)
    (root / "scope" / "assets.yaml").write_text("assets: []\n")
    (root / "scope" / "token-budget.yaml").write_text(
        f"budget_tokens: {budget_tokens}\nalert_threshold_pct: {alert_threshold_pct}\n"
    )
    return root


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


# -- compile_governance_report: verdict computation --------------------------


def test_clean_run_produces_clear_verdict(tmp_path):
    root = _repo_root(tmp_path)

    report = governance.compile_governance_report(
        run_id="run-1", repo_root=root, findings=[_finding()], scenarios=[], events=[], now_fn=FIXED_NOW
    )

    assert report["verdict"] == "clear"
    assert report["kill_switch_engaged"] is False
    assert report["escalation_reason"] is None
    validate_governance_report(report)


def test_policy_violation_drives_critical_verdict(tmp_path):
    root = _repo_root(tmp_path)
    (root / ".claude" / "agents" / "bad-agent.md").write_text(
        "---\nname: bad-agent\ntools: Read, Write\nmodel: sonnet\n---\n\nBody.\n"
    )

    report = governance.compile_governance_report(
        run_id="run-1", repo_root=root, findings=[_finding()], scenarios=[], events=[], now_fn=FIXED_NOW
    )

    assert report["verdict"] == "critical"
    assert report["kill_switch_engaged"] is True
    assert report["escalation_reason"]
    assert len(report["policy"]["violations"]) == 1


def test_ethics_flag_drives_critical_verdict(tmp_path):
    root = _repo_root(tmp_path)

    report = governance.compile_governance_report(
        run_id="run-1",
        repo_root=root,
        findings=[_finding(exploitation_status="fleet_exploited_it")],
        scenarios=[],
        events=[],
        now_fn=FIXED_NOW,
    )

    assert report["verdict"] == "critical"
    assert report["kill_switch_engaged"] is True


def test_cost_alert_alone_drives_warning_not_critical(tmp_path):
    root = _repo_root(tmp_path, budget_tokens=1000, alert_threshold_pct=20)

    report = governance.compile_governance_report(
        run_id="run-1",
        repo_root=root,
        findings=[_finding()],
        scenarios=[],
        events=[],
        tokens_used=900,  # 10% remaining, below the 20% threshold
        now_fn=FIXED_NOW,
    )

    assert report["verdict"] == "warning"
    assert report["kill_switch_engaged"] is False
    assert report["escalation_reason"]
    assert report["cost"]["alert"] is True
    assert report["cost"]["measured"] is True


def test_tokens_used_none_never_writes_the_ledger(tmp_path):
    root = _repo_root(tmp_path)

    report = governance.compile_governance_report(
        run_id="run-1", repo_root=root, findings=[_finding()], scenarios=[], events=[], now_fn=FIXED_NOW
    )

    assert report["cost"]["measured"] is False
    assert not (root / "scope" / "token-usage-ledger.yaml").exists()


def test_report_id_is_deterministic_for_same_run_id_and_timestamp(tmp_path):
    root = _repo_root(tmp_path)

    a = governance.compile_governance_report(
        run_id="run-1", repo_root=root, findings=[], scenarios=[], events=[], now_fn=FIXED_NOW
    )
    b = governance.compile_governance_report(
        run_id="run-1", repo_root=root, findings=[], scenarios=[], events=[], now_fn=FIXED_NOW
    )

    assert a["report_id"] == b["report_id"]


# -- fleet halt lifecycle -----------------------------------------------------


def test_fleet_halt_status_none_when_no_flag(tmp_path):
    assert governance.fleet_halt_status(tmp_path / "FLEET_HALT.flag") is None


def test_trigger_fleet_halt_writes_a_readable_record(tmp_path):
    halt_path = tmp_path / "FLEET_HALT.flag"

    governance.trigger_fleet_halt("something is off", "report-123", halt_path, now_fn=FIXED_NOW)
    record = governance.fleet_halt_status(halt_path)

    assert record["reason"] == "something is off"
    assert record["report_ref"] == "report-123"
    assert record["halted_at"] == "2026-01-01T00:00:00Z"


def test_raise_if_halted_raises_fleet_halted_with_the_record(tmp_path):
    halt_path = tmp_path / "FLEET_HALT.flag"
    governance.trigger_fleet_halt("bad news", "report-123", halt_path, now_fn=FIXED_NOW)

    with pytest.raises(governance.FleetHalted) as exc_info:
        governance.raise_if_halted(halt_path)

    assert exc_info.value.halt_record["reason"] == "bad news"


def test_raise_if_halted_is_a_noop_when_not_halted(tmp_path):
    governance.raise_if_halted(tmp_path / "FLEET_HALT.flag")  # must not raise


def test_clear_fleet_halt_removes_the_flag_and_reports_whether_one_existed(tmp_path):
    halt_path = tmp_path / "FLEET_HALT.flag"
    governance.trigger_fleet_halt("bad news", "report-123", halt_path, now_fn=FIXED_NOW)

    assert governance.clear_fleet_halt(halt_path) is True
    assert governance.fleet_halt_status(halt_path) is None
    assert governance.clear_fleet_halt(halt_path) is False
