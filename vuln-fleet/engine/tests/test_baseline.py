import json

import pytest

from engine import baseline


def _finding(finding_id: str) -> dict:
    return {"finding_id": finding_id, "title": finding_id}


# -- ledger persistence -----------------------------------------------------


def test_load_ledger_missing_file_returns_empty_set(tmp_path):
    assert baseline.load_ledger(tmp_path) == set()


def test_save_and_load_ledger_roundtrips(tmp_path):
    baseline.save_ledger(tmp_path, {"a", "b"})

    assert baseline.load_ledger(tmp_path) == {"a", "b"}


def test_load_ledger_corrupt_file_returns_empty_set_not_raises(tmp_path):
    (tmp_path / baseline.LEDGER_FILENAME).write_text("not valid json{{{")

    assert baseline.load_ledger(tmp_path) == set()


# -- load_previous_findings --------------------------------------------------


def test_load_previous_findings_none_run_id_returns_empty(tmp_path):
    assert baseline.load_previous_findings(tmp_path, None) == []


def test_load_previous_findings_missing_run_returns_empty(tmp_path):
    assert baseline.load_previous_findings(tmp_path, "no-such-run") == []


def test_load_previous_findings_reads_real_file(tmp_path):
    run_dir = tmp_path / "run-1"
    run_dir.mkdir()
    (run_dir / "findings.json").write_text(json.dumps([_finding("f1")]))

    assert baseline.load_previous_findings(tmp_path, "run-1") == [_finding("f1")]


# -- compute_delta ------------------------------------------------------------


def test_first_run_everything_is_new():
    delta = baseline.compute_delta([_finding("f1"), _finding("f2")], previous_findings=[], previously_resolved_ids=set())

    assert delta == {"new": ["f1", "f2"], "recurring": [], "resolved": [], "regressed": []}


def test_still_present_finding_is_recurring():
    delta = baseline.compute_delta([_finding("f1")], previous_findings=[_finding("f1")], previously_resolved_ids=set())

    assert delta["recurring"] == ["f1"]
    assert delta["new"] == []


def test_disappeared_finding_is_resolved():
    delta = baseline.compute_delta([], previous_findings=[_finding("f1")], previously_resolved_ids=set())

    assert delta["resolved"] == ["f1"]


def test_reappearing_previously_resolved_finding_is_regressed_not_new():
    delta = baseline.compute_delta(
        [_finding("f1")], previous_findings=[], previously_resolved_ids={"f1"}
    )

    assert delta["regressed"] == ["f1"]
    assert delta["new"] == []
    assert delta["recurring"] == []


# -- apply_delta_status ---------------------------------------------------------


def test_apply_delta_status_stamps_correct_status_per_finding():
    findings = [_finding("f1"), _finding("f2"), _finding("f3")]
    delta = {"new": ["f1"], "recurring": ["f2"], "resolved": [], "regressed": ["f3"]}

    updated = baseline.apply_delta_status(findings, delta)

    assert {f["finding_id"]: f["status"] for f in updated} == {"f1": "new", "f2": "recurring", "f3": "regressed"}


def test_apply_delta_status_does_not_mutate_input():
    findings = [_finding("f1")]
    baseline.apply_delta_status(findings, {"new": ["f1"], "recurring": [], "resolved": [], "regressed": []})

    assert "status" not in findings[0]


# -- compute_and_apply_delta (the real entry point) + ledger evolution ---------


def test_full_lifecycle_new_recurring_resolved_regressed(tmp_path):
    reports_root = tmp_path

    # run 1: f1 and f2 appear for the first time
    run1, delta1 = baseline.compute_and_apply_delta([_finding("f1"), _finding("f2")], reports_root, previous_run_id=None)
    assert delta1["new"] == ["f1", "f2"]
    (reports_root / "run-1").mkdir()
    (reports_root / "run-1" / "findings.json").write_text(json.dumps(run1))

    # run 2: f1 still present (recurring), f2 disappears (resolved)
    run2, delta2 = baseline.compute_and_apply_delta([_finding("f1")], reports_root, previous_run_id="run-1")
    assert delta2 == {"new": [], "recurring": ["f1"], "resolved": ["f2"], "regressed": []}
    assert baseline.load_ledger(reports_root) == {"f2"}
    (reports_root / "run-2").mkdir()
    (reports_root / "run-2" / "findings.json").write_text(json.dumps(run2))

    # run 3: f2 comes back -> regressed, not new; ledger drops it since it's active again
    run3, delta3 = baseline.compute_and_apply_delta([_finding("f1"), _finding("f2")], reports_root, previous_run_id="run-2")
    assert delta3["regressed"] == ["f2"]
    assert delta3["new"] == []
    assert baseline.load_ledger(reports_root) == set()
    statuses = {f["finding_id"]: f["status"] for f in run3}
    assert statuses == {"f1": "recurring", "f2": "regressed"}


def test_compute_and_apply_delta_handles_no_previous_run_gracefully(tmp_path):
    findings, delta = baseline.compute_and_apply_delta([_finding("f1")], tmp_path, previous_run_id=None)

    assert delta["new"] == ["f1"]
    assert findings[0]["status"] == "new"
