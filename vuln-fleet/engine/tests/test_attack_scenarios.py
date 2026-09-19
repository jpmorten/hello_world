from engine.attack_scenarios import compute_scenario_id, finalize_scenarios


def _raw_scenario(**overrides) -> dict:
    scenario = {
        "title": "Chain A into B",
        "attacker_goal": "Reach the data lake",
        "narrative": "An attacker would chain these.",
        "attack_path": [{"step": 1, "description": "Do the thing", "based_on_finding_id": "f1"}],
        "chained_finding_ids": ["f1", "f2"],
        "likelihood": "medium",
        "confidence": 0.6,
        "potential_impact": "Data exposure.",
        "mitre_attack_techniques": [],
        "evidence_ref": [],
    }
    scenario.update(overrides)
    return scenario


def test_compute_scenario_id_is_deterministic():
    a = compute_scenario_id(run_id="run-1", chained_finding_ids=["f1", "f2"], title="Chain A into B")
    b = compute_scenario_id(run_id="run-1", chained_finding_ids=["f2", "f1"], title="Chain A into B")

    assert a == b  # order of chained_finding_ids never matters
    assert len(a) == 64


def test_compute_scenario_id_differs_for_different_runs():
    a = compute_scenario_id(run_id="run-1", chained_finding_ids=["f1", "f2"], title="Chain A into B")
    b = compute_scenario_id(run_id="run-2", chained_finding_ids=["f1", "f2"], title="Chain A into B")

    assert a != b


def test_finalize_scenarios_accepts_valid_scenario():
    accepted, rejections = finalize_scenarios([_raw_scenario()], "run-1", known_finding_ids={"f1", "f2"})

    assert len(accepted) == 1
    assert rejections == []
    assert accepted[0]["status"] == "predicted"
    assert accepted[0]["run_id"] == "run-1"
    assert len(accepted[0]["scenario_id"]) == 64


def test_finalize_scenarios_rejects_hallucinated_finding_id():
    accepted, rejections = finalize_scenarios(
        [_raw_scenario(chained_finding_ids=["f1", "does-not-exist"])], "run-1", known_finding_ids={"f1", "f2"}
    )

    assert accepted == []
    assert len(rejections) == 1
    assert "does-not-exist" in rejections[0].reason


def test_finalize_scenarios_rejects_single_finding_chain():
    accepted, rejections = finalize_scenarios(
        [_raw_scenario(chained_finding_ids=["f1"])], "run-1", known_finding_ids={"f1", "f2"}
    )

    assert accepted == []
    assert len(rejections) == 1
    assert "needs at least 2" in rejections[0].reason


def test_finalize_scenarios_one_bad_scenario_does_not_block_a_good_one():
    scenarios = [
        _raw_scenario(title="Good chain", chained_finding_ids=["f1", "f2"]),
        _raw_scenario(title="Bad chain", chained_finding_ids=["f1", "ghost"]),
    ]

    accepted, rejections = finalize_scenarios(scenarios, "run-1", known_finding_ids={"f1", "f2"})

    assert len(accepted) == 1
    assert accepted[0]["title"] == "Good chain"
    assert len(rejections) == 1
    assert rejections[0].raw_title == "Bad chain"


def test_finalize_scenarios_empty_input_returns_empty():
    accepted, rejections = finalize_scenarios([], "run-1", known_finding_ids=set())

    assert accepted == []
    assert rejections == []
