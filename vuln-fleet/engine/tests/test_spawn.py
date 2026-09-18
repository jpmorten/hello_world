from datetime import datetime, timedelta, timezone

import pytest

from engine.logbus import LogBus
from engine.spawn import SpawnManager, SpawnRefused, allocate_sub_budgets


class Clock:
    def __init__(self, start: str = "2026-09-18T08:00:00Z"):
        self.now = datetime.fromisoformat(start.replace("Z", "+00:00"))

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)


def _manager(tmp_path, clock=None, **kwargs) -> SpawnManager:
    bus = LogBus("run-test", log_dir=tmp_path)
    return SpawnManager(
        "run-test",
        bus,
        domain_budgets=kwargs.pop("domain_budgets", {}),
        now_fn=clock or Clock(),
        **kwargs,
    )


def _events(tmp_path, run_id="run-test") -> list[dict]:
    import json

    path = tmp_path / f"{run_id}.ndjson"
    return [json.loads(l) for l in path.read_text().strip().splitlines()] if path.exists() else []


# -- lineage -----------------------------------------------------------------


def test_root_spawn_is_tier1_with_orchestrator_as_parent(tmp_path):
    mgr = _manager(tmp_path)

    handle = mgr.spawn(domain="supply-chain", agent_role="supply-chain")

    assert handle.tier == 1
    assert handle.parent_agent_id == "fleet-orchestrator"
    assert handle.parent_span_id == "root"
    assert handle.status == "running"


def test_tier2_spawn_from_tier1_parent(tmp_path):
    mgr = _manager(tmp_path)
    parent = mgr.spawn(domain="supply-chain", agent_role="supply-chain")

    worker = mgr.spawn(domain="supply-chain", agent_role="repo-worker", parent=parent, target_ref="repo:stibo/checkout")

    assert worker.tier == 2
    assert worker.parent_agent_id == parent.agent_id
    assert worker.parent_span_id == parent.span_id


def test_tier2_worker_cannot_spawn_children(tmp_path):
    mgr = _manager(tmp_path)
    domain_agent = mgr.spawn(domain="supply-chain", agent_role="supply-chain")
    worker = mgr.spawn(domain="supply-chain", agent_role="repo-worker", parent=domain_agent, target_ref="repo:a")

    with pytest.raises(SpawnRefused) as exc_info:
        mgr.spawn(domain="supply-chain", agent_role="sub-worker", parent=worker, target_ref="repo:b")

    assert exc_info.value.reason == "depth_exceeded"
    # the refusal itself must be a schema-valid, successfully logged event
    error_events = [e for e in _events(tmp_path) if e["event_type"] == "agent_error"]
    assert any(e["details"]["reason"] == "depth_exceeded" for e in error_events)


# -- duplicate detection -------------------------------------------------------


def test_duplicate_domain_target_refused(tmp_path):
    mgr = _manager(tmp_path, domain_budgets={"supply-chain": 5})
    mgr.spawn(domain="supply-chain", agent_role="repo-worker", target_ref="repo:stibo/checkout")

    with pytest.raises(SpawnRefused) as exc_info:
        mgr.spawn(domain="supply-chain", agent_role="repo-worker", target_ref="repo:stibo/checkout")

    assert exc_info.value.reason == "duplicate_spawn"


def test_same_domain_different_target_is_not_a_duplicate(tmp_path):
    mgr = _manager(tmp_path, domain_budgets={"supply-chain": 5})
    mgr.spawn(domain="supply-chain", agent_role="repo-worker", target_ref="repo:a")

    worker_b = mgr.spawn(domain="supply-chain", agent_role="repo-worker", target_ref="repo:b")

    assert worker_b.status == "running"


# -- budget / queueing ---------------------------------------------------------


def test_budget_exhausted_queues_and_logs_once(tmp_path):
    mgr = _manager(tmp_path, domain_budgets={"supply-chain": 1})

    first = mgr.spawn(domain="supply-chain", agent_role="repo-worker", target_ref="repo:a")
    second = mgr.spawn(domain="supply-chain", agent_role="repo-worker", target_ref="repo:b")
    third = mgr.spawn(domain="supply-chain", agent_role="repo-worker", target_ref="repo:c")

    assert first.status == "running"
    assert second.status == "queued"
    assert third.status == "queued"
    assert mgr.queue_depth("supply-chain") == 2

    budget_events = [e for e in _events(tmp_path) if e["event_type"] == "budget_exhausted"]
    assert len(budget_events) == 1  # edge-triggered: not repeated for the third spawn


def test_complete_dispatches_next_queued(tmp_path):
    mgr = _manager(tmp_path, domain_budgets={"supply-chain": 1})
    first = mgr.spawn(domain="supply-chain", agent_role="repo-worker", target_ref="repo:a")
    second = mgr.spawn(domain="supply-chain", agent_role="repo-worker", target_ref="repo:b")
    assert second.status == "queued"

    mgr.complete(first.agent_id)

    assert second.status == "running"
    assert mgr.queue_depth("supply-chain") == 0


def test_default_domain_budget_applies_when_domain_not_listed(tmp_path):
    mgr = _manager(tmp_path, domain_budgets={}, default_domain_budget=1)

    first = mgr.spawn(domain="api-surface", agent_role="w", target_ref="a")
    second = mgr.spawn(domain="api-surface", agent_role="w", target_ref="b")

    assert first.status == "running"
    assert second.status == "queued"


# -- time budget ----------------------------------------------------------------


def test_time_budget_exhausted_refuses_new_spawns(tmp_path):
    clock = Clock()
    mgr = _manager(tmp_path, clock=clock, domain_budgets={"supply-chain": 5}, time_budget_s=60)
    mgr.spawn(domain="supply-chain", agent_role="w", target_ref="a")

    clock.advance(61)

    with pytest.raises(SpawnRefused) as exc_info:
        mgr.spawn(domain="supply-chain", agent_role="w", target_ref="b")
    assert exc_info.value.reason == "time_budget_exhausted"


def test_queued_agent_stays_queued_once_time_budget_expires(tmp_path):
    clock = Clock()
    mgr = _manager(tmp_path, clock=clock, domain_budgets={"supply-chain": 1}, time_budget_s=60)
    first = mgr.spawn(domain="supply-chain", agent_role="w", target_ref="a")
    second = mgr.spawn(domain="supply-chain", agent_role="w", target_ref="b")
    assert second.status == "queued"

    clock.advance(61)
    mgr.complete(first.agent_id)

    assert second.status == "queued"  # never dispatched: run is wrapping up


# -- heartbeat / liveness --------------------------------------------------------


def test_heartbeat_updates_timestamp_and_logs_event(tmp_path):
    clock = Clock()
    mgr = _manager(tmp_path, clock=clock, domain_budgets={"supply-chain": 5})
    handle = mgr.spawn(domain="supply-chain", agent_role="w", target_ref="a")
    clock.advance(30)

    mgr.heartbeat(handle.agent_id)

    assert handle.last_heartbeat == clock.now
    heartbeats = [e for e in _events(tmp_path) if e["event_type"] == "heartbeat"]
    assert len(heartbeats) == 1


def test_check_liveness_marks_stalled_agent_and_frees_slot(tmp_path):
    clock = Clock()
    mgr = _manager(tmp_path, clock=clock, domain_budgets={"supply-chain": 1}, heartbeat_timeout_s=90)
    handle = mgr.spawn(domain="supply-chain", agent_role="w", target_ref="a")
    queued = mgr.spawn(domain="supply-chain", agent_role="w", target_ref="b")
    assert queued.status == "queued"

    clock.advance(91)
    stalled = mgr.check_liveness()

    assert stalled == [handle.agent_id]
    assert handle.status == "stalled"
    assert queued.status == "running"  # slot freed and re-dispatched


def test_check_liveness_does_not_repeat_report_for_same_agent(tmp_path):
    clock = Clock()
    mgr = _manager(tmp_path, clock=clock, domain_budgets={"supply-chain": 5}, heartbeat_timeout_s=90)
    handle = mgr.spawn(domain="supply-chain", agent_role="w", target_ref="a")
    clock.advance(91)

    first_check = mgr.check_liveness()
    second_check = mgr.check_liveness()

    assert first_check == [handle.agent_id]
    assert second_check == []


# -- kill switch ------------------------------------------------------------------


def test_kill_switch_blocks_new_spawns(tmp_path):
    mgr = _manager(tmp_path, domain_budgets={"supply-chain": 5})
    running = mgr.spawn(domain="supply-chain", agent_role="w", target_ref="a")

    still_running = mgr.trigger_kill_switch("operator abort")

    assert still_running == [running.agent_id]
    assert mgr.kill_switch_active is True
    with pytest.raises(SpawnRefused) as exc_info:
        mgr.spawn(domain="supply-chain", agent_role="w", target_ref="b")
    assert exc_info.value.reason == "kill_switch_active"


def test_kill_switch_is_idempotent(tmp_path):
    mgr = _manager(tmp_path, domain_budgets={"supply-chain": 5})
    mgr.trigger_kill_switch("first")

    result = mgr.trigger_kill_switch("second")

    assert result == []
    kill_events = [e for e in _events(tmp_path) if e["event_type"] == "kill_switch"]
    assert len(kill_events) == 1


# -- allocate_sub_budgets ----------------------------------------------------------


def test_allocate_sub_budgets_sums_to_max_concurrent():
    result = allocate_sub_budgets(10, {"a": 1, "b": 1, "c": 1})

    assert sum(result.values()) == 10


def test_allocate_sub_budgets_equal_weights_split_evenly():
    result = allocate_sub_budgets(9, {"a": 1, "b": 1, "c": 1})

    assert result == {"a": 3, "b": 3, "c": 3}


def test_allocate_sub_budgets_proportional_to_weight():
    result = allocate_sub_budgets(10, {"a": 3, "b": 1})

    assert result == {"a": 8, "b": 2}


def test_allocate_sub_budgets_fewer_slots_than_domains_can_zero_out_low_weight():
    result = allocate_sub_budgets(1, {"a": 100, "b": 1, "c": 1})

    assert sum(result.values()) == 1
    assert result["a"] == 1


def test_allocate_sub_budgets_rejects_non_positive_total_weight():
    with pytest.raises(ValueError):
        allocate_sub_budgets(5, {"a": 0, "b": 0})
