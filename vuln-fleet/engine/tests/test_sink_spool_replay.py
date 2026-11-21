import json

import pytest

from engine.logbus import Sink, SinkError


class FailThenSucceedSink(Sink):
    """Fails on its first `fail_times` _deliver calls, then succeeds."""

    name = "fake"

    def __init__(self, spool_path, fail_times: int, **kwargs):
        super().__init__(spool_path, **kwargs)
        self.fail_times = fail_times
        self.calls = 0

    def _deliver(self, event: dict) -> None:
        self.calls += 1
        if self.calls <= self.fail_times:
            raise SinkError("simulated failure")


class PredicateSink(Sink):
    """Fails _deliver for any event whose id is in `self.blocked`."""

    name = "predicate"

    def __init__(self, spool_path, **kwargs):
        super().__init__(spool_path, **kwargs)
        self.blocked: set[str] = set()
        self.delivered: list[str] = []

    def _deliver(self, event: dict) -> None:
        if event["id"] in self.blocked:
            raise SinkError("blocked")
        self.delivered.append(event["id"])


@pytest.fixture
def no_sleep():
    return lambda seconds: None


def test_send_failure_spools_event(tmp_path, no_sleep):
    sink = FailThenSucceedSink(tmp_path / "spool.ndjson", fail_times=100, sleep_fn=no_sleep)
    event = {"id": "e1"}

    ok = sink.send(event)

    assert ok is False
    lines = (tmp_path / "spool.ndjson").read_text().strip().splitlines()
    assert len(lines) == 1
    entry = json.loads(lines[0])
    assert entry == {"event": event, "attempts": 1}


def test_send_success_never_touches_spool(tmp_path, no_sleep):
    sink = FailThenSucceedSink(tmp_path / "spool.ndjson", fail_times=0, sleep_fn=no_sleep)

    ok = sink.send({"id": "e1"})

    assert ok is True
    assert not (tmp_path / "spool.ndjson").exists()


def test_flush_redelivers_and_empties_spool_on_recovery(tmp_path, no_sleep):
    sink = FailThenSucceedSink(tmp_path / "spool.ndjson", fail_times=1, sleep_fn=no_sleep)
    sink.send({"id": "e1"})  # call #1 fails -> spooled

    exhausted = sink.flush()  # call #2 succeeds

    assert exhausted == []
    assert not (tmp_path / "spool.ndjson").exists()


def test_flush_exhausts_once_then_stops_reporting(tmp_path, no_sleep):
    sink = FailThenSucceedSink(tmp_path / "spool.ndjson", fail_times=10_000, max_retries=3, sleep_fn=no_sleep)
    event = {"id": "e1"}
    sink.send(event)  # attempts -> 1

    first = sink.flush()  # attempts -> 2
    second = sink.flush()  # attempts -> 3 == max_retries: crossing point
    third = sink.flush()  # attempts -> 4: no repeat signal

    assert first == []
    assert second == [event]
    assert third == []
    # never dropped, even after exhausting retries
    entries = [json.loads(l) for l in (tmp_path / "spool.ndjson").read_text().strip().splitlines()]
    assert entries == [{"event": event, "attempts": 4}]


def test_flush_preserves_ordering_head_of_line_blocking(tmp_path, no_sleep):
    sink = PredicateSink(tmp_path / "spool.ndjson", sleep_fn=no_sleep)
    sink.blocked = {"e1", "e2"}
    sink.send({"id": "e1"})
    sink.send({"id": "e2"})

    sink.blocked = {"e1"}  # e2 would now succeed, but e1 is still stuck ahead of it
    sink.flush()

    entries = [json.loads(l) for l in (tmp_path / "spool.ndjson").read_text().strip().splitlines()]
    assert [e["event"]["id"] for e in entries] == ["e1", "e2"]
    assert entries[1]["attempts"] == 1  # e2 was never attempted
    assert sink.delivered == []

    sink.blocked = set()  # both now healthy
    exhausted = sink.flush()

    assert exhausted == []
    assert sink.delivered == ["e1", "e2"]
    assert not (tmp_path / "spool.ndjson").exists()
