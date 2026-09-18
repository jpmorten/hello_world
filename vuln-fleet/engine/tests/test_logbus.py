import json

import pytest

from engine.logbus import GENESIS_HASH, LogBus, Sink, SinkError, compute_integrity_hash
from schema.validate import SchemaValidationError


class RecordingSink(Sink):
    name = "recording"

    def __init__(self, spool_path, fail_ids=(), **kwargs):
        super().__init__(spool_path, **kwargs)
        self.fail_ids = set(fail_ids)
        self.received: list[dict] = []

    def _deliver(self, event: dict) -> None:
        if event.get("span_id") in self.fail_ids:
            raise SinkError("simulated failure")
        self.received.append(event)


def _base_event(**overrides) -> dict:
    event = {
        "timestamp": "2026-09-18T08:00:00Z",
        "run_id": "run-test",
        "agent_id": "fleet-orchestrator",
        "agent_role": "fleet-orchestrator",
        "tier": 0,
        "parent_agent_id": None,
        "span_id": "span-1",
        "parent_span_id": None,
        "event_type": "run_start",
        "severity": "info",
        "entity": None,
        "asset_id": None,
        "scope_ref": None,
        "authorization_ref": None,
        "message": "hello",
        "evidence_ref": [],
    }
    event.update(overrides)
    return event


@pytest.fixture
def no_sleep():
    return lambda seconds: None


def test_first_event_chains_from_genesis(tmp_path):
    bus = LogBus("run-test", log_dir=tmp_path)

    written = bus.emit(_base_event())

    assert written["integrity_hash"] == compute_integrity_hash(GENESIS_HASH, _base_event())


def test_hash_chain_links_sequential_events(tmp_path):
    bus = LogBus("run-test", log_dir=tmp_path)

    first = bus.emit(_base_event(span_id="span-1"))
    second = bus.emit(_base_event(span_id="span-2", event_type="agent_start"))

    assert second["integrity_hash"] == compute_integrity_hash(
        first["integrity_hash"], _base_event(span_id="span-2", event_type="agent_start")
    )


def test_emit_writes_ndjson_lines(tmp_path):
    bus = LogBus("run-test", log_dir=tmp_path)
    bus.emit(_base_event(span_id="span-1"))
    bus.emit(_base_event(span_id="span-2"))

    lines = (tmp_path / "run-test.ndjson").read_text().strip().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["span_id"] == "span-1"
    assert json.loads(lines[1])["span_id"] == "span-2"


def test_emit_rejects_invalid_event(tmp_path):
    bus = LogBus("run-test", log_dir=tmp_path)

    with pytest.raises(SchemaValidationError):
        bus.emit(_base_event(event_type="not_a_real_event_type"))

    assert not (tmp_path / "run-test.ndjson").exists()


def test_emit_rejects_preset_integrity_hash(tmp_path):
    bus = LogBus("run-test", log_dir=tmp_path)

    with pytest.raises(ValueError):
        bus.emit(_base_event(integrity_hash="a" * 64))


def test_new_logbus_resumes_chain_from_existing_file(tmp_path):
    first_bus = LogBus("run-test", log_dir=tmp_path)
    last = first_bus.emit(_base_event(span_id="span-1"))

    second_bus = LogBus("run-test", log_dir=tmp_path)  # simulates process restart
    resumed = second_bus.emit(_base_event(span_id="span-2", event_type="agent_start"))

    assert resumed["integrity_hash"] == compute_integrity_hash(
        last["integrity_hash"], _base_event(span_id="span-2", event_type="agent_start")
    )
    lines = (tmp_path / "run-test.ndjson").read_text().strip().splitlines()
    assert len(lines) == 2


def test_emit_forwards_to_sinks(tmp_path, no_sleep):
    sink = RecordingSink(tmp_path / "spool.ndjson", sleep_fn=no_sleep)
    bus = LogBus("run-test", log_dir=tmp_path, sinks=[sink])

    event = bus.emit(_base_event())

    assert sink.received == [event]


def test_sink_delivery_failed_emitted_once_after_retries_exhausted(tmp_path, no_sleep):
    sink = RecordingSink(tmp_path / "spool.ndjson", fail_ids={"span-1"}, max_retries=2, sleep_fn=no_sleep)
    bus = LogBus("run-test", log_dir=tmp_path, sinks=[sink])

    bus.emit(_base_event(span_id="span-1"))  # forward fails -> spooled, attempts=1
    bus.flush_sinks()  # attempts -> 2 == max_retries -> sink_delivery_failed emitted
    bus.flush_sinks()  # still failing, but no repeat signal

    lines = [json.loads(l) for l in (tmp_path / "run-test.ndjson").read_text().strip().splitlines()]
    failure_events = [e for e in lines if e["event_type"] == "sink_delivery_failed"]
    assert len(failure_events) == 1
    assert failure_events[0]["details"]["sink"] == "recording"
    assert failure_events[0]["details"]["original_span_id"] == "span-1"
    # the sink_delivery_failed event itself was never handed to the (still failing) sink
    assert sink.received == []


def test_sink_recovery_delivers_spooled_event_on_flush(tmp_path, no_sleep):
    sink = RecordingSink(tmp_path / "spool.ndjson", fail_ids={"span-1"}, sleep_fn=no_sleep)
    bus = LogBus("run-test", log_dir=tmp_path, sinks=[sink])
    bus.emit(_base_event(span_id="span-1"))
    assert sink.received == []

    sink.fail_ids = set()  # sink recovers
    bus.flush_sinks()

    assert len(sink.received) == 1
    assert sink.received[0]["span_id"] == "span-1"
