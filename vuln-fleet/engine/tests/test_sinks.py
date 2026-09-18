import re

import pytest

from engine.logbus import SinkError, SyslogSink, WebhookSink, format_rfc5424


EVENT = {
    "timestamp": "2026-09-18T08:00:00Z",
    "run_id": "run-test",
    "agent_id": "supply-chain",
    "agent_role": "supply-chain",
    "event_type": "finding",
    "severity": "critical",
}


def test_format_rfc5424_structure():
    message = format_rfc5424(EVENT, facility=16, app_name="vuln-fleet", hostname="host1")

    # <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG
    match = re.match(r"^<(\d+)>1 (\S+) (\S+) (\S+) (\S+) (\S+) - (.+)$", message)
    assert match is not None
    pri, timestamp, hostname, app_name, procid, msgid, msg = match.groups()
    assert int(pri) == 16 * 8 + 2  # facility*8 + critical(2)
    assert timestamp == EVENT["timestamp"]
    assert hostname == "host1"
    assert app_name == "vuln-fleet"
    assert procid == "supply-chain"
    assert msgid == "finding"
    assert '"event_type":"finding"' in msg


def test_format_rfc5424_unknown_severity_defaults_to_info():
    message = format_rfc5424({**EVENT, "severity": "weird"})
    pri = int(re.match(r"^<(\d+)>", message).group(1))
    assert pri % 8 == 6  # info


def test_syslog_sink_uses_injected_transport(tmp_path):
    calls = []

    def fake_transport(host, port, payload, use_tls):
        calls.append((host, port, payload, use_tls))

    sink = SyslogSink("siem.example.internal", 6514, tmp_path / "spool.ndjson", transport=fake_transport)

    ok = sink.send(EVENT)

    assert ok is True
    assert len(calls) == 1
    host, port, payload, use_tls = calls[0]
    assert host == "siem.example.internal"
    assert port == 6514
    assert use_tls is True
    assert payload.startswith(b"<")


def test_syslog_sink_transport_failure_spools(tmp_path):
    def failing_transport(host, port, payload, use_tls):
        raise SinkError("connection refused")

    sink = SyslogSink("siem.example.internal", 6514, tmp_path / "spool.ndjson", transport=failing_transport)

    ok = sink.send(EVENT)

    assert ok is False
    assert (tmp_path / "spool.ndjson").exists()


def test_webhook_sink_uses_injected_transport(tmp_path):
    calls = []

    def fake_transport(url, body, headers):
        calls.append((url, body, headers))

    sink = WebhookSink("https://siem.example.internal/hook", tmp_path / "spool.ndjson", transport=fake_transport)

    ok = sink.send(EVENT)

    assert ok is True
    assert len(calls) == 1
    url, body, headers = calls[0]
    assert url == "https://siem.example.internal/hook"
    assert b'"event_type":"finding"' in body
    assert headers["Content-Type"] == "application/json"


def test_webhook_sink_transport_failure_spools(tmp_path):
    def failing_transport(url, body, headers):
        raise SinkError("503")

    sink = WebhookSink("https://siem.example.internal/hook", tmp_path / "spool.ndjson", transport=failing_transport)

    ok = sink.send(EVENT)

    assert ok is False
    assert (tmp_path / "spool.ndjson").exists()
