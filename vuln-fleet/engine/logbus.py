"""Append-only, hash-chained event log plus SIEM sink forwarding.

Every event written through LogBus.emit() is:
  1. chained (integrity_hash = sha256(previous_hash + canonical(event)))
  2. validated against schema/event.schema.json
  3. appended to logs/<run_id>.ndjson (the SOC's authoritative record)
  4. forwarded best-effort to each configured sink

A sink that fails spools locally instead of blocking the run. flush_sinks()
attempts redelivery; an event whose retries are exhausted is never dropped
(it stays in the spool for inspection/manual replay) but is surfaced once
as a sink_delivery_failed event so "never drop an event silently" holds
even when every sink is down.
"""
from __future__ import annotations

import hashlib
import json
import socket
import ssl
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from schema.validate import validate_event

GENESIS_HASH = "0" * 64

SYSLOG_SEVERITY = {
    "critical": 2,
    "error": 3,
    "warning": 4,
    "notice": 5,
    "info": 6,
    "debug": 7,
}


def canonical_json(obj: dict) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def compute_integrity_hash(previous_hash: str, event_without_hash: dict) -> str:
    payload = previous_hash + canonical_json(event_without_hash)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def utcnow_rfc3339() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class SinkError(Exception):
    """Raised by a sink's transport when delivery fails."""


class Sink:
    """Spool/replay base class. Subclasses implement only `_deliver`."""

    name = "sink"

    def __init__(
        self,
        spool_path: Path | str,
        max_retries: int = 5,
        backoff_base: float = 1.0,
        sleep_fn: Callable[[float], None] = time.sleep,
    ):
        self.spool_path = Path(spool_path)
        self.spool_path.parent.mkdir(parents=True, exist_ok=True)
        self.max_retries = max_retries
        self.backoff_base = backoff_base
        self._sleep = sleep_fn

    def _deliver(self, event: dict) -> None:
        raise NotImplementedError

    def send(self, event: dict) -> bool:
        """Best-effort immediate delivery. Never raises; spools on failure."""
        try:
            self._deliver(event)
            return True
        except Exception:
            self._spool_append(event, attempts=1)
            return False

    def _spool_append(self, event: dict, attempts: int) -> None:
        with open(self.spool_path, "a", encoding="utf-8") as f:
            f.write(canonical_json({"event": event, "attempts": attempts}) + "\n")

    def _read_spool(self) -> list[dict]:
        if not self.spool_path.exists():
            return []
        entries = []
        with open(self.spool_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    entries.append(json.loads(line))
        return entries

    def _write_spool(self, entries: list[dict]) -> None:
        if not entries:
            self.spool_path.unlink(missing_ok=True)
            return
        with open(self.spool_path, "w", encoding="utf-8") as f:
            for entry in entries:
                f.write(canonical_json(entry) + "\n")

    def flush(self) -> list[dict]:
        """Attempt redelivery of spooled events, oldest first.

        Stops at the first still-failing event so a later event already in
        the spool never gets delivered ahead of an earlier one that is
        still stuck (ordering guarantee).

        Returns the events whose retry count just crossed max_retries on
        this call (edge-triggered — callers emit sink_delivery_failed for
        these). The events themselves stay in the spool either way.
        """
        entries = self._read_spool()
        if not entries:
            return []
        just_exhausted = []
        remaining = []
        stalled = False
        for entry in entries:
            if stalled:
                remaining.append(entry)
                continue
            event, attempts = entry["event"], entry["attempts"]
            self._sleep(self.backoff_base * (2 ** (attempts - 1)))
            try:
                self._deliver(event)
            except Exception:
                attempts += 1
                if attempts == self.max_retries:
                    just_exhausted.append(event)
                remaining.append({"event": event, "attempts": attempts})
                stalled = True
        self._write_spool(remaining)
        return just_exhausted


class WebhookSink(Sink):
    """Generic HTTP(S) webhook sink (JSON POST)."""

    name = "webhook"

    def __init__(
        self,
        url: str,
        spool_path: Path | str,
        headers: Optional[dict] = None,
        transport: Optional[Callable[[str, bytes, dict], None]] = None,
        **kwargs,
    ):
        super().__init__(spool_path, **kwargs)
        self.url = url
        self.headers = headers or {"Content-Type": "application/json"}
        self._transport = transport or self._default_transport

    def _deliver(self, event: dict) -> None:
        self._transport(self.url, canonical_json(event).encode("utf-8"), self.headers)

    @staticmethod
    def _default_transport(url: str, body: bytes, headers: dict) -> None:
        request = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                if response.status >= 300:
                    raise SinkError(f"webhook returned status {response.status}")
        except urllib.error.URLError as exc:
            raise SinkError(str(exc)) from exc


def format_rfc5424(
    event: dict,
    facility: int = 16,
    app_name: str = "vuln-fleet",
    hostname: str = "-",
) -> str:
    """Render an event as an RFC 5424 syslog message. No structured-data set."""
    severity = SYSLOG_SEVERITY.get(event.get("severity", "info"), 6)
    pri = facility * 8 + severity
    timestamp = event.get("timestamp", "-")
    procid = event.get("agent_id", "-")
    msgid = event.get("event_type", "-")
    return f"<{pri}>1 {timestamp} {hostname} {app_name} {procid} {msgid} - {canonical_json(event)}"


class SyslogSink(Sink):
    """RFC 5424 syslog over TCP+TLS."""

    name = "syslog"

    def __init__(
        self,
        host: str,
        port: int,
        spool_path: Path | str,
        facility: int = 16,
        app_name: str = "vuln-fleet",
        hostname: Optional[str] = None,
        use_tls: bool = True,
        transport: Optional[Callable[[str, int, bytes, bool], None]] = None,
        **kwargs,
    ):
        super().__init__(spool_path, **kwargs)
        self.host = host
        self.port = port
        self.facility = facility
        self.app_name = app_name
        self.hostname = hostname or socket.gethostname()
        self.use_tls = use_tls
        self._transport = transport or self._default_transport

    def _deliver(self, event: dict) -> None:
        message = format_rfc5424(event, self.facility, self.app_name, self.hostname)
        self._transport(self.host, self.port, message.encode("utf-8"), self.use_tls)

    @staticmethod
    def _default_transport(host: str, port: int, payload: bytes, use_tls: bool) -> None:
        try:
            sock = socket.create_connection((host, port), timeout=10)
        except OSError as exc:
            raise SinkError(str(exc)) from exc
        try:
            if use_tls:
                sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
            sock.sendall(payload + b"\n")
        except OSError as exc:
            raise SinkError(str(exc)) from exc
        finally:
            sock.close()


class LogBus:
    def __init__(self, run_id: str, log_dir: Path | str = "logs", sinks: Optional[list[Sink]] = None):
        self.run_id = run_id
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.log_path = self.log_dir / f"{run_id}.ndjson"
        self.sinks = sinks or []
        self._last_hash = self._resume_last_hash()

    def _resume_last_hash(self) -> str:
        if not self.log_path.exists():
            return GENESIS_HASH
        last_line = None
        with open(self.log_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    last_line = line
        return json.loads(last_line)["integrity_hash"] if last_line else GENESIS_HASH

    def emit(self, event: dict) -> dict:
        if "integrity_hash" in event:
            raise ValueError("emit() computes integrity_hash; do not set it on the input event")
        chained = {**event, "integrity_hash": compute_integrity_hash(self._last_hash, event)}
        validate_event(chained)

        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(canonical_json(chained) + "\n")
        self._last_hash = chained["integrity_hash"]

        # sink_delivery_failed events are local-only: forwarding them to the
        # sink that just failed (or re-triggering the same failure path on
        # every other sink) would grow the spool it's reporting on.
        if chained["event_type"] != "sink_delivery_failed":
            for sink in self.sinks:
                sink.send(chained)
        return chained

    def flush_sinks(self) -> None:
        for sink in self.sinks:
            for exhausted_event in sink.flush():
                self.emit(
                    {
                        "timestamp": utcnow_rfc3339(),
                        "run_id": self.run_id,
                        "agent_id": "logbus",
                        "agent_role": "logbus",
                        "tier": 0,
                        "parent_agent_id": None,
                        "span_id": f"logbus-{uuid.uuid4()}",
                        "parent_span_id": None,
                        "event_type": "sink_delivery_failed",
                        "severity": "error",
                        "entity": None,
                        "asset_id": None,
                        "scope_ref": None,
                        "authorization_ref": None,
                        "message": f"Sink '{sink.name}' exhausted {sink.max_retries} delivery retries.",
                        "evidence_ref": [],
                        "details": {
                            "sink": sink.name,
                            "original_span_id": exhausted_event.get("span_id"),
                            "original_event_type": exhausted_event.get("event_type"),
                        },
                    }
                )
