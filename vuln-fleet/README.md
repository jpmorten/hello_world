# vuln-fleet

Hierarchical, orchestrated fleet of AI agents that continuously discovers and
reports security vulnerabilities across Stibo Software Group entities
(Stibo Software Group A/S, Stibo Systems, Stibo DX, and subsidiaries).

This is a **defensive security programme**: read-only by default, no
exploitation, active scanning gated on signed authorization records, and a
hard scope boundary enforced by a pre-tool guard hook. See `THREAT-MODEL.md`
(to come) for the full governance model.

## Status

Build is proceeding per the staged build order. Completed so far:

1. **Schemas locked** — `schema/finding.schema.json` (OCSF Vulnerability
   Finding-aligned) and `schema/event.schema.json` (the common log envelope),
   with `schema/validate.py` and a passing test suite in `schema/tests/`.
2. **Log bus** — `engine/logbus.py`: append-only, hash-chained NDJSON writer
   (`logs/<run_id>.ndjson`) with syslog (RFC 5424 over TLS) and generic
   webhook sinks. Every event is schema-validated before it's written. Sink
   failures spool locally instead of blocking the run; `flush_sinks()`
   replays the spool with backoff, preserving delivery order, and never
   drops a spooled event — one whose retries are exhausted is surfaced as a
   `sink_delivery_failed` event instead. Tests in `engine/tests/`.

Not built yet: scope model, spawn/budget engine, domain/worker agents,
real adapters, dedupe/correlation/risk scoring, reports.

## Running the tests

```bash
cd vuln-fleet
pip install -r requirements.txt
pytest
```

## Layout

See the design note in the originating PR/commit for the full planned
repository layout. Directories present now are placeholders for upcoming
build steps; most are empty until their step is built.
