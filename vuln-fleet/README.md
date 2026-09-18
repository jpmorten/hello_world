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

3. **Scope model + pre-tool scope guard** — `scope/assets.yaml`,
   `scope/exclusions.yaml`, `scope/authorized-active.yaml` (example data;
   see the comments in each file) plus `engine/scope.py`, the deterministic
   resolver every scope decision goes through: does a target resolve to an
   in-scope asset, is it on the never-touch exclusion list, and — for
   active-scan actions specifically — is there a signed, in-window
   authorization covering it. `.claude/hooks/scope_guard.py` is the
   PreToolUse hook wired in `.claude/settings.json`: it inspects Bash calls
   that invoke an adapter (`adapters/*.py --target ... --action ...`),
   denies anything out of scope, excluded, or missing a target entirely
   (fail closed), and logs every decision — allow or deny — as a
   `scope_check`/`scope_violation` event via the same hash-chained logbus
   from step 2. The `VULN_FLEET_*` environment variables the hook reads
   (`RUN_ID`, `AGENT_ID`, `AGENT_ROLE`, `TIER`, `SPAN_ID`,
   `PARENT_AGENT_ID`, `PARENT_SPAN_ID`, `LOG_DIR`) are the contract
   step 4's spawn engine will set when it launches each agent.

Not built yet: spawn/budget engine, domain/worker agents, real adapters,
dedupe/correlation/risk scoring, reports.

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
