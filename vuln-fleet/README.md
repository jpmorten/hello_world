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

Nothing downstream (logbus, scope model, spawn/budget engine, agents,
adapters) has been built yet — per the build order, those don't start until
the schemas are reviewed and locked.

## Running the schema tests

```bash
cd vuln-fleet
pip install -r requirements.txt
pytest
```

## Layout

See the design note in the originating PR/commit for the full planned
repository layout. Directories present now are placeholders for upcoming
build steps; most are empty until their step is built.
