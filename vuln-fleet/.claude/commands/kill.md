---
description: Write a kill flag that stops a running (or about-to-run) vuln-fleet sweep, producing a partial report.
argument-hint: [run_id]
---

Stop a vuln-fleet sweep: `$ARGUMENTS` (a run_id, or empty to target the most recently active run).

1. If no run_id was given, tell the user which run this will target *before* running anything: check `logs/` for the most recently modified `*.ndjson` file (that's what `python3 -m engine.cli kill` picks by default) and confirm that's the run they mean if more than one log file has been touched recently.
2. Run: `python3 -m engine.cli kill` (or `python3 -m engine.cli kill --run-id <run_id>` if one was given or confirmed).
3. This only writes a flag file (`reports/<run_id>.kill`) — it does not forcibly terminate a process. The running sweep notices it between targets/domains (see `Orchestrator._kill_requested` in `engine/orchestrator.py`) and stops there, so there can be a short delay before it actually exits, and a very fast sweep may finish before it ever checks. Say this plainly rather than implying an instant stop.
4. A killed run still produces a full report suite — the un-swept targets show up as coverage gaps with reason `kill_switch: ...` in `posture.md` and `by-domain.md`, not a crash or a missing report. Point this out once the run actually finishes.
5. Do not write a kill flag for a run_id you're not confident about — ask rather than guess if it's ambiguous which run the user means.
