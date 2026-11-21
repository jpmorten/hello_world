---
description: Run a vuln-fleet sweep diffed against the last completed run and highlight what changed.
---

Run a delta sweep: the same full sweep as `/full-sweep`, but diffed against the most recently completed run so the summary is about what *changed*, not the full finding list again.

1. From the `vuln-fleet/` directory, run: `python3 -m engine.cli delta-sweep`
   - This picks the previous run automatically (the most recent `reports/<run_id>/findings.json`). To compare against a specific run instead, pass `--previous-run-id <run_id>`.
   - If stderr says no previous completed run was found, say so — this run's delta is meaningless (everything will show as `new`), not because anything is wrong, but because there's nothing to diff against yet.
2. Read the command's stdout and `reports/<run_id>/posture.md`'s "## Delta vs. previous run" section.
3. Lead the summary with what changed, in this priority order:
   - **Regressed** findings first, by name — something reappearing after being resolved is the most alarming category and must never be buried under a bigger "new" count.
   - **New** findings, especially any that are KEV-listed or land in the top 10 by risk.
   - **Resolved** count (good news, but brief).
   - **Recurring** count (context, not a headline).
4. Name coverage gaps exactly as `posture.md` states them (target + reason).

This is read-only: do not modify `scope/*.yaml`, `adapters/`, or `engine/` as part of running this command.
