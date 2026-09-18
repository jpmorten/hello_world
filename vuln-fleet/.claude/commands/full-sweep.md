---
description: Run a full vuln-fleet sweep across every registered domain and summarize the results.
---

Run a full sweep of vuln-fleet across every registered Tier 1 domain (see `engine/domains.py`'s `DOMAIN_REGISTRY`) and report back.

1. From the `vuln-fleet/` directory, run: `python3 -m engine.cli full-sweep`
2. Read its stdout: the run_id, finding/issue counts, the new/recurring/resolved/regressed delta, any coverage gaps, and the paths to every report file it wrote.
3. Read `reports/<run_id>/posture.md` in full and summarize it for the user in your own words: overall risk posture, the top issues by risk (name the highest few), and any coverage gaps with their stated reasons — never drop a gap silently.
4. Name the other report files (`by-domain.md`, `remediation-board.md`, `compliance-view.md`, `issues.json`, `findings.json`) and what each is for, rather than reproducing them in full in the conversation.
5. If the command exits non-zero or writes anything to stderr, say so plainly — never report a sweep as clean when it didn't complete without error.

This is read-only: do not modify `scope/*.yaml`, `adapters/`, or `engine/` as part of running this command.
