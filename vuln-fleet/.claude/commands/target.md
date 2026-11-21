---
description: Sweep a single target ref (e.g. repo:stibo/checkout) across whichever domains claim it.
argument-hint: <target_ref>
---

Run a targeted sweep against exactly one target: `$ARGUMENTS`

1. From the `vuln-fleet/` directory, run: `python3 -m engine.cli target "$ARGUMENTS"`
2. The target ref must use one of the schemes `engine/scope.py` understands: `repo:`, `host:`, `ip:`, `endpoint:`, or `cidr:`. If the user gave you something else (a bare hostname, a repo name without the `repo:` prefix), ask which asset they mean rather than guessing a scheme.
3. If the command refuses with "not a valid target" (exit code 1, message on stderr), that's `engine/scope.py` doing its job — the target is out of scope, excluded, or not resolvable to any asset in `scope/assets.yaml`. Report the exact reason it gave; do not retry with a different scheme or attempt the target another way. Scope is a hard boundary, not a suggestion.
4. If the command refuses because no registered domain's decomposition includes this target, say so — it means the target exists in `scope/assets.yaml` but isn't the kind of thing any current domain looks at (e.g. its asset `type` doesn't match any domain's filter in `engine/domains.py`).
5. On success, summarize the findings the same way `/full-sweep` does, from `reports/<run_id>/posture.md`.

This is read-only: do not modify `scope/*.yaml`, `adapters/`, or `engine/` as part of running this command.
