"""Tier 0.5 attack-scenario analysis: runs once per run, after every
Tier 1 domain's findings are gathered, correlated, and risk-scored --
never per-target, never per-domain, because its whole value is seeing
across domains a single domain worker never would (a red-team-recon
subdomain finding + a code-firstparty hardcoded credential + a
infra-network permissive firewall rule chain into something none of the
three domains alone would surface).

This module owns exactly two things: the AnalystFn contract an analyst
(mock or live) must satisfy, and turning that analyst's raw output into
schema-valid, integrity-checked AttackScenario records. It never predicts
anything itself -- narrative "how could an attacker chain these"
reasoning is precisely the kind of contextual judgement this project's
own design principle reserves for an agent, not deterministic code (see
README.md: "agents reason about context and narrative; matching and
scoring are code"). That's also why this is a new top-level `analysts/`
package (analysts/mock/attack_scenario.py) rather than another
adapters/*.py: an adapter answers "what's wrong with this one target";
an analyst answers "what could someone do with everything that's wrong."

The one hard rule, enforced structurally, not just by convention: a
scenario is a PREDICTION, never a validation. schema/attack_scenario.
schema.json locks `status` to the single value "predicted" -- there is
no schema-legal way to mark a scenario "confirmed" or "exploited" -- and
finalize_scenario() below refuses (drops, logs, never raises the whole
run) any scenario that references a finding_id not actually present in
this run's own finding set, so a hallucinated or fabricated chain can
never reach a report.
"""
from __future__ import annotations

import hashlib
from typing import Callable, NamedTuple, Optional

AnalystFn = Callable[[list[dict], list[dict]], list[dict]]


class ScenarioRejection(NamedTuple):
    raw_title: str
    reason: str


def compute_scenario_id(*, run_id: str, chained_finding_ids: list[str], title: str) -> str:
    """Deterministic fingerprint: sha256(run_id, sorted chained_finding_ids, title).
    Mirrors engine/dedupe.py's compute_finding_id -- an id is computed by
    code from the scenario's own content, never asserted by the analyst."""
    payload = "|".join([run_id, ",".join(sorted(chained_finding_ids)), title])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def finalize_scenarios(
    raw_scenarios: list[dict], run_id: str, known_finding_ids: set[str]
) -> tuple[list[dict], list[ScenarioRejection]]:
    """Adds scenario_id/run_id/status to each raw scenario dict an
    AnalystFn returned, and rejects (rather than silently keeping or
    raising) any scenario chaining a finding_id that doesn't actually
    exist in `known_finding_ids` -- this run's real, deduplicated
    findings. A hallucinated finding_id is exactly the kind of
    unevidenced claim this fleet's whole reporting discipline refuses to
    let through; rejecting just that one scenario (not the run) mirrors
    how a single bad adapter target becomes a coverage gap, not a crash.

    Returns (accepted_scenarios, rejections) -- callers log both.
    """
    accepted: list[dict] = []
    rejections: list[ScenarioRejection] = []

    for raw in raw_scenarios:
        chained = raw.get("chained_finding_ids") or []
        unknown = [fid for fid in chained if fid not in known_finding_ids]
        if unknown:
            rejections.append(
                ScenarioRejection(
                    raw_title=raw.get("title", "<untitled>"),
                    reason=f"references finding_id(s) not present in this run: {unknown}",
                )
            )
            continue
        if len(chained) < 2:
            rejections.append(
                ScenarioRejection(
                    raw_title=raw.get("title", "<untitled>"),
                    reason=f"chains {len(chained)} finding(s); a scenario needs at least 2",
                )
            )
            continue

        scenario = dict(raw)
        scenario["run_id"] = run_id
        scenario["status"] = "predicted"
        scenario["scenario_id"] = compute_scenario_id(
            run_id=run_id, chained_finding_ids=chained, title=raw.get("title", "")
        )
        accepted.append(scenario)

    return accepted, rejections
