"""Ethica's guardrail checks: deterministic, read-only inspection of a
completed run's own findings, attack scenarios, and hash-chained event
log, verifying the fleet actually stayed inside the non-exploitation
guarantees it documents (THREAT-MODEL.md, every domain agent's own .md
file, and schema/attack_scenario.schema.json's locked `status`).

Ethica never acts on what it finds here -- it only ever reports up to
Warden (an `escalation` event in engine/governance.py), exactly like a
live Ethica agent's own tool grant (Read/Grep/Glob, no Bash) makes
structurally true for it. Every check below is defense-in-depth: the
things it looks for should already be structurally impossible (a scope
violation can't produce a finding; a scenario's status is schema-locked
to "predicted"), so an empty flags list is the expected, healthy result,
never a fabricated one.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

_SAFE_EXPLOITATION_STATUSES = {"known_exploited", "poc_public", "no_known_exploitation"}
_SUSPICIOUS_EVIDENCE_REF_LENGTH = 500

GUARDRAILS_CHECKED = [
    "no_self_exploitation",
    "predictions_never_validated",
    "refused_targets_produce_no_findings",
    "red_team_never_captures_content",
]


@dataclass(frozen=True)
class EthicsFlag:
    guardrail: str
    severity: str  # info | warning | critical
    description: str
    evidence_ref: list[str]

    def to_dict(self) -> dict:
        return {
            "guardrail": self.guardrail,
            "severity": self.severity,
            "description": self.description,
            "evidence_ref": self.evidence_ref,
        }


def check_exploitation_status_vocabulary(findings: list[dict]) -> list[EthicsFlag]:
    """Every finding's exploitation_status must be one of the schema's
    own safe, third-party-observation values -- there is no schema-legal
    value meaning "the fleet itself exploited this," so a value outside
    the known vocabulary is itself the anomaly worth flagging: defense in
    depth against a future schema or adapter regression, not an
    expectation this ever fires."""
    flags = []
    for finding in findings:
        status = finding.get("exploitation_status")
        if status not in _SAFE_EXPLOITATION_STATUSES:
            flags.append(
                EthicsFlag(
                    guardrail="no_self_exploitation",
                    severity="critical",
                    description=f"Finding {finding.get('finding_id', '?')!r} has unrecognized exploitation_status {status!r}.",
                    evidence_ref=[finding.get("finding_id") or ""],
                )
            )
    return flags


def check_attack_scenarios_never_confirmed(scenarios: list[dict]) -> list[EthicsFlag]:
    """Defense-in-depth re-check of what schema/attack_scenario.schema.json
    already enforces at write time: every scenario's status is
    'predicted', never anything implying validation or exploitation."""
    flags = []
    for scenario in scenarios:
        if scenario.get("status") != "predicted":
            flags.append(
                EthicsFlag(
                    guardrail="predictions_never_validated",
                    severity="critical",
                    description=f"Scenario {scenario.get('scenario_id', '?')!r} has status {scenario.get('status')!r}, not 'predicted'.",
                    evidence_ref=[scenario.get("scenario_id") or ""],
                )
            )
    return flags


def check_scope_violations_were_actually_refused(events: list[dict]) -> list[EthicsFlag]:
    """Cross-checks the run's own hash-chained log: a target refused as
    out of scope should never also appear inside a `finding` event's
    details this same run. Structurally this can't happen --
    ScopeModel.assert_in_scope() raises before any adapter is ever
    called -- so this is a tripwire for a future regression, not an
    expectation of ever firing."""
    violated_targets = {
        (e.get("details") or {}).get("target_ref")
        for e in events
        if e.get("event_type") == "scope_violation"
    }
    violated_targets.discard(None)
    if not violated_targets:
        return []

    flags = []
    for event in events:
        if event.get("event_type") != "finding":
            continue
        details = event.get("details") or {}
        location_ref = (details.get("location") or {}).get("ref", "")
        for target in violated_targets:
            target_value = target.split(":", 1)[-1] if ":" in target else target
            if target_value and target_value in location_ref:
                flags.append(
                    EthicsFlag(
                        guardrail="refused_targets_produce_no_findings",
                        severity="critical",
                        description=(
                            f"Target {target!r} was refused as out of scope, but a finding this run's "
                            f"location.ref ({location_ref!r}) still appears to reference it."
                        ),
                        evidence_ref=[target],
                    )
                )
    return flags


def check_red_team_no_body_capture(findings: list[dict]) -> list[EthicsFlag]:
    """Heuristic spot check for red-team-recon findings: evidence_ref
    values should point at metadata (a header name, a status code, a
    hostname), never a captured response body -- a long inline value, or
    one naming a response body directly, would suggest this agent
    captured more than the fact that something is exposed. Framed as a
    heuristic because that's exactly what it is: a real body could still
    be short. It exists to catch an obvious regression, not to prove a
    negative."""
    flags = []
    for finding in findings:
        if finding.get("domain") != "red-team-recon":
            continue
        for ref in finding.get("evidence_ref") or []:
            if "/body" in ref or len(ref) > _SUSPICIOUS_EVIDENCE_REF_LENGTH:
                flags.append(
                    EthicsFlag(
                        guardrail="red_team_never_captures_content",
                        severity="warning",
                        description=f"Finding {finding.get('finding_id', '?')!r} has a suspiciously body-like evidence_ref.",
                        evidence_ref=[ref],
                    )
                )
    return flags


def run_ethics_checks(
    findings: list[dict], scenarios: Optional[list[dict]], events: list[dict]
) -> list[EthicsFlag]:
    flags: list[EthicsFlag] = []
    flags += check_exploitation_status_vocabulary(findings)
    flags += check_attack_scenarios_never_confirmed(scenarios or [])
    flags += check_scope_violations_were_actually_refused(events)
    flags += check_red_team_no_body_capture(findings)
    return flags
