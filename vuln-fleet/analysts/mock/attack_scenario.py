"""Mock attack-scenario analyst: proves the Tier 0.5 pipeline (schema
validation, integrity checking, report rendering, orchestrator
sequencing) end-to-end, exactly the same role adapters/mock/*.py played
for the nine Tier 1 domains before real adapters existed for two of them.

This is NOT real analysis. Predicting how a real attacker would chain
findings together requires genuine contextual reasoning -- exactly what
this project's own design principle reserves for an agent
(.claude/agents/attack-scenario-analyst.md), never for deterministic
code (see README.md: "agents reason about context and narrative;
matching and scoring are code"). There is no way to build a "real"
version of this the way adapters/supply_chain.py became real by calling
a genuine external data source: an attack-scenario analyst's product is
the reasoning itself, not a fact retrievable from an API. So unlike the
Tier 1 domains, this one has no upgrade path from mock to real adapter
-- its real counterpart is a live agent, not more code here.

synthesize() picks the two highest-risk issues from the run (if at least
two exist) and produces exactly one clearly-labeled illustrative
scenario chaining their findings, using generic, templated language.
It never invents a finding_id, never claims a specific attacker
technique it can't ground in the actual titles it was given, and never
omits the "MOCK ANALYSIS" label -- a human or downstream tooling reading
a report must never mistake this for genuine adversary-perspective
judgement.
"""
from __future__ import annotations

_MOCK_LABEL = "[MOCK ANALYSIS -- ILLUSTRATIVE ONLY, NOT A REAL ATTACKER ASSESSMENT]"


def synthesize(findings: list[dict], issues: list[dict]) -> list[dict]:
    if len(issues) < 2:
        return []

    ranked = sorted(issues, key=lambda issue: issue["risk_score"], reverse=True)[:2]
    findings_by_id = {f["finding_id"]: f for f in findings}
    first_finding_id = ranked[0]["finding_ids"][0]
    second_finding_id = ranked[1]["finding_ids"][0]
    first = findings_by_id.get(first_finding_id)
    second = findings_by_id.get(second_finding_id)
    if first is None or second is None:
        return []

    return [
        {
            "title": f"{_MOCK_LABEL} Chaining '{first['title']}' with '{second['title']}'",
            "attacker_goal": "Escalate from the higher-risk finding into whatever the lower-risk one exposes next.",
            "narrative": (
                f"{_MOCK_LABEL} This is a templated placeholder, not a genuine adversary-perspective assessment. "
                f"A real analyst would describe, in the attacker's own terms, how someone could start from "
                f"'{first['title']}' and use it to reach '{second['title']}', and what that combination would let "
                "them do that neither finding alone would."
            ),
            "attack_path": [
                {"step": 1, "description": f"{_MOCK_LABEL} Placeholder step grounded in: {first['title']}", "based_on_finding_id": first["finding_id"]},
                {"step": 2, "description": f"{_MOCK_LABEL} Placeholder step grounded in: {second['title']}", "based_on_finding_id": second["finding_id"]},
            ],
            "chained_finding_ids": [first["finding_id"], second["finding_id"]],
            "likelihood": "low",
            "confidence": 0.1,
            "potential_impact": f"{_MOCK_LABEL} Not assessed -- a real analyst would state a concrete, evidenced impact here.",
            "mitre_attack_techniques": [],
            "evidence_ref": sorted(set(first["evidence_ref"]) | set(second["evidence_ref"])),
        }
    ]
