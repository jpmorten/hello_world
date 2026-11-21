"""Tier G (governance): Warden's aggregate review, compiled once per run
after every Tier 1 domain and the Tier 0.5 attack-scenario-analyst have
reported in (engine/orchestrator.py calls this unconditionally -- unlike
`attack_scenario_fn`, governance needs no live agent to produce a real,
useful result: PolicyCop/CostCop/Ethica's checks are all deterministic
code, the same way engine/scope.py's checks are. A live Warden/PolicyCop/
CostCop/Ethica session adds narrative and discretionary judgement on top
of this module's real numbers; it never re-derives them by itself).

Combines:
  - PolicyCop  (engine/policy_checks.py)  -- EU regulatory/legislative conduct
  - CostCop    (engine/token_budget.py)   -- token-spend budget status
  - Ethica     (engine/ethics_checks.py)  -- non-exploitation/guardrail conduct
into one GovernanceReport (schema/governance_report.schema.json) and a
single verdict Warden acts on.

A `critical` verdict makes the orchestrator trigger this run's own kill
switch (a record -- governance runs after everything else this run does,
so there's nothing left in THIS run to stop) AND write a fleet-wide halt
flag via `trigger_fleet_halt`, which every future `full-sweep`/
`delta-sweep`/`target`/`red-team-recon` invocation refuses to run past
(engine/cli.py) until a human runs `python3 -m engine.cli resume` --
deliberately not something any agent, live or otherwise, can clear on
its own. See RUNBOOK.md.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from engine import ethics_checks, policy_checks, token_budget

DEFAULT_HALT_PATH = "reports/FLEET_HALT.flag"


class FleetHalted(Exception):
    """Raised when a caller tries to start a new run while a Warden-
    triggered fleet-wide halt is in effect. Carries the halt record so
    the caller (engine/cli.py) can print who/why without re-reading the
    flag file itself."""

    def __init__(self, halt_record: dict):
        self.halt_record = halt_record
        super().__init__(f"Fleet halted: {halt_record.get('reason', 'no reason recorded')}")


def compute_report_id(*, run_id: str, generated_at: str) -> str:
    """Deterministic fingerprint: sha256(run_id, generated_at). Mirrors
    engine/dedupe.py's compute_finding_id and engine/attack_scenarios.py's
    compute_scenario_id -- an id is computed by code from the report's
    own content, never asserted."""
    payload = "|".join([run_id, generated_at])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _severity_rank(severity: str) -> int:
    return {"critical": 2, "warning": 1, "info": 0}.get(severity, 0)


def compile_governance_report(
    *,
    run_id: str,
    repo_root: Path,
    findings: list[dict],
    scenarios: Optional[list[dict]],
    events: list[dict],
    tokens_used: Optional[int] = None,
    now_fn: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    token_budget_path: Optional[Path] = None,
    token_ledger_path: Optional[Path] = None,
) -> dict:
    """Runs PolicyCop + Ethica's deterministic checks and CostCop's
    budget arithmetic against this run's real output, and computes
    Warden's verdict. `tokens_used`, when given by a live session that
    actually knows its own real usage, is recorded to the ledger before
    the status is computed; when None (the honest default), the ledger
    is only read, never written."""
    now = now_fn()
    generated_at = now.strftime("%Y-%m-%dT%H:%M:%SZ")

    policy_violations = policy_checks.run_policy_checks(repo_root, now)
    ethics_flags = ethics_checks.run_ethics_checks(findings, scenarios, events)

    budget_path = token_budget_path or (repo_root / "scope" / "token-budget.yaml")
    ledger_path = token_ledger_path or (repo_root / "scope" / "token-usage-ledger.yaml")
    budget = token_budget.TokenBudget.load(budget_path)
    if tokens_used is not None:
        token_budget.record_usage(run_id, tokens_used, generated_at, ledger_path)
    cost_status = token_budget.status(budget, token_budget.load_ledger(ledger_path))

    worst = max(
        [_severity_rank(v.severity) for v in policy_violations]
        + [_severity_rank(f.severity) for f in ethics_flags]
        + [1 if cost_status["alert"] else 0],
        default=0,
    )
    verdict = {2: "critical", 1: "warning", 0: "clear"}[worst]

    escalation_reason = None
    if verdict != "clear":
        threshold = 2 if verdict == "critical" else 1
        items = [v.description for v in policy_violations if _severity_rank(v.severity) >= threshold]
        items += [f.description for f in ethics_flags if _severity_rank(f.severity) >= threshold]
        if verdict == "warning" and cost_status["alert"]:
            items.append(
                f"Token budget below alert threshold: {cost_status['remaining_pct']}% remaining "
                f"(threshold {cost_status['alert_threshold_pct']}%)."
            )
        escalation_reason = "; ".join(items) if items else None

    return {
        "report_id": compute_report_id(run_id=run_id, generated_at=generated_at),
        "run_id": run_id,
        "generated_at": generated_at,
        "policy": {
            "regulations_checked": policy_checks.REGULATIONS_CHECKED,
            "violations": [v.to_dict() for v in policy_violations],
        },
        "cost": cost_status,
        "ethics": {
            "guardrails_checked": ethics_checks.GUARDRAILS_CHECKED,
            "flags": [f.to_dict() for f in ethics_flags],
        },
        "verdict": verdict,
        "kill_switch_engaged": verdict == "critical",
        "escalation_reason": escalation_reason,
    }


def trigger_fleet_halt(
    reason: str,
    report_ref: str,
    halt_path: Path | str = DEFAULT_HALT_PATH,
    now_fn: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> Path:
    path = Path(halt_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    # Written via yaml.safe_dump (not hand-built f-string interpolation)
    # so a reason/report_ref containing a colon, quote, or an
    # ISO8601-timestamp-shaped value round-trips back as the plain
    # string it is -- yaml.safe_load auto-converts an unquoted bare
    # timestamp to a datetime, which is not what fleet_halt_status()'s
    # callers expect halted_at to be.
    import yaml

    path.write_text(
        yaml.safe_dump(
            {
                "halted_at": now_fn().strftime("%Y-%m-%dT%H:%M:%SZ"),
                "reason": reason.replace("\n", " "),
                "report_ref": report_ref,
            },
            sort_keys=False,
        )
    )
    return path


def clear_fleet_halt(halt_path: Path | str = DEFAULT_HALT_PATH) -> bool:
    """Human-operator action only -- see RUNBOOK.md. Nothing in this
    codebase calls this from an automated or agent-driven code path; it
    exists for `engine.cli resume`, which a person runs deliberately.
    Returns True if a halt was actually cleared, False if none was set."""
    path = Path(halt_path)
    if path.exists():
        path.unlink()
        return True
    return False


def fleet_halt_status(halt_path: Path | str = DEFAULT_HALT_PATH) -> Optional[dict]:
    """None when no halt is in effect; otherwise the halt record
    (halted_at/reason/report_ref) written by trigger_fleet_halt."""
    import yaml

    path = Path(halt_path)
    if not path.exists():
        return None
    return yaml.safe_load(path.read_text()) or {}


def raise_if_halted(halt_path: Path | str = DEFAULT_HALT_PATH) -> None:
    record = fleet_halt_status(halt_path)
    if record is not None:
        raise FleetHalted(record)
