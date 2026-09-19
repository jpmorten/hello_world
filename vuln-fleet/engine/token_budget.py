"""CostCop's arithmetic: a token-spend ledger checked against a declared
budget. Pure deterministic code -- no model judgement -- per this
project's governance discipline that arithmetic is unit-tested code, not
agent output (see engine/scope.py's own module docstring for the same
principle applied to scope decisions). A live CostCop agent narrates and
prioritizes this module's numbers; it never recomputes them by eye.

Real numbers in, real numbers out: this module never estimates or
fabricates a token count. Only a live Claude Code session -- the only
party in this fleet that actually knows its own token usage, since the
deterministic engine/adapter code makes no model calls at all -- can
supply one, via `python3 -m engine.cli record-usage <run_id> <tokens>`.
A run nobody reports usage for stays honestly "not measured" rather than
defaulting to zero (which would look like a free run) or a guess.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import yaml

DEFAULT_BUDGET_PATH = "scope/token-budget.yaml"
DEFAULT_LEDGER_PATH = "scope/token-usage-ledger.yaml"


class TokenBudgetConfigError(Exception):
    """scope/token-budget.yaml is missing or malformed."""


@dataclass(frozen=True)
class TokenBudget:
    budget_tokens: int
    alert_threshold_pct: float

    @classmethod
    def load(cls, path: Path | str = DEFAULT_BUDGET_PATH) -> "TokenBudget":
        path = Path(path)
        if not path.exists():
            raise TokenBudgetConfigError(f"{path}: not found")
        doc = yaml.safe_load(path.read_text()) or {}
        if "budget_tokens" not in doc or "alert_threshold_pct" not in doc:
            raise TokenBudgetConfigError(f"{path}: missing budget_tokens/alert_threshold_pct")
        budget_tokens = doc["budget_tokens"]
        alert_threshold_pct = doc["alert_threshold_pct"]
        if not isinstance(budget_tokens, int) or isinstance(budget_tokens, bool) or budget_tokens <= 0:
            raise TokenBudgetConfigError(f"{path}: budget_tokens must be a positive integer")
        if not isinstance(alert_threshold_pct, (int, float)) or isinstance(alert_threshold_pct, bool) or not (0 < alert_threshold_pct <= 100):
            raise TokenBudgetConfigError(f"{path}: alert_threshold_pct must be in (0, 100]")
        return cls(budget_tokens=budget_tokens, alert_threshold_pct=float(alert_threshold_pct))


def load_ledger(path: Path | str = DEFAULT_LEDGER_PATH) -> list[dict]:
    path = Path(path)
    if not path.exists():
        return []
    doc = yaml.safe_load(path.read_text()) or {}
    return doc.get("entries") or []


def record_usage(run_id: str, tokens: int, recorded_at: str, path: Path | str = DEFAULT_LEDGER_PATH) -> list[dict]:
    """Appends one ledger entry -- never mutates an existing one, so a
    run's usage is recorded exactly once per `record-usage` call anyone
    ever made, and the ledger's sum always equals the sum of those calls.
    Returns the full, updated ledger."""
    if tokens < 0:
        raise ValueError("tokens must be >= 0")
    path = Path(path)
    entries = load_ledger(path)
    entries.append({"run_id": run_id, "tokens": tokens, "recorded_at": recorded_at})
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump({"entries": entries}, sort_keys=False))
    return entries


def status(budget: TokenBudget, entries: list[dict]) -> dict:
    """Real arithmetic only: sums the ledger, compares to budget.
    `measured` is false for a genuinely empty ledger (nobody has ever
    called record_usage) -- distinct from a ledger that legitimately
    recorded a 0-token run. `alert` is true once remaining_pct drops
    below the configured threshold -- CostCop's whole job is noticing
    that transition, not guessing at it."""
    spent = sum(e["tokens"] for e in entries)
    remaining = max(budget.budget_tokens - spent, 0)
    remaining_pct = 100.0 * remaining / budget.budget_tokens
    return {
        "measured": bool(entries),
        "budget_tokens": budget.budget_tokens,
        "spent_tokens": spent,
        "remaining_tokens": remaining,
        "remaining_pct": round(remaining_pct, 2),
        "alert_threshold_pct": budget.alert_threshold_pct,
        "alert": remaining_pct < budget.alert_threshold_pct,
    }
