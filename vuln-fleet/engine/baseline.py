"""Cross-run baseline delta: new / recurring / resolved / regressed.

A run's own findings.json only ever lists what's present *now* —
"resolved" findings are absent from it by definition, so tracking them
needs state that outlives a single run. That state is
reports/.baseline_ledger.json: a flat, accumulated set of finding_ids
that have been resolved at some point, ever. A finding_id lands there
the run after it stops appearing in the current sweep, and stays there
until (if ever) it reappears — at which point it's a *regression*, not a
fresh "new" finding, and stays out of the ledger going forward since it's
active again. That distinction is exactly what the design's baseline
delta block exists for: something coming back after being fixed is a
different, larger signal than something nobody had looked at before.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

LEDGER_FILENAME = ".baseline_ledger.json"


def _ledger_path(reports_root: Path) -> Path:
    return reports_root / LEDGER_FILENAME


def load_ledger(reports_root: Path) -> set[str]:
    """Never raises: a missing or corrupt ledger reads as empty (nothing
    known resolved yet), the honest state for "we don't have history."""
    path = _ledger_path(reports_root)
    if not path.exists():
        return set()
    try:
        return set(json.loads(path.read_text()).get("resolved_ids", []))
    except (json.JSONDecodeError, OSError, AttributeError):
        return set()


def save_ledger(reports_root: Path, resolved_ids: set[str]) -> None:
    reports_root.mkdir(parents=True, exist_ok=True)
    _ledger_path(reports_root).write_text(json.dumps({"resolved_ids": sorted(resolved_ids)}, indent=2))


def load_previous_findings(reports_root: Path, previous_run_id: Optional[str]) -> list[dict]:
    """[] when there's no previous run to compare against (first run, or
    the caller didn't supply one) — never raises on a missing/corrupt file."""
    if previous_run_id is None:
        return []
    findings_path = reports_root / previous_run_id / "findings.json"
    if not findings_path.exists():
        return []
    try:
        return json.loads(findings_path.read_text())
    except (json.JSONDecodeError, OSError):
        return []


def compute_delta(current_findings: list[dict], previous_findings: list[dict], previously_resolved_ids: set[str]) -> dict:
    """Set arithmetic over finding_ids only — plain, deterministic code,
    same as everything else in this fleet that isn't narrative. Regressed
    takes priority over recurring for a finding_id that (through a
    corrupted or manually-edited ledger) ended up in both current and
    previously_resolved_ids — an id in the resolved ledger to begin with
    should never also have been in the last active run, but if it is,
    treating it as a regression is the safer of the two misreadings.
    """
    current_ids = {f["finding_id"] for f in current_findings}
    previous_ids = {f["finding_id"] for f in previous_findings}

    regressed_ids = current_ids & previously_resolved_ids
    new_ids = current_ids - previous_ids - regressed_ids
    recurring_ids = (current_ids & previous_ids) - regressed_ids
    resolved_ids = previous_ids - current_ids

    return {
        "new": sorted(new_ids),
        "recurring": sorted(recurring_ids),
        "resolved": sorted(resolved_ids),
        "regressed": sorted(regressed_ids),
    }


def apply_delta_status(findings: list[dict], delta: dict) -> list[dict]:
    """Returns findings with `status` set per the delta (new copies —
    never mutates the input list/dicts)."""
    status_by_id = {}
    for fid in delta["new"]:
        status_by_id[fid] = "new"
    for fid in delta["recurring"]:
        status_by_id[fid] = "recurring"
    for fid in delta["regressed"]:
        status_by_id[fid] = "regressed"

    updated = []
    for finding in findings:
        finding = dict(finding)
        finding["status"] = status_by_id.get(finding["finding_id"], "new")
        updated.append(finding)
    return updated


def compute_and_apply_delta(
    current_findings: list[dict], reports_root: Path, previous_run_id: Optional[str]
) -> tuple[list[dict], dict]:
    """The one entry point a run actually calls: loads history, computes
    the delta, stamps `status` onto every current finding, updates and
    persists the ledger, and returns (updated_findings, delta)."""
    previous_findings = load_previous_findings(reports_root, previous_run_id)
    previously_resolved = load_ledger(reports_root)

    delta = compute_delta(current_findings, previous_findings, previously_resolved)
    updated_findings = apply_delta_status(current_findings, delta)

    resolved_going_forward = (previously_resolved | set(delta["resolved"])) - set(delta["regressed"])
    save_ledger(reports_root, resolved_going_forward)

    return updated_findings, delta
