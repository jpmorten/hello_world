"""Tier 0 orchestrator: proves the spawn -> worker -> rollup -> log ->
report loop end-to-end.

Real Tier 1/Tier 2 agents will eventually be Claude Code subagents
(.claude/agents/*.md, step 6) coordinating through this same
SpawnManager/LogBus/ScopeModel. Until then, this module runs the domain
decomposition and worker logic directly as Python, against
adapters/mock/*.py, so the fan-out, scope enforcement, dedup, and
reporting plumbing can be proven and unit-tested without a live Claude
Code session.

Adding a domain is meant to stay a DomainSpec entry, not a change to this
file's control flow — see the design brief's "declarative and
extensible" requirement for Tier 1 agents.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from engine import baseline, reports
from engine.dedupe import compute_finding_id, correlate_findings, dedupe_findings
from engine.logbus import LogBus, Sink
from engine.risk import score_finding
from engine.scope import ScopeModel, ScopeResolution, ScopeViolation
from engine.spawn import SpawnManager, SpawnRefused
from schema.validate import validate_finding

AdapterFn = Callable[[str, ScopeResolution], list[dict]]


@dataclass(frozen=True)
class DomainSpec:
    domain: str
    worker_role: str
    targets: list[str]
    adapter_fn: AdapterFn


@dataclass
class DomainRollup:
    domain: str
    findings: list[dict]
    targets_attempted: list[str]
    targets_failed: dict[str, str] = field(default_factory=dict)


class Orchestrator:
    def __init__(
        self,
        run_id: str,
        scope_model: ScopeModel,
        log_dir: Path | str = "logs",
        report_dir: Path | str = "reports",
        sinks: Optional[list[Sink]] = None,
        domain_budgets: Optional[dict[str, int]] = None,
        previous_run_id: Optional[str] = None,
        now_fn: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ):
        self.run_id = run_id
        self.scope_model = scope_model
        self.reports_root = Path(report_dir)
        self.report_dir = self.reports_root / run_id
        self.previous_run_id = previous_run_id
        self._now = now_fn
        self.logbus = LogBus(run_id, log_dir=log_dir, sinks=sinks or [])
        self.spawn_manager = SpawnManager(
            run_id,
            self.logbus,
            domain_budgets=domain_budgets or {},
            default_domain_budget=3,
            now_fn=now_fn,
        )
        self.rollups: dict[str, DomainRollup] = {}

    def _emit_root_event(self, event_type: str, severity: str, message: str, details: Optional[dict] = None) -> None:
        event = {
            "timestamp": self._now().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "run_id": self.run_id,
            "agent_id": self.spawn_manager.orchestrator_agent_id,
            "agent_role": "fleet-orchestrator",
            "tier": 0,
            "parent_agent_id": None,
            "span_id": self.spawn_manager.orchestrator_span_id,
            "parent_span_id": None,
            "event_type": event_type,
            "severity": severity,
            "entity": None,
            "asset_id": None,
            "scope_ref": None,
            "authorization_ref": None,
            "message": message,
            "evidence_ref": [],
        }
        if details:
            event["details"] = details
        self.logbus.emit(event)

    def run(self, domain_specs: list[DomainSpec]) -> dict:
        self._emit_root_event(
            "run_start", "info", f"Run {self.run_id} starting.", details={"domains": [d.domain for d in domain_specs]}
        )

        for spec in domain_specs:
            self.rollups[spec.domain] = self._run_domain(spec)

        all_findings = [f for rollup in self.rollups.values() for f in rollup.findings]
        deduped = dedupe_findings(all_findings)
        for finding in deduped:
            finding["risk_score"] = score_finding(finding)

        deduped, delta = baseline.compute_and_apply_delta(deduped, self.reports_root, self.previous_run_id)
        issues = correlate_findings(deduped)
        report_paths = reports.write_reports(
            self.report_dir, self.run_id, deduped, issues, self.rollups, delta, self.previous_run_id
        )

        self._emit_root_event(
            "run_complete",
            "info",
            f"Run {self.run_id} complete: {len(deduped)} finding(s) across {len(self.rollups)} domain(s).",
            details={"finding_count": len(deduped), "domains": list(self.rollups.keys()), "delta": delta},
        )
        return {"findings": deduped, "rollups": self.rollups, "issues": issues, "delta": delta, "report_paths": report_paths}

    def _run_domain(self, spec: DomainSpec) -> DomainRollup:
        domain_handle = self.spawn_manager.spawn(domain=spec.domain, agent_role=spec.domain)
        findings: list[dict] = []
        targets_failed: dict[str, str] = {}

        for target_ref in spec.targets:
            try:
                worker_handle = self.spawn_manager.spawn(
                    domain=spec.domain,
                    agent_role=spec.worker_role,
                    parent=domain_handle,
                    target_ref=target_ref,
                )
            except SpawnRefused as refused:
                # already logged by spawn_manager; this target is a
                # coverage gap for the rollup, not a reason to stop.
                targets_failed[target_ref] = refused.reason
                continue

            try:
                resolution = self.scope_model.assert_in_scope(target_ref)
            except ScopeViolation as violation:
                targets_failed[target_ref] = f"scope_violation: {violation.reason}"
                self.spawn_manager.emit_event_for(
                    worker_handle,
                    "scope_violation",
                    "error",
                    f"Refused {target_ref!r}: {violation.reason}",
                    details={"target_ref": target_ref},
                )
                self.spawn_manager.complete(
                    worker_handle.agent_id, event_type="agent_error", message=f"Refused: {violation.reason}"
                )
                continue

            self.spawn_manager.heartbeat(worker_handle.agent_id)

            try:
                raw_findings = spec.adapter_fn(target_ref, resolution)
            except Exception as exc:  # an adapter failure is a coverage gap, not a crash
                targets_failed[target_ref] = f"adapter_error: {exc}"
                self.spawn_manager.complete(worker_handle.agent_id, event_type="agent_error", message=str(exc))
                continue

            for raw in raw_findings:
                finding = self._finalize_finding(raw, spec, resolution)
                validate_finding(finding)
                self.spawn_manager.emit_event_for(
                    worker_handle, "finding", "info", f"Finding: {finding['title']}", details=finding
                )
                findings.append(finding)

            self.spawn_manager.complete(
                worker_handle.agent_id, message=f"{len(raw_findings)} finding(s) for {target_ref!r}."
            )

        self.spawn_manager.complete(
            domain_handle.agent_id,
            message=f"{len(findings)} finding(s) across {len(spec.targets)} target(s), {len(targets_failed)} gap(s).",
        )
        self.spawn_manager.emit_event_for(
            domain_handle,
            "rollup",
            "info",
            f"{spec.domain} rollup: {len(findings)} finding(s), {len(targets_failed)} target(s) failed.",
            details={"finding_count": len(findings), "targets_failed": targets_failed},
        )
        return DomainRollup(
            domain=spec.domain, findings=findings, targets_attempted=list(spec.targets), targets_failed=targets_failed
        )

    def _finalize_finding(self, raw: dict, spec: DomainSpec, resolution: ScopeResolution) -> dict:
        now = self._now().strftime("%Y-%m-%dT%H:%M:%SZ")
        finding_id = compute_finding_id(
            domain=spec.domain,
            identifiers=raw.get("identifiers", {}),
            asset_id=resolution.asset_id,
            location_ref=raw["location"]["ref"],
            title=raw.get("title", ""),
        )
        return {
            "finding_id": finding_id,
            "run_id": self.run_id,
            "domain": spec.domain,
            "entity": resolution.entity,
            "asset": {
                "asset_id": resolution.asset_id,
                "type": resolution.asset_type,
                "owner_team": resolution.owner_team,
                "criticality": resolution.criticality,
            },
            "first_seen": now,
            "last_seen": now,
            "status": "new",
            "scope_ref": resolution.scope_ref,
            "authorization_ref": None,
            **raw,
        }

