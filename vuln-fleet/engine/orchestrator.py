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

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from engine import baseline, governance, reports
from engine.attack_scenarios import AnalystFn, finalize_scenarios
from engine.dedupe import compute_finding_id, correlate_findings, dedupe_findings
from engine.logbus import LogBus, Sink
from engine.risk import score_finding
from engine.scope import ScopeModel, ScopeResolution, ScopeViolation
from engine.spawn import SpawnManager, SpawnRefused
from schema.validate import validate_attack_scenario, validate_finding

AdapterFn = Callable[[str, ScopeResolution], list[dict]]

# vuln-fleet/ -- this file lives at vuln-fleet/engine/orchestrator.py.
# Tier G's PolicyCop/Ethica checks (engine/policy_checks.py,
# engine/ethics_checks.py) inspect the fleet's own real, current repo
# state (.claude/agents/, schema/, analysts/mock/, scope/) -- not
# anything scoped to a particular run's report_dir/log_dir, which tests
# point at tmp_path -- so every run's governance review looks at the
# same real tree a live operator would.
_REPO_ROOT = Path(__file__).resolve().parent.parent


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
        kill_flag_path: Optional[Path | str] = None,
        now_fn: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
        attack_scenario_fn: Optional[AnalystFn] = None,
    ):
        self.run_id = run_id
        self.scope_model = scope_model
        # None (the default) means the feature is honestly off: no Tier
        # 0.5 analysis stage runs, no attack_scenario events are logged,
        # and run()'s result has an empty attack_scenarios list -- never
        # a silently-skipped step dressed up as "nothing to report."
        self.attack_scenario_fn = attack_scenario_fn
        self.reports_root = Path(report_dir)
        self.report_dir = self.reports_root / run_id
        self.previous_run_id = previous_run_id
        # Checked between targets/domains, not just at startup: a run can
        # take real wall-clock time (live adapters hit real networks), and
        # this file is how a separate `engine.cli kill` invocation reaches
        # an already-running orchestrator.run() call -- there's no other
        # IPC between them.
        self.kill_flag_path = Path(kill_flag_path) if kill_flag_path else self.reports_root / f"{run_id}.kill"
        # Fleet-wide, not per-run (unlike kill_flag_path above): Warden's
        # critical-verdict halt refuses every FUTURE run against this same
        # reports_root, not just this one -- see engine/governance.py and
        # engine/cli.py's halt/resume subcommands.
        self.halt_flag_path = self.reports_root / "FLEET_HALT.flag"
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

    def _kill_requested(self) -> bool:
        return self.kill_flag_path.exists()

    def _gap_rollup(self, spec: DomainSpec, reason: str) -> DomainRollup:
        return DomainRollup(
            domain=spec.domain,
            findings=[],
            targets_attempted=list(spec.targets),
            targets_failed={t: reason for t in spec.targets},
        )

    def run(self, domain_specs: list[DomainSpec], tokens_used: Optional[int] = None) -> dict:
        # Checked before this run's own log even exists: a fleet-wide halt
        # (Warden's response to a prior run's critical governance verdict)
        # refuses to start a new run at all, rather than starting one and
        # immediately killing it -- there is nothing this run could
        # legitimately do while a human hasn't yet reviewed why it was
        # halted. See engine/governance.py's module docstring.
        governance.raise_if_halted(self.halt_flag_path)

        self._emit_root_event(
            "run_start", "info", f"Run {self.run_id} starting.", details={"domains": [d.domain for d in domain_specs]}
        )

        for spec in domain_specs:
            if self.spawn_manager.kill_switch_active:
                # a prior domain in this same run already tripped the kill
                # switch; every domain after it is a full gap, and never
                # even gets a domain_spawn event -- it was never reached.
                self.rollups[spec.domain] = self._gap_rollup(
                    spec, "kill_switch: run terminated before this domain started"
                )
                continue
            self.rollups[spec.domain] = self._run_domain(spec)

        all_findings = [f for rollup in self.rollups.values() for f in rollup.findings]
        deduped = dedupe_findings(all_findings)
        for finding in deduped:
            finding["risk_score"] = score_finding(finding)

        deduped, delta = baseline.compute_and_apply_delta(deduped, self.reports_root, self.previous_run_id)
        issues = correlate_findings(deduped)
        scenarios = self._run_attack_scenario_analysis(deduped, issues)
        governance_report = self._run_governance_review(deduped, scenarios, tokens_used)
        report_paths = reports.write_reports(
            self.report_dir,
            self.run_id,
            deduped,
            issues,
            self.rollups,
            delta,
            self.previous_run_id,
            scenarios,
            governance_report,
        )

        self._emit_root_event(
            "run_complete",
            "info",
            f"Run {self.run_id} complete: {len(deduped)} finding(s) across {len(self.rollups)} domain(s).",
            details={"finding_count": len(deduped), "domains": list(self.rollups.keys()), "delta": delta},
        )
        return {
            "findings": deduped,
            "rollups": self.rollups,
            "issues": issues,
            "delta": delta,
            "report_paths": report_paths,
            "attack_scenarios": scenarios,
            "governance_report": governance_report,
        }

    def _run_attack_scenario_analysis(self, findings: list[dict], issues: list[dict]) -> Optional[list[dict]]:
        """Tier 0.5: one analysis pass over the whole run's findings, after
        every domain has reported in -- never per-domain, per-target. See
        engine/attack_scenarios.py's module docstring for why this exists
        as a separate module/stage rather than another adapter.

        Returns None (not []) when no analyst is wired in at all -- the
        report suite needs to say "this stage never ran" distinctly from
        "it ran and found/kept nothing," the same distinction the rest of
        this fleet draws between a missing capability and a clean result.
        """
        if self.attack_scenario_fn is None:
            return None

        if self.spawn_manager.kill_switch_active:
            # A killed run is wrapping up -- no new activity starts,
            # exactly like a domain _run_domain never reaches (see run()'s
            # own kill_switch check above). [] (not None): the stage would
            # have run had the kill switch not tripped, so this isn't "no
            # analyst wired in," it's "skipped because the run stopped."
            return []

        handle = self.spawn_manager.spawn(domain="attack-scenario-analysis", agent_role="attack-scenario-analyst")

        if not findings:
            self.spawn_manager.complete(handle.agent_id, message="No findings this run; nothing to chain into a scenario.")
            return []

        known_finding_ids = {f["finding_id"] for f in findings}
        try:
            raw_scenarios = self.attack_scenario_fn(findings, issues)
        except Exception as exc:  # an analyst failure is a soft gap, not a crashed run
            self.spawn_manager.complete(handle.agent_id, event_type="agent_error", message=str(exc))
            return []

        scenarios, rejections = finalize_scenarios(raw_scenarios, self.run_id, known_finding_ids)

        for rejection in rejections:
            self.spawn_manager.emit_event_for(
                handle,
                "agent_error",
                "warning",
                f"Attack scenario rejected: {rejection.raw_title!r} -- {rejection.reason}",
                details={"reason": rejection.reason, "title": rejection.raw_title},
            )

        for scenario in scenarios:
            validate_attack_scenario(scenario)
            self.spawn_manager.emit_event_for(
                handle,
                "attack_scenario",
                "notice",
                f"Predicted attack scenario: {scenario['title']}",
                details=scenario,
            )

        self.spawn_manager.complete(
            handle.agent_id, message=f"{len(scenarios)} predicted scenario(s), {len(rejections)} rejected."
        )
        return scenarios

    def _read_run_events(self) -> list[dict]:
        """Reads back this run's own persisted hash-chained log --
        Ethica's checks (engine/ethics_checks.py) cross-reference the
        run's real event stream, not an in-memory copy LogBus doesn't
        keep. Safe to call here: every event this run will ever emit
        before governance review runs has already been flushed to disk."""
        if not self.logbus.log_path.exists():
            return []
        with open(self.logbus.log_path, encoding="utf-8") as f:
            return [json.loads(line) for line in f if line.strip()]

    def _run_governance_review(
        self, findings: list[dict], scenarios: Optional[list[dict]], tokens_used: Optional[int]
    ) -> dict:
        """Tier G: Warden's aggregate review, compiled once per run after
        everything else this run does -- see engine/governance.py's
        module docstring for why this always runs (no live-agent
        dependency, unlike attack-scenario analysis) and what a critical
        verdict actually does. A live Warden/PolicyCop/CostCop/Ethica
        session narrates and prioritizes this report; it never
        recomputes the numbers in it.
        """
        report = governance.compile_governance_report(
            run_id=self.run_id,
            repo_root=_REPO_ROOT,
            findings=findings,
            scenarios=scenarios,
            events=self._read_run_events(),
            tokens_used=tokens_used,
            now_fn=self._now,
        )

        # A prior domain in this same run may already have tripped the
        # per-run kill switch (the OLD, unrelated `<run_id>.kill` flag
        # mechanism) -- spawn() refuses every new spawn once that's
        # true, exactly like it does for a Tier 1 domain (see run()'s own
        # kill_switch check). Governance review still runs and is still
        # logged either way; it just logs as a tier-0 orchestrator event
        # instead of a spawned "warden" agent when a new spawn isn't
        # possible, the same distinction _emit_root_event vs.
        # emit_event_for already draws elsewhere in this file.
        handle = None
        if not self.spawn_manager.kill_switch_active:
            handle = self.spawn_manager.spawn(domain="fleet-governance", agent_role="warden")

        def _emit(event_type: str, severity: str, message: str) -> None:
            if handle is not None:
                self.spawn_manager.emit_event_for(handle, event_type, severity, message, details=report)
            else:
                self._emit_root_event(event_type, severity, message, details=report)

        severity = {"clear": "info", "warning": "warning", "critical": "critical"}[report["verdict"]]
        _emit(
            "governance_report",
            severity,
            f"Governance verdict: {report['verdict']} "
            f"({len(report['policy']['violations'])} policy violation(s), "
            f"{len(report['ethics']['flags'])} ethics flag(s), "
            f"cost alert={report['cost']['alert']}).",
        )

        if report["kill_switch_engaged"]:
            reason = report["escalation_reason"] or "critical governance verdict"
            _emit("escalation", "critical", f"\U0001f6a8 GOVERNANCE ALERT — Warden escalating: {reason}")
            # Idempotent and, at this point in run(), a record rather than
            # an in-flight stop (nothing is left running this late) --
            # the flag file below is what actually stops the NEXT run.
            self.spawn_manager.trigger_kill_switch(f"governance: {reason}")
            governance.trigger_fleet_halt(reason, report["report_id"], self.halt_flag_path, now_fn=self._now)

        if handle is not None:
            self.spawn_manager.complete(handle.agent_id, message=f"Governance verdict: {report['verdict']}.")
        return report

    def _run_domain(self, spec: DomainSpec) -> DomainRollup:
        domain_handle = self.spawn_manager.spawn(domain=spec.domain, agent_role=spec.domain)
        findings: list[dict] = []
        targets_failed: dict[str, str] = {}

        for target_ref in spec.targets:
            if self._kill_requested():
                if not self.spawn_manager.kill_switch_active:
                    self.spawn_manager.trigger_kill_switch(f"kill flag present: {self.kill_flag_path}")
                targets_failed[target_ref] = "kill_switch: run terminated before this target was assessed"
                continue

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

            # Logged on the success path too, not just violations: the SOC
            # audit trail should show every scope decision this run made,
            # not only the refusals — matching .claude/hooks/scope_guard.py,
            # which logs scope_check the same way for the live-agent path.
            self.spawn_manager.emit_event_for(
                worker_handle,
                "scope_check",
                "info",
                f"Target {target_ref!r} resolved in scope.",
                details={"target_ref": target_ref, "asset_id": resolution.asset_id},
            )

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

