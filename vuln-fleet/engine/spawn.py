"""Budgeted, depth-limited spawning with lineage, dedup, and heartbeats.

Tier 0 (the orchestrator) is singular and pre-exists this manager — it is
never itself an AgentHandle. spawn() with parent=None creates a Tier 1
domain agent on the orchestrator's behalf; spawn() with a Tier 1 parent
creates a Tier 2 worker. A Tier 2 handle can never be a parent: the
resulting tier would be 3, over the cap, so it is refused the same way any
other depth violation is — this is what "workers never spawn further
children" reduces to structurally, not a rule enforced by convention.

All decisions (spawned, queued, refused, budget hit, heartbeat missed,
kill switch) are streamed through LogBus as they happen, per the same
"never buffer to the end of the run" contract the rest of the fleet
follows.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Optional

from engine.logbus import LogBus

MAX_TIER = 2


def allocate_sub_budgets(max_concurrent: int, weights: dict[str, float]) -> dict[str, int]:
    """Largest-remainder proportional split of max_concurrent across domains.

    Deterministic and independent of dict ordering: ties in the fractional
    remainder are broken by domain name so the same inputs always produce
    the same allocation. A domain can land on 0 slots if max_concurrent is
    smaller than the domain count and its weight is low — an operator
    running a tight budget across many domains should expect most of them
    to queue immediately, not receive a free slot they weren't budgeted.
    """
    if not weights:
        return {}
    if max_concurrent <= 0:
        return {domain: 0 for domain in weights}
    total_weight = sum(weights.values())
    if total_weight <= 0:
        raise ValueError("weights must sum to a positive number")

    raw = {d: (w / total_weight) * max_concurrent for d, w in weights.items()}
    floors = {d: int(raw[d]) for d in weights}
    remainder = max_concurrent - sum(floors.values())
    fractional_order = sorted(weights, key=lambda d: (-(raw[d] - floors[d]), d))
    for domain in fractional_order[:remainder]:
        floors[domain] += 1
    return floors


class SpawnRefused(Exception):
    def __init__(self, reason: str, message: str):
        self.reason = reason
        super().__init__(message)


@dataclass
class AgentHandle:
    agent_id: str
    run_id: str
    tier: int
    parent_agent_id: Optional[str]
    span_id: str
    parent_span_id: Optional[str]
    domain: str
    agent_role: str
    target_ref: Optional[str]
    status: str = "queued"  # queued | running | completed | error | stalled | killed
    queued_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    last_heartbeat: Optional[datetime] = None
    completed_at: Optional[datetime] = None


class SpawnManager:
    def __init__(
        self,
        run_id: str,
        logbus: LogBus,
        domain_budgets: dict[str, int],
        default_domain_budget: int = 1,
        time_budget_s: Optional[float] = None,
        heartbeat_timeout_s: float = 90.0,
        orchestrator_agent_id: str = "fleet-orchestrator",
        orchestrator_span_id: str = "root",
        now_fn: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ):
        self.run_id = run_id
        self.logbus = logbus
        self.domain_budgets = domain_budgets
        self.default_domain_budget = default_domain_budget
        self.time_budget_s = time_budget_s
        self.heartbeat_timeout_s = heartbeat_timeout_s
        self.orchestrator_agent_id = orchestrator_agent_id
        self.orchestrator_span_id = orchestrator_span_id
        self._now = now_fn
        self._start_time = now_fn()

        self.agents: dict[str, AgentHandle] = {}
        self._queue: list[str] = []  # agent_ids, FIFO, spans all domains
        self._running_count: dict[str, int] = {}
        self._budget_exhausted_logged: set[str] = set()
        self._seen_fingerprints: set[tuple[str, Optional[str]]] = set()
        self._kill_switch_active = False

    # -- budget -----------------------------------------------------------

    def _sub_budget(self, domain: str) -> int:
        return self.domain_budgets.get(domain, self.default_domain_budget)

    def _time_budget_exceeded(self) -> bool:
        if self.time_budget_s is None:
            return False
        return (self._now() - self._start_time).total_seconds() >= self.time_budget_s

    # -- logging ------------------------------------------------------------

    def _emit(
        self,
        *,
        agent_id: str,
        agent_role: str,
        tier: int,
        parent_agent_id: Optional[str],
        span_id: str,
        parent_span_id: Optional[str],
        event_type: str,
        severity: str,
        message: str,
        details: Optional[dict] = None,
    ) -> None:
        event = {
            "timestamp": self._now().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "run_id": self.run_id,
            "agent_id": agent_id,
            "agent_role": agent_role,
            "tier": tier,
            "parent_agent_id": parent_agent_id,
            "span_id": span_id,
            "parent_span_id": parent_span_id,
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

    def _emit_for_handle(self, handle: AgentHandle, event_type: str, severity: str, message: str, details=None) -> None:
        self._emit(
            agent_id=handle.agent_id,
            agent_role=handle.agent_role,
            tier=handle.tier,
            parent_agent_id=handle.parent_agent_id,
            span_id=handle.span_id,
            parent_span_id=handle.parent_span_id,
            event_type=event_type,
            severity=severity,
            message=message,
            details=details,
        )

    def emit_event_for(self, handle: AgentHandle, event_type: str, severity: str, message: str, details=None) -> None:
        """Public hook for a caller (e.g. the orchestrator) to log a
        domain-specific event — `finding`, `rollup` — under an agent's own
        identity, using the same lineage this manager already tracks for it."""
        self._emit_for_handle(handle, event_type, severity, message, details=details)

    def _refuse(self, *, tier: int, parent: Optional[AgentHandle], domain: str, reason: str, message: str) -> None:
        parent_agent_id = parent.agent_id if parent else self.orchestrator_agent_id
        parent_span_id = parent.span_id if parent else self.orchestrator_span_id
        # tier may exceed MAX_TIER here (that's exactly what depth_exceeded
        # reports); the event schema caps tier at MAX_TIER, so the event
        # records the requester's own tier instead of the rejected one.
        self._emit(
            agent_id="spawn-manager",
            agent_role="spawn-manager",
            tier=min(tier, MAX_TIER),
            parent_agent_id=parent_agent_id,
            span_id=f"spawn-refusal-{uuid.uuid4()}",
            parent_span_id=parent_span_id,
            event_type="agent_error",
            severity="warning",
            message=message,
            details={"reason": reason, "domain": domain},
        )
        raise SpawnRefused(reason, message)

    # -- spawning -----------------------------------------------------------

    def spawn(
        self,
        *,
        domain: str,
        agent_role: str,
        parent: Optional[AgentHandle] = None,
        target_ref: Optional[str] = None,
    ) -> AgentHandle:
        tier = 1 if parent is None else parent.tier + 1

        if self._kill_switch_active:
            self._refuse(tier=tier, parent=parent, domain=domain, reason="kill_switch_active", message="Kill switch is active; no new spawns accepted.")

        if tier > MAX_TIER:
            self._refuse(
                tier=tier,
                parent=parent,
                domain=domain,
                reason="depth_exceeded",
                message=f"Spawn would create a tier-{tier} agent; max tier is {MAX_TIER}. Workers never spawn children.",
            )

        fingerprint = (domain, target_ref)
        if fingerprint in self._seen_fingerprints:
            self._refuse(
                tier=tier,
                parent=parent,
                domain=domain,
                reason="duplicate_spawn",
                message=f"Duplicate spawn refused: domain={domain!r} target_ref={target_ref!r} already spawned this run.",
            )

        if self._time_budget_exceeded():
            self._refuse(
                tier=tier,
                parent=parent,
                domain=domain,
                reason="time_budget_exhausted",
                message="Run time budget exhausted; no new spawns accepted.",
            )

        self._seen_fingerprints.add(fingerprint)
        now = self._now()
        handle = AgentHandle(
            agent_id=f"{domain}-{uuid.uuid4()}",
            run_id=self.run_id,
            tier=tier,
            parent_agent_id=parent.agent_id if parent else self.orchestrator_agent_id,
            span_id=f"span-{uuid.uuid4()}",
            parent_span_id=parent.span_id if parent else self.orchestrator_span_id,
            domain=domain,
            agent_role=agent_role,
            target_ref=target_ref,
            queued_at=now,
        )
        self.agents[handle.agent_id] = handle
        self._emit_for_handle(
            handle,
            "agent_spawn",
            "info",
            f"Spawn accepted: {agent_role!r} (tier {tier}) for domain {domain!r}"
            + (f" target {target_ref!r}" if target_ref else "") + ".",
        )

        if self._running_count.get(domain, 0) < self._sub_budget(domain):
            self._dispatch(handle)
        else:
            if domain not in self._budget_exhausted_logged:
                self._budget_exhausted_logged.add(domain)
                self._emit_for_handle(
                    handle,
                    "budget_exhausted",
                    "notice",
                    f"Domain {domain!r} at its concurrency budget ({self._sub_budget(domain)}); queuing further spawns.",
                    details={"sub_budget": self._sub_budget(domain)},
                )
            self._queue.append(handle.agent_id)

        return handle

    def _dispatch(self, handle: AgentHandle) -> None:
        now = self._now()
        handle.status = "running"
        handle.started_at = now
        handle.last_heartbeat = now
        self._running_count[handle.domain] = self._running_count.get(handle.domain, 0) + 1
        self._emit_for_handle(handle, "agent_start", "info", f"Agent {handle.agent_id!r} started.")

    def _dispatch_next_queued(self, domain: str) -> None:
        for agent_id in list(self._queue):
            handle = self.agents[agent_id]
            if handle.domain != domain:
                continue
            if self._kill_switch_active or self._time_budget_exceeded():
                return  # leave it queued; run is wrapping up
            if self._running_count.get(domain, 0) >= self._sub_budget(domain):
                return
            self._queue.remove(agent_id)
            self._dispatch(handle)
            return

    def complete(self, agent_id: str, *, event_type: str = "agent_complete", message: str = "", details=None) -> None:
        handle = self.agents[agent_id]
        was_running = handle.status == "running"
        handle.status = "completed" if event_type == "agent_complete" else "error"
        handle.completed_at = self._now()
        if was_running:
            self._running_count[handle.domain] = max(0, self._running_count.get(handle.domain, 0) - 1)
        self._emit_for_handle(handle, event_type, "info" if event_type == "agent_complete" else "error", message or f"Agent {agent_id!r} finished.", details=details)
        if was_running:
            self._dispatch_next_queued(handle.domain)

    # -- heartbeat / liveness ------------------------------------------------

    def heartbeat(self, agent_id: str) -> None:
        handle = self.agents[agent_id]
        handle.last_heartbeat = self._now()
        self._emit_for_handle(handle, "heartbeat", "debug", f"Agent {agent_id!r} heartbeat.")

    def check_liveness(self) -> list[str]:
        """Marks running agents silent for longer than heartbeat_timeout_s
        as stalled, frees their budget slot, and returns their agent_ids
        (edge-triggered: an agent is reported at most once)."""
        now = self._now()
        stalled = []
        for handle in self.agents.values():
            if handle.status != "running" or handle.last_heartbeat is None:
                continue
            if (now - handle.last_heartbeat).total_seconds() > self.heartbeat_timeout_s:
                handle.status = "stalled"
                handle.completed_at = now
                self._running_count[handle.domain] = max(0, self._running_count.get(handle.domain, 0) - 1)
                self._emit_for_handle(
                    handle,
                    "agent_error",
                    "error",
                    f"Agent {handle.agent_id!r} missed heartbeat deadline ({self.heartbeat_timeout_s}s); marked stalled.",
                    details={"reason": "heartbeat_timeout"},
                )
                stalled.append(handle.agent_id)
                self._dispatch_next_queued(handle.domain)
        return stalled

    # -- kill switch ----------------------------------------------------------

    def trigger_kill_switch(self, reason: str) -> list[str]:
        """Idempotent. Returns the agent_ids that were running at the
        moment of the trigger, for the caller to terminate/flush."""
        if self._kill_switch_active:
            return []
        self._kill_switch_active = True
        running = [h.agent_id for h in self.agents.values() if h.status == "running"]
        self._emit(
            agent_id="spawn-manager",
            agent_role="spawn-manager",
            tier=0,
            parent_agent_id=None,
            span_id=f"kill-switch-{uuid.uuid4()}",
            parent_span_id=None,
            event_type="kill_switch",
            severity="critical",
            message=f"Kill switch triggered: {reason}",
            details={"running_agent_ids": running, "queued_agent_ids": list(self._queue)},
        )
        return running

    @property
    def kill_switch_active(self) -> bool:
        return self._kill_switch_active

    def queue_depth(self, domain: Optional[str] = None) -> int:
        if domain is None:
            return len(self._queue)
        return sum(1 for agent_id in self._queue if self.agents[agent_id].domain == domain)
