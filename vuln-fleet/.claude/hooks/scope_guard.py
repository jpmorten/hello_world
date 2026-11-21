#!/usr/bin/env python3
"""PreToolUse hook: refuse tool calls that act on an out-of-scope target.

Claude Code invokes this on every Bash tool call and feeds it the tool-call
JSON on stdin; it prints a permission decision to stdout and exits 0 (the
decision, not the exit code, is what blocks the call — a non-zero exit here
would surface as a hook error, not a scope violation).

Only Bash commands that invoke an adapter (adapters/*.py, per the contract
future adapters follow — see adapters/README.md once step 7 adds it) are
in scope for this check; everything else is allowed through untouched.
An adapter invocation with no extractable --target is denied rather than
allowed: scope is a hard boundary (section 1 of the design brief), so a
call we can't verify is treated the same as one that fails verification.

Every check — pass or fail — is logged via the same hash-chained logbus
used everywhere else, as a scope_check or scope_violation event, so the
SOC sees every scope decision this fleet makes, not just the refusals.
"""
from __future__ import annotations

import json
import os
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from engine.logbus import LogBus  # noqa: E402
from engine.scope import ScopeModel, ScopeViolation  # noqa: E402

ADAPTER_INVOCATION_RE = re.compile(r"\badapters/\S+\.py\b")
TARGET_FLAG_RE = re.compile(r"--target[=\s]+(\S+)")
ACTION_FLAG_RE = re.compile(r"--action[=\s]+(\S+)")

# Actions that send traffic to a target and therefore require a signed
# authorized-active.yaml record, not just scope membership.
ACTIVE_ACTIONS = {"port_scan", "service_fingerprint", "authenticated_config_pull", "dast"}


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _scope_paths() -> tuple[Path, Path, Path]:
    scope_dir = REPO_ROOT / "scope"
    return scope_dir / "assets.yaml", scope_dir / "exclusions.yaml", scope_dir / "authorized-active.yaml"


def _log_event(event_type: str, severity: str, message: str, target_ref: str | None, details: dict) -> None:
    log_dir = os.environ.get("VULN_FLEET_LOG_DIR", str(REPO_ROOT / "logs"))
    run_id = os.environ.get("VULN_FLEET_RUN_ID", "adhoc")
    bus = LogBus(run_id, log_dir=log_dir)
    bus.emit(
        {
            "timestamp": _utcnow(),
            "run_id": run_id,
            "agent_id": os.environ.get("VULN_FLEET_AGENT_ID", "unknown-agent"),
            "agent_role": os.environ.get("VULN_FLEET_AGENT_ROLE", "unknown"),
            "tier": int(os.environ.get("VULN_FLEET_TIER", "2")),
            "parent_agent_id": os.environ.get("VULN_FLEET_PARENT_AGENT_ID") or None,
            "span_id": os.environ.get("VULN_FLEET_SPAN_ID") or f"scope-guard-{uuid.uuid4()}",
            "parent_span_id": os.environ.get("VULN_FLEET_PARENT_SPAN_ID") or None,
            "event_type": event_type,
            "severity": severity,
            "entity": details.pop("entity", None),
            "asset_id": details.pop("asset_id", None),
            "scope_ref": details.pop("scope_ref", None),
            "authorization_ref": details.pop("authorization_ref", None),
            "message": message,
            "evidence_ref": [],
            **({"details": {"target_ref": target_ref, **details}} if (target_ref or details) else {}),
        }
    )


def _decide(command: str) -> dict:
    """Returns a hookSpecificOutput payload: allow (with no reason needed
    downstream) or deny (with a reason Claude will see and can act on)."""
    if not ADAPTER_INVOCATION_RE.search(command):
        return {"permissionDecision": "allow"}

    target_match = TARGET_FLAG_RE.search(command)
    if not target_match:
        _log_event(
            "scope_violation",
            "error",
            "Adapter invocation missing --target; cannot verify scope.",
            None,
            {},
        )
        return {
            "permissionDecision": "deny",
            "permissionDecisionReason": "Adapter call has no --target; scope cannot be verified, so it is refused.",
        }

    target_ref = target_match.group(1)
    action_match = ACTION_FLAG_RE.search(command)
    action = action_match.group(1) if action_match else "read"

    assets_path, exclusions_path, auth_path = _scope_paths()
    now_override = os.environ.get("VULN_FLEET_NOW")  # test-only escape hatch; unset in production
    now_fn = (
        (lambda: datetime.fromisoformat(now_override.replace("Z", "+00:00")))
        if now_override
        else (lambda: datetime.now(timezone.utc))
    )
    model = ScopeModel(assets_path, exclusions_path, auth_path, now_fn=now_fn)

    try:
        if action in ACTIVE_ACTIONS:
            auth = model.check_active_authorization(target_ref, action)
            resolution = model.resolve(target_ref)
            _log_event(
                "scope_check",
                "info",
                f"Active-scan action {action!r} authorized for {target_ref!r}.",
                target_ref,
                {
                    "entity": resolution.entity,
                    "asset_id": resolution.asset_id,
                    "scope_ref": resolution.scope_ref,
                    "authorization_ref": auth.authorization_ref,
                },
            )
        else:
            resolution = model.assert_in_scope(target_ref)
            _log_event(
                "scope_check",
                "info",
                f"Target {target_ref!r} resolved in scope.",
                target_ref,
                {
                    "entity": resolution.entity,
                    "asset_id": resolution.asset_id,
                    "scope_ref": resolution.scope_ref,
                },
            )
    except ScopeViolation as violation:
        _log_event(
            "scope_violation",
            "error",
            f"Refused {action!r} on {target_ref!r}: {violation.reason}",
            target_ref,
            {},
        )
        return {
            "permissionDecision": "deny",
            "permissionDecisionReason": f"Scope violation: {violation.reason}",
        }

    return {"permissionDecision": "allow"}


def main() -> int:
    try:
        hook_input = json.load(sys.stdin)
    except json.JSONDecodeError:
        # Malformed hook input is a harness problem, not a scope decision.
        print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow"}}))
        return 0

    if hook_input.get("tool_name") != "Bash":
        print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow"}}))
        return 0

    command = (hook_input.get("tool_input") or {}).get("command", "")
    decision = _decide(command)

    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", **decision}}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
