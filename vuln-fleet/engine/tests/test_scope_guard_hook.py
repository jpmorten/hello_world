"""Exercises .claude/hooks/scope_guard.py as Claude Code will actually run
it: a subprocess fed hook-input JSON on stdin, judged by its stdout
decision and the scope_check/scope_violation event it logs.
"""
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent.parent
HOOK_PATH = REPO_ROOT / ".claude" / "hooks" / "scope_guard.py"


def _run_hook(command: str, tmp_path: Path, run_id: str = "hook-test", now: str = "2026-09-15T00:00:00Z") -> tuple[dict, Path]:
    hook_input = {"tool_name": "Bash", "tool_input": {"command": command}}
    log_dir = tmp_path / "logs"
    result = subprocess.run(
        [sys.executable, str(HOOK_PATH)],
        input=json.dumps(hook_input),
        capture_output=True,
        text=True,
        env={
            "PATH": "/usr/bin:/bin",
            "VULN_FLEET_RUN_ID": run_id,
            "VULN_FLEET_LOG_DIR": str(log_dir),
            "VULN_FLEET_NOW": now,
        },
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)["hookSpecificOutput"], log_dir / f"{run_id}.ndjson"


def _events(log_path: Path) -> list[dict]:
    if not log_path.exists():
        return []
    return [json.loads(line) for line in log_path.read_text().strip().splitlines() if line]


def test_in_scope_read_is_allowed_and_logs_scope_check(tmp_path):
    decision, log_path = _run_hook(
        "python3 adapters/sbom_scan.py --target repo:stibo/checkout --action read", tmp_path
    )

    assert decision["permissionDecision"] == "allow"
    events = _events(log_path)
    assert len(events) == 1
    assert events[0]["event_type"] == "scope_check"
    assert events[0]["asset_id"] == "svc-checkout"


def test_out_of_scope_target_is_denied_and_logs_violation(tmp_path):
    decision, log_path = _run_hook(
        "python3 adapters/net_scan.py --target host:evil.example.com --action read", tmp_path
    )

    assert decision["permissionDecision"] == "deny"
    assert "does not resolve" in decision["permissionDecisionReason"]
    events = _events(log_path)
    assert events[0]["event_type"] == "scope_violation"


def test_excluded_target_is_denied_even_though_it_would_resolve(tmp_path):
    decision, log_path = _run_hook(
        "python3 adapters/net_scan.py --target host:tenant7.customerprod.example.com --action read", tmp_path
    )

    assert decision["permissionDecision"] == "deny"
    assert "excluded" in decision["permissionDecisionReason"]


def test_active_action_without_authorization_is_denied(tmp_path):
    decision, _ = _run_hook(
        "python3 adapters/net_scan.py --target repo:stibo/checkout --action port_scan", tmp_path
    )

    assert decision["permissionDecision"] == "deny"
    assert "authorization" in decision["permissionDecisionReason"]


def test_active_action_with_authorization_is_allowed(tmp_path):
    decision, log_path = _run_hook(
        "python3 adapters/net_scan.py --target ip:10.20.0.5 --action port_scan", tmp_path
    )

    assert decision["permissionDecision"] == "allow"
    events = _events(log_path)
    assert events[0]["authorization_ref"] == "mdm-core-nsg-sweep-2026-09"


def test_active_action_with_expired_authorization_is_denied(tmp_path):
    decision, _ = _run_hook(
        "python3 adapters/net_scan.py --target ip:10.20.0.5 --action port_scan",
        tmp_path,
        now="2027-01-01T00:00:00Z",
    )

    assert decision["permissionDecision"] == "deny"
    assert "no in-window" in decision["permissionDecisionReason"]


def test_missing_target_is_denied_fail_closed(tmp_path):
    decision, log_path = _run_hook("python3 adapters/net_scan.py --action read", tmp_path)

    assert decision["permissionDecision"] == "deny"
    assert "--target" in decision["permissionDecisionReason"]
    events = _events(log_path)
    assert events[0]["event_type"] == "scope_violation"


def test_non_adapter_command_passes_through_untouched(tmp_path):
    decision, log_path = _run_hook("ls -la", tmp_path)

    assert decision["permissionDecision"] == "allow"
    assert _events(log_path) == []  # not an adapter call: no scope decision to log


def test_non_bash_tool_passes_through(tmp_path):
    hook_input = {"tool_name": "Read", "tool_input": {"file_path": "foo.txt"}}
    result = subprocess.run(
        [sys.executable, str(HOOK_PATH)],
        input=json.dumps(hook_input),
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin", "VULN_FLEET_LOG_DIR": str(tmp_path / "logs")},
        timeout=10,
    )

    assert result.returncode == 0
    decision = json.loads(result.stdout)["hookSpecificOutput"]
    assert decision["permissionDecision"] == "allow"
