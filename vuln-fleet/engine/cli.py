"""python3 -m engine.cli <full-sweep|delta-sweep|target|kill> ...

The real entry point behind the `.claude/commands/*.md` slash commands
and what RUNBOOK.md tells Security Ops to run directly when there's no
live Claude Code session. Everything here is a thin wrapper around
engine.orchestrator.Orchestrator + engine.domains — no logic lives here
that isn't argument handling and printing a summary.
"""
from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from engine.domains import DOMAIN_REGISTRY, build_domain_specs
from engine.orchestrator import DomainSpec, Orchestrator
from engine.scope import ScopeModel, ScopeViolation

REPO_ROOT = Path(__file__).resolve().parent.parent
SCOPE_DIR = REPO_ROOT / "scope"
LOG_DIR = REPO_ROOT / "logs"
REPORT_DIR = REPO_ROOT / "reports"

DEFAULT_DOMAIN_BUDGET = 5


def _scope_model() -> ScopeModel:
    return ScopeModel(SCOPE_DIR / "assets.yaml", SCOPE_DIR / "exclusions.yaml", SCOPE_DIR / "authorized-active.yaml")


def _new_run_id(prefix: str) -> str:
    return f"{prefix}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"


def _latest_completed_run_id(report_dir: Optional[Path] = None) -> Optional[str]:
    """The most recent run with a finished findings.json — used to pick
    delta-sweep's default comparison baseline. Not the same thing as "the
    currently running sweep" (see _latest_active_run_id): a run that's
    still in flight hasn't written findings.json yet.

    report_dir defaults to the *current* value of the module-level
    REPORT_DIR, read at call time — not bound as a def-time default
    argument, which would freeze in the original value from module load
    and silently ignore anything that later points REPORT_DIR elsewhere
    (as every test in this suite does).
    """
    report_dir = report_dir if report_dir is not None else REPORT_DIR
    if not report_dir.exists():
        return None
    completed = [p for p in report_dir.iterdir() if p.is_dir() and (p / "findings.json").exists()]
    if not completed:
        return None
    return max(completed, key=lambda p: p.stat().st_mtime).name


def _latest_active_run_id(log_dir: Optional[Path] = None) -> Optional[str]:
    """The most recently written-to run log — used as /kill's default
    target. A run's log file is created at its very first event
    (run_start) and appended to throughout, so this finds an in-flight
    run that _latest_completed_run_id can't see yet. See
    _latest_completed_run_id's docstring for why log_dir isn't a
    def-time default."""
    log_dir = log_dir if log_dir is not None else LOG_DIR
    if not log_dir.exists():
        return None
    logs = list(log_dir.glob("*.ndjson"))
    if not logs:
        return None
    return max(logs, key=lambda p: p.stat().st_mtime).stem


def _print_summary(run_id: str, result: dict) -> None:
    print(f"Run {run_id}: {len(result['findings'])} finding(s), {len(result['issues'])} correlated issue(s).")
    delta = result["delta"]
    print(f"Delta: {len(delta['new'])} new, {len(delta['recurring'])} recurring, "
          f"{len(delta['resolved'])} resolved, {len(delta['regressed'])} regressed.")
    gaps = {domain: rollup.targets_failed for domain, rollup in result["rollups"].items() if rollup.targets_failed}
    if gaps:
        print("Coverage gaps:")
        for domain, targets_failed in gaps.items():
            for target, reason in targets_failed.items():
                print(f"  [{domain}] {target}: {reason}")
    print("Reports:")
    for name, path in result["report_paths"].items():
        print(f"  {name}: {path}")


def _run_sweep(run_id: str, previous_run_id: Optional[str], domains: Optional[list[str]], max_concurrent: int) -> dict:
    scope = _scope_model()
    orchestrator = Orchestrator(
        run_id,
        scope,
        log_dir=LOG_DIR,
        report_dir=REPORT_DIR,
        domain_budgets={d: max_concurrent for d in DOMAIN_REGISTRY},
        previous_run_id=previous_run_id,
    )
    specs = build_domain_specs(scope, domains=domains)
    return orchestrator.run(specs)


def cmd_full_sweep(args: argparse.Namespace) -> int:
    run_id = args.run_id or _new_run_id("full-sweep")
    result = _run_sweep(run_id, args.previous_run_id, domains=None, max_concurrent=args.max_concurrent_per_domain)
    _print_summary(run_id, result)
    return 0


def cmd_delta_sweep(args: argparse.Namespace) -> int:
    run_id = args.run_id or _new_run_id("delta-sweep")
    previous_run_id = args.previous_run_id or _latest_completed_run_id()
    if previous_run_id is None:
        print("No previous completed run found — this delta-sweep will report everything as new.", file=sys.stderr)
    result = _run_sweep(run_id, previous_run_id, domains=None, max_concurrent=args.max_concurrent_per_domain)
    _print_summary(run_id, result)
    return 0


def cmd_target(args: argparse.Namespace) -> int:
    scope = _scope_model()
    try:
        resolution = scope.assert_in_scope(args.target_ref)
    except ScopeViolation as violation:
        print(f"Refused: {args.target_ref!r} is not a valid target — {violation.reason}", file=sys.stderr)
        return 1

    matching_domains = [
        domain for domain, registration in DOMAIN_REGISTRY.items() if args.target_ref in registration.decompose_fn(scope)
    ]
    if not matching_domains:
        print(
            f"{args.target_ref!r} resolves to asset {resolution.asset_id!r} but no registered domain's "
            "decomposition currently includes it (nothing to run).",
            file=sys.stderr,
        )
        return 1

    run_id = args.run_id or _new_run_id("target")
    orchestrator = Orchestrator(
        run_id,
        scope,
        log_dir=LOG_DIR,
        report_dir=REPORT_DIR,
        domain_budgets={d: 3 for d in matching_domains},
        previous_run_id=args.previous_run_id,
    )
    specs = [
        DomainSpec(
            domain=domain,
            worker_role=DOMAIN_REGISTRY[domain].worker_role,
            targets=[args.target_ref],
            adapter_fn=DOMAIN_REGISTRY[domain].adapter_fn,
        )
        for domain in matching_domains
    ]
    result = orchestrator.run(specs)
    _print_summary(run_id, result)
    return 0


def cmd_kill(args: argparse.Namespace) -> int:
    run_id = args.run_id or _latest_active_run_id()
    if run_id is None:
        print("No run found to kill (no log files under logs/).", file=sys.stderr)
        return 1
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    flag_path = REPORT_DIR / f"{run_id}.kill"
    flag_path.write_text(f"kill requested at {datetime.now(timezone.utc).isoformat()}\n")
    print(f"Kill flag written for run {run_id!r}: {flag_path}")
    print("The run will stop before its next target/domain and produce a partial report with the gap recorded.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python3 -m engine.cli")
    subparsers = parser.add_subparsers(dest="command", required=True)

    def add_common_sweep_args(sub: argparse.ArgumentParser) -> None:
        sub.add_argument("--run-id", help="Defaults to an auto-generated timestamped id.")
        sub.add_argument("--previous-run-id", help="Baseline to diff against for the new/recurring/resolved/regressed delta.")
        sub.add_argument("--max-concurrent-per-domain", type=int, default=DEFAULT_DOMAIN_BUDGET)

    full_sweep = subparsers.add_parser("full-sweep", help="Sweep every registered domain.")
    add_common_sweep_args(full_sweep)
    full_sweep.set_defaults(func=cmd_full_sweep)

    delta_sweep = subparsers.add_parser(
        "delta-sweep", help="Sweep every registered domain, diffed against the last completed run by default."
    )
    add_common_sweep_args(delta_sweep)
    delta_sweep.set_defaults(func=cmd_delta_sweep)

    target = subparsers.add_parser("target", help="Sweep a single target ref across whichever domains claim it.")
    target.add_argument("target_ref", help="e.g. repo:stibo/checkout or endpoint:https://cms-edge.example-stibodx.com")
    target.add_argument("--run-id")
    target.add_argument("--previous-run-id")
    target.set_defaults(func=cmd_target)

    kill = subparsers.add_parser("kill", help="Write a kill flag for a run (defaults to the most recently active one).")
    kill.add_argument("--run-id", help="Defaults to the most recently written-to run log.")
    kill.set_defaults(func=cmd_kill)

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
