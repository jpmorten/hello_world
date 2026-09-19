"""python3 -m engine.cli <full-sweep|delta-sweep|target|red-team-recon|kill|halt|resume|record-usage|governance-status> ...

The real entry point behind the `.claude/commands/*.md` slash commands
and what RUNBOOK.md tells Security Ops to run directly when there's no
live Claude Code session. Everything here is a thin wrapper around
engine.orchestrator.Orchestrator + engine.domains — no logic lives here
that isn't argument handling and printing a summary.
"""
from __future__ import annotations

import argparse
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import yaml

from adapters import dns_recon
from analysts.mock import attack_scenario as mock_attack_scenario
from engine import governance, token_budget
from engine.domains import DOMAIN_REGISTRY, RED_TEAM_DOMAIN, build_domain_specs
from engine.orchestrator import DomainSpec, Orchestrator
from engine.scope import ScopeModel, ScopeViolation

REPO_ROOT = Path(__file__).resolve().parent.parent
SCOPE_DIR = REPO_ROOT / "scope"
LOG_DIR = REPO_ROOT / "logs"
REPORT_DIR = REPO_ROOT / "reports"

DEFAULT_DOMAIN_BUDGET = 5

RED_TEAM_TARGETS_PATH = SCOPE_DIR / "red-team-targets.yaml"
RED_TEAM_AUTH_PATH = SCOPE_DIR / "red-team-active-authorizations.yaml"
TOKEN_BUDGET_PATH = SCOPE_DIR / "token-budget.yaml"
TOKEN_LEDGER_PATH = SCOPE_DIR / "token-usage-ledger.yaml"
_ACTIVE_AUTHORIZATION_ACTION = "external_recon_active"
_ACTIVE_AUTHORIZATION_WINDOW = timedelta(hours=24)
# RFC 1035-ish: labels of 1-63 chars, no leading/trailing hyphen, at least
# one dot. Deliberately not exhaustive (real DNS allows more exotic
# labels) -- it only needs to reject obvious non-domains (URLs, IPs typed
# by mistake, empty strings) before anything touches the network.
_DOMAIN_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$")


def _scope_model() -> ScopeModel:
    return ScopeModel(SCOPE_DIR / "assets.yaml", SCOPE_DIR / "exclusions.yaml", SCOPE_DIR / "authorized-active.yaml")


def _merged_scope_model() -> ScopeModel:
    """Stibo's own assets.yaml merged with red-team-recon's externally-
    supplied targets file -- used by both cmd_red_team_recon and
    _run_sweep now that a full/delta sweep includes the last-selected
    red-team target alongside the nine Tier 1 domains."""
    return ScopeModel(
        [SCOPE_DIR / "assets.yaml", RED_TEAM_TARGETS_PATH],
        SCOPE_DIR / "exclusions.yaml",
        [SCOPE_DIR / "authorized-active.yaml", RED_TEAM_AUTH_PATH],
    )


def _last_red_team_target() -> Optional[str]:
    """The domain of the most recently registered red-team-recon target
    -- the last entry in scope/red-team-targets.yaml's assets list, which
    _register_red_team_target only ever appends to -- or None if no
    domain has ever been registered. "Last selected" is that file's own
    append-only history, not a separate pointer this module has to keep
    in sync with it."""
    if not RED_TEAM_TARGETS_PATH.exists():
        return None
    doc = yaml.safe_load(RED_TEAM_TARGETS_PATH.read_text()) or {}
    assets = doc.get("assets") or []
    if not assets:
        return None
    for target_ref in assets[-1].get("targets") or []:
        if target_ref.startswith("domain:"):
            return target_ref[len("domain:") :]
    return None


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
    governance_report = result.get("governance_report")
    if governance_report:
        verdict = governance_report["verdict"]
        print(f"Governance (Warden): {verdict}" + (f" — {governance_report['escalation_reason']}" if governance_report["escalation_reason"] else ""))
        if governance_report["kill_switch_engaged"]:
            print("  🔴 Fleet halted — run `python3 -m engine.cli resume` after review to allow further runs.", file=sys.stderr)
    print("Reports:")
    for name, path in result["report_paths"].items():
        print(f"  {name}: {path}")


def _print_fleet_halted(halted: governance.FleetHalted) -> None:
    record = halted.halt_record
    print("Refused: the fleet is halted by a prior critical governance verdict.", file=sys.stderr)
    print(f"  halted_at: {record.get('halted_at', '?')}", file=sys.stderr)
    print(f"  reason: {record.get('reason', '?')}", file=sys.stderr)
    print(f"  report_ref: {record.get('report_ref', '?')}", file=sys.stderr)
    print("A human operator must review this and run `python3 -m engine.cli resume` before any further run.", file=sys.stderr)


def _run_sweep(
    run_id: str,
    previous_run_id: Optional[str],
    domains: Optional[list[str]],
    max_concurrent: int,
    tokens_used: Optional[int] = None,
) -> dict:
    # _merged_scope_model (not the Stibo-only _scope_model) so a red-team
    # target below resolves against the same ScopeModel the Tier 1
    # domains do -- one run, one scope resolution, one report.
    scope = _merged_scope_model()
    domain_budgets = {d: max_concurrent for d in DOMAIN_REGISTRY}
    specs = build_domain_specs(scope, domains=domains)

    # Folds the purple-team story into every full/delta sweep: whichever
    # domain was last submitted through red-team-recon (the last entry in
    # scope/red-team-targets.yaml -- an operator's most recent "go look at
    # this" request) rides along in the same run as Stibo's own nine
    # domains, rather than staying a separate invocation someone has to
    # remember to run and reconcile by hand. Active checks only join in if
    # a still-valid self-attested authorization is already on file for it
    # (cleared first so a stale one from a prior process can never leak in
    # -- see adapters/dns_recon.py's module docstring); otherwise this
    # target gets the same honest passive-only default a bare
    # `red-team-recon <domain>` run would.
    dns_recon._ACTIVE_AUTHORIZATION_BY_TARGET.clear()
    red_team_domain = _last_red_team_target()
    if red_team_domain and (domains is None or RED_TEAM_DOMAIN.domain in domains):
        target_ref = f"domain:{red_team_domain}"
        try:
            authorization = scope.check_active_authorization(target_ref, _ACTIVE_AUTHORIZATION_ACTION)
            dns_recon._ACTIVE_AUTHORIZATION_BY_TARGET[target_ref] = authorization.authorization_ref
        except ScopeViolation:
            pass  # no valid authorization on file -- passive checks only, same as red-team-recon's own default
        specs = specs + [
            DomainSpec(
                domain=RED_TEAM_DOMAIN.domain,
                worker_role=RED_TEAM_DOMAIN.worker_role,
                targets=[target_ref],
                adapter_fn=RED_TEAM_DOMAIN.adapter_fn,
            )
        ]
        domain_budgets[RED_TEAM_DOMAIN.domain] = 1

    orchestrator = Orchestrator(
        run_id,
        scope,
        log_dir=LOG_DIR,
        report_dir=REPORT_DIR,
        domain_budgets=domain_budgets,
        previous_run_id=previous_run_id,
        # Runs once, after every domain above reports in -- see
        # engine/attack_scenarios.py and analysts/mock/attack_scenario.py's
        # own docstrings for why this is a labeled placeholder, not real
        # analysis: predicting attacker behavior is a live agent's job
        # (.claude/agents/attack-scenario-analyst.md), not deterministic
        # code's.
        attack_scenario_fn=mock_attack_scenario.synthesize,
    )
    return orchestrator.run(specs, tokens_used=tokens_used)


def cmd_full_sweep(args: argparse.Namespace) -> int:
    run_id = args.run_id or _new_run_id("full-sweep")
    try:
        result = _run_sweep(
            run_id, args.previous_run_id, domains=None, max_concurrent=args.max_concurrent_per_domain,
            tokens_used=args.tokens_used,
        )
    except governance.FleetHalted as halted:
        _print_fleet_halted(halted)
        return 1
    _print_summary(run_id, result)
    return 0


def cmd_delta_sweep(args: argparse.Namespace) -> int:
    run_id = args.run_id or _new_run_id("delta-sweep")
    previous_run_id = args.previous_run_id or _latest_completed_run_id()
    if previous_run_id is None:
        print("No previous completed run found — this delta-sweep will report everything as new.", file=sys.stderr)
    try:
        result = _run_sweep(
            run_id, previous_run_id, domains=None, max_concurrent=args.max_concurrent_per_domain,
            tokens_used=args.tokens_used,
        )
    except governance.FleetHalted as halted:
        _print_fleet_halted(halted)
        return 1
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
        attack_scenario_fn=mock_attack_scenario.synthesize,
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
    try:
        result = orchestrator.run(specs, tokens_used=args.tokens_used)
    except governance.FleetHalted as halted:
        _print_fleet_halted(halted)
        return 1
    _print_summary(run_id, result)
    return 0


def _register_red_team_target(domain: str, requested_by: str, criticality: str) -> None:
    """Idempotent: appends an asset entry for `domain` to
    scope/red-team-targets.yaml only if one doesn't already exist there,
    so re-running red-team-recon for the same domain never duplicates it
    but every domain ever requested stays in the file's git history."""
    doc = yaml.safe_load(RED_TEAM_TARGETS_PATH.read_text()) or {}
    doc.setdefault("entities", [{"id": "red-team-engagement", "name": "Red-team engagement (externally supplied target)"}])
    doc.setdefault("assets", [])
    target_ref = f"domain:{domain}"
    if any(target_ref in asset.get("targets", []) for asset in doc["assets"]):
        return
    doc["assets"].append(
        {
            "asset_id": f"red-team-{domain}",
            "entity": "red-team-engagement",
            "type": "external_domain",
            "owner_team": requested_by,
            "criticality": criticality,
            "targets": [target_ref],
        }
    )
    RED_TEAM_TARGETS_PATH.write_text(yaml.safe_dump(doc, sort_keys=False))


def _register_active_authorization(domain: str, requested_by: str, now: datetime) -> None:
    """Appends a fresh, short-lived (24h) self-attested authorization
    covering `domain`'s active checks. Deliberately not idempotent like
    _register_red_team_target: every --authorize-active run gets its own
    dated record rather than silently extending a stale one, so the
    audit trail shows exactly when each attestation was actually made."""
    doc = yaml.safe_load(RED_TEAM_AUTH_PATH.read_text()) or {}
    doc.setdefault("authorizations", [])
    doc["authorizations"].append(
        {
            "authorization_ref": f"red-team-{domain}-{now.strftime('%Y%m%dT%H%M%SZ')}",
            "scope": [f"domain:{domain}"],
            "actions": [_ACTIVE_AUTHORIZATION_ACTION],
            "approved_by": requested_by,
            "signed_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "valid_from": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "valid_until": (now + _ACTIVE_AUTHORIZATION_WINDOW).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "signature": "SELF-ATTESTED",
        }
    )
    RED_TEAM_AUTH_PATH.write_text(yaml.safe_dump(doc, sort_keys=False))


def cmd_red_team_recon(args: argparse.Namespace) -> int:
    domain = args.domain.strip().lower()
    if not _DOMAIN_RE.match(domain):
        print(f"Refused: {domain!r} doesn't look like a bare DNS domain (e.g. example.com).", file=sys.stderr)
        return 1

    now = datetime.now(timezone.utc)
    _register_red_team_target(domain, args.requested_by, args.criticality)

    target_ref = f"domain:{domain}"
    # Cleared every invocation so a stale authorization from a previous
    # domain in the same process can never leak onto this one -- see
    # adapters/dns_recon.py's module docstring for why this is a runtime
    # map, not a persistent config table.
    dns_recon._ACTIVE_AUTHORIZATION_BY_TARGET.clear()

    if args.authorize_active:
        _register_active_authorization(domain, args.requested_by, now)
        scope = _merged_scope_model()
        try:
            authorization = scope.check_active_authorization(target_ref, _ACTIVE_AUTHORIZATION_ACTION)
            dns_recon._ACTIVE_AUTHORIZATION_BY_TARGET[target_ref] = authorization.authorization_ref
        except ScopeViolation as violation:
            print(f"Note: active checks not enabled — {violation.reason}", file=sys.stderr)
    else:
        scope = _merged_scope_model()
        print(
            "Note: running passive checks only (DNS hygiene, SPF/DMARC email-auth posture, CT-log subdomain "
            "exposure). Pass --authorize-active to also run TLS/HTTP-header/exposed-path checks against the live "
            "domain.",
            file=sys.stderr,
        )

    run_id = args.run_id or _new_run_id("red-team-recon")
    orchestrator = Orchestrator(
        run_id,
        scope,
        log_dir=LOG_DIR,
        report_dir=REPORT_DIR,
        domain_budgets={RED_TEAM_DOMAIN.domain: 1},
        previous_run_id=args.previous_run_id,
        # A single target can still produce plenty to chain -- this run's
        # own DNS/email/CT-log/TLS/HTTP checks are exactly the kind of
        # varied findings a white-hat analyst would look at together
        # (e.g. "100 discovered subdomains" + "missing security headers"
        # is a real chain), so there's no good reason to withhold this
        # stage just because the sweep covered one domain instead of nine.
        attack_scenario_fn=mock_attack_scenario.synthesize,
    )
    spec = DomainSpec(
        domain=RED_TEAM_DOMAIN.domain,
        worker_role=RED_TEAM_DOMAIN.worker_role,
        targets=[target_ref],
        adapter_fn=RED_TEAM_DOMAIN.adapter_fn,
    )
    try:
        result = orchestrator.run([spec], tokens_used=args.tokens_used)
    except governance.FleetHalted as halted:
        _print_fleet_halted(halted)
        return 1
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


def _halt_flag_path() -> Path:
    return REPORT_DIR / "FLEET_HALT.flag"


def cmd_halt(args: argparse.Namespace) -> int:
    path = governance.trigger_fleet_halt(args.reason, args.report_ref, _halt_flag_path())
    print(f"Fleet-wide halt flag written: {path}")
    print("No full-sweep/delta-sweep/target/red-team-recon run will start until `resume` is run.")
    return 0


def cmd_resume(args: argparse.Namespace) -> int:
    cleared = governance.clear_fleet_halt(_halt_flag_path())
    if cleared:
        print("Fleet-wide halt cleared. Runs may proceed again.")
    else:
        print("No fleet-wide halt was in effect.")
    return 0


def cmd_record_usage(args: argparse.Namespace) -> int:
    budget = token_budget.TokenBudget.load(TOKEN_BUDGET_PATH)
    recorded_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    entries = token_budget.record_usage(args.run_id, args.tokens, recorded_at, TOKEN_LEDGER_PATH)
    status = token_budget.status(budget, entries)
    print(f"Recorded {args.tokens} token(s) for run {args.run_id!r}.")
    print(
        f"Budget status: {status['spent_tokens']}/{status['budget_tokens']} spent "
        f"({status['remaining_pct']}% remaining, alert threshold {status['alert_threshold_pct']}%)."
    )
    if status["alert"]:
        print("⚠️  CostCop alert: remaining budget is below the alert threshold.", file=sys.stderr)
    return 0


def cmd_governance_status(args: argparse.Namespace) -> int:
    budget = token_budget.TokenBudget.load(TOKEN_BUDGET_PATH)
    entries = token_budget.load_ledger(TOKEN_LEDGER_PATH)
    status = token_budget.status(budget, entries)
    print("CostCop — token budget:")
    if not status["measured"]:
        print(f"  Not measured yet (budget on file: {status['budget_tokens']} tokens).")
    else:
        print(
            f"  {status['spent_tokens']}/{status['budget_tokens']} tokens spent "
            f"({status['remaining_pct']}% remaining, alert threshold {status['alert_threshold_pct']}%)"
            + (" — ALERT" if status["alert"] else "")
        )

    halt_record = governance.fleet_halt_status(_halt_flag_path())
    print("Warden — fleet status:")
    if halt_record is None:
        print("  Not halted.")
    else:
        print(f"  HALTED at {halt_record.get('halted_at', '?')}: {halt_record.get('reason', '?')}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python3 -m engine.cli")
    subparsers = parser.add_subparsers(dest="command", required=True)

    def add_common_sweep_args(sub: argparse.ArgumentParser) -> None:
        sub.add_argument("--run-id", help="Defaults to an auto-generated timestamped id.")
        sub.add_argument("--previous-run-id", help="Baseline to diff against for the new/recurring/resolved/regressed delta.")
        sub.add_argument("--max-concurrent-per-domain", type=int, default=DEFAULT_DOMAIN_BUDGET)
        sub.add_argument(
            "--tokens-used",
            type=int,
            default=None,
            help=(
                "Real token cost of this run, if you know it (only a live Claude Code session actually "
                "does — this CLI's own deterministic code makes no model calls). Recorded to CostCop's "
                "ledger (scope/token-usage-ledger.yaml) before Warden's governance verdict is computed. "
                "Omit it and CostCop honestly reports the run as 'not measured' rather than guessing."
            ),
        )

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
    target.add_argument("--tokens-used", type=int, default=None)
    target.set_defaults(func=cmd_target)

    red_team_recon = subparsers.add_parser(
        "red-team-recon",
        help=(
            "Real, non-exploitative external recon against a user-supplied DNS domain: DNS hygiene, "
            "SPF/DMARC posture, and CT-log subdomain exposure always run (passive, no authorization needed); "
            "--authorize-active additionally self-attests authorization to run a TLS handshake, an HTTP "
            "security-header check, and a common-exposed-path check against the live domain."
        ),
    )
    red_team_recon.add_argument("domain", help="Bare DNS domain to reconnoiter, e.g. example.com. Only ever run this against a domain you own or are authorized to assess.")
    red_team_recon.add_argument(
        "--requested-by",
        required=True,
        help="Who is requesting this (name/email) — recorded in scope/red-team-targets.yaml and, with --authorize-active, as approved_by in scope/red-team-active-authorizations.yaml.",
    )
    red_team_recon.add_argument("--criticality", choices=["critical", "high", "medium", "low"], default="medium")
    red_team_recon.add_argument(
        "--authorize-active",
        action="store_true",
        help="Self-attest authorization for the active checks (TLS handshake, HTTP header probe, exposed-path check) against the live domain. Without this flag, only passive checks run.",
    )
    red_team_recon.add_argument("--run-id")
    red_team_recon.add_argument("--previous-run-id")
    red_team_recon.add_argument("--tokens-used", type=int, default=None)
    red_team_recon.set_defaults(func=cmd_red_team_recon)

    kill = subparsers.add_parser("kill", help="Write a kill flag for a run (defaults to the most recently active one).")
    kill.add_argument("--run-id", help="Defaults to the most recently written-to run log.")
    kill.set_defaults(func=cmd_kill)

    halt = subparsers.add_parser(
        "halt",
        help=(
            "Warden's fleet-wide kill switch: refuses every future full-sweep/delta-sweep/target/"
            "red-team-recon run until a human runs `resume`. Distinct from `kill` (which stops one "
            "in-flight run) -- this stops the fleet from starting a NEW one at all."
        ),
    )
    halt.add_argument("--reason", required=True, help="Why the fleet is being halted -- recorded in the halt flag.")
    halt.add_argument("--report-ref", default="manual", help="A governance report id this halt relates to, if any.")
    halt.set_defaults(func=cmd_halt)

    resume = subparsers.add_parser(
        "resume",
        help=(
            "Clears a fleet-wide halt (Warden's kill switch or a manual `halt`). Intended for a human "
            "operator only, after reviewing why the halt was triggered -- see RUNBOOK.md. No agent in this "
            "fleet is documented or expected to run this on its own."
        ),
    )
    resume.set_defaults(func=cmd_resume)

    record_usage = subparsers.add_parser(
        "record-usage",
        help="CostCop: record a run's real token spend and print the resulting budget status.",
    )
    record_usage.add_argument("run_id")
    record_usage.add_argument("tokens", type=int)
    record_usage.set_defaults(func=cmd_record_usage)

    governance_status = subparsers.add_parser(
        "governance-status", help="Print CostCop's current token-budget status and Warden's halt status."
    )
    governance_status.set_defaults(func=cmd_governance_status)

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
