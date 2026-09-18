"""Report generation: turns a run's findings/issues/rollups/delta into
the report suite reports/<run_id>/ ships. Kept separate from
engine/orchestrator.py so report formatting is unit-testable against
synthetic data without running a full sweep.

Never reports a number it can't evidence: a coverage gap is named with
its target and reason (not folded into a bare percentage), an empty
compliance section says so explicitly rather than being silently
omitted, and remediation effort/SLA bands are declared, documented
policy defaults — not a per-finding judgement call dressed up as fact.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

REGULATORY_HEADLINE_TAGS = ["NIS2", "CRA", "ISO27001", "GDPR"]

# (risk_score floor, band name, SLA in days). Declared policy, not a
# per-finding judgement — tune the table to change policy, not the finding.
SEVERITY_BANDS = [
    (90.0, "Critical", 15),
    (70.0, "High", 30),
    (40.0, "Medium", 90),
    (0.0, "Low", 180),
]

# Coarse, domain-level default: real effort depends on the specific
# finding, but a dependency bump is reliably cheaper than a network
# change needing a maintenance window, so this is a defensible starting
# point rather than a made-up per-finding estimate.
EFFORT_ESTIMATE_BY_DOMAIN = {
    "supply-chain": "Low (dependency version bump)",
    "code-firstparty": "Low-Medium (code change + review)",
    "api-surface": "Medium (API change, needs a release)",
    "identity-access": "Medium (access/role change, needs an owner sign-off)",
    "data-exposure": "Medium (data-handling/config change)",
    "endpoint-posture": "Medium (fleet-wide config/agent rollout)",
    "infra-cloud": "Medium (IaC/config change, requires a change window)",
    "infra-network": "Medium-High (network change, requires a change window)",
    "firmware-hardware": "High (maintenance window / vendor coordination)",
}
DEFAULT_EFFORT_ESTIMATE = "Medium (not yet mapped for this domain)"


def severity_band(risk_score: float) -> tuple[str, int]:
    """(band_name, sla_days) for a risk_score. The table always matches
    (the 0.0 floor is unconditional), so this never falls through."""
    for threshold, band, sla_days in SEVERITY_BANDS:
        if risk_score >= threshold:
            return band, sla_days
    return "Low", 180  # unreachable given the 0.0 floor; kept as a safe default


def write_reports(
    report_dir: Path,
    run_id: str,
    findings: list[dict],
    issues: list[dict],
    rollups: dict,
    delta: dict,
    previous_run_id: Optional[str],
) -> dict[str, str]:
    report_dir.mkdir(parents=True, exist_ok=True)

    findings_path = report_dir / "findings.json"
    findings_path.write_text(json.dumps(findings, indent=2, sort_keys=True))

    issues_path = report_dir / "issues.json"
    issues_path.write_text(json.dumps(issues, indent=2, sort_keys=True))

    posture_path = report_dir / "posture.md"
    posture_path.write_text(_render_posture(run_id, findings, issues, rollups, delta, previous_run_id))

    by_domain_path = report_dir / "by-domain.md"
    by_domain_path.write_text(_render_by_domain(rollups))

    remediation_path = report_dir / "remediation-board.md"
    remediation_path.write_text(_render_remediation_board(issues, findings))

    compliance_path = report_dir / "compliance-view.md"
    compliance_path.write_text(_render_compliance_view(findings))

    return {
        "findings_json": str(findings_path),
        "issues_json": str(issues_path),
        "posture_md": str(posture_path),
        "by_domain_md": str(by_domain_path),
        "remediation_board_md": str(remediation_path),
        "compliance_view_md": str(compliance_path),
    }


def _render_posture(
    run_id: str,
    findings: list[dict],
    issues: list[dict],
    rollups: dict,
    delta: dict,
    previous_run_id: Optional[str],
) -> str:
    lines = [f"# Posture Report — {run_id}", ""]

    lines += ["## Executive summary", ""]
    if issues:
        max_risk = max(i["risk_score"] for i in issues)
        band, _ = severity_band(max_risk)
        lines.append(f"- Overall risk posture: **{band.upper()}** (highest single issue risk: {max_risk})")
    else:
        lines.append("- Overall risk posture: **CLEAN** (no findings this run)")
    lines.append(f"- {len(findings)} finding(s) across {len(issues)} correlated issue(s)")
    lines.append("")

    lines += ["## Top 10 issues by business risk", ""]
    top_issues = sorted(issues, key=lambda issue: issue["risk_score"], reverse=True)[:10]
    if top_issues:
        for rank, issue in enumerate(top_issues, start=1):
            band, _ = severity_band(issue["risk_score"])
            kev_note = " — **KEV-listed**" if issue["kev_listed"] else ""
            lines.append(
                f"{rank}. **{issue['issue_id']}** — risk {issue['risk_score']} ({band}), "
                f"{issue['exposure_count']} exposure(s) across {', '.join(issue['domains'])}{kev_note}"
            )
    else:
        lines.append("No findings this run.")
    lines.append("")

    lines += ["## Coverage achieved vs. scope", ""]
    total_attempted = sum(len(rollup.targets_attempted) for rollup in rollups.values())
    total_failed = sum(len(rollup.targets_failed) for rollup in rollups.values())
    total_assessed = total_attempted - total_failed
    pct = (100.0 * total_assessed / total_attempted) if total_attempted else 100.0
    lines.append(f"Overall: {total_assessed}/{total_attempted} target(s) assessed ({pct:.0f}%).")
    lines.append("")
    for domain, rollup in rollups.items():
        assessed = len(rollup.targets_attempted) - len(rollup.targets_failed)
        lines.append(f"- **{domain}**: {assessed}/{len(rollup.targets_attempted)} target(s) assessed")
        if rollup.targets_failed:
            for target, reason in rollup.targets_failed.items():
                lines.append(f"  - Coverage gap: `{target}` — {reason}")
    lines.append("")

    lines += ["## Delta vs. previous run", ""]
    if previous_run_id is None:
        lines.append("No previous run to compare against — every finding above is reported as `new`.")
    else:
        lines.append(f"Compared against `{previous_run_id}`:")
        lines.append("")
        lines.append(f"- New: {len(delta['new'])}")
        lines.append(f"- Recurring: {len(delta['recurring'])}")
        lines.append(f"- Resolved: {len(delta['resolved'])}")
        lines.append(f"- Regressed: {len(delta['regressed'])}")
        if delta["regressed"]:
            titles_by_id = {f["finding_id"]: f["title"] for f in findings}
            regressed_titles = [titles_by_id[fid] for fid in delta["regressed"] if fid in titles_by_id]
            lines.append(f"  - Regressed (reappeared after being resolved): {'; '.join(regressed_titles)}")
    lines.append("")

    return "\n".join(lines)


def _render_by_domain(rollups: dict) -> str:
    lines = ["# Findings by Domain", ""]
    for domain, rollup in rollups.items():
        lines.append(f"## {domain}")
        lines.append("")
        assessed = len(rollup.targets_attempted) - len(rollup.targets_failed)
        lines.append(f"Targets assessed: {assessed}/{len(rollup.targets_attempted)}")
        lines.append("")
        if rollup.targets_failed:
            lines.append("Coverage gaps:")
            for target, reason in rollup.targets_failed.items():
                lines.append(f"- `{target}`: {reason}")
            lines.append("")
        if rollup.findings:
            lines.append("Findings (highest risk first):")
            ranked = sorted(rollup.findings, key=lambda f: f.get("risk_score", 0.0), reverse=True)
            for finding in ranked:
                lines.append(
                    f"- **{finding['title']}** (risk {finding.get('risk_score', 'n/a')}) — "
                    f"asset `{finding['asset']['asset_id']}`, location `{finding['location']['ref']}`"
                )
        else:
            lines.append("No findings.")
        lines.append("")
    return "\n".join(lines)


def _render_remediation_board(issues: list[dict], findings: list[dict]) -> str:
    lines = [
        "# Remediation Board",
        "",
        "Ranked by business risk. SLA clock starts at each finding's `first_seen`.",
        "",
    ]
    if not issues:
        lines.append("No open issues.")
        return "\n".join(lines) + "\n"

    findings_by_id = {f["finding_id"]: f for f in findings}
    lines.append("| Rank | Issue | Risk | Severity | Owner team(s) | Effort estimate | SLA (days) |")
    lines.append("|---|---|---|---|---|---|---|")

    ranked = sorted(issues, key=lambda issue: issue["risk_score"], reverse=True)
    for rank, issue in enumerate(ranked, start=1):
        band, sla_days = severity_band(issue["risk_score"])
        members = [findings_by_id[fid] for fid in issue["finding_ids"] if fid in findings_by_id]
        owners = sorted({f["asset"]["owner_team"] for f in members}) or ["unassigned"]
        efforts = sorted({EFFORT_ESTIMATE_BY_DOMAIN.get(d, DEFAULT_EFFORT_ESTIMATE) for d in issue["domains"]})
        lines.append(
            f"| {rank} | {issue['issue_id']} | {issue['risk_score']} | {band} | "
            f"{', '.join(owners)} | {'; '.join(efforts)} | {sla_days} |"
        )
    lines.append("")
    return "\n".join(lines)


def _render_compliance_view(findings: list[dict]) -> str:
    lines = [
        "# Compliance View",
        "",
        "Findings mapped to their declared `regulatory_tags` — regulation/",
        "framework *relevance* only. This does NOT map to specific ISO 27001",
        "Annex A control numbers: that requires a control taxonomy this fleet",
        "does not yet implement, and inventing plausible-looking control IDs",
        "here would be an unevidenced number, which this report suite refuses",
        "to produce.",
        "",
    ]
    for tag in REGULATORY_HEADLINE_TAGS:
        matching = [f for f in findings if tag in (f.get("regulatory_tags") or [])]
        lines.append(f"## {tag}")
        lines.append("")
        if matching:
            lines.append(f"{len(matching)} finding(s):")
            for finding in sorted(matching, key=lambda f: f.get("risk_score", 0.0), reverse=True):
                lines.append(
                    f"- **{finding['title']}** (risk {finding.get('risk_score', 'n/a')}) — "
                    f"`{finding['domain']}` / `{finding['asset']['asset_id']}`"
                )
        else:
            lines.append(f"No findings currently tagged {tag}.")
        lines.append("")

    other_tags = sorted({tag for f in findings for tag in (f.get("regulatory_tags") or []) if tag not in REGULATORY_HEADLINE_TAGS})
    if other_tags:
        lines.append("## Other tags present this run")
        lines.append("")
        for tag in other_tags:
            count = sum(1 for f in findings if tag in (f.get("regulatory_tags") or []))
            lines.append(f"- **{tag}**: {count} finding(s)")
        lines.append("")

    return "\n".join(lines)
