"""PolicyCop's regulatory/legislative checks: static, deterministic
inspection of this fleet's OWN configuration and schemas against the EU
regulatory/legislative requirements this project's design brief cites --
the EU AI Act, the Cyber Resilience Act (CRA), NIS2, and GDPR (see
schema/finding.schema.json's `regulatory_tags` enum, which already
carries exactly these four plus ISO27001/SOC2).

This module never judges a TARGET's compliance -- that's what a
Finding's own `regulatory_tags` already does, per-finding. It judges the
fleet's OWN conduct: does every agent stay inside its documented,
non-unilateral-action tool grant, does every finding schema still carry
the transparency/honesty fields these regulations expect, does synthetic
output still self-disclose, is the fleet's own tracked config free of
anything it shouldn't be carrying. Deterministic and unit-tested, like
every other governance-relevant arithmetic in this codebase (see
engine/scope.py's own module docstring) -- a live PolicyCop agent
narrates and prioritizes what this module finds; it never re-derives
compliance judgement by itself.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import yaml

_AGENT_FRONTMATTER_RE = re.compile(r"^---\n(.*?)\n---", re.DOTALL)
_FORBIDDEN_TOOLS = {"Write", "Edit"}
_MOCK_DISCLOSURE_TAG = "[MOCK ANALYSIS"
_SECRET_LIKE_RE = re.compile(r"AKIA[0-9A-Z]{16}")
_STALE_AUTHORIZATION_AGE_DAYS = 90

REGULATIONS_CHECKED = ["EU_AI_Act", "CRA", "NIS2", "GDPR"]


@dataclass(frozen=True)
class PolicyFinding:
    rule: str
    regulation: str
    severity: str  # info | warning | critical
    description: str
    evidence_ref: list[str]

    def to_dict(self) -> dict:
        return {
            "rule": self.rule,
            "regulation": self.regulation,
            "severity": self.severity,
            "description": self.description,
            "evidence_ref": self.evidence_ref,
        }


def _parse_dt(value: str) -> datetime:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _agent_frontmatter(text: str) -> dict:
    match = _AGENT_FRONTMATTER_RE.match(text)
    if not match:
        return {}
    doc = yaml.safe_load(match.group(1)) or {}
    return doc if isinstance(doc, dict) else {}


def check_tool_boundaries(agents_dir: Path) -> list[PolicyFinding]:
    """EU AI Act (human oversight / no autonomous action beyond a
    documented role) and CRA (secure-by-design, no unauthorized
    modification): every agent definition's own `tools:` grant is this
    fleet's actual, structural enforcement of "an agent reports, it never
    unilaterally changes state." This is a regression guard that the
    grant list itself hasn't quietly grown a Write/Edit somewhere -- a
    hit here means the fleet's most basic non-action guarantee is no
    longer true in the code, not just the prose describing it."""
    if not agents_dir.exists():
        return []
    findings = []
    for path in sorted(agents_dir.glob("*.md")):
        frontmatter = _agent_frontmatter(path.read_text())
        tools = {t.strip() for t in (frontmatter.get("tools") or "").split(",") if t.strip()}
        forbidden = tools & _FORBIDDEN_TOOLS
        if forbidden:
            findings.append(
                PolicyFinding(
                    rule="no_unilateral_action_tools",
                    regulation="EU_AI_Act",
                    severity="critical",
                    description=(
                        f"{path.name} grants {sorted(forbidden)} -- this fleet's non-exploitation / "
                        "human-oversight guarantee depends on every agent being read-only-plus-Bash "
                        "against read-only engine commands, never able to directly write or edit files."
                    ),
                    evidence_ref=[str(path)],
                )
            )
    return findings


def check_finding_schema_discipline(schema_path: Path) -> list[PolicyFinding]:
    """GDPR Art. 22 / AI Act Art. 13 transparency: an automated finding
    must carry the fields that let a human judge how much to trust it
    (confidence, false_positive_likelihood) and where it applies
    (regulatory_tags), with real evidence (evidence_ref). Checks the
    SCHEMA still requires them, not any one finding, so a future schema
    edit can't quietly drop the obligation fleet-wide."""
    if not schema_path.exists():
        return []
    doc = json.loads(schema_path.read_text())
    required = set(doc.get("required") or [])
    needed = {"confidence", "false_positive_likelihood", "regulatory_tags", "evidence_ref"}
    missing = needed - required
    if not missing:
        return []
    return [
        PolicyFinding(
            rule="finding_transparency_fields_required",
            regulation="EU_AI_Act",
            severity="critical",
            description=(
                f"{schema_path.name} no longer requires {sorted(missing)} on every Finding -- these are "
                "the fields a human reviewer needs to judge an automated finding's trustworthiness."
            ),
            evidence_ref=[str(schema_path)],
        )
    ]


def check_remediation_guidance_required(schema_path: Path) -> list[PolicyFinding]:
    """CRA Art. 13 (vulnerability handling: a manufacturer must address
    vulnerabilities without undue delay and provide guidance): checks the
    schema still requires `suggested_remediation` on every Finding."""
    if not schema_path.exists():
        return []
    doc = json.loads(schema_path.read_text())
    required = set(doc.get("required") or [])
    if "suggested_remediation" in required:
        return []
    return [
        PolicyFinding(
            rule="remediation_guidance_required",
            regulation="CRA",
            severity="critical",
            description=f"{schema_path.name} no longer requires suggested_remediation on every Finding.",
            evidence_ref=[str(schema_path)],
        )
    ]


def check_mock_disclosure(analysts_mock_dir: Path) -> list[PolicyFinding]:
    """EU AI Act Art. 50 (transparency obligation for AI-generated/
    synthetic content): placeholder analysis must disclose itself as
    such. Regression guard on the literal disclosure tag this fleet's
    mock analyst uses -- see analysts/mock/attack_scenario.py."""
    if not analysts_mock_dir.exists():
        return []
    findings = []
    for path in sorted(analysts_mock_dir.glob("*.py")):
        if path.name == "__init__.py":
            continue
        if _MOCK_DISCLOSURE_TAG not in path.read_text():
            findings.append(
                PolicyFinding(
                    rule="synthetic_content_must_self_disclose",
                    regulation="EU_AI_Act",
                    severity="critical",
                    description=(
                        f"{path.name} no longer contains the {_MOCK_DISCLOSURE_TAG!r} disclosure tag its "
                        "output is supposed to carry on every synthetic scenario/finding it produces."
                    ),
                    evidence_ref=[str(path)],
                )
            )
    return findings


def check_authorization_hygiene(scope_dir: Path, now: datetime) -> list[PolicyFinding]:
    """NIS2 due-diligence: an active-scan authorization file shouldn't
    silently accumulate long-expired, un-pruned records that could be
    mistaken for still covering something. This is a hygiene nudge, not
    a scope decision -- engine/scope.py's own in-window check already
    refuses an expired authorization at the moment it matters; PolicyCop
    just flags that the paper trail is getting stale."""
    findings = []
    for name in ("authorized-active.yaml", "red-team-active-authorizations.yaml"):
        path = scope_dir / name
        if not path.exists():
            continue
        doc = yaml.safe_load(path.read_text()) or {}
        for auth in doc.get("authorizations") or []:
            valid_until = auth.get("valid_until")
            if not valid_until:
                continue
            try:
                expiry = _parse_dt(valid_until)
            except ValueError:
                continue
            age_days = (now - expiry).days
            if age_days > _STALE_AUTHORIZATION_AGE_DAYS:
                findings.append(
                    PolicyFinding(
                        rule="stale_authorization_record",
                        regulation="NIS2",
                        severity="info",
                        description=(
                            f"{name}: {auth.get('authorization_ref', '?')!r} expired {age_days} day(s) ago "
                            "and is still on file -- prune it or document why it's kept for audit history."
                        ),
                        evidence_ref=[str(path)],
                    )
                )
    return findings


def check_no_hardcoded_secrets(scope_dir: Path) -> list[PolicyFinding]:
    """GDPR/CRA data-minimization: the fleet's own tracked config
    (scope/*.yaml) should never itself carry a real-looking secret value
    -- a genuine hit here would be this fleet's own supply chain leaking
    a credential, not a target's."""
    if not scope_dir.exists():
        return []
    findings = []
    for path in sorted(scope_dir.glob("*.yaml")):
        if _SECRET_LIKE_RE.search(path.read_text()):
            findings.append(
                PolicyFinding(
                    rule="no_secret_like_values_in_tracked_config",
                    regulation="GDPR",
                    severity="critical",
                    description=f"{path.name} contains a value matching a real credential format (AWS access key).",
                    evidence_ref=[str(path)],
                )
            )
    return findings


def run_policy_checks(repo_root: Path, now: datetime) -> list[PolicyFinding]:
    """Runs every check above against the real, current repo state at
    `repo_root`."""
    findings: list[PolicyFinding] = []
    findings += check_tool_boundaries(repo_root / ".claude" / "agents")
    findings += check_finding_schema_discipline(repo_root / "schema" / "finding.schema.json")
    findings += check_remediation_guidance_required(repo_root / "schema" / "finding.schema.json")
    findings += check_mock_disclosure(repo_root / "analysts" / "mock")
    findings += check_authorization_hygiene(repo_root / "scope", now)
    findings += check_no_hardcoded_secrets(repo_root / "scope")
    return findings
