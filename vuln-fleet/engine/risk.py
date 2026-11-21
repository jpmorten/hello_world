"""Deterministic risk scoring: CVSS x EPSS x KEV x asset criticality per
finding, plus an exposure-breadth boost for a correlated issue (the same
CVE found across multiple assets/domains). Plain arithmetic, no model
judgement — per the governance requirement that risk scoring is
unit-tested code, not agent discretion.
"""
from __future__ import annotations

SEVERITY_WEIGHT = 0.5
LIKELIHOOD_WEIGHT = 0.3
ASSET_WEIGHT = 0.2
KEV_BOOST = 1.2
EXPOSURE_BOOST_PER_EXTRA = 0.05
EXPOSURE_BOOST_CAP = 1.5

_ASSET_CRITICALITY_WEIGHT = {"critical": 1.0, "high": 0.75, "medium": 0.5, "low": 0.25}
_DEFAULT_ASSET_WEIGHT = 0.5


def score_finding(finding: dict) -> float:
    """0-100, higher is riskier.

    An additive blend, not a pure product: severity, likelihood, and
    asset weight are summed (weighted 50/30/20) rather than multiplied,
    so a severe-but-unlikely-to-be-exploited finding doesn't collapse
    toward zero the way CVSS x EPSS alone would — a CVSS 9.8 with a
    vanishingly small EPSS still contributes half its weight from
    severity and stays visible in a ranking, it just doesn't outrank an
    actually-exploited finding with a lower CVSS.

    Likelihood is EPSS, or forced to 1.0 when KEV-listed: a KEV listing
    is confirmed real-world exploitation, which should never be
    outweighed by an EPSS model that hasn't caught up yet. The KEV boost
    on top exists because two findings can otherwise tie on the additive
    blend (both maxed on likelihood) despite one being confirmed and the
    other merely probable — the boost keeps KEV-listed findings sorting
    strictly above equally-scored non-KEV ones.
    """
    severity = finding["cvss_v4"]["base"] / 10.0
    kev_listed = finding["kev_listed"]
    likelihood = 1.0 if kev_listed else finding.get("epss", 0.0)
    asset_weight = _ASSET_CRITICALITY_WEIGHT.get(finding["asset"]["criticality"], _DEFAULT_ASSET_WEIGHT)

    raw = SEVERITY_WEIGHT * severity + LIKELIHOOD_WEIGHT * likelihood + ASSET_WEIGHT * asset_weight
    boosted = raw * (KEV_BOOST if kev_listed else 1.0)
    return round(min(100.0, boosted * 100.0), 2)


def score_issue(findings: list[dict]) -> float:
    """Aggregate risk for a correlated issue (engine/dedupe.py's
    correlate_findings): the worst single exposure's score, boosted by
    how many independent exposures exist. The same CVE live in five
    places is a bigger organizational problem than the same CVE live in
    one, even though no individual exposure's own CVSS/EPSS/KEV changed
    — that's exactly the "exposure" factor the design brief calls for
    alongside CVSS/EPSS/KEV/asset criticality.
    """
    if not findings:
        return 0.0
    worst = max(score_finding(f) for f in findings)
    exposure_boost = min(1.0 + EXPOSURE_BOOST_PER_EXTRA * (len(findings) - 1), EXPOSURE_BOOST_CAP)
    return round(min(100.0, worst * exposure_boost), 2)
