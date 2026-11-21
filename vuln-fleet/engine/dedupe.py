"""Finding fingerprinting, exact-match dedup, and cross-domain
correlation.

finding_id and dedupe_findings are the minimal slice step 5 needed to
close the spawn -> worker -> rollup -> log -> report loop: a
deterministic fingerprint, and collapsing findings that hash identically
(the same worker re-reporting, or two workers whose scope happened to
overlap).

correlate_findings is step 8's addition: the same CVE seen in firmware +
container + SBOM is one real-world issue with three exposures, not three
unrelated findings, and engine/risk.py's per-finding score alone can't
say that — grouping is this module's job. It's deliberately CVE-keyed
only: a shared GHSA id with no CVE alias, or two non-CVE findings that
happen to share wording, are NOT correlated here. A CVE identifier means
the same vulnerability; two findings' titles merely reading alike does
not, and grouping them on that basis risks hiding a real second issue
behind a coincidental resemblance. That fuzzy pass, if it's ever added,
belongs here too — this module gains passes, it doesn't move — but stays
out of scope until there's a concrete non-CVE correlation need backed by
real adapter data, not a guess at what one might look like.

Baseline delta (new/resolved/recurring/regressed) lives in
engine/baseline.py instead of here: it's a different concern (state that
persists *across* runs, not a same-run grouping) and needed its own
small ledger, which didn't belong bolted onto a fingerprinting module.
"""
from __future__ import annotations

import hashlib
from typing import Optional

from engine.risk import score_issue


def compute_finding_id(*, domain: str, identifiers: dict, asset_id: str, location_ref: str, title: str = "") -> str:
    """Deterministic fingerprint: sha256(domain, cve-ids-or-title, asset_id, location).

    CVE ids (sorted, so order never matters) are the identifying key when
    present; a finding with no CVE (a misconfiguration, a policy gap) falls
    back to its exact title text. Two different non-CVE findings on the
    same asset+location with different titles get different ids; two with
    the same title collide on purpose — that's the "worker re-reported the
    same thing" case this function exists to catch. Distinguishing two
    genuinely different non-CVE findings that happen to share a title is
    the fuzzy-matching problem step 8 owns, not this one.
    """
    cve_ids = sorted((identifiers or {}).get("cve") or [])
    key_identifier = ",".join(cve_ids) if cve_ids else f"title:{title}"
    payload = "|".join([domain, key_identifier, asset_id, location_ref])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def dedupe_findings(findings: list[dict]) -> list[dict]:
    """Collapses findings sharing a finding_id, merging evidence_ref and
    widening the first_seen/last_seen window. Order-preserving and
    deterministic given deterministic input order."""
    by_id: dict[str, dict] = {}
    for finding in findings:
        fid = finding["finding_id"]
        if fid not in by_id:
            by_id[fid] = dict(finding)
            continue
        existing = by_id[fid]
        existing["evidence_ref"] = sorted(set(existing["evidence_ref"]) | set(finding["evidence_ref"]))
        existing["first_seen"] = min(existing["first_seen"], finding["first_seen"])
        existing["last_seen"] = max(existing["last_seen"], finding["last_seen"])
    return list(by_id.values())


def correlate_findings(findings: list[dict]) -> list[dict]:
    """Groups findings sharing a CVE into one issue with multiple
    exposures. A finding with no CVE becomes its own single-exposure
    issue rather than being dropped — every finding ends up in exactly
    one issue, so nothing this function touches can silently disappear
    from a report built on top of it. A finding listing more than one CVE
    (rare, but the schema allows it) is correlated under each.

    Order is deterministic: CVE-keyed issues first, in the order their
    CVE was first encountered in `findings`, then standalone issues in
    the same order as their source findings.
    """
    issues_by_cve: dict[str, list[dict]] = {}
    standalone: list[dict] = []
    for finding in findings:
        cve_ids = finding.get("identifiers", {}).get("cve") or []
        if not cve_ids:
            standalone.append(finding)
            continue
        for cve_id in cve_ids:
            issues_by_cve.setdefault(cve_id, []).append(finding)

    issues = [_build_issue(cve_id, members) for cve_id, members in issues_by_cve.items()]
    issues += [_build_issue(None, [finding]) for finding in standalone]
    return issues


def _build_issue(cve_id: Optional[str], members: list[dict]) -> dict:
    return {
        "issue_id": cve_id or members[0]["finding_id"],
        "cve": cve_id,
        "finding_ids": [f["finding_id"] for f in members],
        "domains": sorted({f["domain"] for f in members}),
        "asset_ids": sorted({f["asset"]["asset_id"] for f in members}),
        "exposure_count": len(members),
        "kev_listed": any(f["kev_listed"] for f in members),
        "risk_score": score_issue(members),
    }
