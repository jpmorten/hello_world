"""Finding fingerprinting and exact-match dedup.

This is deliberately the minimal slice needed to close the step-5
spawn -> worker -> rollup -> log -> report loop: a deterministic
finding_id, and collapsing findings that hash identically (the same
worker re-reporting, or two workers whose scope happened to overlap).

The richer cross-domain correlation the design calls for — the same CVE
seen in firmware + container + SBOM collapsing into one issue with three
exposures, via fuzzy title/location matching for non-CVE findings — is
step 8's job (dedupe.py grows there; this module doesn't move a second
time, it gains a correlation pass alongside compute_finding_id).
"""
from __future__ import annotations

import hashlib


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
