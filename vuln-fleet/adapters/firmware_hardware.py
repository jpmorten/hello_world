"""Real firmware-hardware adapter: real NVD keyword search for the
device's vendor/product, enriched with real KEV/EPSS/CVSS from
adapters/cve_intel.py. Replaces adapters/mock/firmware_hardware.py in
engine/domains.py's registry (the mock stays in the repo, unaffected).

Weaker signal than adapters/supply_chain.py, and honestly so: OSV.dev
gives supply-chain an exact package *version* to match against, so a hit
means "this precise version is affected." NVD keyword search has no
version to check against a firmware image — it returns every CVE whose
text mentions the product name, going back over a decade, whether or not
it applies to whatever's actually installed. Every finding here says so
explicitly (lower confidence, higher false_positive_likelihood, and a
remediation string that asks the reader to verify the version before
treating it as live) rather than presenting an unversioned keyword match
as a confirmed vulnerability the way supply-chain's exact-version match
can.

What's still a placeholder: which product name to search for a given
device (`_DEVICE_INVENTORY_BY_TARGET` stands in for a real CMDB/firmware
inventory, same limitation adapters/supply_chain.py has for SBOMs).
"""
from __future__ import annotations

from adapters import cve_intel
from engine.scope import ScopeResolution

_DEVICE_INVENTORY_BY_TARGET: dict[str, dict] = {
    "host:idrac-mdm-01.example-stibo.internal": {"vendor": "Dell", "product_keyword": "iDRAC"},
}

_RESULTS_PER_DEVICE = 5


def _description(cve_entry: dict) -> str:
    for entry in cve_entry.get("descriptions") or []:
        if entry.get("lang") == "en":
            return entry.get("value", "")
    return ""


def _cwe_ids(cve_entry: dict) -> list[str]:
    cwes = []
    for weakness in cve_entry.get("weaknesses") or []:
        for entry in weakness.get("description") or []:
            value = entry.get("value", "")
            if value.startswith("CWE-"):
                cwes.append(value)
    return cwes


def _build_finding(target_ref: str, inventory: dict, cve_entry: dict) -> dict:
    cve_id = cve_entry["id"]
    intel = cve_intel.enrich_cve(cve_id)
    cvss_base = intel["cvss_v4_base"]
    if cvss_base is None:
        cvss_base = cve_intel.cvss_base_from_metrics(cve_entry.get("metrics", {})) or 5.0

    return {
        "title": f"{inventory['vendor']} {inventory['product_keyword']} keyword-matched to {cve_id}",
        "description": (
            (_description(cve_entry) or f"{cve_id} mentions {inventory['product_keyword']} in its NVD description.")[:450]
            + " [Unversioned NVD keyword match — not yet confirmed against the device's actual installed firmware version.]"
        ),
        "technology": "BMC firmware",
        "location": {"kind": "firmware_image", "ref": target_ref},
        "identifiers": {"cve": [cve_id], "cwe": _cwe_ids(cve_entry), "ghsa": []},
        "cvss_v4": {"base": cvss_base, "environmental": None},
        "epss": intel["epss"],
        "kev_listed": intel["kev_listed"],
        "exploitation_status": intel["exploitation_status"],
        "evidence_ref": [f"nvd-keyword://{inventory['product_keyword']}/{cve_id}"],
        # Lower than supply-chain's 0.9: an OSV hit is an exact-version
        # match, this is an unversioned keyword match against a firmware
        # image with no confirmed installed-version inventory yet.
        "confidence": 0.35,
        "false_positive_likelihood": 0.45,
        "regulatory_tags": ["CRA", "NIS2"],
        "suggested_remediation": (
            f"Confirm the installed {inventory['product_keyword']} firmware version is within {cve_id}'s "
            "affected range before treating this as live; if confirmed, apply the vendor's current firmware."
        ),
    }


def scan(target_ref: str, resolution: ScopeResolution) -> list[dict]:
    inventory = _DEVICE_INVENTORY_BY_TARGET.get(target_ref)
    if not inventory:
        return []
    entries = cve_intel.search_nvd_by_keyword(inventory["product_keyword"], results_limit=_RESULTS_PER_DEVICE)
    return [_build_finding(target_ref, inventory, entry["cve"]) for entry in entries]
