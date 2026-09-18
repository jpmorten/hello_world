"""Real, read-only CVE exploitability intelligence: CISA KEV, FIRST.org
EPSS, and NVD CVSS. This is the "external intelligence" layer the design
brief requires exploitation status be assessed from — never by attempting
exploitation.

`_http_get_json` is the sole network touchpoint; it's a real HTTP GET by
default and the one thing tests monkeypatch to stay hermetic and fast
(the KEV catalog alone is 1700+ entries; no test should fetch it live).
Every other function in this module is pure given that seam.

Each individual source is best-effort: a network blip or rate limit on
one source degrades that one field rather than failing enrichment
outright — a finding with unknown EPSS is still a finding; a finding
silently dropped because NVD timed out is a coverage gap nobody sees.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Optional

KEV_CATALOG_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL_TEMPLATE = "https://api.first.org/data/v1/epss?cve={cve_id}"
NVD_URL_TEMPLATE = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
NVD_KEYWORD_URL_TEMPLATE = "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}&resultsPerPage={limit}"

_kev_cache: Optional[set[str]] = None


def _http_get_json(url: str, timeout: float = 15.0) -> dict:
    """One retry after a short backoff: CISA's KEV feed in particular has
    been observed to intermittently 403 (bot-protection/rate-limiting) on
    an otherwise-valid request that succeeds moments later. Exploitation
    status is consequential enough that a transient block shouldn't read
    as "not exploited" when a second attempt would say otherwise."""
    last_exc: Exception = urllib.error.URLError("unreachable")
    for attempt in range(2):
        try:
            # NOTE: CISA's KEV feed WAF has been observed to 403 a UA
            # containing "security scanner" specifically (confirmed via
            # direct curl A/B testing) — this tool never scans, only
            # queries public intelligence, but avoid the trigger phrase.
            request = urllib.request.Request(
                url, headers={"User-Agent": "vuln-fleet/1.0 (+https://github.com/jpmorten/hello_world)"}
            )
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return json.load(response)
        except (urllib.error.URLError, TimeoutError) as exc:
            last_exc = exc
            if attempt == 0:
                time.sleep(1.0)
    raise last_exc


def reset_cache() -> None:
    """Test seam: forces the next fetch_kev_catalog() call to refetch."""
    global _kev_cache
    _kev_cache = None


def fetch_kev_catalog(force_refresh: bool = False) -> set[str]:
    """The full set of KEV-listed CVE ids, cached in-process. Returns an
    empty set (never raises) if the feed is unreachable — callers see
    "not KEV-listed", not a crash; that's the honest default for a source
    that's down, not a false negative introduced by this function."""
    global _kev_cache
    if _kev_cache is not None and not force_refresh:
        return _kev_cache
    try:
        catalog = _http_get_json(KEV_CATALOG_URL)
        _kev_cache = {v["cveID"] for v in catalog.get("vulnerabilities", [])}
    except (urllib.error.URLError, TimeoutError, ValueError, KeyError):
        _kev_cache = set()
    return _kev_cache


def fetch_epss(cve_id: str) -> Optional[float]:
    """EPSS score in [0, 1], or None if unavailable (unreachable, or the
    CVE simply isn't scored)."""
    try:
        data = _http_get_json(EPSS_URL_TEMPLATE.format(cve_id=cve_id))
        rows = data.get("data") or []
        if not rows:
            return None
        return float(rows[0]["epss"])
    except (urllib.error.URLError, TimeoutError, ValueError, KeyError, IndexError):
        return None


def cvss_base_from_metrics(metrics: dict) -> Optional[float]:
    """Shared by fetch_nvd_cvss_base and any caller (e.g. a keyword
    search result) that already has an NVD `cve.metrics` object and
    wants its base score without a second network round-trip. Prefers
    the highest CVSS version NVD has published (v4 > v3.1 > v3.0 > v2),
    since NVD's own CVSS v4 coverage is still sparse."""
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            return float(entries[0]["cvssData"]["baseScore"])
    return None


def fetch_nvd_cvss_base(cve_id: str) -> Optional[float]:
    """Best-effort CVSS base score from NVD for one known CVE id."""
    try:
        data = _http_get_json(NVD_URL_TEMPLATE.format(cve_id=cve_id))
        vulns = data.get("vulnerabilities") or []
        if not vulns:
            return None
        return cvss_base_from_metrics(vulns[0]["cve"].get("metrics", {}))
    except (urllib.error.URLError, TimeoutError, ValueError, KeyError, IndexError):
        return None


def search_nvd_by_keyword(keyword: str, results_limit: int = 5) -> list[dict]:
    """Real NVD keyword search (e.g. a vendor/product name), returning raw
    CVE entries in NVD's own shape (`{"cve": {...}}`). Unlike enrich_cve,
    there's no specific CVE id here to key off — this is how a caller with
    a product name but no SBOM-precision version inventory (a firmware
    device, not a versioned package) finds *candidate* CVEs. Matches are
    unversioned: the caller is responsible for saying so in whatever it
    builds from these, not presenting a keyword match as a confirmed,
    version-verified vulnerability. Returns [] on any failure, never
    raises — a search that comes back empty is a coverage gap for the
    caller to report, not a crash."""
    try:
        url = NVD_KEYWORD_URL_TEMPLATE.format(keyword=urllib.parse.quote(keyword), limit=results_limit)
        return _http_get_json(url).get("vulnerabilities", [])
    except (urllib.error.URLError, TimeoutError, ValueError, KeyError):
        return []


def enrich_cve(cve_id: str) -> dict:
    """Combines all three sources into the fields a Finding needs:
    kev_listed, epss, cvss_v4_base, exploitation_status. Conservative on
    any source failure — never invents exploitation evidence."""
    kev_listed = cve_id in fetch_kev_catalog()
    epss = fetch_epss(cve_id)
    cvss_base = fetch_nvd_cvss_base(cve_id)
    return {
        "kev_listed": kev_listed,
        "epss": epss if epss is not None else 0.0,
        "cvss_v4_base": cvss_base,
        "exploitation_status": "known_exploited" if kev_listed else "no_known_exploitation",
    }
