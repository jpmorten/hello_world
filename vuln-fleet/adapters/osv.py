"""Real, read-only dependency vulnerability lookup against OSV.dev
(https://osv.dev) — public, unauthenticated, and covers npm/PyPI/Maven/Go/
etc. `_http_post_json` is the sole network touchpoint and the one thing
tests monkeypatch to stay hermetic.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Optional

OSV_QUERY_URL = "https://api.osv.dev/v1/query"


def _http_post_json(url: str, payload: dict, timeout: float = 15.0) -> dict:
    """One retry after a short backoff — see adapters.cve_intel._http_get_json
    for why a single transient failure shouldn't read as a clean scan."""
    last_exc: Exception = urllib.error.URLError("unreachable")
    for attempt in range(2):
        try:
            request = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return json.load(response)
        except (urllib.error.URLError, TimeoutError) as exc:
            last_exc = exc
            if attempt == 0:
                time.sleep(1.0)
    raise last_exc


def query_package(ecosystem: str, name: str, version: str) -> list[dict]:
    """Real vulnerabilities affecting this exact package version, per
    OSV.dev. Returns [] on any failure (unreachable, malformed response,
    or genuinely no known vulnerabilities) — indistinguishable to the
    caller by design: a lookup failure here is a coverage gap for
    whatever calls this, not a reason to fabricate a finding or crash."""
    try:
        payload = {"package": {"name": name, "ecosystem": ecosystem}, "version": version}
        data = _http_post_json(OSV_QUERY_URL, payload)
        return data.get("vulns", [])
    except (urllib.error.URLError, TimeoutError, ValueError, KeyError):
        return []


def extract_cve(vuln: dict) -> Optional[str]:
    """OSV entries are keyed by GHSA/OSV id; a CVE, when one exists, is
    listed as an alias. Returns the first CVE-shaped alias, or None."""
    for alias in vuln.get("aliases") or []:
        if alias.startswith("CVE-"):
            return alias
    return None


def extract_fixed_version(vuln: dict) -> Optional[str]:
    """Best-effort: the first 'fixed' version OSV lists across this
    vuln's affected ranges, for a more actionable remediation string."""
    for affected in vuln.get("affected") or []:
        for range_ in affected.get("ranges") or []:
            for event in range_.get("events") or []:
                if "fixed" in event:
                    return event["fixed"]
    return None
