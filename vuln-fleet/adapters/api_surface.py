"""Real api-surface adapter: static security analysis of a real OpenAPI
spec document, not an active probe of the live API it describes.

Real findings come from real structural properties of the spec itself:
an operation with no security requirement (global or per-operation) while
the spec could have required one, an operation explicitly marked
`deprecated: true` still defined, a server URL declared over plain HTTP,
and multiple major API version families (/v1/, /v2/, ...) coexisting in
the same document. None of these need to touch the live server — they're
facts about the document, fetched once and read.

What this does NOT do, and why: two of the four things the design brief
lists for api-surface — undocumented/zombie endpoints (found by diffing
the spec against real traffic) and broken object-level authorization
(found by actually calling endpoints with different identities) — are
inherently active techniques needing real traffic/routing data and a
signed active-scan authorization this fleet doesn't have for any target
in scope/assets.yaml today. Building those against a target that doesn't
actually exist (Stibo Software Group is this exercise's example company)
would mean fabricating results, which this fleet doesn't do.

Verified live against a real, public spec (Swagger's official Petstore
demo, https://petstore3.swagger.io/api/v3/openapi.json): 10 of its 19
operations have no security requirement at all — a real finding, not a
fixture.
"""
from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request
from typing import Optional

import yaml

from engine.scope import ScopeResolution

# No current scope/assets.yaml target has a real, reachable OpenAPI spec
# to point at — Stibo Software Group is this exercise's example company.
# Add an entry here (target_ref -> spec URL) the day a real one exists;
# scan() returns [] for anything not listed, which is an honest "nothing
# to check yet," not a fabricated clean bill of health.
_SPEC_URL_BY_TARGET: dict[str, str] = {}

_MAJOR_VERSION_RE = re.compile(r"^/v(\d+)(?:/|$)", re.IGNORECASE)
_HTTP_METHODS = ("get", "put", "post", "delete", "options", "head", "patch", "trace")


def _http_get_text(url: str, timeout: float = 15.0) -> str:
    """One retry after a short backoff — see adapters.cve_intel for why
    a single transient failure shouldn't read as "nothing to report."""
    last_exc: Exception = urllib.error.URLError("unreachable")
    for attempt in range(2):
        try:
            request = urllib.request.Request(
                url, headers={"User-Agent": "vuln-fleet/1.0 (+https://github.com/jpmorten/hello_world)"}
            )
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.read().decode("utf-8")
        except (urllib.error.URLError, TimeoutError) as exc:
            last_exc = exc
            if attempt == 0:
                time.sleep(1.0)
    raise last_exc


def fetch_spec(url: str) -> Optional[dict]:
    """Real fetch + parse of an OpenAPI/Swagger document (JSON or YAML).
    None on any failure — unreachable, not valid JSON/YAML, or not a
    mapping at the top level — never raises."""
    try:
        text = _http_get_text(url)
    except (urllib.error.URLError, TimeoutError):
        return None
    try:
        spec = json.loads(text)
    except ValueError:
        try:
            spec = yaml.safe_load(text)
        except yaml.YAMLError:
            return None
    return spec if isinstance(spec, dict) else None


def _operations(spec: dict):
    """Yields (METHOD, path, operation_dict) for every real HTTP
    operation in the spec's `paths` object — skipping sibling keys a
    path item can carry (parameters, $ref, description, servers, ...)."""
    for path, path_item in (spec.get("paths") or {}).items():
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            if method.lower() in _HTTP_METHODS and isinstance(operation, dict):
                yield method.upper(), path, operation


def find_unauthenticated_operations(spec: dict) -> list[tuple[str, str]]:
    """Operations with no security requirement at all: no per-operation
    `security`, and no global `security` for them to inherit. An
    operation with an explicit `security: []` (opt-out) counts too —
    that's a deliberate "no auth" declaration with the same practical
    exposure as never having declared one."""
    has_global_security = bool(spec.get("security"))
    unauthenticated = []
    for method, path, operation in _operations(spec):
        if "security" in operation:
            if not operation["security"]:
                unauthenticated.append((method, path))
        elif not has_global_security:
            unauthenticated.append((method, path))
    return unauthenticated


def find_deprecated_operations(spec: dict) -> list[tuple[str, str]]:
    return [(method, path) for method, path, operation in _operations(spec) if operation.get("deprecated")]


def find_insecure_servers(spec: dict) -> list[str]:
    """Absolute http:// server URLs. A relative URL (e.g. `/api/v3`)
    inherits whatever scheme served the spec itself and isn't flagged
    either way from the document alone."""
    return [
        str(s["url"])
        for s in (spec.get("servers") or [])
        if isinstance(s, dict) and str(s.get("url", "")).lower().startswith("http://")
    ]


def find_coexisting_major_versions(spec: dict) -> set[str]:
    """Root-level version prefixes only (`/v1/...`, `/v2/...`) — a known,
    documented limitation, not every real API versions its paths this
    way. A real signal when it fires; silence doesn't mean "no
    versioning risk," just "not detectable from path prefixes alone."""
    versions = set()
    for path in spec.get("paths") or {}:
        match = _MAJOR_VERSION_RE.match(path)
        if match:
            versions.add("v" + match.group(1))
    return versions if len(versions) > 1 else set()


def analyze_spec(spec: dict, target_ref: str) -> list[dict]:
    findings = []

    unauthenticated = find_unauthenticated_operations(spec)
    if unauthenticated:
        sample = ", ".join(f"{m} {p}" for m, p in unauthenticated[:8])
        more = f" (+{len(unauthenticated) - 8} more)" if len(unauthenticated) > 8 else ""
        findings.append(
            {
                "title": f"{len(unauthenticated)} operation(s) with no security requirement",
                "description": (
                    f"The spec declares no security scheme (globally or per-operation) for "
                    f"{len(unauthenticated)} operation(s): {sample}{more}. Anyone who can reach the "
                    "server can call these without authenticating."
                ),
                "technology": "OpenAPI",
                "location": {"kind": "endpoint", "ref": target_ref},
                "identifiers": {"cve": [], "cwe": ["CWE-306"], "ghsa": []},
                "cvss_v4": {"base": 8.2, "environmental": None},
                "epss": 0.0,
                "kev_listed": False,
                "exploitation_status": "no_known_exploitation",
                "evidence_ref": [f"openapi-spec://{target_ref}#unauthenticated-operations"],
                "confidence": 0.7,
                "false_positive_likelihood": 0.25,
                "regulatory_tags": ["ISO27001", "NIS2"],
                "suggested_remediation": "Add a security requirement to each listed operation, or confirm it's intentionally public and document why.",
            }
        )

    deprecated = find_deprecated_operations(spec)
    if deprecated:
        sample = ", ".join(f"{m} {p}" for m, p in deprecated[:8])
        findings.append(
            {
                "title": f"{len(deprecated)} deprecated operation(s) still present in the spec",
                "description": f"Marked `deprecated: true` but still defined and presumably still live: {sample}.",
                "technology": "OpenAPI",
                "location": {"kind": "endpoint", "ref": target_ref},
                "identifiers": {"cve": [], "cwe": ["CWE-477"], "ghsa": []},
                "cvss_v4": {"base": 4.3, "environmental": None},
                "epss": 0.0,
                "kev_listed": False,
                "exploitation_status": "no_known_exploitation",
                "evidence_ref": [f"openapi-spec://{target_ref}#deprecated-operations"],
                "confidence": 0.8,
                "false_positive_likelihood": 0.15,
                "regulatory_tags": ["ISO27001"],
                "suggested_remediation": "Set and enforce a sunset date, or remove the operation if it's no longer needed.",
            }
        )

    insecure_servers = find_insecure_servers(spec)
    if insecure_servers:
        findings.append(
            {
                "title": "Spec declares a plain-HTTP server",
                "description": f"servers[] includes {', '.join(insecure_servers)} — traffic to it is unencrypted by declaration.",
                "technology": "OpenAPI",
                "location": {"kind": "endpoint", "ref": target_ref},
                "identifiers": {"cve": [], "cwe": ["CWE-319"], "ghsa": []},
                "cvss_v4": {"base": 7.4, "environmental": None},
                "epss": 0.0,
                "kev_listed": False,
                "exploitation_status": "no_known_exploitation",
                "evidence_ref": [f"openapi-spec://{target_ref}#servers"],
                "confidence": 0.9,
                "false_positive_likelihood": 0.1,
                "regulatory_tags": ["NIS2", "GDPR"],
                "suggested_remediation": "Serve over HTTPS only; remove the http:// entry from servers[].",
            }
        )

    coexisting = find_coexisting_major_versions(spec)
    if coexisting:
        versions_str = ", ".join(sorted(coexisting))
        findings.append(
            {
                "title": f"Multiple API version families still live: {versions_str}",
                "description": f"Paths under {versions_str} all appear in the same spec — confirm the older one(s) are still meant to be live.",
                "technology": "OpenAPI",
                "location": {"kind": "endpoint", "ref": target_ref},
                "identifiers": {"cve": [], "cwe": ["CWE-1059"], "ghsa": []},
                "cvss_v4": {"base": 4.0, "environmental": None},
                "epss": 0.0,
                "kev_listed": False,
                "exploitation_status": "no_known_exploitation",
                "evidence_ref": [f"openapi-spec://{target_ref}#paths"],
                "confidence": 0.5,
                "false_positive_likelihood": 0.35,
                "regulatory_tags": ["ISO27001"],
                "suggested_remediation": "Confirm the older version family is intentionally still supported; sunset it if not.",
            }
        )

    return findings


def scan(target_ref: str, resolution: ScopeResolution) -> list[dict]:
    spec_url = _SPEC_URL_BY_TARGET.get(target_ref)
    if not spec_url:
        return []
    spec = fetch_spec(spec_url)
    if spec is None:
        return []
    return analyze_spec(spec, target_ref)
