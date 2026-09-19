"""Unit tests for adapters/api_surface.py: static OpenAPI-spec security
analysis, exercised hermetically via the module's one HTTP seam
(_http_get_text). No live spec is fetched here — see the module docstring
for the live verification against the real Swagger Petstore spec.
"""
import json

import pytest
import yaml

from adapters import api_surface
from engine.scope import ScopeResolution
from schema.validate import validate_finding

TARGET_REF = "endpoint:https://cms-edge.example-stibodx.com"

_SPEC_ALL_ISSUES = {
    "servers": [{"url": "http://cms-edge.example-stibodx.com"}, {"url": "https://cms-edge.example-stibodx.com"}],
    "security": [{"apiKeyAuth": []}],
    "paths": {
        "/v1/items": {
            "get": {"operationId": "listItemsV1"},
            "post": {"operationId": "createItem", "security": [{"apiKeyAuth": []}]},
        },
        "/v2/items": {
            "get": {"operationId": "listItemsV2", "security": [{"apiKeyAuth": []}]},
        },
        "/v1/legacy-export": {
            "get": {"operationId": "legacyExport", "deprecated": True, "security": [{"apiKeyAuth": []}]},
        },
        "/v1/public-ping": {
            "get": {"operationId": "ping", "security": []},
        },
        "/v1/items/{id}": {
            "parameters": [{"name": "id", "in": "path"}],
            "get": {"operationId": "getItem", "security": [{"apiKeyAuth": []}]},
        },
    },
}

_SPEC_CLEAN = {
    "servers": [{"url": "https://clean.example.com"}],
    "security": [{"apiKeyAuth": []}],
    "paths": {
        "/items": {"get": {"operationId": "listItems"}},
    },
}


def _resolution() -> ScopeResolution:
    return ScopeResolution(
        target_ref=TARGET_REF,
        asset_id="cms-edge",
        entity="Stibo Digital Experience",
        asset_type="service",
        criticality="high",
        owner_team="cms-platform",
        scope_ref="assets.yaml#cms-edge",
    )


# -- fetch_spec ---------------------------------------------------------


def test_fetch_spec_parses_json(monkeypatch):
    monkeypatch.setattr(api_surface, "_http_get_text", lambda url, timeout=15.0: json.dumps(_SPEC_CLEAN))

    assert api_surface.fetch_spec("https://example.com/openapi.json") == _SPEC_CLEAN


def test_fetch_spec_falls_back_to_yaml(monkeypatch):
    monkeypatch.setattr(api_surface, "_http_get_text", lambda url, timeout=15.0: yaml.safe_dump(_SPEC_CLEAN))

    assert api_surface.fetch_spec("https://example.com/openapi.yaml") == _SPEC_CLEAN


def test_fetch_spec_returns_none_for_invalid_data(monkeypatch):
    monkeypatch.setattr(api_surface, "_http_get_text", lambda url, timeout=15.0: "not json and: not: valid: yaml: [")

    assert api_surface.fetch_spec("https://example.com/openapi.json") is None


def test_fetch_spec_returns_none_for_non_mapping_document(monkeypatch):
    monkeypatch.setattr(api_surface, "_http_get_text", lambda url, timeout=15.0: json.dumps([1, 2, 3]))

    assert api_surface.fetch_spec("https://example.com/openapi.json") is None


def test_fetch_spec_returns_none_on_network_failure(monkeypatch):
    import urllib.error

    def boom(url, timeout=15.0):
        raise urllib.error.URLError("unreachable")

    monkeypatch.setattr(api_surface, "_http_get_text", boom)

    assert api_surface.fetch_spec("https://example.com/openapi.json") is None


# -- individual find_* functions -----------------------------------------


def test_find_unauthenticated_operations():
    # GET /v1/items has no per-operation `security`, but the spec declares
    # a global one, so it inherits coverage; only /v1/public-ping's
    # explicit `security: []` opts out.
    result = api_surface.find_unauthenticated_operations(_SPEC_ALL_ISSUES)

    assert set(result) == {("GET", "/v1/public-ping")}


def test_find_unauthenticated_operations_empty_when_all_covered():
    assert api_surface.find_unauthenticated_operations(_SPEC_CLEAN) == []


def test_find_deprecated_operations():
    assert api_surface.find_deprecated_operations(_SPEC_ALL_ISSUES) == [("GET", "/v1/legacy-export")]


def test_find_insecure_servers():
    assert api_surface.find_insecure_servers(_SPEC_ALL_ISSUES) == ["http://cms-edge.example-stibodx.com"]


def test_find_insecure_servers_empty_for_relative_or_https_urls():
    spec = {"servers": [{"url": "https://a.example.com"}, {"url": "/api/v3"}]}

    assert api_surface.find_insecure_servers(spec) == []


def test_find_coexisting_major_versions():
    assert api_surface.find_coexisting_major_versions(_SPEC_ALL_ISSUES) == {"v1", "v2"}


def test_find_coexisting_major_versions_empty_when_only_one_family():
    spec = {"paths": {"/v1/a": {"get": {}}, "/v1/b": {"get": {}}}}

    assert api_surface.find_coexisting_major_versions(spec) == set()


# -- analyze_spec ---------------------------------------------------------


def test_analyze_spec_reports_all_four_issue_types():
    findings = api_surface.analyze_spec(_SPEC_ALL_ISSUES, TARGET_REF)

    titles = " | ".join(f["title"] for f in findings)
    assert "no security requirement" in titles
    assert "deprecated operation" in titles
    assert "plain-HTTP server" in titles
    assert "Multiple API version families" in titles
    assert len(findings) == 4


def test_analyze_spec_returns_no_findings_for_a_clean_spec():
    assert api_surface.analyze_spec(_SPEC_CLEAN, TARGET_REF) == []


# -- scan -------------------------------------------------------------------


def test_scan_unmapped_target_returns_empty_list_without_network(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("should not touch the network for a target with no spec URL mapped")

    monkeypatch.setattr(api_surface, "_http_get_text", boom)

    assert api_surface.scan("endpoint:https://no-such-target.example.com", _resolution()) == []


def test_scan_returns_findings_for_a_mapped_target(monkeypatch):
    monkeypatch.setattr(api_surface, "_SPEC_URL_BY_TARGET", {TARGET_REF: "https://cms-edge.example-stibodx.com/openapi.json"})
    monkeypatch.setattr(api_surface, "_http_get_text", lambda url, timeout=15.0: json.dumps(_SPEC_ALL_ISSUES))

    findings = api_surface.scan(TARGET_REF, _resolution())

    assert len(findings) == 4


def test_scan_returns_empty_list_when_spec_fetch_fails(monkeypatch):
    monkeypatch.setattr(api_surface, "_SPEC_URL_BY_TARGET", {TARGET_REF: "https://cms-edge.example-stibodx.com/openapi.json"})
    monkeypatch.setattr(api_surface, "_http_get_text", lambda url, timeout=15.0: "not valid")

    assert api_surface.scan(TARGET_REF, _resolution()) == []


def test_finding_is_schema_valid(monkeypatch):
    monkeypatch.setattr(api_surface, "_SPEC_URL_BY_TARGET", {TARGET_REF: "https://cms-edge.example-stibodx.com/openapi.json"})
    monkeypatch.setattr(api_surface, "_http_get_text", lambda url, timeout=15.0: json.dumps(_SPEC_ALL_ISSUES))

    raw = api_surface.scan(TARGET_REF, _resolution())[0]
    finding = dict(raw)
    finding.update(
        finding_id="a" * 64,
        run_id="run-test",
        domain="api-surface",
        entity="Stibo Digital Experience",
        asset={"asset_id": "cms-edge", "type": "service", "owner_team": "cms-platform", "criticality": "high"},
        first_seen="2026-09-19T00:00:00Z",
        last_seen="2026-09-19T00:00:00Z",
        status="new",
        scope_ref="assets.yaml#cms-edge",
        authorization_ref=None,
    )
    validate_finding(finding)  # must not raise
