"""Unit tests for adapters/osv.py, monkeypatching the one real network
seam (_http_post_json) with a frozen, real-recorded-shape fixture (the
actual lodash@4.17.15 / GHSA-29mw-wpgm-hmr9 response, trimmed) so these
never touch the live OSV.dev API.
"""
import io
import json
import urllib.error

import pytest

from adapters import osv


class _FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        self.close()

LODASH_VULN_FIXTURE = {
    "vulns": [
        {
            "id": "GHSA-29mw-wpgm-hmr9",
            "summary": "Regular Expression Denial of Service (ReDoS) in lodash",
            "details": "All versions of package lodash prior to 4.17.21 are vulnerable to ReDoS.",
            "aliases": ["CVE-2020-28500"],
            "database_specific": {"severity": "MODERATE", "cwe_ids": ["CWE-1333", "CWE-400"]},
            "affected": [
                {
                    "ranges": [
                        {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}
                    ]
                }
            ],
        }
    ]
}

NO_VULNS_FIXTURE = {"vulns": []}


def test_query_package_returns_vulns(monkeypatch):
    monkeypatch.setattr(osv, "_http_post_json", lambda url, payload, timeout=15.0: LODASH_VULN_FIXTURE)

    vulns = osv.query_package("npm", "lodash", "4.17.15")

    assert len(vulns) == 1
    assert vulns[0]["id"] == "GHSA-29mw-wpgm-hmr9"


def test_query_package_no_vulns_returns_empty_list(monkeypatch):
    monkeypatch.setattr(osv, "_http_post_json", lambda url, payload, timeout=15.0: NO_VULNS_FIXTURE)

    assert osv.query_package("npm", "left-pad", "1.3.0") == []


def test_query_package_unreachable_returns_empty_list_not_raises(monkeypatch):
    def boom(url, payload, timeout=15.0):
        raise TimeoutError("osv unreachable")

    monkeypatch.setattr(osv, "_http_post_json", boom)

    assert osv.query_package("npm", "lodash", "4.17.15") == []


def test_query_package_sends_correct_payload(monkeypatch):
    captured = {}

    def fake_post(url, payload, timeout=15.0):
        captured["url"] = url
        captured["payload"] = payload
        return NO_VULNS_FIXTURE

    monkeypatch.setattr(osv, "_http_post_json", fake_post)

    osv.query_package("PyPI", "requests", "2.6.0")

    assert captured["url"] == osv.OSV_QUERY_URL
    assert captured["payload"] == {"package": {"name": "requests", "ecosystem": "PyPI"}, "version": "2.6.0"}


def test_extract_cve_returns_cve_alias():
    vuln = LODASH_VULN_FIXTURE["vulns"][0]

    assert osv.extract_cve(vuln) == "CVE-2020-28500"


def test_extract_cve_returns_none_when_no_cve_alias():
    vuln = {"id": "GHSA-xxxx-xxxx-xxxx", "aliases": ["GHSA-yyyy-yyyy-yyyy"]}

    assert osv.extract_cve(vuln) is None


def test_extract_cve_returns_none_when_no_aliases_field():
    assert osv.extract_cve({"id": "GHSA-xxxx-xxxx-xxxx"}) is None


def test_extract_fixed_version_finds_fixed_event():
    vuln = LODASH_VULN_FIXTURE["vulns"][0]

    assert osv.extract_fixed_version(vuln) == "4.17.21"


def test_extract_fixed_version_returns_none_when_absent():
    vuln = {"affected": [{"ranges": [{"events": [{"introduced": "0"}]}]}]}

    assert osv.extract_fixed_version(vuln) is None


# -- _http_post_json's own retry, exercised below urlopen -----------------


def test_http_post_json_retries_once_then_succeeds(monkeypatch):
    monkeypatch.setattr(osv.time, "sleep", lambda seconds: None)
    calls = {"n": 0}

    def fake_urlopen(request, timeout=15.0):
        calls["n"] += 1
        if calls["n"] == 1:
            raise urllib.error.URLError("transient failure")
        return _FakeResponse(json.dumps({"vulns": []}).encode())

    monkeypatch.setattr(osv.urllib.request, "urlopen", fake_urlopen)

    result = osv._http_post_json(osv.OSV_QUERY_URL, {"package": {}})

    assert result == {"vulns": []}
    assert calls["n"] == 2


def test_http_post_json_raises_after_two_failures(monkeypatch):
    monkeypatch.setattr(osv.time, "sleep", lambda seconds: None)

    def always_fails(request, timeout=15.0):
        raise urllib.error.URLError("still down")

    monkeypatch.setattr(osv.urllib.request, "urlopen", always_fails)

    with pytest.raises(urllib.error.URLError):
        osv._http_post_json(osv.OSV_QUERY_URL, {"package": {}})
