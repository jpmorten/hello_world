"""Unit tests for adapters/cve_intel.py, monkeypatching the one real
network seam (_http_get_json) with frozen, recorded-shape fixture data —
these never touch the live KEV/EPSS/NVD feeds, so they're fast and
deterministic even though the module's default behavior is real.
"""
import io
import json
import urllib.error

import pytest

from adapters import cve_intel


class _FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        self.close()

KEV_FIXTURE = {
    "catalogVersion": "2026.09.18",
    "count": 2,
    "vulnerabilities": [
        {"cveID": "CVE-2021-44228", "vendorProject": "Apache", "product": "Log4j"},
        {"cveID": "CVE-2022-88888", "vendorProject": "Dell", "product": "iDRAC"},
    ],
}

EPSS_FIXTURE = {
    "status": "OK",
    "data": [{"cve": "CVE-2021-44228", "epss": "0.999990000", "percentile": "1.000000000"}],
}

EPSS_EMPTY_FIXTURE = {"status": "OK", "data": []}

NVD_FIXTURE = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2021-44228",
                "metrics": {
                    "cvssMetricV31": [{"cvssData": {"baseScore": 10.0}}],
                    "cvssMetricV2": [{"cvssData": {"baseScore": 9.3}}],
                },
            }
        }
    ]
}

NVD_EMPTY_FIXTURE = {"vulnerabilities": []}


@pytest.fixture(autouse=True)
def _reset_kev_cache():
    cve_intel.reset_cache()
    yield
    cve_intel.reset_cache()


def test_fetch_kev_catalog_returns_cve_ids(monkeypatch):
    monkeypatch.setattr(cve_intel, "_http_get_json", lambda url, timeout=15.0: KEV_FIXTURE)

    catalog = cve_intel.fetch_kev_catalog()

    assert catalog == {"CVE-2021-44228", "CVE-2022-88888"}


def test_fetch_kev_catalog_is_cached_across_calls(monkeypatch):
    calls = []

    def fake_get(url, timeout=15.0):
        calls.append(url)
        return KEV_FIXTURE

    monkeypatch.setattr(cve_intel, "_http_get_json", fake_get)

    cve_intel.fetch_kev_catalog()
    cve_intel.fetch_kev_catalog()

    assert len(calls) == 1  # second call served from cache


def test_fetch_kev_catalog_unreachable_returns_empty_set_not_raises(monkeypatch):
    def boom(url, timeout=15.0):
        raise TimeoutError("feed unreachable")

    monkeypatch.setattr(cve_intel, "_http_get_json", boom)

    assert cve_intel.fetch_kev_catalog() == set()


def test_fetch_epss_returns_score(monkeypatch):
    monkeypatch.setattr(cve_intel, "_http_get_json", lambda url, timeout=15.0: EPSS_FIXTURE)

    assert cve_intel.fetch_epss("CVE-2021-44228") == pytest.approx(0.99999)


def test_fetch_epss_no_data_returns_none(monkeypatch):
    monkeypatch.setattr(cve_intel, "_http_get_json", lambda url, timeout=15.0: EPSS_EMPTY_FIXTURE)

    assert cve_intel.fetch_epss("CVE-9999-00001") is None


def test_fetch_epss_unreachable_returns_none_not_raises(monkeypatch):
    def boom(url, timeout=15.0):
        raise TimeoutError("epss unreachable")

    monkeypatch.setattr(cve_intel, "_http_get_json", boom)

    assert cve_intel.fetch_epss("CVE-2021-44228") is None


def test_fetch_nvd_cvss_base_prefers_v31_over_v2(monkeypatch):
    monkeypatch.setattr(cve_intel, "_http_get_json", lambda url, timeout=15.0: NVD_FIXTURE)

    assert cve_intel.fetch_nvd_cvss_base("CVE-2021-44228") == 10.0


def test_fetch_nvd_cvss_base_no_results_returns_none(monkeypatch):
    monkeypatch.setattr(cve_intel, "_http_get_json", lambda url, timeout=15.0: NVD_EMPTY_FIXTURE)

    assert cve_intel.fetch_nvd_cvss_base("CVE-9999-00001") is None


def test_enrich_cve_kev_listed_forces_known_exploited(monkeypatch):
    responses = {"kev": KEV_FIXTURE, "epss": EPSS_FIXTURE, "nvd": NVD_FIXTURE}

    def fake_get(url, timeout=15.0):
        if "cisa.gov" in url:
            return responses["kev"]
        if "first.org" in url:
            return responses["epss"]
        return responses["nvd"]

    monkeypatch.setattr(cve_intel, "_http_get_json", fake_get)

    result = cve_intel.enrich_cve("CVE-2021-44228")

    assert result == {
        "kev_listed": True,
        "epss": pytest.approx(0.99999),
        "cvss_v4_base": 10.0,
        "exploitation_status": "known_exploited",
    }


def test_enrich_cve_not_kev_listed(monkeypatch):
    def fake_get(url, timeout=15.0):
        if "cisa.gov" in url:
            return KEV_FIXTURE
        if "first.org" in url:
            return EPSS_EMPTY_FIXTURE
        return NVD_EMPTY_FIXTURE

    monkeypatch.setattr(cve_intel, "_http_get_json", fake_get)

    result = cve_intel.enrich_cve("CVE-2020-28500")

    assert result["kev_listed"] is False
    assert result["exploitation_status"] == "no_known_exploitation"
    assert result["epss"] == 0.0  # None coerced to 0.0, not left null
    assert result["cvss_v4_base"] is None


# -- _http_get_json's own retry, exercised below urlopen rather than at
# the _http_get_json seam the tests above patch out entirely -----------------


def test_http_get_json_retries_once_then_succeeds(monkeypatch):
    monkeypatch.setattr(cve_intel.time, "sleep", lambda seconds: None)
    calls = {"n": 0}

    def fake_urlopen(request, timeout=15.0):
        calls["n"] += 1
        if calls["n"] == 1:
            raise urllib.error.URLError("transient 403")
        return _FakeResponse(json.dumps({"ok": True}).encode())

    monkeypatch.setattr(cve_intel.urllib.request, "urlopen", fake_urlopen)

    result = cve_intel._http_get_json("https://example.invalid/x")

    assert result == {"ok": True}
    assert calls["n"] == 2


def test_http_get_json_raises_after_two_failures(monkeypatch):
    monkeypatch.setattr(cve_intel.time, "sleep", lambda seconds: None)

    def always_fails(request, timeout=15.0):
        raise urllib.error.URLError("still down")

    monkeypatch.setattr(cve_intel.urllib.request, "urlopen", always_fails)

    with pytest.raises(urllib.error.URLError):
        cve_intel._http_get_json("https://example.invalid/x")


def test_fetch_kev_catalog_recovers_from_one_transient_failure(monkeypatch):
    monkeypatch.setattr(cve_intel.time, "sleep", lambda seconds: None)
    calls = {"n": 0}

    def fake_urlopen(request, timeout=15.0):
        calls["n"] += 1
        if calls["n"] == 1:
            raise urllib.error.HTTPError("url", 403, "Forbidden", {}, None)
        return _FakeResponse(json.dumps(KEV_FIXTURE).encode())

    monkeypatch.setattr(cve_intel.urllib.request, "urlopen", fake_urlopen)

    assert cve_intel.fetch_kev_catalog() == {"CVE-2021-44228", "CVE-2022-88888"}


# -- search_nvd_by_keyword -----------------------------------------------------

KEYWORD_SEARCH_FIXTURE = {
    "totalResults": 2,
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2013-4783",
                "descriptions": [{"lang": "en", "value": "The Dell iDRAC6 with firmware ... allows remote attackers to bypass authentication."}],
                "weaknesses": [{"description": [{"lang": "en", "value": "CWE-287"}]}],
                "metrics": {"cvssMetricV2": [{"cvssData": {"baseScore": 10.0}}]},
            }
        },
        {
            "cve": {
                "id": "CVE-2016-5685",
                "descriptions": [{"lang": "en", "value": "Dell iDRAC7 and iDRAC8 devices allow authenticated users to gain access."}],
                "weaknesses": [],
                "metrics": {},
            }
        },
    ],
}


def test_search_nvd_by_keyword_returns_raw_entries(monkeypatch):
    captured = {}

    def fake_get(url, timeout=15.0):
        captured["url"] = url
        return KEYWORD_SEARCH_FIXTURE

    monkeypatch.setattr(cve_intel, "_http_get_json", fake_get)

    results = cve_intel.search_nvd_by_keyword("iDRAC", results_limit=5)

    assert len(results) == 2
    assert results[0]["cve"]["id"] == "CVE-2013-4783"
    assert "keywordSearch=iDRAC" in captured["url"]
    assert "resultsPerPage=5" in captured["url"]


def test_search_nvd_by_keyword_unreachable_returns_empty_list(monkeypatch):
    def boom(url, timeout=15.0):
        raise TimeoutError("nvd unreachable")

    monkeypatch.setattr(cve_intel, "_http_get_json", boom)

    assert cve_intel.search_nvd_by_keyword("iDRAC") == []


def test_search_nvd_by_keyword_url_encodes_the_keyword(monkeypatch):
    captured = {}

    def fake_get(url, timeout=15.0):
        captured["url"] = url
        return {"vulnerabilities": []}

    monkeypatch.setattr(cve_intel, "_http_get_json", fake_get)

    cve_intel.search_nvd_by_keyword("Dell iDRAC")

    assert "Dell+iDRAC" in captured["url"] or "Dell%20iDRAC" in captured["url"]


# -- cvss_base_from_metrics ----------------------------------------------------


def test_cvss_base_from_metrics_prefers_higher_version():
    metrics = {
        "cvssMetricV2": [{"cvssData": {"baseScore": 9.3}}],
        "cvssMetricV31": [{"cvssData": {"baseScore": 10.0}}],
    }

    assert cve_intel.cvss_base_from_metrics(metrics) == 10.0


def test_cvss_base_from_metrics_empty_returns_none():
    assert cve_intel.cvss_base_from_metrics({}) is None
