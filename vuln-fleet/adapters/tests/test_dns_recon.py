"""Unit tests for adapters/dns_recon.py: DNS/email/CT-log passive checks
and TLS/HTTP/exposed-path active checks, exercised hermetically via the
module's three HTTP/DNS seams (_resolve, _http_get_text, _http_request)
plus the socket-level TLS helpers.
"""
import urllib.error

import dns.exception
import pytest

from adapters import dns_recon
from engine.scope import ScopeResolution

TARGET_REF = "domain:example-red-team-target.test"
DOMAIN = "example-red-team-target.test"


def _resolution() -> ScopeResolution:
    return ScopeResolution(
        target_ref=TARGET_REF,
        asset_id=f"red-team-{DOMAIN}",
        entity="Red-team engagement (externally supplied target)",
        asset_type="external_domain",
        criticality="medium",
        owner_team="tester@example.com",
        scope_ref="red-team-targets.yaml#red-team-example",
    )


@pytest.fixture(autouse=True)
def _clear_authorization_map():
    dns_recon._ACTIVE_AUTHORIZATION_BY_TARGET.clear()
    yield
    dns_recon._ACTIVE_AUTHORIZATION_BY_TARGET.clear()


# -- analyze_spf / analyze_dmarc -----------------------------------------


def test_analyze_spf_missing():
    assert dns_recon.analyze_spf(["\"some-other-txt-record\""]) == {"status": "missing"}


def test_analyze_spf_permissive():
    result = dns_recon.analyze_spf(['"v=spf1 include:_spf.example.com +all"'])
    assert result["status"] == "permissive"


def test_analyze_spf_ok():
    result = dns_recon.analyze_spf(['"v=spf1 include:_spf.example.com -all"'])
    assert result["status"] == "ok"


def test_analyze_spf_multiple():
    result = dns_recon.analyze_spf(['"v=spf1 -all"', '"v=spf1 include:other.com -all"'])
    assert result["status"] == "multiple"
    assert len(result["records"]) == 2


def test_analyze_dmarc_missing(monkeypatch):
    monkeypatch.setattr(dns_recon, "_resolve", lambda domain, rtype: [])

    assert dns_recon.analyze_dmarc(DOMAIN) == {"status": "missing"}


def test_analyze_dmarc_present_with_policy(monkeypatch):
    monkeypatch.setattr(dns_recon, "_resolve", lambda domain, rtype: ['"v=DMARC1; p=none; rua=mailto:d@example.com"'])

    result = dns_recon.analyze_dmarc(DOMAIN)

    assert result["status"] == "present"
    assert result["policy"] == "none"


def test_analyze_dmarc_resolver_failure_reads_as_missing(monkeypatch):
    def boom(domain, rtype):
        raise dns.exception.DNSException("timeout")

    monkeypatch.setattr(dns_recon, "_resolve", boom)

    assert dns_recon.analyze_dmarc(DOMAIN) == {"status": "missing"}


# -- resolve_dns_records --------------------------------------------------


def test_resolve_dns_records_degrades_per_record_type(monkeypatch):
    def fake_resolve(domain, rtype):
        if rtype == "MX":
            raise dns.exception.DNSException("no MX")
        return [f"{rtype}-value"]

    monkeypatch.setattr(dns_recon, "_resolve", fake_resolve)

    records = dns_recon.resolve_dns_records(DOMAIN)

    assert records["MX"] == []
    assert records["A"] == ["A-value"]


# -- enumerate_subdomains_via_ct ------------------------------------------

_CT_RESPONSE = [
    {"name_value": "api.example-red-team-target.test\nexample-red-team-target.test", "serial_number": "AABBCC"},
    {"name_value": "*.example-red-team-target.test", "serial_number": "DDEEFF"},
    {"name_value": "unrelated.other-domain.test", "serial_number": "112233"},
]


def test_enumerate_subdomains_via_ct_parses_names_and_serials(monkeypatch):
    import json

    monkeypatch.setattr(dns_recon, "_http_get_text", lambda url, timeout=15.0: json.dumps(_CT_RESPONSE))

    result = dns_recon.enumerate_subdomains_via_ct(DOMAIN)

    assert result["available"] is True
    # the apex domain itself isn't counted as a "subdomain"; the wildcard
    # entry (*.domain) is excluded here too, counted via `wildcard` instead.
    assert result["subdomains"] == {"api.example-red-team-target.test"}
    assert result["wildcard"] is True
    assert result["serials"] == {"AABBCC", "DDEEFF"}
    # a name under an unrelated domain must never leak in
    assert "unrelated.other-domain.test" not in result["subdomains"]


def test_enumerate_subdomains_via_ct_unavailable_on_network_failure(monkeypatch):
    def boom(url, timeout=15.0):
        raise urllib.error.URLError("unreachable")

    monkeypatch.setattr(dns_recon, "_http_get_text", boom)

    result = dns_recon.enumerate_subdomains_via_ct(DOMAIN)

    assert result["available"] is False
    assert result["subdomains"] == set()


def test_enumerate_subdomains_via_ct_unavailable_on_invalid_json(monkeypatch):
    monkeypatch.setattr(dns_recon, "_http_get_text", lambda url, timeout=15.0: "not json")

    assert dns_recon.enumerate_subdomains_via_ct(DOMAIN)["available"] is False


# -- check_tls_posture ------------------------------------------------------


def test_check_tls_posture_flags_interception_when_serial_not_in_ct_logs(monkeypatch):
    class _FakeSSock:
        def version(self):
            return "TLSv1.3"

        def getpeercert(self):
            return {"serialNumber": "11:22:33", "notAfter": "Jan 1 00:00:00 2099 GMT"}

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    class _FakeCtx:
        def wrap_socket(self, sock, server_hostname=None):
            return _FakeSSock()

    import socket as socket_mod

    monkeypatch.setattr(dns_recon.ssl, "create_default_context", lambda: _FakeCtx())
    monkeypatch.setattr(socket_mod, "create_connection", lambda addr, timeout=10: _DummySocket())

    result = dns_recon.check_tls_posture(DOMAIN, known_cert_serials={"AABBCC"})

    assert result["reachable"] is True
    assert result["interception_suspected"] is True
    assert "accepts_legacy_tls" not in result


def test_check_tls_posture_proceeds_normally_when_serial_matches(monkeypatch):
    class _FakeSSock:
        def version(self):
            return "TLSv1.3"

        def getpeercert(self):
            return {"serialNumber": "AA:BB:CC", "notAfter": "Jan 1 00:00:00 2099 GMT"}

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    class _FakeCtx:
        def wrap_socket(self, sock, server_hostname=None):
            return _FakeSSock()

    import socket as socket_mod

    monkeypatch.setattr(dns_recon.ssl, "create_default_context", lambda: _FakeCtx())
    monkeypatch.setattr(socket_mod, "create_connection", lambda addr, timeout=10: _DummySocket())
    monkeypatch.setattr(dns_recon, "_probe_legacy_tls", lambda domain: False)

    result = dns_recon.check_tls_posture(DOMAIN, known_cert_serials={"AABBCC"})

    assert result["interception_suspected"] is False
    assert result["accepts_legacy_tls"] is False


def test_check_tls_posture_unreachable_returns_not_reachable(monkeypatch):
    import socket as socket_mod

    def boom(addr, timeout=10):
        raise OSError("connection refused")

    monkeypatch.setattr(socket_mod, "create_connection", boom)

    result = dns_recon.check_tls_posture(DOMAIN, known_cert_serials=set())

    assert result == {"reachable": False, "interception_suspected": False}


class _DummySocket:
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


# -- check_http_security_headers / check_exposed_paths -----------------------


def test_check_http_security_headers_reports_missing_and_disclosed(monkeypatch):
    monkeypatch.setattr(
        dns_recon,
        "_http_request",
        lambda url, method="GET", timeout=15.0: (200, {"Server": "nginx/1.18.0", "Content-Type": "text/html"}),
    )

    result = dns_recon.check_http_security_headers(DOMAIN)

    assert "Strict-Transport-Security" in result["missing_headers"]
    assert result["disclosed_banners"] == {"Server": "nginx/1.18.0"}


def test_check_http_security_headers_none_all_present(monkeypatch):
    full_headers = {h: "set" for h in dns_recon._SECURITY_HEADERS}
    monkeypatch.setattr(dns_recon, "_http_request", lambda url, method="GET", timeout=15.0: (200, full_headers))

    result = dns_recon.check_http_security_headers(DOMAIN)

    assert result["missing_headers"] == []
    assert result["disclosed_banners"] == {}


def test_check_http_security_headers_network_failure_returns_none(monkeypatch):
    def boom(url, method="GET", timeout=15.0):
        raise urllib.error.URLError("unreachable")

    monkeypatch.setattr(dns_recon, "_http_request", boom)

    assert dns_recon.check_http_security_headers(DOMAIN) is None


def test_check_exposed_paths_reports_status_per_path(monkeypatch):
    def fake_request(url, method="GET", timeout=15.0):
        if url.endswith("/.git/config"):
            return 200, {}
        if url.endswith("/.env"):
            return 404, {}
        return 404, {}  # security.txt absent

    monkeypatch.setattr(dns_recon, "_http_request", fake_request)

    result = dns_recon.check_exposed_paths(DOMAIN)

    assert result["/.git/config"] == 200
    assert result["/.env"] == 404


# -- scan: passive-only vs. authorized-active -----------------------------


def test_scan_runs_passive_checks_without_authorization(monkeypatch):
    monkeypatch.setattr(dns_recon, "resolve_dns_records", lambda domain: {"TXT": []})
    monkeypatch.setattr(dns_recon, "enumerate_subdomains_via_ct", lambda domain: {"available": False, "subdomains": set(), "serials": set(), "wildcard": False})

    def boom_active(*a, **k):
        raise AssertionError("active checks must not run without authorization")

    monkeypatch.setattr(dns_recon, "check_tls_posture", boom_active)
    monkeypatch.setattr(dns_recon, "check_http_security_headers", boom_active)
    monkeypatch.setattr(dns_recon, "check_exposed_paths", boom_active)

    findings = dns_recon.scan(TARGET_REF, _resolution())

    # SPF missing + DMARC missing, no CT data available
    assert len(findings) == 2
    assert all(f.get("authorization_ref") is None for f in findings)


def test_scan_runs_active_checks_when_authorized(monkeypatch):
    monkeypatch.setattr(dns_recon, "resolve_dns_records", lambda domain: {"TXT": ['"v=spf1 -all"']})
    monkeypatch.setattr(dns_recon, "analyze_dmarc", lambda domain: {"status": "present", "policy": "reject"})
    monkeypatch.setattr(dns_recon, "enumerate_subdomains_via_ct", lambda domain: {"available": False, "subdomains": set(), "serials": set(), "wildcard": False})
    monkeypatch.setattr(dns_recon, "check_tls_posture", lambda domain, known_cert_serials=None: {"reachable": False, "interception_suspected": False})
    monkeypatch.setattr(dns_recon, "check_http_security_headers", lambda domain: {"status": 200, "missing_headers": ["Strict-Transport-Security"], "disclosed_banners": {}})
    monkeypatch.setattr(dns_recon, "check_exposed_paths", lambda domain: {"/.git/config": 404, "/.env": 404, "/.well-known/security.txt": 200})

    dns_recon._ACTIVE_AUTHORIZATION_BY_TARGET[TARGET_REF] = "red-team-example-20260919T000000Z"

    findings = dns_recon.scan(TARGET_REF, _resolution())

    assert len(findings) == 1  # only the missing-headers finding
    assert findings[0]["authorization_ref"] == "red-team-example-20260919T000000Z"


def test_scan_target_domain_extraction_handles_bare_and_prefixed_refs():
    assert dns_recon._target_domain("domain:example.com") == "example.com"
    assert dns_recon._target_domain("example.com") == "example.com"


# -- schema validity --------------------------------------------------------


def test_finding_is_schema_valid(monkeypatch):
    from schema.validate import validate_finding

    monkeypatch.setattr(dns_recon, "resolve_dns_records", lambda domain: {"TXT": []})
    monkeypatch.setattr(dns_recon, "enumerate_subdomains_via_ct", lambda domain: {"available": False, "subdomains": set(), "serials": set(), "wildcard": False})

    raw = dns_recon.scan(TARGET_REF, _resolution())[0]
    finding = dict(raw)
    finding.update(
        finding_id="a" * 64,
        run_id="run-test",
        domain="red-team-recon",
        entity="Red-team engagement (externally supplied target)",
        asset={"asset_id": f"red-team-{DOMAIN}", "type": "external_domain", "owner_team": "tester@example.com", "criticality": "medium"},
        first_seen="2026-09-19T00:00:00Z",
        last_seen="2026-09-19T00:00:00Z",
        status="new",
        scope_ref="red-team-targets.yaml#red-team-example",
        authorization_ref=None,
    )
    validate_finding(finding)  # must not raise
