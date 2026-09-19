"""Registry decomposition correctness, and a full 9-domain sweep proving
the spawn -> worker -> rollup -> log -> report loop from step 5 scales to
every Tier 1 domain in the design brief, not just the two that need no
active scanning.

supply-chain and firmware-hardware are real adapters (adapters/
supply_chain.py, adapters/firmware_hardware.py): both call out to
OSV.dev/CISA KEV/FIRST.org EPSS/NVD over the network by default. The
autouse fixture below patches those HTTP seams with frozen fixture data
so this file's tests stay hermetic and fast, the same as every other
adapter in the registry (still mocks, no I/O at all). api-surface
(adapters/api_surface.py) is also real, but its own HTTP seam
(_http_get_text) is never reached here: no current scope target has a
spec URL mapped in api_surface._SPEC_URL_BY_TARGET, so scan() returns []
without any network call — an honest "nothing to check yet," not a
fixture that needs patching.
"""
import json
from pathlib import Path

import pytest

from adapters import cve_intel, osv
from engine.domains import DOMAIN_REGISTRY, build_domain_specs
from engine.orchestrator import Orchestrator
from engine.scope import ScopeModel
from schema.validate import validate_event, validate_finding

REPO_SCOPE_DIR = Path(__file__).parent.parent.parent / "scope"

_LODASH_VULN_FIXTURE = {
    "vulns": [
        {
            "id": "GHSA-29mw-wpgm-hmr9",
            "summary": "Regular Expression Denial of Service (ReDoS) in lodash",
            "aliases": ["CVE-2020-28500"],
            "database_specific": {"severity": "MODERATE", "cwe_ids": ["CWE-1333", "CWE-400"]},
            "affected": [{"ranges": [{"events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}],
        }
    ]
}
_IDRAC_KEYWORD_FIXTURE = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2013-4783",
                "descriptions": [{"lang": "en", "value": "The Dell iDRAC6 allows remote attackers to bypass authentication via cipher zero."}],
                "weaknesses": [{"description": [{"lang": "en", "value": "CWE-287"}]}],
                "metrics": {"cvssMetricV2": [{"cvssData": {"baseScore": 10.0}}]},
            }
        }
    ]
}
_KEV_NOT_LISTED = {"vulnerabilities": []}
_EPSS_SOME_SCORE = {"data": [{"cve": "CVE-2020-28500", "epss": "0.04"}]}
_NVD_NO_RESULT = {"vulnerabilities": []}


@pytest.fixture(autouse=True)
def _hermetic_supply_chain_network(monkeypatch):
    monkeypatch.setattr(osv, "_http_post_json", lambda url, payload, timeout=15.0: _LODASH_VULN_FIXTURE)

    def fake_nvd_get(url, timeout=15.0):
        if "cisa.gov" in url:
            return _KEV_NOT_LISTED
        if "first.org" in url:
            return _EPSS_SOME_SCORE
        if "keywordSearch=" in url:
            return _IDRAC_KEYWORD_FIXTURE
        return _NVD_NO_RESULT

    monkeypatch.setattr(cve_intel, "_http_get_json", fake_nvd_get)
    cve_intel.reset_cache()
    yield
    cve_intel.reset_cache()


def _scope_model() -> ScopeModel:
    return ScopeModel(
        REPO_SCOPE_DIR / "assets.yaml", REPO_SCOPE_DIR / "exclusions.yaml", REPO_SCOPE_DIR / "authorized-active.yaml"
    )


def test_registry_has_all_nine_design_brief_domains():
    assert set(DOMAIN_REGISTRY) == {
        "infra-network",
        "infra-cloud",
        "api-surface",
        "firmware-hardware",
        "code-firstparty",
        "supply-chain",
        "identity-access",
        "endpoint-posture",
        "data-exposure",
    }


def test_supply_chain_decomposes_to_every_repo():
    specs = build_domain_specs(_scope_model(), domains=["supply-chain"])

    assert set(specs[0].targets) == {"repo:stibo/checkout", "repo:stibo/mdm-core", "repo:stibo/cms-edge"}


def test_infra_network_decomposes_to_subnets_and_firewall_platforms():
    specs = build_domain_specs(_scope_model(), domains=["infra-network"])

    assert set(specs[0].targets) == {"cidr:10.20.0.0/24", "endpoint:https://fw-mgmt.example-stibo.internal"}


def test_api_surface_decomposes_to_service_endpoints_only():
    specs = build_domain_specs(_scope_model(), domains=["api-surface"])

    # cms-edge is type "service" and has an endpoint: target; corp-idp's
    # endpoint is type "identity" and belongs to identity-access instead.
    assert specs[0].targets == ["endpoint:https://cms-edge.example-stibodx.com"]


def test_identity_access_decomposes_to_identity_endpoints_only():
    specs = build_domain_specs(_scope_model(), domains=["identity-access"])

    assert specs[0].targets == ["endpoint:https://login.example-stibo.com"]


def test_firmware_hardware_decomposes_to_firmware_assets():
    specs = build_domain_specs(_scope_model(), domains=["firmware-hardware"])

    assert specs[0].targets == ["host:idrac-mdm-01.example-stibo.internal"]


def test_data_exposure_decomposes_to_data_store_assets():
    specs = build_domain_specs(_scope_model(), domains=["data-exposure"])

    assert specs[0].targets == ["host:analytics-lake-01.example-stibo.internal"]


def test_infra_cloud_decomposes_to_cloud_resource_assets():
    specs = build_domain_specs(_scope_model(), domains=["infra-cloud"])

    assert specs[0].targets == ["endpoint:https://public-bucket.example-stibo-storage.com"]


def test_endpoint_posture_decomposes_to_service_hosts():
    specs = build_domain_specs(_scope_model(), domains=["endpoint-posture"])

    assert set(specs[0].targets) == {
        "host:checkout-prod-01.example-stibo.internal",
        "host:cms-edge-01.example-stibodx.internal",
    }


def test_code_firstparty_shares_repos_with_supply_chain_without_colliding():
    supply_chain_specs = build_domain_specs(_scope_model(), domains=["supply-chain"])
    code_firstparty_specs = build_domain_specs(_scope_model(), domains=["code-firstparty"])

    assert set(supply_chain_specs[0].targets) == set(code_firstparty_specs[0].targets)


def test_build_domain_specs_defaults_to_full_registry():
    specs = build_domain_specs(_scope_model())

    assert {s.domain for s in specs} == set(DOMAIN_REGISTRY)


def test_build_domain_specs_respects_domain_subset():
    specs = build_domain_specs(_scope_model(), domains=["supply-chain", "data-exposure"])

    assert {s.domain for s in specs} == {"supply-chain", "data-exposure"}


# -- full 9-domain sweep, end-to-end -----------------------------------------


def test_full_sweep_across_all_nine_domains(tmp_path):
    orchestrator = Orchestrator(
        "full-sweep",
        _scope_model(),
        log_dir=tmp_path / "logs",
        report_dir=tmp_path / "reports",
        domain_budgets={d: 5 for d in DOMAIN_REGISTRY},
    )
    specs = build_domain_specs(_scope_model())

    result = orchestrator.run(specs)

    assert set(result["rollups"]) == set(DOMAIN_REGISTRY)
    # 7 mock findings (infra-network:2, infra-cloud:1, code-firstparty:1,
    # identity-access:1, endpoint-posture:1, data-exposure:1) + 1 real
    # supply-chain finding + 1 real firmware-hardware finding, both from
    # the patched fixtures. api-surface is real but contributes 0: no
    # current scope target has a spec URL mapped, so it returns []
    # honestly rather than fabricating a finding to keep the count even.
    assert len(result["findings"]) == 9

    for finding in result["findings"]:
        validate_finding(finding)

    events = [json.loads(l) for l in (tmp_path / "logs" / "full-sweep.ndjson").read_text().strip().splitlines()]
    for event in events:
        validate_event(event)
    # every domain's rollup event actually fired: one distinct agent_id
    # per domain agent posted a "rollup" event.
    rollup_agent_ids = {e["agent_id"] for e in events if e["event_type"] == "rollup"}
    assert len(rollup_agent_ids) == 9

    assert (tmp_path / "reports" / "full-sweep" / "findings.json").exists()
    assert (tmp_path / "reports" / "full-sweep" / "posture.md").exists()


def test_full_sweep_has_no_unexpected_coverage_gaps(tmp_path):
    """Every target in the real scope/assets.yaml resolves cleanly for
    the domain that claims it via the registry -- no accidental
    scope/exclusion mismatch introduced when the example inventory grew
    for this step."""
    orchestrator = Orchestrator(
        "full-sweep-2",
        _scope_model(),
        log_dir=tmp_path / "logs",
        report_dir=tmp_path / "reports",
        domain_budgets={d: 5 for d in DOMAIN_REGISTRY},
    )
    specs = build_domain_specs(_scope_model())

    result = orchestrator.run(specs)

    all_gaps = {domain: rollup.targets_failed for domain, rollup in result["rollups"].items() if rollup.targets_failed}
    assert all_gaps == {}
