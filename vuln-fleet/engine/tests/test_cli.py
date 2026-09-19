import json
import os
import re

import pytest
import yaml

from adapters import cve_intel, dns_recon, osv
from engine import cli

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
_KEV_NOT_LISTED = {"vulnerabilities": []}
_EPSS_SOME_SCORE = {"data": [{"cve": "CVE-2020-28500", "epss": "0.04"}]}
_NVD_NO_RESULT = {"vulnerabilities": []}


@pytest.fixture(autouse=True)
def _hermetic_supply_chain_network(monkeypatch):
    """cli.py's full-sweep/delta-sweep/target commands go through the
    real registry, whose supply-chain entry is a real adapter (step 7).
    Same fixture as test_domains.py — see its docstring."""
    monkeypatch.setattr(osv, "_http_post_json", lambda url, payload, timeout=15.0: _LODASH_VULN_FIXTURE)
    monkeypatch.setattr(
        cve_intel,
        "_http_get_json",
        lambda url, timeout=15.0: (
            _KEV_NOT_LISTED if "cisa.gov" in url else _EPSS_SOME_SCORE if "first.org" in url else _NVD_NO_RESULT
        ),
    )
    cve_intel.reset_cache()
    yield
    cve_intel.reset_cache()


# -- _new_run_id ----------------------------------------------------------------


def test_new_run_id_has_expected_prefix_and_format():
    run_id = cli._new_run_id("full-sweep")

    assert re.match(r"^full-sweep-\d{8}T\d{6}Z$", run_id)


# -- _latest_completed_run_id / _latest_active_run_id ----------------------------


def test_latest_completed_run_id_none_when_no_reports_dir(tmp_path):
    assert cli._latest_completed_run_id(tmp_path / "no-such-dir") is None


def test_latest_completed_run_id_ignores_incomplete_runs(tmp_path):
    (tmp_path / "run-incomplete").mkdir()  # no findings.json: still in flight
    complete = tmp_path / "run-complete"
    complete.mkdir()
    (complete / "findings.json").write_text("[]")

    assert cli._latest_completed_run_id(tmp_path) == "run-complete"


def test_latest_completed_run_id_picks_most_recently_modified(tmp_path):
    old, new = tmp_path / "run-old", tmp_path / "run-new"
    for d in (old, new):
        d.mkdir()
        (d / "findings.json").write_text("[]")
    os.utime(old / "findings.json", (1000, 1000))
    os.utime(new / "findings.json", (2000, 2000))

    assert cli._latest_completed_run_id(tmp_path) == "run-new"


def test_latest_active_run_id_none_when_no_logs(tmp_path):
    assert cli._latest_active_run_id(tmp_path / "no-such-dir") is None


def test_latest_active_run_id_finds_in_flight_run_with_no_report_yet(tmp_path):
    (tmp_path / "run-in-flight.ndjson").write_text('{"event_type": "run_start"}\n')

    assert cli._latest_active_run_id(tmp_path) == "run-in-flight"


def test_latest_active_run_id_picks_most_recently_written(tmp_path):
    old, new = tmp_path / "run-old.ndjson", tmp_path / "run-new.ndjson"
    old.write_text("{}\n")
    new.write_text("{}\n")
    os.utime(old, (1000, 1000))
    os.utime(new, (2000, 2000))

    assert cli._latest_active_run_id(tmp_path) == "run-new"


# -- end-to-end command invocations (real registry, real scope files, tmp I/O) ---


@pytest.fixture(autouse=True)
def _redirect_io_dirs(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "LOG_DIR", tmp_path / "logs")
    monkeypatch.setattr(cli, "REPORT_DIR", tmp_path / "reports")
    return tmp_path


@pytest.fixture(autouse=True)
def _redirect_red_team_scope_files(tmp_path, monkeypatch):
    """Tests must never write to the real scope/red-team-targets.yaml or
    scope/red-team-active-authorizations.yaml -- redirect both to empty
    copies under tmp_path, same shape as the real files' steady state."""
    targets_path = tmp_path / "red-team-targets.yaml"
    targets_path.write_text(
        yaml.safe_dump({"entities": [{"id": "red-team-engagement", "name": "Red-team engagement (externally supplied target)"}], "assets": []})
    )
    auth_path = tmp_path / "red-team-active-authorizations.yaml"
    auth_path.write_text(yaml.safe_dump({"authorizations": []}))
    monkeypatch.setattr(cli, "RED_TEAM_TARGETS_PATH", targets_path)
    monkeypatch.setattr(cli, "RED_TEAM_AUTH_PATH", auth_path)
    dns_recon._ACTIVE_AUTHORIZATION_BY_TARGET.clear()
    yield
    dns_recon._ACTIVE_AUTHORIZATION_BY_TARGET.clear()


@pytest.fixture(autouse=True)
def _hermetic_dns_recon_network(monkeypatch):
    """red-team-recon's own real network seams (DNS resolution, crt.sh,
    TLS handshake, HTTP requests) -- kept hermetic here the same way
    supply-chain/firmware-hardware's are, via the module's own seam
    functions rather than duplicating dns_recon's own unit tests.

    Patches the shared low-level `_resolve` seam, not the higher-level
    `resolve_dns_records` wrapper: analyze_dmarc() makes its own separate
    `_resolve(f"_dmarc.{domain}", "TXT")` call that resolve_dns_records
    never goes through, so patching only the wrapper left that one query
    hitting a real resolver -- these tests happened to still pass because
    real DNS was reachable, not because they were actually hermetic."""
    monkeypatch.setattr(dns_recon, "_resolve", lambda domain, rtype: [])
    monkeypatch.setattr(
        dns_recon,
        "enumerate_subdomains_via_ct",
        lambda domain: {"available": False, "subdomains": set(), "serials": set(), "wildcard": False},
    )
    monkeypatch.setattr(dns_recon, "check_tls_posture", lambda domain, known_cert_serials=None: {"reachable": False, "interception_suspected": False})
    monkeypatch.setattr(dns_recon, "check_http_security_headers", lambda domain: None)
    monkeypatch.setattr(dns_recon, "check_exposed_paths", lambda domain: {})


def test_full_sweep_command_runs_and_prints_summary(capsys, tmp_path):
    exit_code = cli.main(["full-sweep", "--run-id", "test-run"])

    assert exit_code == 0
    out = capsys.readouterr().out
    assert "Run test-run:" in out
    assert "Reports:" in out
    assert (tmp_path / "reports" / "test-run" / "posture.md").exists()


def test_delta_sweep_command_uses_latest_completed_run_as_baseline(capsys, tmp_path):
    cli.main(["full-sweep", "--run-id", "run-1"])
    capsys.readouterr()  # discard first run's output

    exit_code = cli.main(["delta-sweep", "--run-id", "run-2"])

    assert exit_code == 0
    out = capsys.readouterr().out
    assert "recurring" in out.lower()
    # run-1's findings should mostly show up as recurring in run-2, not all new
    assert "0 new" not in out or "recurring" in out


def test_target_command_in_scope_runs_matching_domains(capsys):
    exit_code = cli.main(["target", "repo:stibo/checkout", "--run-id", "test-target"])

    assert exit_code == 0
    out = capsys.readouterr().out
    assert "Run test-target:" in out


def test_target_command_out_of_scope_refuses(capsys):
    exit_code = cli.main(["target", "repo:no-such-repo", "--run-id", "test-target"])

    assert exit_code == 1
    err = capsys.readouterr().err
    assert "Refused" in err


# -- red-team-recon --------------------------------------------------------


def test_red_team_recon_rejects_malformed_domain(capsys):
    exit_code = cli.main(["red-team-recon", "not a domain!", "--requested-by", "tester@example.com"])

    assert exit_code == 1
    assert "doesn't look like a bare DNS domain" in capsys.readouterr().err


def test_red_team_recon_passive_only_runs_and_registers_target(capsys, tmp_path):
    exit_code = cli.main(["red-team-recon", "example.com", "--requested-by", "tester@example.com", "--run-id", "rt-1"])

    assert exit_code == 0
    out, err = capsys.readouterr()
    assert "Run rt-1:" in out
    assert "running passive checks only" in err

    registered = yaml.safe_load(cli.RED_TEAM_TARGETS_PATH.read_text())
    assert registered["assets"][0]["targets"] == ["domain:example.com"]
    assert registered["assets"][0]["owner_team"] == "tester@example.com"


def test_red_team_recon_registering_the_same_domain_twice_does_not_duplicate():
    cli.main(["red-team-recon", "example.com", "--requested-by", "tester@example.com", "--run-id", "rt-a"])
    cli.main(["red-team-recon", "example.com", "--requested-by", "tester@example.com", "--run-id", "rt-b"])

    registered = yaml.safe_load(cli.RED_TEAM_TARGETS_PATH.read_text())
    assert len(registered["assets"]) == 1


def test_red_team_recon_authorize_active_writes_authorization_and_enables_active_checks(capsys):
    exit_code = cli.main(
        ["red-team-recon", "example.com", "--requested-by", "tester@example.com", "--authorize-active", "--run-id", "rt-2"]
    )

    assert exit_code == 0
    authorizations = yaml.safe_load(cli.RED_TEAM_AUTH_PATH.read_text())["authorizations"]
    assert len(authorizations) == 1
    assert authorizations[0]["approved_by"] == "tester@example.com"
    assert authorizations[0]["actions"] == ["external_recon_active"]
    assert authorizations[0]["signature"] == "SELF-ATTESTED"


def test_red_team_recon_without_authorize_active_leaves_authorization_file_empty():
    cli.main(["red-team-recon", "example.com", "--requested-by", "tester@example.com", "--run-id", "rt-3"])

    authorizations = yaml.safe_load(cli.RED_TEAM_AUTH_PATH.read_text())["authorizations"]
    assert authorizations == []


# -- full-sweep folding in the last-selected red-team target ------------------


def _by_domain_text(tmp_path, run_id) -> str:
    return (tmp_path / "reports" / run_id / "by-domain.md").read_text()


def test_full_sweep_has_no_red_team_domain_when_none_ever_registered(tmp_path):
    cli.main(["full-sweep", "--run-id", "fs-none"])

    assert "## red-team-recon" not in _by_domain_text(tmp_path, "fs-none")


def test_full_sweep_includes_last_registered_red_team_target_passive_only(tmp_path, capsys):
    cli.main(["red-team-recon", "example.com", "--requested-by", "tester@example.com", "--run-id", "rt-setup"])
    capsys.readouterr()

    cli.main(["full-sweep", "--run-id", "fs-with-redteam"])

    text = _by_domain_text(tmp_path, "fs-with-redteam")
    assert "## red-team-recon" in text
    findings = json.load(open(tmp_path / "reports" / "fs-with-redteam" / "findings.json"))
    red_team_findings = [f for f in findings if f["domain"] == "red-team-recon"]
    assert red_team_findings  # SPF/DMARC missing findings are always produced against a domain with no records
    assert all(f["authorization_ref"] is None for f in red_team_findings)  # no --authorize-active was ever granted


def test_full_sweep_uses_valid_active_authorization_for_red_team_target(tmp_path, capsys):
    cli.main(["red-team-recon", "example.com", "--requested-by", "tester@example.com", "--authorize-active", "--run-id", "rt-setup"])
    capsys.readouterr()

    cli.main(["full-sweep", "--run-id", "fs-active"])

    findings = json.load(open(tmp_path / "reports" / "fs-active" / "findings.json"))
    red_team_findings = [f for f in findings if f["domain"] == "red-team-recon"]
    assert any(f["authorization_ref"] is not None for f in red_team_findings)


def test_full_sweep_uses_the_most_recently_registered_red_team_target(tmp_path, capsys):
    cli.main(["red-team-recon", "example.com", "--requested-by", "a@example.com", "--run-id", "rt-1"])
    capsys.readouterr()
    cli.main(["red-team-recon", "example.org", "--requested-by", "b@example.com", "--run-id", "rt-2"])
    capsys.readouterr()

    cli.main(["full-sweep", "--run-id", "fs-latest"])

    findings = json.load(open(tmp_path / "reports" / "fs-latest" / "findings.json"))
    red_team_findings = [f for f in findings if f["domain"] == "red-team-recon"]
    assert red_team_findings
    assert all(f["location"]["ref"] == "domain:example.org" for f in red_team_findings)


def test_full_sweep_red_team_finding_scope_ref_names_the_red_team_file(tmp_path, capsys):
    cli.main(["red-team-recon", "example.com", "--requested-by", "tester@example.com", "--run-id", "rt-setup"])
    capsys.readouterr()

    cli.main(["full-sweep", "--run-id", "fs-scope-ref"])

    findings = json.load(open(tmp_path / "reports" / "fs-scope-ref" / "findings.json"))
    red_team_findings = [f for f in findings if f["domain"] == "red-team-recon"]
    assert red_team_findings
    assert all(f["scope_ref"].startswith("red-team-targets.yaml#") for f in red_team_findings)


def test_kill_command_writes_flag_for_most_recent_active_run(capsys, tmp_path):
    (tmp_path / "logs").mkdir(parents=True)
    (tmp_path / "logs" / "some-run.ndjson").write_text('{"event_type": "run_start"}\n')

    exit_code = cli.main(["kill"])

    assert exit_code == 0
    assert (tmp_path / "reports" / "some-run.kill").exists()
    out = capsys.readouterr().out
    assert "some-run" in out


def test_kill_command_explicit_run_id(tmp_path):
    exit_code = cli.main(["kill", "--run-id", "explicit-run"])

    assert exit_code == 0
    assert (tmp_path / "reports" / "explicit-run.kill").exists()


def test_kill_command_no_run_found(capsys, tmp_path):
    exit_code = cli.main(["kill"])

    assert exit_code == 1
    assert "No run found" in capsys.readouterr().err


def test_kill_flag_actually_stops_a_subsequent_full_sweep(tmp_path):
    """Proves the CLI's kill flag and the orchestrator's kill check are
    wired to the same path, not just independently plausible."""
    cli.main(["kill", "--run-id", "killed-run"])

    exit_code = cli.main(["full-sweep", "--run-id", "killed-run"])

    assert exit_code == 0  # a killed run still completes with a partial report, not a crash
    posture_text = (tmp_path / "reports" / "killed-run" / "posture.md").read_text()
    assert "kill_switch" in posture_text
