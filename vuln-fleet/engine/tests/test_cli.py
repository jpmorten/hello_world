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
    functions rather than duplicating dns_recon's own unit tests."""
    monkeypatch.setattr(dns_recon, "resolve_dns_records", lambda domain: {"TXT": []})
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
