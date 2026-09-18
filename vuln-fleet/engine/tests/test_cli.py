import os
import re

import pytest

from adapters import cve_intel, osv
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
