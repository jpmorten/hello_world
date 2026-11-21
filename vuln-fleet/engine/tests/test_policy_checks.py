from datetime import datetime, timezone
from pathlib import Path

from engine import policy_checks

REPO_ROOT = Path(__file__).parent.parent.parent


# -- real repo state --------------------------------------------------------


def test_real_repo_has_no_tool_boundary_violations():
    """Regression guard: every shipped .claude/agents/*.md must stay
    Write/Edit-free. This is the fleet's own structural non-action
    guarantee -- if this ever fails, something granted an agent a tool
    it was never supposed to have."""
    findings = policy_checks.check_tool_boundaries(REPO_ROOT / ".claude" / "agents")

    assert findings == []


def test_real_finding_schema_still_requires_transparency_fields():
    findings = policy_checks.check_finding_schema_discipline(REPO_ROOT / "schema" / "finding.schema.json")

    assert findings == []


def test_real_finding_schema_still_requires_remediation_guidance():
    findings = policy_checks.check_remediation_guidance_required(REPO_ROOT / "schema" / "finding.schema.json")

    assert findings == []


def test_real_mock_analyst_still_self_discloses():
    findings = policy_checks.check_mock_disclosure(REPO_ROOT / "analysts" / "mock")

    assert findings == []


def test_real_scope_dir_has_no_hardcoded_secrets():
    findings = policy_checks.check_no_hardcoded_secrets(REPO_ROOT / "scope")

    assert findings == []


def test_run_policy_checks_against_real_repo_returns_a_list():
    now = datetime.now(timezone.utc)

    findings = policy_checks.run_policy_checks(REPO_ROOT, now)

    assert isinstance(findings, list)
    for f in findings:
        assert f.severity in {"info", "warning", "critical"}
        assert f.regulation in policy_checks.REGULATIONS_CHECKED


# -- synthetic violations ---------------------------------------------------


def test_check_tool_boundaries_flags_write_grant(tmp_path):
    agents_dir = tmp_path / "agents"
    agents_dir.mkdir()
    (agents_dir / "bad-agent.md").write_text(
        "---\nname: bad-agent\ntools: Read, Grep, Glob, Write\nmodel: sonnet\n---\n\nBody.\n"
    )

    findings = policy_checks.check_tool_boundaries(agents_dir)

    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert findings[0].regulation == "EU_AI_Act"
    assert "Write" in findings[0].description


def test_check_tool_boundaries_ignores_clean_agent(tmp_path):
    agents_dir = tmp_path / "agents"
    agents_dir.mkdir()
    (agents_dir / "good-agent.md").write_text(
        "---\nname: good-agent\ntools: Read, Grep, Glob, Bash\nmodel: sonnet\n---\n\nBody.\n"
    )

    assert policy_checks.check_tool_boundaries(agents_dir) == []


def test_check_tool_boundaries_handles_missing_dir(tmp_path):
    assert policy_checks.check_tool_boundaries(tmp_path / "does-not-exist") == []


def test_check_finding_schema_discipline_flags_missing_required_field(tmp_path):
    schema_path = tmp_path / "finding.schema.json"
    schema_path.write_text('{"required": ["confidence", "regulatory_tags"]}')

    findings = policy_checks.check_finding_schema_discipline(schema_path)

    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert "false_positive_likelihood" in findings[0].description
    assert "evidence_ref" in findings[0].description


def test_check_remediation_guidance_required_flags_missing_field(tmp_path):
    schema_path = tmp_path / "finding.schema.json"
    schema_path.write_text('{"required": ["confidence"]}')

    findings = policy_checks.check_remediation_guidance_required(schema_path)

    assert len(findings) == 1
    assert findings[0].regulation == "CRA"


def test_check_mock_disclosure_flags_undisclosed_synthetic_output(tmp_path):
    mock_dir = tmp_path / "mock"
    mock_dir.mkdir()
    (mock_dir / "attack_scenario.py").write_text("def synthesize():\n    return []\n")

    findings = policy_checks.check_mock_disclosure(mock_dir)

    assert len(findings) == 1
    assert findings[0].regulation == "EU_AI_Act"


def test_check_mock_disclosure_ignores_init(tmp_path):
    mock_dir = tmp_path / "mock"
    mock_dir.mkdir()
    (mock_dir / "__init__.py").write_text("")

    assert policy_checks.check_mock_disclosure(mock_dir) == []


def test_check_authorization_hygiene_flags_long_expired_record(tmp_path):
    scope_dir = tmp_path / "scope"
    scope_dir.mkdir()
    (scope_dir / "authorized-active.yaml").write_text(
        "authorizations:\n"
        "- authorization_ref: old-one\n"
        "  scope: [ip:10.0.0.1]\n"
        "  actions: [port_scan]\n"
        "  approved_by: someone@example.com\n"
        "  valid_from: '2025-01-01T00:00:00Z'\n"
        "  valid_until: '2025-01-02T00:00:00Z'\n"
    )
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)

    findings = policy_checks.check_authorization_hygiene(scope_dir, now)

    assert len(findings) == 1
    assert findings[0].severity == "info"
    assert findings[0].regulation == "NIS2"
    assert "old-one" in findings[0].description


def test_check_authorization_hygiene_ignores_recently_expired(tmp_path):
    scope_dir = tmp_path / "scope"
    scope_dir.mkdir()
    (scope_dir / "authorized-active.yaml").write_text(
        "authorizations:\n"
        "- authorization_ref: recent\n"
        "  scope: [ip:10.0.0.1]\n"
        "  actions: [port_scan]\n"
        "  approved_by: someone@example.com\n"
        "  valid_from: '2025-12-30T00:00:00Z'\n"
        "  valid_until: '2025-12-31T00:00:00Z'\n"
    )
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)

    assert policy_checks.check_authorization_hygiene(scope_dir, now) == []


def test_check_no_hardcoded_secrets_flags_aws_key_pattern(tmp_path):
    scope_dir = tmp_path / "scope"
    scope_dir.mkdir()
    (scope_dir / "assets.yaml").write_text("note: AKIAABCDEFGHIJKLMNOP\n")

    findings = policy_checks.check_no_hardcoded_secrets(scope_dir)

    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert findings[0].regulation == "GDPR"


def test_check_no_hardcoded_secrets_clean_dir(tmp_path):
    scope_dir = tmp_path / "scope"
    scope_dir.mkdir()
    (scope_dir / "assets.yaml").write_text("assets: []\n")

    assert policy_checks.check_no_hardcoded_secrets(scope_dir) == []
