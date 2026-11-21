import pytest

from engine.token_budget import TokenBudget, TokenBudgetConfigError, load_ledger, record_usage, status


def _write_budget(path, budget_tokens=1000, alert_threshold_pct=20):
    path.write_text(f"budget_tokens: {budget_tokens}\nalert_threshold_pct: {alert_threshold_pct}\n")


def test_load_reads_real_yaml(tmp_path):
    path = tmp_path / "token-budget.yaml"
    _write_budget(path, budget_tokens=5000, alert_threshold_pct=15)

    budget = TokenBudget.load(path)

    assert budget.budget_tokens == 5000
    assert budget.alert_threshold_pct == 15.0


def test_load_missing_file_raises(tmp_path):
    with pytest.raises(TokenBudgetConfigError, match="not found"):
        TokenBudget.load(tmp_path / "nope.yaml")


@pytest.mark.parametrize(
    "doc,match",
    [
        ("alert_threshold_pct: 20\n", "missing"),
        ("budget_tokens: 1000\n", "missing"),
        ("budget_tokens: -5\nalert_threshold_pct: 20\n", "positive integer"),
        ("budget_tokens: 1000\nalert_threshold_pct: 0\n", "alert_threshold_pct"),
        ("budget_tokens: 1000\nalert_threshold_pct: 150\n", "alert_threshold_pct"),
        ("budget_tokens: true\nalert_threshold_pct: 20\n", "positive integer"),
    ],
)
def test_load_rejects_malformed_config(tmp_path, doc, match):
    path = tmp_path / "token-budget.yaml"
    path.write_text(doc)

    with pytest.raises(TokenBudgetConfigError, match=match):
        TokenBudget.load(path)


def test_load_ledger_missing_file_returns_empty(tmp_path):
    assert load_ledger(tmp_path / "nope.yaml") == []


def test_record_usage_appends_and_returns_full_ledger(tmp_path):
    ledger_path = tmp_path / "ledger.yaml"

    first = record_usage("run-1", 100, "2026-01-01T00:00:00Z", ledger_path)
    second = record_usage("run-2", 200, "2026-01-02T00:00:00Z", ledger_path)

    assert first == [{"run_id": "run-1", "tokens": 100, "recorded_at": "2026-01-01T00:00:00Z"}]
    assert second == [
        {"run_id": "run-1", "tokens": 100, "recorded_at": "2026-01-01T00:00:00Z"},
        {"run_id": "run-2", "tokens": 200, "recorded_at": "2026-01-02T00:00:00Z"},
    ]
    assert load_ledger(ledger_path) == second


def test_record_usage_rejects_negative_tokens(tmp_path):
    with pytest.raises(ValueError):
        record_usage("run-1", -1, "2026-01-01T00:00:00Z", tmp_path / "ledger.yaml")


def test_record_usage_never_overwrites_a_prior_entry_for_the_same_run(tmp_path):
    ledger_path = tmp_path / "ledger.yaml"
    record_usage("run-1", 100, "2026-01-01T00:00:00Z", ledger_path)
    record_usage("run-1", 50, "2026-01-01T01:00:00Z", ledger_path)

    entries = load_ledger(ledger_path)

    assert len(entries) == 2
    assert sum(e["tokens"] for e in entries) == 150


# -- status ---------------------------------------------------------------


def test_status_never_measured_when_ledger_empty():
    budget = TokenBudget(budget_tokens=1000, alert_threshold_pct=20)

    result = status(budget, [])

    assert result["measured"] is False
    assert result["spent_tokens"] == 0
    assert result["remaining_tokens"] == 1000
    assert result["remaining_pct"] == 100.0
    assert result["alert"] is False


def test_status_measured_true_even_for_a_real_zero_spend_entry():
    budget = TokenBudget(budget_tokens=1000, alert_threshold_pct=20)

    result = status(budget, [{"run_id": "run-1", "tokens": 0, "recorded_at": "x"}])

    assert result["measured"] is True
    assert result["spent_tokens"] == 0


def test_status_computes_remaining_pct_and_no_alert_above_threshold():
    budget = TokenBudget(budget_tokens=1000, alert_threshold_pct=20)

    result = status(budget, [{"run_id": "run-1", "tokens": 700, "recorded_at": "x"}])

    assert result["spent_tokens"] == 700
    assert result["remaining_tokens"] == 300
    assert result["remaining_pct"] == 30.0
    assert result["alert"] is False


def test_status_alert_true_once_remaining_pct_below_threshold():
    budget = TokenBudget(budget_tokens=1000, alert_threshold_pct=20)

    result = status(budget, [{"run_id": "run-1", "tokens": 850, "recorded_at": "x"}])

    assert result["remaining_pct"] == 15.0
    assert result["alert"] is True


def test_status_spend_exceeding_budget_floors_remaining_at_zero():
    budget = TokenBudget(budget_tokens=1000, alert_threshold_pct=20)

    result = status(budget, [{"run_id": "run-1", "tokens": 1500, "recorded_at": "x"}])

    assert result["remaining_tokens"] == 0
    assert result["remaining_pct"] == 0.0
    assert result["alert"] is True
