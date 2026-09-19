from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml

from engine.scope import ScopeConfigError, ScopeModel, ScopeViolation

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "scope"


def _model(now: str = "2026-09-15T00:00:00Z") -> ScopeModel:
    dt = datetime.fromisoformat(now.replace("Z", "+00:00"))
    return ScopeModel(
        FIXTURE_DIR / "assets.yaml",
        FIXTURE_DIR / "exclusions.yaml",
        FIXTURE_DIR / "authorized-active.yaml",
        now_fn=lambda: dt,
    )


def test_repo_target_resolves_to_its_asset():
    model = _model()

    resolution = model.resolve("repo:stibo/checkout")

    assert resolution.asset_id == "svc-checkout"
    assert resolution.entity == "Stibo Systems"
    assert resolution.asset_type == "service"
    assert resolution.criticality == "high"
    assert resolution.scope_ref == "assets.yaml#svc-checkout"


def test_unknown_target_raises_scope_violation():
    model = _model()

    with pytest.raises(ScopeViolation):
        model.resolve("repo:someone-else/unrelated")


def test_ip_target_matches_cidr_pattern():
    model = _model()

    resolution = model.resolve("ip:10.20.0.5")

    assert resolution.asset_id == "mdm-core"


def test_ip_target_outside_cidr_is_out_of_scope():
    model = _model()

    with pytest.raises(ScopeViolation):
        model.resolve("ip:10.21.0.5")


def test_exclusion_wins_even_if_target_would_otherwise_resolve():
    model = _model()

    with pytest.raises(ScopeViolation, match="excluded"):
        model.assert_in_scope("host:tenant7.customerprod.example.com")


def test_assert_in_scope_passes_for_in_scope_non_excluded_target():
    model = _model()

    resolution = model.assert_in_scope("repo:stibo/checkout")

    assert resolution.asset_id == "svc-checkout"


def test_active_authorization_within_window_succeeds():
    model = _model(now="2026-09-15T00:00:00Z")

    auth = model.check_active_authorization("ip:10.20.0.5", "port_scan")

    assert auth.authorization_ref == "mdm-core-nsg-sweep-2026-09"


def test_active_authorization_before_window_fails():
    model = _model(now="2026-08-31T23:59:59Z")

    with pytest.raises(ScopeViolation, match="no in-window"):
        model.check_active_authorization("ip:10.20.0.5", "port_scan")


def test_active_authorization_after_window_fails():
    model = _model(now="2026-10-01T00:00:00Z")

    with pytest.raises(ScopeViolation, match="no in-window"):
        model.check_active_authorization("ip:10.20.0.5", "port_scan")


def test_active_authorization_wrong_action_fails():
    model = _model()

    with pytest.raises(ScopeViolation, match="no in-window"):
        model.check_active_authorization("ip:10.20.0.5", "dast")


def test_active_authorization_requires_in_scope_target_first():
    model = _model()

    with pytest.raises(ScopeViolation, match="does not resolve"):
        model.check_active_authorization("ip:192.0.2.1", "port_scan")


def test_active_authorization_excluded_target_fails_as_excluded_not_missing_auth():
    model = _model()

    with pytest.raises(ScopeViolation, match="excluded"):
        model.check_active_authorization("host:tenant7.customerprod.example.com", "port_scan")


@pytest.mark.parametrize(
    "mutate,error_match",
    [
        (lambda doc: doc["assets"][0].pop("criticality"), "missing field"),
        (lambda doc: doc["assets"][0].__setitem__("criticality", "apocalyptic"), "invalid criticality"),
        (lambda doc: doc["assets"][0].__setitem__("entity", "no-such-entity"), "unknown entity"),
    ],
)
def test_malformed_assets_yaml_rejected(tmp_path, mutate, error_match):
    doc = yaml.safe_load((FIXTURE_DIR / "assets.yaml").read_text())
    mutate(doc)
    bad_assets = tmp_path / "assets.yaml"
    bad_assets.write_text(yaml.safe_dump(doc))

    with pytest.raises(ScopeConfigError, match=error_match):
        ScopeModel(bad_assets, FIXTURE_DIR / "exclusions.yaml", FIXTURE_DIR / "authorized-active.yaml")


def test_malformed_exclusions_yaml_rejected(tmp_path):
    bad_exclusions = tmp_path / "exclusions.yaml"
    bad_exclusions.write_text(yaml.safe_dump({"exclusions": [{"pattern": "host:*"}]}))  # missing reason

    with pytest.raises(ScopeConfigError, match="missing pattern/reason"):
        ScopeModel(FIXTURE_DIR / "assets.yaml", bad_exclusions, FIXTURE_DIR / "authorized-active.yaml")


def test_malformed_authorization_yaml_rejected(tmp_path):
    bad_auth = tmp_path / "authorized-active.yaml"
    bad_auth.write_text(yaml.safe_dump({"authorizations": [{"authorization_ref": "x"}]}))  # missing fields

    with pytest.raises(ScopeConfigError, match="missing field"):
        ScopeModel(FIXTURE_DIR / "assets.yaml", FIXTURE_DIR / "exclusions.yaml", bad_auth)


def test_non_mapping_yaml_top_level_rejected(tmp_path):
    bad_assets = tmp_path / "assets.yaml"
    bad_assets.write_text("- just\n- a\n- list\n")

    with pytest.raises(ScopeConfigError, match="expected a YAML mapping"):
        ScopeModel(bad_assets, FIXTURE_DIR / "exclusions.yaml", FIXTURE_DIR / "authorized-active.yaml")


def test_targets_filters_by_scheme_only():
    model = _model()

    assert set(model.targets(scheme="repo")) == {"repo:stibo/checkout", "repo:stibo/mdm-core"}


def test_targets_filters_by_asset_type_only():
    model = _model()

    # both fixture assets are type "service", so both contribute their targets
    assert set(model.targets(asset_type="service")) == {
        "repo:stibo/checkout",
        "repo:stibo/mdm-core",
        "cidr:10.20.0.0/24",
    }


def test_targets_combined_scheme_and_asset_type():
    model = _model()

    assert model.targets(scheme="cidr", asset_type="service") == ["cidr:10.20.0.0/24"]


def test_targets_no_filters_returns_everything():
    model = _model()

    assert set(model.targets()) == {"repo:stibo/checkout", "repo:stibo/mdm-core", "cidr:10.20.0.0/24"}


def test_targets_no_match_returns_empty_list():
    model = _model()

    assert model.targets(asset_type="no-such-type") == []
    assert model.targets(scheme="ip") == []


def test_targets_does_not_consult_exclusions(tmp_path):
    """targets() is a planning aid, not a scope decision: an excluded
    target still comes back from it. assert_in_scope is what refuses it,
    later, when a worker actually tries to touch it — exclusion handling
    lives in exactly one place, not duplicated into every domain's plan."""
    excluding = tmp_path / "exclusions.yaml"
    excluding.write_text(
        yaml.safe_dump({"exclusions": [{"pattern": "repo:stibo/checkout", "reason": "test exclusion"}]})
    )
    model = ScopeModel(FIXTURE_DIR / "assets.yaml", excluding, FIXTURE_DIR / "authorized-active.yaml")

    assert "repo:stibo/checkout" in model.targets(scheme="repo")
    with pytest.raises(ScopeViolation, match="excluded"):
        model.assert_in_scope("repo:stibo/checkout")


def test_real_scope_files_load_without_error():
    """The actual scope/*.yaml shipped in the repo must parse and validate."""
    repo_scope_dir = Path(__file__).parent.parent.parent / "scope"

    model = ScopeModel(
        repo_scope_dir / "assets.yaml",
        repo_scope_dir / "exclusions.yaml",
        repo_scope_dir / "authorized-active.yaml",
    )

    assert model.assets
    assert model.resolve("repo:stibo/checkout").asset_id == "svc-checkout"


def test_real_red_team_scope_files_load_and_merge_without_error():
    """scope/red-team-targets.yaml and scope/red-team-active-
    authorizations.yaml -- the two files engine.cli's red-team-recon
    subcommand merges alongside assets.yaml/authorized-active.yaml -- must
    also parse cleanly even while still empty (their steady state until
    someone actually runs red-team-recon)."""
    repo_scope_dir = Path(__file__).parent.parent.parent / "scope"

    model = ScopeModel(
        [repo_scope_dir / "assets.yaml", repo_scope_dir / "red-team-targets.yaml"],
        repo_scope_dir / "exclusions.yaml",
        [repo_scope_dir / "authorized-active.yaml", repo_scope_dir / "red-team-active-authorizations.yaml"],
    )

    assert model.resolve("repo:stibo/checkout").asset_id == "svc-checkout"
    assert "red-team-engagement" in model.entities


# -- multi-file assets/authorizations merging -----------------------------


def test_scope_ref_names_the_actual_source_file_in_a_multi_file_model(tmp_path):
    """A regression guard: resolve() used to hardcode scope_ref to
    "assets.yaml#<id>" for every asset regardless of which file it
    actually came from -- misattributing every red-team-targets.yaml
    asset's scope_ref to a file it was never in."""
    extra_assets = tmp_path / "extra-assets.yaml"
    extra_assets.write_text(
        yaml.safe_dump(
            {
                "entities": [{"id": "external", "name": "External Target"}],
                "assets": [
                    {
                        "asset_id": "extra-domain",
                        "entity": "external",
                        "type": "external_domain",
                        "owner_team": "someone@example.com",
                        "criticality": "medium",
                        "targets": ["domain:extra.example.com"],
                    }
                ],
            }
        )
    )
    model = ScopeModel(
        [FIXTURE_DIR / "assets.yaml", extra_assets], FIXTURE_DIR / "exclusions.yaml", FIXTURE_DIR / "authorized-active.yaml"
    )

    assert model.resolve("repo:stibo/checkout").scope_ref == "assets.yaml#svc-checkout"
    assert model.resolve("domain:extra.example.com").scope_ref == "extra-assets.yaml#extra-domain"


def test_assets_path_accepts_a_list_and_merges_entities_and_assets(tmp_path):
    extra_assets = tmp_path / "extra-assets.yaml"
    extra_assets.write_text(
        yaml.safe_dump(
            {
                "entities": [{"id": "external", "name": "External Target"}],
                "assets": [
                    {
                        "asset_id": "extra-domain",
                        "entity": "external",
                        "type": "external_domain",
                        "owner_team": "someone@example.com",
                        "criticality": "medium",
                        "targets": ["domain:extra.example.com"],
                    }
                ],
            }
        )
    )
    model = ScopeModel(
        [FIXTURE_DIR / "assets.yaml", extra_assets], FIXTURE_DIR / "exclusions.yaml", FIXTURE_DIR / "authorized-active.yaml"
    )

    assert model.resolve("repo:stibo/checkout").asset_id == "svc-checkout"
    resolution = model.resolve("domain:extra.example.com")
    assert resolution.asset_id == "extra-domain"
    assert resolution.entity == "External Target"


def test_authorized_active_path_accepts_a_list_and_merges_authorizations(tmp_path):
    extra_auth = tmp_path / "extra-auth.yaml"
    extra_auth.write_text(
        yaml.safe_dump(
            {
                "authorizations": [
                    {
                        "authorization_ref": "extra-auth-ref",
                        "scope": ["ip:10.20.0.5"],
                        "actions": ["dast"],
                        "approved_by": "someone@example.com",
                        "valid_from": "2026-09-01T00:00:00Z",
                        "valid_until": "2026-09-30T23:59:59Z",
                    }
                ]
            }
        )
    )
    model = _model_with_authorized_active_paths([FIXTURE_DIR / "authorized-active.yaml", extra_auth])

    auth = model.check_active_authorization("ip:10.20.0.5", "dast")
    assert auth.authorization_ref == "extra-auth-ref"


def _model_with_authorized_active_paths(authorized_active_paths):
    dt = datetime.fromisoformat("2026-09-15T00:00:00+00:00")
    return ScopeModel(
        FIXTURE_DIR / "assets.yaml",
        FIXTURE_DIR / "exclusions.yaml",
        authorized_active_paths,
        now_fn=lambda: dt,
    )
