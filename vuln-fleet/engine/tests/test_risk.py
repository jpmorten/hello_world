import pytest

from engine import risk


def _finding(cvss=5.0, epss=0.1, kev=False, criticality="medium") -> dict:
    return {
        "cvss_v4": {"base": cvss},
        "epss": epss,
        "kev_listed": kev,
        "asset": {"criticality": criticality},
    }


def test_score_finding_is_bounded_0_to_100():
    assert 0.0 <= risk.score_finding(_finding(cvss=0.0, epss=0.0, criticality="low")) <= 100.0
    assert 0.0 <= risk.score_finding(_finding(cvss=10.0, epss=1.0, kev=True, criticality="critical")) <= 100.0


def test_higher_cvss_scores_higher_all_else_equal():
    low = risk.score_finding(_finding(cvss=2.0))
    high = risk.score_finding(_finding(cvss=9.0))

    assert high > low


def test_higher_epss_scores_higher_all_else_equal():
    low = risk.score_finding(_finding(epss=0.01))
    high = risk.score_finding(_finding(epss=0.9))

    assert high > low


def test_higher_asset_criticality_scores_higher_all_else_equal():
    low = risk.score_finding(_finding(criticality="low"))
    high = risk.score_finding(_finding(criticality="critical"))

    assert high > low


def test_kev_listed_forces_likelihood_to_max_regardless_of_epss():
    kev_with_low_epss = risk.score_finding(_finding(epss=0.001, kev=True))
    non_kev_with_low_epss = risk.score_finding(_finding(epss=0.001, kev=False))

    assert kev_with_low_epss > non_kev_with_low_epss


def test_kev_boost_breaks_ties_between_equal_likelihood_findings():
    # both have likelihood forced/near 1.0, so the additive blend alone
    # would tie them; the KEV boost must still separate them.
    kev = risk.score_finding(_finding(epss=1.0, kev=True))
    non_kev_same_epss = risk.score_finding(_finding(epss=1.0, kev=False))

    assert kev > non_kev_same_epss


def test_severe_but_unexploited_finding_does_not_collapse_to_near_zero():
    """A CVSS 9.8 with near-zero EPSS should stay meaningfully visible in
    a ranking, not vanish the way a pure CVSS*EPSS product would."""
    score = risk.score_finding(_finding(cvss=9.8, epss=0.001, criticality="high"))

    assert score > 40.0  # severity alone contributes ~49 points of the blend


def test_unknown_criticality_falls_back_to_default_weight():
    score = risk.score_finding(_finding(criticality="not-a-real-level"))

    assert score == risk.score_finding(_finding(criticality="medium"))


def test_score_issue_matches_score_finding_for_single_exposure():
    finding = _finding(cvss=7.0, epss=0.3)

    assert risk.score_issue([finding]) == risk.score_finding(finding)


def test_score_issue_increases_with_more_exposures():
    findings = [_finding(cvss=7.0, epss=0.3) for _ in range(5)]

    single = risk.score_issue(findings[:1])
    five = risk.score_issue(findings)

    assert five > single


def test_score_issue_exposure_boost_is_capped():
    many_findings = [_finding(cvss=10.0, epss=1.0, kev=True, criticality="critical") for _ in range(50)]

    assert risk.score_issue(many_findings) <= 100.0


def test_score_issue_empty_list_is_zero():
    assert risk.score_issue([]) == 0.0


def test_score_issue_uses_worst_exposure_not_average():
    findings = [_finding(cvss=1.0, epss=0.0, criticality="low"), _finding(cvss=10.0, epss=1.0, kev=True, criticality="critical")]

    # with 2 exposures, boost is 1.05x; worst single score should dominate
    worst_alone = risk.score_finding(findings[1])
    issue_score = risk.score_issue(findings)

    assert issue_score >= worst_alone
