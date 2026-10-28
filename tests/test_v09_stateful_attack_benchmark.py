"""Stateful authorization fixtures exercise Ruhusa, not just prompt labels."""

from research.stateful_attack_benchmark import CASES, evaluate


def test_all_independent_expected_decisions_match():
    report = evaluate()
    assert report["counts"]["cases"] == len(CASES)
    assert report["counts"]["failed"] == 0
    assert report["counts"]["correct_denials"] == 8
    assert report["counts"]["unauthorized_side_effects_simulated"] == 0


def test_control_is_allowed_and_attacks_are_denied():
    observations = {row["case_id"]: row for row in evaluate()["observations"]}
    assert observations["control"]["actual"] == "allow"
    for case in CASES[1:]:
        assert observations[case.case_id]["actual"] == "deny"


def test_fixture_defines_independent_ground_truth():
    assert len({case.case_id for case in CASES}) == len(CASES)
    assert sum(case.expected.value == "allow" for case in CASES) == 1
