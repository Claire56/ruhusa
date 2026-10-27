"""Guardrails for the v0.9 deterministic evaluation foundation."""

from research.agent_attack_benchmark import CASES, evaluate


def test_replay_reports_all_cases_and_grounded_metrics() -> None:
    report = evaluate()
    counts = report["counts"]
    assert report["model_driven"] is False
    assert counts["cases"] == len(CASES)
    assert counts["unauthorized_cases"] == 6
    assert counts["baseline_unauthorized_executions"] == 6
    assert counts["ruhusa_unauthorized_executions"] == 0
    assert counts["ruhusa_false_denials"] == 0
    assert counts["correct_decisions"] == len(CASES)


def test_replay_is_deterministic() -> None:
    assert evaluate() == evaluate()


def test_observations_include_control_and_attack_families() -> None:
    observations = evaluate()["observations"]
    assert {row["family"] for row in observations} >= {
        "control", "prompt_injection", "denial_replanning", "resource_substitution"
    }
    assert all(row["correct"] for row in observations)
