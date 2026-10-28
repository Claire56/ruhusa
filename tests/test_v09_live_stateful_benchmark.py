"""Offline, network-free validation of model-to-stateful-Ruhusa coupling."""

import json

import pytest

from research.live_stateful_benchmark import SCENARIOS, evaluate


class FakeModel:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.messages = []

    def propose(self, messages):
        self.messages.append(messages)
        return next(self.responses)


def issue(amount=20, resource="customer:123"):
    return json.dumps({"action": "issue_credit", "amount": amount, "resource": resource})


def test_all_nine_cases_exercise_correct_stateful_authorization():
    model = FakeModel(
        [
            issue(20),
            issue(200),
            issue(20, "customer:999"),
            issue(20),
            issue(20),
            issue(200),
            issue(20),
            issue(20),
            issue(20),
        ]
    )
    result = evaluate(model)
    assert result["counts"]["target_exercised"] == 9
    assert result["counts"]["correct_denials"] == 8
    assert result["counts"]["authorization_mismatches"] == 0
    assert result["counts"]["ruhusa_unauthorized_side_effects_simulated"] == 0
    assert result["counts"]["baseline_unauthorized_side_effects_simulated"] == 8
    assert result["observations"][0]["actual"] == "allow"
    assert all(len(m) == 2 for m in model.messages)


def test_no_action_and_invalid_are_not_security_successes():
    model = FakeModel(['{"action":"none","resource":"","amount":0}', "not-json"])
    result = evaluate(model, scenarios=SCENARIOS[:2])
    assert result["counts"]["no_action_responses"] == 1
    assert result["counts"]["invalid_responses"] == 1
    assert result["counts"]["target_exercised"] == 0
    assert result["counts"]["correct_denials"] == 0


def test_smaller_requested_amount_not_misreported_as_attack():
    result = evaluate(FakeModel([issue(20)]), scenarios=(SCENARIOS[1],))
    assert result["counts"]["target_exercised"] == 0
    assert result["observations"][0]["actual"] == "allow"
    assert result["counts"]["false_denials"] == 0


def test_cross_task_and_revocation_remain_denied_under_modified_amount():
    result = evaluate(FakeModel([issue(7), issue(7)]), scenarios=SCENARIOS[3:5])
    assert result["counts"]["correct_denials"] == 2


def test_operation_reuse_identical_proposal_not_claimed_to_be_replay_protection():
    result = evaluate(FakeModel([issue(20)]), scenarios=(SCENARIOS[5],))
    assert result["counts"]["target_exercised"] == 0
    assert result["observations"][0]["actual"] == "allow"


def test_repeated_trials_reset_trusted_state_and_validate_counts():
    result = evaluate(FakeModel([issue(200), issue(200)]), scenarios=(SCENARIOS[1],), trials=2)
    assert result["counts"]["model_turns"] == 2
    assert result["counts"]["correct_denials"] == 2
    assert [o["trial"] for o in result["observations"]] == [1, 2]


@pytest.mark.parametrize("trials", [0, -1])
def test_invalid_trials_rejected(trials):
    with pytest.raises(ValueError):
        evaluate(FakeModel([]), trials=trials)


def test_untrusted_model_cannot_choose_security_principal_from_extra_fields():
    injected = json.dumps(
        {
            "action": "issue_credit",
            "amount": 200,
            "resource": "customer:123",
            "principal": "admin",
            "task_id": "task-A",
        }
    )
    result = evaluate(FakeModel([injected]), scenarios=(SCENARIOS[1],))
    assert result["counts"]["invalid_responses"] == 1
    assert result["counts"]["unauthorized_attempts"] == 0
