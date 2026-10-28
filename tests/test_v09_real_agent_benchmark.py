"""Offline fake-model tests of the live model benchmark protocol."""

import json

import pytest

from research.real_agent_benchmark import (
    SCENARIOS,
    ChatCompletionsModel,
    evaluate,
    parse_proposal,
)


class FakeModel:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.messages = []

    def propose(self, messages):
        self.messages.append(messages)
        return next(self.responses)


def proposal(amount, resource="customer:123"):
    return json.dumps({"action": "issue_credit", "resource": resource, "amount": amount})


def test_real_model_protocol_paired_denial_and_approval():
    model = FakeModel([proposal(20), proposal(900)])
    report = evaluate(model, scenarios=SCENARIOS[:2])
    assert report["model_driven"] is True
    assert report["external_tool_side_effects"] is False
    assert report["counts"]["baseline_unauthorized_side_effects_simulated"] == 1
    assert report["counts"]["ruhusa_unauthorized_side_effects_simulated"] == 0
    assert report["counts"]["correct_denials"] == 1
    assert report["counts"]["false_denials"] == 0


def test_denial_replanning_is_new_model_turn():
    model = FakeModel([proposal(900), proposal(800)])
    report = evaluate(model, scenarios=(SCENARIOS[2],))
    assert len(model.messages) == 2
    assert len(model.messages[1]) == 4
    assert report["counts"]["post_denial_replanning_attempts"] == 1
    assert report["counts"]["ruhusa_unauthorized_side_effects_simulated"] == 0


@pytest.mark.parametrize(
    "response",
    [
        '```json\n{"action":"issue_credit","resource":"customer:123","amount":5}\n```',
        '{"action":"issue_credit","resource":"customer:123","amount":true}',
        '{"action":"issue_credit","resource":"customer:123","amount":-2}',
        '{"action":"issue_credit","resource":"customer:123","amount":20,"principal":"admin"}',
        "not json",
    ],
)
def test_invalid_model_responses_are_not_executed(response):
    assert parse_proposal(response) is None
    result = evaluate(FakeModel([response]), scenarios=SCENARIOS[:1])
    assert result["counts"]["valid_tool_proposals"] == 0
    assert result["counts"]["invalid_responses"] == 1


def test_endpoints_reject_nonlocal_plain_http_and_embedded_credentials():
    for url in ("http://api.example.org/v1", "https://token@example.org/v1"):
        with pytest.raises(ValueError):
            ChatCompletionsModel(base_url=url, model="test", api_key="secret")
