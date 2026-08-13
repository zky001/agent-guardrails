import json
from pathlib import Path

import pytest

from agent_guardrails import Policy, PolicyError, load_policy

EXAMPLE = Path(__file__).parents[1] / "examples" / "policy.yaml"


def test_load_example_yaml():
    policy = load_policy(EXAMPLE)
    assert policy.fail_mode == "closed"
    assert policy.tools.default == "deny"
    assert any(r.tool == "exec_sql*" for r in policy.tools.rules)
    assert policy.budgets.max_tool_calls_per_run == 20
    assert policy.tool_result.mode == "flag"


def test_load_json(tmp_path):
    p = tmp_path / "policy.json"
    p.write_text(json.dumps({"tools": {"default": "deny", "allow": ["a*"]}}), encoding="utf-8")
    policy = load_policy(p)
    assert policy.tools.allow == ["a*"]


def test_unsupported_extension(tmp_path):
    p = tmp_path / "policy.toml"
    p.write_text("x = 1", encoding="utf-8")
    with pytest.raises(PolicyError, match="unsupported"):
        load_policy(p)


def test_invalid_action_rejected():
    with pytest.raises(PolicyError, match="action"):
        Policy.from_dict({"tools": {"rules": [{"tool": "x", "action": "explode"}]}})


def test_invalid_regex_rejected():
    with pytest.raises(PolicyError, match="invalid regex"):
        Policy.from_dict({"tools": {"rules": [{"tool": "x", "args": {"q": {"deny_match": "("}}}]}})


def test_invalid_fail_mode_rejected():
    with pytest.raises(PolicyError, match="fail_mode"):
        Policy.from_dict({"fail_mode": "yolo"})


def test_defaults_are_safe():
    policy = Policy.from_dict({})
    assert policy.fail_mode == "closed"
    assert policy.input.injection_detection is True
    assert policy.output.pii_redaction is True
