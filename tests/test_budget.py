from agent_guardrails import Action, GuardrailEngine, RunContext, ToolCall


def test_per_run_budget():
    engine = GuardrailEngine.from_dict(
        {"tools": {"default": "allow"}, "budgets": {"max_tool_calls_per_run": 2}}
    )
    ctx = RunContext(run_id="r1")
    assert engine.check_tool_call(ToolCall("a"), ctx).action == Action.ALLOW
    assert engine.check_tool_call(ToolCall("b"), ctx).action == Action.ALLOW
    third = engine.check_tool_call(ToolCall("c"), ctx)
    assert third.action == Action.DENY
    assert "budget" in third.reason


def test_budget_is_per_run():
    engine = GuardrailEngine.from_dict(
        {"tools": {"default": "allow"}, "budgets": {"max_tool_calls_per_run": 1}}
    )
    assert engine.check_tool_call(ToolCall("a"), RunContext(run_id="r1")).action == Action.ALLOW
    assert engine.check_tool_call(ToolCall("a"), RunContext(run_id="r2")).action == Action.ALLOW


def test_per_tool_budget():
    engine = GuardrailEngine.from_dict(
        {"tools": {"default": "allow"}, "budgets": {"max_calls_per_tool": {"search": 1}}}
    )
    ctx = RunContext(run_id="r1")
    assert engine.check_tool_call(ToolCall("search"), ctx).action == Action.ALLOW
    assert engine.check_tool_call(ToolCall("search"), ctx).action == Action.DENY
    assert engine.check_tool_call(ToolCall("other"), ctx).action == Action.ALLOW


def test_denied_calls_do_not_consume_budget():
    engine = GuardrailEngine.from_dict(
        {
            "tools": {"default": "allow", "deny": ["shell*"]},
            "budgets": {"max_tool_calls_per_run": 1},
        }
    )
    ctx = RunContext(run_id="r1")
    assert engine.check_tool_call(ToolCall("shell_0"), ctx).action == Action.DENY
    assert engine.check_tool_call(ToolCall("ok"), ctx).action == Action.ALLOW


def test_reset_run_clears_budget():
    engine = GuardrailEngine.from_dict(
        {"tools": {"default": "allow"}, "budgets": {"max_tool_calls_per_run": 1}}
    )
    ctx = RunContext(run_id="r1")
    assert engine.check_tool_call(ToolCall("a"), ctx).action == Action.ALLOW
    assert engine.check_tool_call(ToolCall("a"), ctx).action == Action.DENY
    engine.reset_run(ctx.run_id)
    assert engine.check_tool_call(ToolCall("a"), ctx).action == Action.ALLOW
