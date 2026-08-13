from agent_guardrails import Action, GuardrailEngine, RunContext, ToolCall


def make_engine(tools: dict) -> GuardrailEngine:
    return GuardrailEngine.from_dict({"tools": tools, "audit": {}})


CTX = RunContext(run_id="t")


def test_default_deny_blocks_unlisted():
    engine = make_engine({"default": "deny", "allow": ["search*"]})
    assert engine.check_tool_call(ToolCall("shell"), CTX).action == Action.DENY
    assert engine.check_tool_call(ToolCall("search_0"), CTX).action == Action.ALLOW


def test_default_allow_permits_unlisted():
    engine = make_engine({"default": "allow"})
    assert engine.check_tool_call(ToolCall("anything"), CTX).action == Action.ALLOW


def test_deny_pattern_wins_over_allow():
    engine = make_engine({"default": "allow", "allow": ["*"], "deny": ["shell*"]})
    verdict = engine.check_tool_call(ToolCall("shell_0"), CTX)
    assert verdict.action == Action.DENY
    assert "deny pattern" in verdict.reason


def test_sql_arg_rules():
    engine = make_engine(
        {
            "default": "deny",
            "rules": [
                {
                    "tool": "exec_sql*",
                    "args": {
                        "sql": {
                            "must_match": r"(?i)^\s*select\b",
                            "deny_match": r"(?i)\b(drop|delete|update)\b",
                        }
                    },
                }
            ],
        }
    )
    ok = engine.check_tool_call(ToolCall("exec_sql_0", {"sql": "SELECT * FROM t"}), CTX)
    assert ok.action == Action.ALLOW
    bad = engine.check_tool_call(ToolCall("exec_sql_0", {"sql": "DROP TABLE t"}), CTX)
    assert bad.action == Action.DENY
    sneaky = engine.check_tool_call(ToolCall("exec_sql_0", {"sql": "SELECT 1; DELETE FROM t"}), CTX)
    assert sneaky.action == Action.DENY


def test_domain_allowlist():
    engine = make_engine(
        {
            "default": "deny",
            "rules": [{"tool": "crawler*", "args": {"url": {"allowed_domains": ["arxiv.org"]}}}],
        }
    )
    ok = engine.check_tool_call(ToolCall("crawler_0", {"url": "https://arxiv.org/abs/1"}), CTX)
    assert ok.action == Action.ALLOW
    sub = engine.check_tool_call(ToolCall("crawler_0", {"url": "http://export.arxiv.org/x"}), CTX)
    assert sub.action == Action.ALLOW
    bad = engine.check_tool_call(ToolCall("crawler_0", {"url": "https://evil.io/arxiv.org"}), CTX)
    assert bad.action == Action.DENY
    lookalike = engine.check_tool_call(ToolCall("crawler_0", {"url": "https://notarxiv.org/"}), CTX)
    assert lookalike.action == Action.DENY


def test_max_length():
    engine = make_engine(
        {"default": "deny", "rules": [{"tool": "t", "args": {"q": {"max_length": 5}}}]}
    )
    assert engine.check_tool_call(ToolCall("t", {"q": "short"}), CTX).action == Action.ALLOW
    assert engine.check_tool_call(ToolCall("t", {"q": "toolong"}), CTX).action == Action.DENY


def test_missing_arg_is_not_a_violation():
    engine = make_engine(
        {"default": "deny", "rules": [{"tool": "t", "args": {"q": {"must_match": "x"}}}]}
    )
    assert engine.check_tool_call(ToolCall("t", {}), CTX).action == Action.ALLOW


def test_require_approval_without_gate_stays_pending():
    engine = make_engine({"default": "deny", "rules": [{"tool": "email*", "action": "require_approval"}]})
    verdict = engine.check_tool_call(ToolCall("email_0", {"to": "a@b.c"}), CTX)
    assert verdict.action == Action.REQUIRE_APPROVAL
