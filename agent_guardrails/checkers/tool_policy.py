"""Tool allow/deny/approval policy plus per-argument constraints.

Evaluation order for a TOOL_CALL:
1. explicit ``deny`` patterns  → DENY
2. matching rule's arg constraints → DENY on violation
3. matching rule's action (deny / require_approval / allow)
4. ``allow`` patterns → ALLOW
5. ``default`` (allow | deny)

Tool names match with fnmatch, so indexed/prefixed registrations
(``web_search_0``, ``mcp_*``) can be covered by patterns.
"""

from __future__ import annotations

from fnmatch import fnmatch
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from ..policy import ArgRule, ToolRule
from ..types import CheckRequest, Stage, Verdict
from .base import Checker

if TYPE_CHECKING:  # pragma: no cover
    from ..engine import GuardrailEngine


def _host_of(value: str) -> str:
    parsed = urlparse(value if "://" in value else f"//{value}", scheme="")
    return (parsed.hostname or value).lower()


def _domain_allowed(host: str, allowed: list[str]) -> bool:
    return any(host == d or host.endswith("." + d) for d in allowed)


class ToolPolicyChecker(Checker):
    name = "tool_policy"
    stages = (Stage.TOOL_CALL,)

    def check(self, req: CheckRequest, engine: "GuardrailEngine") -> Verdict | None:
        call = req.tool_call
        policy = engine.policy.tools
        assert call is not None

        for pattern in policy.deny:
            if fnmatch(call.name, pattern):
                return Verdict.deny(f"tool '{call.name}' matches deny pattern '{pattern}'", self.name)

        rule = self._match_rule(call.name, policy.rules)
        if rule is not None:
            violation = self._check_args(call.args, rule)
            if violation:
                return Verdict.deny(violation, self.name)
            if rule.action == "deny":
                return Verdict.deny(f"tool '{call.name}' denied by rule '{rule.tool}'", self.name)
            if rule.action == "require_approval":
                return Verdict.require_approval(
                    f"tool '{call.name}' requires human approval (rule '{rule.tool}')", self.name
                )
            return Verdict.allow(self.name)

        if any(fnmatch(call.name, pattern) for pattern in policy.allow):
            return Verdict.allow(self.name)

        if policy.default == "deny":
            return Verdict.deny(f"tool '{call.name}' is not in the allowlist (default: deny)", self.name)
        return None

    @staticmethod
    def _match_rule(name: str, rules: list[ToolRule]) -> ToolRule | None:
        for rule in rules:
            if fnmatch(name, rule.tool):
                return rule
        return None

    @staticmethod
    def _check_args(args: dict, rule: ToolRule) -> str | None:
        for spec in rule.args:
            if spec.arg not in args or args[spec.arg] is None:
                continue
            value = str(args[spec.arg])
            if spec.max_length is not None and len(value) > spec.max_length:
                return f"arg '{spec.arg}' exceeds max_length {spec.max_length}"
            if spec.must_match and not spec.must_match.search(value):
                return f"arg '{spec.arg}' does not match required pattern {spec.must_match.pattern!r}"
            if spec.deny_match and spec.deny_match.search(value):
                return f"arg '{spec.arg}' matches denied pattern {spec.deny_match.pattern!r}"
            if spec.allowed_domains and not _domain_allowed(_host_of(value), spec.allowed_domains):
                return f"arg '{spec.arg}' targets host outside allowed domains {spec.allowed_domains}"
        return None


__all__ = ["ToolPolicyChecker", "ArgRule"]
