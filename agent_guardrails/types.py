"""Core datatypes shared across the guardrail engine and checkers."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Stage(str, Enum):
    """Interception surfaces in an agent run."""

    INPUT = "input"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    OUTPUT = "output"


class Action(str, Enum):
    """Final decision for a checked payload."""

    ALLOW = "allow"
    DENY = "deny"
    REWRITE = "rewrite"
    REQUIRE_APPROVAL = "require_approval"


@dataclass
class ToolCall:
    """A tool invocation the agent is about to make."""

    name: str
    args: dict[str, Any] = field(default_factory=dict)
    call_id: str | None = None


@dataclass
class RunContext:
    """Identifies one agent run; budgets and approvals are scoped to run_id."""

    run_id: str
    tenant_id: str | None = None
    user_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class CheckRequest:
    """What a checker sees: the stage plus the payload for that stage.

    - INPUT / OUTPUT: ``text`` is set.
    - TOOL_CALL: ``tool_call`` is set.
    - TOOL_RESULT: both are set (the call that produced the result, and the
      result rendered as text).
    """

    stage: Stage
    ctx: RunContext
    text: str | None = None
    tool_call: ToolCall | None = None


@dataclass
class Verdict:
    """Outcome of a check. ``rewritten`` carries the replacement payload for
    REWRITE verdicts: new args for TOOL_CALL, new text otherwise."""

    action: Action
    reason: str = ""
    checker: str = ""
    rewritten: Any | None = None
    approval_id: str | None = None
    flags: list[str] = field(default_factory=list)

    @property
    def allowed(self) -> bool:
        return self.action in (Action.ALLOW, Action.REWRITE)

    @classmethod
    def allow(cls, checker: str = "", reason: str = "") -> "Verdict":
        return cls(Action.ALLOW, reason=reason, checker=checker)

    @classmethod
    def deny(cls, reason: str, checker: str = "") -> "Verdict":
        return cls(Action.DENY, reason=reason, checker=checker)

    @classmethod
    def rewrite(cls, rewritten: Any, reason: str, checker: str = "") -> "Verdict":
        return cls(Action.REWRITE, reason=reason, checker=checker, rewritten=rewritten)

    @classmethod
    def require_approval(cls, reason: str, checker: str = "") -> "Verdict":
        return cls(Action.REQUIRE_APPROVAL, reason=reason, checker=checker)


class GuardrailDenied(Exception):
    """Raised by guarded dispatch when a payload is denied."""

    def __init__(self, verdict: Verdict):
        self.verdict = verdict
        super().__init__(f"[{verdict.checker}] {verdict.reason}")


class ApprovalRequired(Exception):
    """Raised by guarded dispatch when a tool call is pending human approval.

    ``verdict.approval_id`` identifies the pending request; resolve it via the
    engine's approval gate, then re-run the same call.
    """

    def __init__(self, verdict: Verdict):
        self.verdict = verdict
        super().__init__(f"approval required: {verdict.reason} (id={verdict.approval_id})")
