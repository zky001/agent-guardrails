"""The guardrail engine: runs the checker chain for each interception stage,
applies fail-open/fail-closed semantics, tracks budgets, resolves approvals,
and audits every final verdict."""

from __future__ import annotations

import threading
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable

from . import approval as approval_mod
from .audit import AuditLogger
from .checkers import DEFAULT_CHECKERS, Checker
from .policy import Policy, load_policy
from .types import (
    Action,
    ApprovalRequired,
    CheckRequest,
    GuardrailDenied,
    RunContext,
    Stage,
    ToolCall,
    Verdict,
)


@dataclass
class _RunBudget:
    total: int = 0
    per_tool: Counter = field(default_factory=Counter)


class GuardrailEngine:
    def __init__(
        self,
        policy: Policy,
        approval_gate: approval_mod.ApprovalGate | None = None,
        audit: AuditLogger | None = None,
        checkers: Iterable[type[Checker] | Checker] | None = None,
    ):
        self.policy = policy
        self.approval_gate = approval_gate
        self.audit = audit if audit is not None else AuditLogger(policy.audit.path)
        self._checkers: list[Checker] = [
            c() if isinstance(c, type) else c for c in (checkers or DEFAULT_CHECKERS)
        ]
        self._budget_lock = threading.Lock()
        self._budgets: dict[str, _RunBudget] = {}

    # ---------- construction ----------

    @classmethod
    def from_policy_file(cls, path: str | Path, **kwargs: Any) -> "GuardrailEngine":
        return cls(load_policy(path), **kwargs)

    @classmethod
    def from_dict(cls, data: dict[str, Any], **kwargs: Any) -> "GuardrailEngine":
        return cls(Policy.from_dict(data), **kwargs)

    def register(self, checker: Checker) -> None:
        """Append a custom checker to the chain (runs after the defaults)."""
        self._checkers.append(checker)

    @property
    def checkers(self) -> tuple[Checker, ...]:
        """The active checker chain (read-only view)."""
        return tuple(self._checkers)

    def apply_policy(self, policy: Policy, actor: str = "api") -> None:
        """Hot-swap the active policy. Checkers read ``engine.policy`` on every
        check, so the swap takes effect immediately; per-run budgets and pending
        approvals are left untouched. The change itself is audited."""
        self.policy = policy
        self.audit.log(
            stage="policy",
            action="policy_update",
            checker="console",
            reason=f"policy replaced by {actor} (tools.default={policy.tools.default}, fail_mode={policy.fail_mode})",
        )

    # ---------- budgets ----------

    def budget_usage(self, run_id: str, tool: str) -> tuple[int, int]:
        with self._budget_lock:
            b = self._budgets.get(run_id)
            return (b.total, b.per_tool[tool]) if b else (0, 0)

    def _consume_budget(self, run_id: str, tool: str) -> None:
        with self._budget_lock:
            b = self._budgets.setdefault(run_id, _RunBudget())
            b.total += 1
            b.per_tool[tool] += 1

    @property
    def active_runs(self) -> int:
        """Number of runs with budget state (started but not reset)."""
        with self._budget_lock:
            return len(self._budgets)

    def reset_run(self, run_id: str) -> None:
        """Free per-run state once an agent run finishes."""
        with self._budget_lock:
            self._budgets.pop(run_id, None)
        clear = getattr(self.approval_gate, "clear_run", None)
        if callable(clear):
            clear(run_id)

    # ---------- core ----------

    def check(self, req: CheckRequest) -> Verdict:
        flags: list[str] = []
        rewrite_reasons: list[str] = []
        final: Verdict | None = None

        for checker in self._checkers:
            if req.stage not in checker.stages:
                continue
            try:
                verdict = checker.check(req, self)
            except Exception as e:  # a broken checker must not break the run silently
                if self.policy.fail_mode == "open":
                    flags.append(f"checker '{checker.name}' crashed ({e}); fail_mode=open, continuing")
                    continue
                final = Verdict.deny(f"checker '{checker.name}' crashed: {e} (fail_mode=closed)", checker.name)
                break
            if verdict is None:
                continue
            if verdict.action == Action.ALLOW:
                flags.extend(verdict.flags)
                continue
            if verdict.action == Action.REWRITE:
                if req.stage == Stage.TOOL_CALL and req.tool_call is not None:
                    req.tool_call.args = verdict.rewritten
                else:
                    req.text = verdict.rewritten
                rewrite_reasons.append(f"[{verdict.checker}] {verdict.reason}")
                continue
            final = verdict  # DENY or REQUIRE_APPROVAL stops the chain
            break

        if final is None:
            if rewrite_reasons:
                rewritten = req.tool_call.args if req.stage == Stage.TOOL_CALL and req.tool_call else req.text
                final = Verdict(Action.REWRITE, reason="; ".join(rewrite_reasons), rewritten=rewritten)
            else:
                final = Verdict.allow()

        if final.action == Action.REQUIRE_APPROVAL and self.approval_gate and req.tool_call:
            final = self._resolve_approval(final, req)

        final.flags = [*flags, *final.flags]

        if final.allowed and req.stage == Stage.TOOL_CALL and req.tool_call:
            self._consume_budget(req.ctx.run_id, req.tool_call.name)

        self.audit.log(
            run_id=req.ctx.run_id,
            tenant_id=req.ctx.tenant_id,
            stage=req.stage.value,
            tool=req.tool_call.name if req.tool_call else None,
            args=req.tool_call.args if req.stage == Stage.TOOL_CALL and req.tool_call else None,
            action=final.action.value,
            checker=final.checker,
            reason=final.reason,
            flags=final.flags,
            approval_id=final.approval_id,
        )
        return final

    def _resolve_approval(self, verdict: Verdict, req: CheckRequest) -> Verdict:
        request = self.approval_gate.request(req.tool_call, req.ctx, verdict.reason)
        if request.status == approval_mod.APPROVED:
            resolved = Verdict.allow("approval", f"approved by reviewer (id={request.approval_id})")
        elif request.status == approval_mod.DENIED:
            resolved = Verdict.deny(f"denied by reviewer (id={request.approval_id})", "approval")
        else:
            resolved = verdict
        resolved.approval_id = request.approval_id
        return resolved

    # ---------- stage helpers ----------

    def check_input(self, text: str, ctx: RunContext) -> Verdict:
        return self.check(CheckRequest(Stage.INPUT, ctx, text=text))

    def check_tool_call(self, call: ToolCall, ctx: RunContext) -> Verdict:
        return self.check(CheckRequest(Stage.TOOL_CALL, ctx, tool_call=call))

    def check_tool_result(self, call: ToolCall, result_text: str, ctx: RunContext) -> Verdict:
        return self.check(CheckRequest(Stage.TOOL_RESULT, ctx, text=result_text, tool_call=call))

    def check_output(self, text: str, ctx: RunContext) -> Verdict:
        return self.check(CheckRequest(Stage.OUTPUT, ctx, text=text))

    # ---------- integration ----------

    def wrap(self, dispatch: Callable[[str, dict], Any], ctx: RunContext) -> Callable[[str, dict], Any]:
        """Wrap a tool-dispatch callable ``dispatch(name, args) -> result`` so
        every call passes TOOL_CALL checks going in and TOOL_RESULT checks
        coming back. Raises GuardrailDenied / ApprovalRequired accordingly."""

        def guarded(name: str, args: dict | None = None) -> Any:
            call = ToolCall(name, dict(args or {}))
            verdict = self.check_tool_call(call, ctx)
            if verdict.action == Action.DENY:
                raise GuardrailDenied(verdict)
            if verdict.action == Action.REQUIRE_APPROVAL:
                raise ApprovalRequired(verdict)
            final_args = (
                verdict.rewritten
                if verdict.action == Action.REWRITE and isinstance(verdict.rewritten, dict)
                else call.args
            )
            result = dispatch(name, final_args)
            result_verdict = self.check_tool_result(ToolCall(name, final_args), str(result), ctx)
            if result_verdict.action == Action.DENY:
                raise GuardrailDenied(result_verdict)
            if result_verdict.action == Action.REWRITE:
                return result_verdict.rewritten
            return result

        return guarded
