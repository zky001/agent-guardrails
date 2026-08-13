"""Runtime budgets: cap tool-call volume per run and per tool, so a looping
or hijacked agent runs out of rope instead of running up damage."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..types import CheckRequest, Stage, Verdict
from .base import Checker

if TYPE_CHECKING:  # pragma: no cover
    from ..engine import GuardrailEngine


class BudgetChecker(Checker):
    name = "budget"
    stages = (Stage.TOOL_CALL,)

    def check(self, req: CheckRequest, engine: "GuardrailEngine") -> Verdict | None:
        budgets = engine.policy.budgets
        call = req.tool_call
        assert call is not None
        total, per_tool = engine.budget_usage(req.ctx.run_id, call.name)

        if budgets.max_tool_calls_per_run is not None and total >= budgets.max_tool_calls_per_run:
            return Verdict.deny(
                f"run budget exhausted: {total}/{budgets.max_tool_calls_per_run} tool calls used",
                self.name,
            )
        cap = budgets.max_calls_per_tool.get(call.name)
        if cap is not None and per_tool >= cap:
            return Verdict.deny(
                f"tool budget exhausted: '{call.name}' used {per_tool}/{cap} calls", self.name
            )
        return None
