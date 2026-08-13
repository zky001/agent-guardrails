"""Checker protocol. Checkers are stateless; run-scoped state (budgets,
approvals) lives on the engine so checkers stay trivially composable."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from ..types import CheckRequest, Stage, Verdict

if TYPE_CHECKING:  # pragma: no cover
    from ..engine import GuardrailEngine


class Checker(ABC):
    """One guardrail check. Return ``None`` for "no opinion" (engine treats it
    as allow), or a Verdict to influence the outcome. REWRITE verdicts are
    applied and the chain continues; DENY / REQUIRE_APPROVAL stop the chain."""

    name: str = "checker"
    stages: tuple[Stage, ...] = ()

    @abstractmethod
    def check(self, req: CheckRequest, engine: "GuardrailEngine") -> Verdict | None: ...
