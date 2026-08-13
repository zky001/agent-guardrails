"""Regex-based PII redaction for OUTPUT (and TOOL_RESULT) text.

Covers emails, CN mobile numbers, CN national IDs, and long card-like digit
runs. Order matters: the 18-digit national ID is matched before generic card
numbers so it gets the more specific label.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from ..types import CheckRequest, Stage, Verdict
from .base import Checker

if TYPE_CHECKING:  # pragma: no cover
    from ..engine import GuardrailEngine

_RULES: list[tuple[str, re.Pattern]] = [
    ("email", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")),
    ("cn_id", re.compile(r"(?<!\d)\d{17}[\dXx](?!\d)")),
    ("cn_mobile", re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")),
    ("card_number", re.compile(r"(?<!\d)\d{16,19}(?!\d)")),
]


def redact(text: str) -> tuple[str, list[str]]:
    found: list[str] = []
    for label, pattern in _RULES:
        text, n = pattern.subn(f"[REDACTED:{label}]", text)
        if n:
            found.append(f"{label}×{n}")
    return text, found


class PIIChecker(Checker):
    name = "pii"
    stages = (Stage.OUTPUT,)

    def check(self, req: CheckRequest, engine: "GuardrailEngine") -> Verdict | None:
        if not engine.policy.output.pii_redaction or not req.text:
            return None
        redacted, found = redact(req.text)
        if not found:
            return None
        return Verdict.rewrite(redacted, f"PII redacted: {', '.join(found)}", self.name)


class OutputDenyChecker(Checker):
    """Hard-stop patterns for final output (e.g. known secrets formats)."""

    name = "output_deny"
    stages = (Stage.OUTPUT,)

    def check(self, req: CheckRequest, engine: "GuardrailEngine") -> Verdict | None:
        if not req.text:
            return None
        for pattern in engine.policy.output.deny_match:
            if pattern.search(req.text):
                return Verdict.deny(f"output matches denied pattern {pattern.pattern!r}", self.name)
        return None
