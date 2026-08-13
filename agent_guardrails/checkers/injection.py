"""Heuristic prompt-injection scanning for INPUT and TOOL_RESULT text.

Pattern-based detection is a first line of defense, not a complete one — the
policy's ``extra_patterns`` and a pluggable model-based checker are the
intended upgrade path. TOOL_RESULT defaults to ``flag`` mode (annotate and
audit, don't block) because web/retrieval content legitimately talks *about*
injection more often than it performs one.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from ..types import CheckRequest, Stage, Verdict
from .base import Checker

if TYPE_CHECKING:  # pragma: no cover
    from ..engine import GuardrailEngine

_PATTERNS: list[re.Pattern] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"(ignore|disregard|forget)\s+((all|any|the)\s+)?(previous|prior|above|earlier|preceding|initial|system)\s+(instructions?|prompts?|rules?|messages?)",
        r"(ignore|disregard)\s+(all|any|every)\s+(instructions?|prompts?|rules?)",
        r"(reveal|print|show|output|repeat)\s+(your\s+)?(hidden\s+|system\s+)(prompt|instructions?)",
        r"you\s+are\s+now\s+(in\s+)?(developer|dan)\s*mode",
        r"do\s+anything\s+now",
        r"begin\s+system\s+(prompt|message)",
        r"</?(system|assistant)\s*>",
        # Chinese variants
        r"忽略(之前|以上|上面|前面|所有|先前)的?(指令|提示|规则|设定|要求)",
        r"无视(之前|以上|上面|所有)的?(指令|提示|规则|设定)",
        r"(输出|打印|显示|重复)(你的)?(系统提示词|系统提示|系统指令)",
        r"现在开始你(是|扮演|进入)",
    ]
]

_ZERO_WIDTH = re.compile(r"[​‌‍⁠﻿]")


def scan_text(text: str, extra: list[re.Pattern]) -> list[str]:
    hits = [p.pattern for p in [*_PATTERNS, *extra] if p.search(text)]
    if _ZERO_WIDTH.search(text):
        hits.append("zero-width characters present")
    return hits


class InjectionChecker(Checker):
    name = "injection"
    stages = (Stage.INPUT, Stage.TOOL_RESULT)

    def check(self, req: CheckRequest, engine: "GuardrailEngine") -> Verdict | None:
        cfg = engine.policy.input if req.stage == Stage.INPUT else engine.policy.tool_result
        if not cfg.injection_detection or not req.text:
            return None
        hits = scan_text(req.text, cfg.extra_patterns)
        if not hits:
            return None
        summary = f"possible prompt injection ({len(hits)} pattern hit(s)): {hits[0]!r}"
        if cfg.mode == "deny":
            return Verdict.deny(summary, self.name)
        verdict = Verdict.allow(self.name, reason=summary)
        verdict.flags = hits
        return verdict
