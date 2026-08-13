"""Append-only JSONL audit trail.

Every final verdict is recorded — including plain allows — so the log answers
"what did the agent do and what did the guardrail decide" without gaps.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_MAX_FIELD = 500


def _truncate(value: Any) -> Any:
    s = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, default=str)
    if len(s) > _MAX_FIELD:
        return s[:_MAX_FIELD] + f"...[+{len(s) - _MAX_FIELD} chars]"
    return value


class AuditLogger:
    """Thread-safe JSONL writer. ``path=None`` keeps records in memory only
    (useful for tests and for exporting via API instead of a file)."""

    def __init__(self, path: str | Path | None = None, keep_in_memory: int = 1000):
        self.path = Path(path) if path else None
        self._lock = threading.Lock()
        self._recent: list[dict[str, Any]] = []
        self._keep = keep_in_memory
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)

    def log(self, **record: Any) -> dict[str, Any]:
        record = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            **{k: _truncate(v) if k in {"args", "detail", "reason"} else v for k, v in record.items() if v not in (None, "", [])},
        }
        line = json.dumps(record, ensure_ascii=False, default=str)
        with self._lock:
            self._recent.append(record)
            if len(self._recent) > self._keep:
                self._recent = self._recent[-self._keep :]
            if self.path:
                with self.path.open("a", encoding="utf-8") as f:
                    f.write(line + "\n")
        return record

    def recent(self, n: int = 20) -> list[dict[str, Any]]:
        with self._lock:
            return self._recent[-n:]
