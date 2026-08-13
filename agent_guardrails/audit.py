"""Append-only JSONL audit trail with in-memory aggregates.

Every final verdict is recorded — including plain allows — so the log answers
"what did the agent do and what did the guardrail decide" without gaps. The
logger also maintains cumulative counters and per-minute buckets so the
embedded console can render statistics without re-reading the file.
"""

from __future__ import annotations

import json
import threading
import time
from collections import Counter
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

    def __init__(self, path: str | Path | None = None, keep_in_memory: int = 2000):
        self.path = Path(path) if path else None
        self.started_at = time.time()
        self._lock = threading.Lock()
        self._recent: list[dict[str, Any]] = []
        self._keep = keep_in_memory
        self._seq = 0
        self._total = 0
        self._by_action: Counter = Counter()
        self._by_stage: Counter = Counter()
        self._by_checker: Counter = Counter()
        self._denied_tools: Counter = Counter()
        self._minutes: dict[int, dict[str, int]] = {}
        self._minutes_keep = 240
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)

    def log(self, **record: Any) -> dict[str, Any]:
        now = time.time()
        with self._lock:
            self._seq += 1
            rec = {
                "seq": self._seq,
                "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                **{
                    k: _truncate(v) if k in {"args", "detail", "reason"} else v
                    for k, v in record.items()
                    if v not in (None, "", [])
                },
            }
            self._update_aggregates(rec, now)
            self._recent.append(rec)
            if len(self._recent) > self._keep:
                self._recent = self._recent[-self._keep :]
            if self.path:
                with self.path.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")
            return rec

    def _update_aggregates(self, rec: dict[str, Any], now: float) -> None:
        action = rec.get("action", "")
        self._total += 1
        if action:
            self._by_action[action] += 1
        if rec.get("stage"):
            self._by_stage[rec["stage"]] += 1
        if rec.get("checker"):
            self._by_checker[rec["checker"]] += 1
        if action == "deny" and rec.get("tool"):
            self._denied_tools[rec["tool"]] += 1
        minute = int(now // 60) * 60
        bucket = self._minutes.setdefault(minute, {"total": 0, "deny": 0})
        bucket["total"] += 1
        if action == "deny":
            bucket["deny"] += 1
        if len(self._minutes) > self._minutes_keep:
            for key in sorted(self._minutes)[: len(self._minutes) - self._minutes_keep]:
                del self._minutes[key]

    def recent(self, n: int = 20) -> list[dict[str, Any]]:
        with self._lock:
            return self._recent[-n:]

    def tail(
        self,
        since: int = 0,
        limit: int = 200,
        stage: str | None = None,
        action: str | None = None,
        run_id: str | None = None,
        tool: str | None = None,
        q: str | None = None,
    ) -> tuple[list[dict[str, Any]], int]:
        """Filtered records with ``seq > since`` (oldest first) plus the current
        max seq, for incremental tailing from the console."""
        needle = q.lower() if q else None
        with self._lock:
            max_seq = self._seq
            out = []
            for rec in self._recent:
                if rec["seq"] <= since:
                    continue
                if stage and rec.get("stage") != stage:
                    continue
                if action and rec.get("action") != action:
                    continue
                if run_id and rec.get("run_id") != run_id:
                    continue
                if tool and tool not in str(rec.get("tool", "")):
                    continue
                if needle and needle not in json.dumps(rec, ensure_ascii=False, default=str).lower():
                    continue
                out.append(rec)
                if len(out) >= limit:
                    break
            return out, max_seq

    def run_records(self, run_id: str) -> list[dict[str, Any]]:
        with self._lock:
            return [r for r in self._recent if r.get("run_id") == run_id]

    def stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                "total": self._total,
                "by_action": dict(self._by_action),
                "by_stage": dict(self._by_stage),
                "by_checker": dict(self._by_checker),
                "denied_tools": dict(self._denied_tools.most_common(10)),
                "started_at": self.started_at,
                "seq": self._seq,
            }

    def timeline(self, minutes: int = 30) -> list[dict[str, int]]:
        """Continuous per-minute buckets for the last N minutes (zeros filled)."""
        end = int(time.time() // 60) * 60
        with self._lock:
            return [
                {"t": t, **self._minutes.get(t, {"total": 0, "deny": 0})}
                for t in range(end - (minutes - 1) * 60, end + 60, 60)
            ]
