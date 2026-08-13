"""Human-approval gates for high-risk tool calls.

The engine asks the gate whenever a TOOL_CALL verdict is ``require_approval``.
Requests are idempotent per (run_id, tool, args) fingerprint, so re-checking
the same call after a human resolves it flows through as approved/denied
instead of opening a second request — this is what lets an agent runtime
suspend on ``ApprovalRequired`` and simply re-dispatch after resolution.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable

from .types import RunContext, ToolCall

PENDING = "pending"
APPROVED = "approved"
DENIED = "denied"


def fingerprint(call: ToolCall, ctx: RunContext) -> str:
    payload = json.dumps(
        {"run": ctx.run_id, "tool": call.name, "args": call.args},
        sort_keys=True,
        ensure_ascii=False,
        default=str,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


@dataclass
class ApprovalRequest:
    approval_id: str
    run_id: str
    tool: str
    args: dict[str, Any]
    reason: str
    status: str = PENDING
    created_at: float = field(default_factory=time.time)
    resolved_at: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "approval_id": self.approval_id,
            "run_id": self.run_id,
            "tool": self.tool,
            "args": self.args,
            "reason": self.reason,
            "status": self.status,
            "created_at": self.created_at,
            "resolved_at": self.resolved_at,
        }


class ApprovalGate(ABC):
    @abstractmethod
    def request(self, call: ToolCall, ctx: RunContext, reason: str) -> ApprovalRequest:
        """Return the (existing or newly created) request for this call."""


class MemoryApprovalGate(ApprovalGate):
    """In-memory pending queue; a human (or an external system polling
    ``pending()``) resolves requests via ``resolve()``."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._requests: dict[str, ApprovalRequest] = {}

    def request(self, call: ToolCall, ctx: RunContext, reason: str) -> ApprovalRequest:
        fid = fingerprint(call, ctx)
        with self._lock:
            req = self._requests.get(fid)
            if req is None:
                req = ApprovalRequest(fid, ctx.run_id, call.name, dict(call.args), reason)
                self._requests[fid] = req
            return req

    def resolve(self, approval_id: str, approved: bool) -> None:
        with self._lock:
            req = self._requests.get(approval_id)
            if req is None:
                raise KeyError(f"unknown approval id: {approval_id}")
            req.status = APPROVED if approved else DENIED
            req.resolved_at = time.time()

    def pending(self) -> list[ApprovalRequest]:
        with self._lock:
            return [r for r in self._requests.values() if r.status == PENDING]

    def history(self) -> list[ApprovalRequest]:
        """Resolved requests, most recently resolved first."""
        with self._lock:
            done = [r for r in self._requests.values() if r.status != PENDING]
            return sorted(done, key=lambda r: r.resolved_at or 0, reverse=True)

    def clear_run(self, run_id: str) -> None:
        with self._lock:
            self._requests = {k: r for k, r in self._requests.items() if r.run_id != run_id}


class CallbackApprovalGate(ApprovalGate):
    """Synchronous gate: delegates the decision to a callable immediately.
    Useful when the host app already has its own review UI/flow."""

    def __init__(self, decide: Callable[[ToolCall, RunContext, str], bool]):
        self._decide = decide

    def request(self, call: ToolCall, ctx: RunContext, reason: str) -> ApprovalRequest:
        approved = bool(self._decide(call, ctx, reason))
        return ApprovalRequest(
            fingerprint(call, ctx), ctx.run_id, call.name, dict(call.args), reason,
            status=APPROVED if approved else DENIED,
        )
