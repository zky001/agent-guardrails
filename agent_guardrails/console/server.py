"""Stdlib HTTP server backing the embedded console.

Design constraints, in order:
1. Zero dependencies (air-gapped customers) — ``http.server`` + one HTML file.
2. Read paths never block the engine: all data comes from the audit logger's
   in-memory aggregates and the approval gate's own locks.
3. Mutations are few and explicit: resolve an approval, apply a policy.

Not a general-purpose web framework, and deliberately so: an admin console
for humans, bound to localhost unless the operator says otherwise.
"""

from __future__ import annotations

import json
import threading
import time
from functools import partial
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from typing import Any
from urllib.parse import parse_qs, urlparse

from .. import __version__
from ..approval import MemoryApprovalGate
from ..audit import AuditLogger
from ..engine import GuardrailEngine
from ..policy import Policy, PolicyError
from ..types import RunContext, Stage, ToolCall, Verdict


def _parse_policy_text(text: str) -> dict[str, Any]:
    """Parse policy source as JSON or (if available) YAML."""
    stripped = text.strip()
    if not stripped:
        raise PolicyError("policy text is empty")
    if stripped.startswith("{"):
        try:
            return json.loads(stripped)
        except json.JSONDecodeError as e:
            raise PolicyError(f"invalid JSON: {e}") from e
    try:
        import yaml
    except ImportError as e:
        raise PolicyError("YAML support needs pyyaml (pip install 'agent-guardrails[yaml]'); or paste JSON") from e
    try:
        data = yaml.safe_load(stripped)
    except yaml.YAMLError as e:
        raise PolicyError(f"invalid YAML: {e}") from e
    if not isinstance(data, dict):
        raise PolicyError("policy root must be a mapping")
    return data


def _policy_yaml(policy: Policy) -> str | None:
    try:
        import yaml
    except ImportError:
        return None
    return yaml.safe_dump(policy.to_dict(), allow_unicode=True, sort_keys=False)


def _verdict_payload(verdict: Verdict) -> dict[str, Any]:
    return {
        "action": verdict.action.value,
        "reason": verdict.reason,
        "checker": verdict.checker,
        "rewritten": verdict.rewritten,
        "flags": verdict.flags,
        "approval_id": verdict.approval_id,
    }


class GuardrailConsole:
    """Embedded console server. ``start()`` runs in a daemon thread so it
    shuts down with the host process; ``stop()`` for explicit teardown."""

    def __init__(
        self,
        engine: GuardrailEngine,
        host: str = "127.0.0.1",
        port: int = 8787,
        token: str | None = None,
    ):
        self.engine = engine
        self.host = host
        self.port = port
        self.token = token
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    # ---------- lifecycle ----------

    def start(self) -> str:
        if self._server is not None:
            return self.url
        handler = partial(_Handler, console=self)
        self._server = ThreadingHTTPServer((self.host, self.port), handler)
        self.port = self._server.server_address[1]  # resolve port 0
        self._thread = threading.Thread(target=self._server.serve_forever, name="guardrail-console", daemon=True)
        self._thread.start()
        return self.url

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
            self._thread = None

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"

    # ---------- data assembly (called from handler threads) ----------

    def overview(self) -> dict[str, Any]:
        stats = self.engine.audit.stats()
        by_action = stats["by_action"]
        gate = self.engine.approval_gate
        return {
            "version": __version__,
            "uptime_s": round(time.time() - self.engine.audit.started_at, 1),
            "fail_mode": self.engine.policy.fail_mode,
            "tools_default": self.engine.policy.tools.default,
            "totals": {
                "checks": stats["total"],
                "allow": by_action.get("allow", 0),
                "deny": by_action.get("deny", 0),
                "rewrite": by_action.get("rewrite", 0),
                "require_approval": by_action.get("require_approval", 0),
            },
            "by_stage": stats["by_stage"],
            "by_checker": stats["by_checker"],
            "denied_tools": stats["denied_tools"],
            "timeline": self.engine.audit.timeline(30),
            "checkers": [c.name for c in self.engine.checkers],
            "active_runs": self.engine.active_runs,
            "pending_approvals": len(gate.pending()) if isinstance(gate, MemoryApprovalGate) else 0,
            "gate": type(gate).__name__ if gate else None,
        }

    def approvals(self) -> dict[str, Any]:
        gate = self.engine.approval_gate
        if not isinstance(gate, MemoryApprovalGate):
            return {"resolvable": False, "gate": type(gate).__name__ if gate else None, "pending": [], "history": []}
        return {
            "resolvable": True,
            "gate": "MemoryApprovalGate",
            "pending": [r.to_dict() for r in sorted(gate.pending(), key=lambda r: r.created_at)],
            "history": [r.to_dict() for r in gate.history()[:100]],
        }

    def resolve_approval(self, approval_id: str, approved: bool) -> None:
        gate = self.engine.approval_gate
        if not isinstance(gate, MemoryApprovalGate):
            raise ValueError("approval gate is not resolvable from the console")
        gate.resolve(approval_id, approved)
        self.engine.audit.log(
            stage="approval",
            action="approved" if approved else "rejected",
            checker="console",
            reason=f"reviewer resolved approval {approval_id} via console",
            approval_id=approval_id,
        )

    def playground(self, body: dict[str, Any]) -> dict[str, Any]:
        """Dry-run a check against the live policy without touching budgets,
        approvals, or the real audit trail."""
        shadow = GuardrailEngine(
            policy=self.engine.policy,
            approval_gate=None,
            audit=AuditLogger(None),
            checkers=self.engine.checkers,
        )
        ctx = RunContext(run_id="__playground__")
        stage = str(body.get("stage", "tool_call"))
        text = str(body.get("text", "") or "")
        tool = str(body.get("tool", "") or "")
        args = body.get("args") or {}
        if not isinstance(args, dict):
            raise ValueError("args must be a JSON object")
        if stage == Stage.TOOL_CALL.value:
            verdict = shadow.check_tool_call(ToolCall(tool, args), ctx)
        elif stage == Stage.TOOL_RESULT.value:
            verdict = shadow.check_tool_result(ToolCall(tool, args), text, ctx)
        elif stage == Stage.INPUT.value:
            verdict = shadow.check_input(text, ctx)
        elif stage == Stage.OUTPUT.value:
            verdict = shadow.check_output(text, ctx)
        else:
            raise ValueError(f"unknown stage: {stage}")
        return _verdict_payload(verdict)


class _Handler(BaseHTTPRequestHandler):
    server_version = "GuardrailConsole"

    def __init__(self, *args: Any, console: GuardrailConsole, **kwargs: Any):
        self.console = console
        super().__init__(*args, **kwargs)

    # silence per-request stderr noise
    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003
        pass

    # ---------- plumbing ----------

    def _send(self, code: int, payload: Any, content_type: str = "application/json; charset=utf-8") -> None:
        body = payload if isinstance(payload, bytes) else json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self) -> bool:
        token = self.console.token
        if not token:
            return True
        header = self.headers.get("Authorization", "")
        if header == f"Bearer {token}" or self.headers.get("X-Console-Token") == token:
            return True
        query = parse_qs(urlparse(self.path).query)
        return query.get("token", [None])[0] == token

    def _body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        data = json.loads(raw.decode("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("request body must be a JSON object")
        return data

    # ---------- routes ----------

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        route = parsed.path.rstrip("/") or "/"
        if route in ("/", "/index.html"):
            page = resources.files("agent_guardrails.console").joinpath("static/index.html").read_bytes()
            self._send(200, page, content_type="text/html; charset=utf-8")
            return
        if not route.startswith("/api"):
            self._send(404, {"error": "not found"})
            return
        if not self._authorized():
            self._send(401, {"error": "unauthorized"})
            return
        query = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        try:
            if route == "/api/overview":
                self._send(200, self.console.overview())
            elif route == "/api/audit":
                records, max_seq = self.console.engine.audit.tail(
                    since=int(query.get("since", 0)),
                    limit=min(int(query.get("limit", 200)), 1000),
                    stage=query.get("stage") or None,
                    action=query.get("action") or None,
                    run_id=query.get("run_id") or None,
                    tool=query.get("tool") or None,
                    q=query.get("q") or None,
                )
                self._send(200, {"records": records, "max_seq": max_seq})
            elif route == "/api/run":
                run_id = query.get("id", "")
                self._send(200, {"run_id": run_id, "records": self.console.engine.audit.run_records(run_id)})
            elif route == "/api/approvals":
                self._send(200, self.console.approvals())
            elif route == "/api/policy":
                policy = self.console.engine.policy
                self._send(200, {"policy": policy.to_dict(), "yaml": _policy_yaml(policy)})
            elif route == "/api/export":
                records, _ = self.console.engine.audit.tail(limit=min(int(query.get("limit", 2000)), 5000))
                lines = "\n".join(json.dumps(r, ensure_ascii=False, default=str) for r in records)
                self._send(200, lines.encode("utf-8"), content_type="application/x-ndjson; charset=utf-8")
            else:
                self._send(404, {"error": "not found"})
        except Exception as e:  # surface handler bugs as JSON, not broken sockets
            self._send(500, {"error": str(e)})

    def do_POST(self) -> None:  # noqa: N802
        route = urlparse(self.path).path.rstrip("/")
        if not self._authorized():
            self._send(401, {"error": "unauthorized"})
            return
        try:
            body = self._body()
            if route == "/api/approvals/resolve":
                self.console.resolve_approval(str(body["approval_id"]), bool(body["approved"]))
                self._send(200, {"ok": True})
            elif route in ("/api/policy/validate", "/api/policy/apply"):
                # an invalid policy is a validation *result*, not a bad request
                try:
                    policy = Policy.from_dict(_parse_policy_text(str(body.get("text", ""))))
                except PolicyError as e:
                    self._send(200, {"ok": False, "error": str(e)})
                    return
                if route.endswith("/apply"):
                    self.console.engine.apply_policy(policy, actor="console")
                self._send(200, {"ok": True, "policy": policy.to_dict()})
            elif route == "/api/playground":
                self._send(200, self.console.playground(body))
            else:
                self._send(404, {"error": "not found"})
        except (PolicyError, ValueError, KeyError) as e:
            self._send(400, {"ok": False, "error": str(e)})
        except Exception as e:
            self._send(500, {"error": str(e)})
