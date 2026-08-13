"""Embedded web console for a GuardrailEngine.

Optional and dependency-free: a stdlib HTTP server plus one self-contained
HTML page, so it works in fully offline / air-gapped deployments.

    from agent_guardrails.console import GuardrailConsole
    console = GuardrailConsole(engine, port=8787, token="secret")
    console.start()          # background thread; console.url → http://127.0.0.1:8787
"""

from .server import GuardrailConsole

__all__ = ["GuardrailConsole"]
