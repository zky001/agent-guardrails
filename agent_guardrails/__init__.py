"""agent-guardrails: runtime guardrails for LLM agents.

Five interception surfaces — user input, tool calls, tool results, final
output, and run budgets — driven by a declarative policy file, with human
approval gates and a JSONL audit trail.
"""

from .approval import ApprovalGate, ApprovalRequest, CallbackApprovalGate, MemoryApprovalGate
from .audit import AuditLogger
from .checkers import Checker, DEFAULT_CHECKERS
from .engine import GuardrailEngine
from .policy import Policy, PolicyError, load_policy
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

__version__ = "0.2.0"

__all__ = [
    "Action",
    "ApprovalGate",
    "ApprovalRequest",
    "ApprovalRequired",
    "AuditLogger",
    "CallbackApprovalGate",
    "CheckRequest",
    "Checker",
    "DEFAULT_CHECKERS",
    "GuardrailDenied",
    "GuardrailEngine",
    "MemoryApprovalGate",
    "Policy",
    "PolicyError",
    "RunContext",
    "Stage",
    "ToolCall",
    "Verdict",
    "load_policy",
    "__version__",
]
