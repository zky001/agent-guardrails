"""Policy schema and loaders.

A policy is plain data (YAML or JSON). Regexes are compiled at load time so a
broken policy fails fast at startup, not mid-run.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class PolicyError(ValueError):
    pass


_ACTIONS = {"allow", "deny", "require_approval"}
_FAIL_MODES = {"open", "closed"}
_SCAN_MODES = {"deny", "flag"}


def _compile(pattern: str, where: str) -> re.Pattern:
    try:
        return re.compile(pattern, re.IGNORECASE)
    except re.error as e:
        raise PolicyError(f"invalid regex in {where}: {pattern!r} ({e})") from e


@dataclass
class ArgRule:
    """Constraints on a single tool argument."""

    arg: str
    must_match: re.Pattern | None = None
    deny_match: re.Pattern | None = None
    allowed_domains: list[str] = field(default_factory=list)
    max_length: int | None = None

    @classmethod
    def from_dict(cls, tool: str, arg: str, d: dict[str, Any]) -> "ArgRule":
        where = f"tools.rules[{tool}].args.{arg}"
        if not isinstance(d, dict):
            raise PolicyError(f"{where} must be a mapping")
        return cls(
            arg=arg,
            must_match=_compile(d["must_match"], where) if d.get("must_match") else None,
            deny_match=_compile(d["deny_match"], where) if d.get("deny_match") else None,
            allowed_domains=[str(x).lower() for x in d.get("allowed_domains", [])],
            max_length=int(d["max_length"]) if d.get("max_length") is not None else None,
        )


@dataclass
class ToolRule:
    """Per-tool rule; ``tool`` supports fnmatch patterns (e.g. ``search_*``)."""

    tool: str
    action: str = "allow"
    args: list[ArgRule] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ToolRule":
        tool = d.get("tool")
        if not tool:
            raise PolicyError("tools.rules entries need a 'tool' name/pattern")
        action = d.get("action", "allow")
        if action not in _ACTIONS:
            raise PolicyError(f"tools.rules[{tool}].action must be one of {sorted(_ACTIONS)}")
        args = [ArgRule.from_dict(tool, arg, spec) for arg, spec in (d.get("args") or {}).items()]
        return cls(tool=tool, action=action, args=args)


@dataclass
class ToolPolicy:
    default: str = "allow"  # allow | deny
    allow: list[str] = field(default_factory=list)
    deny: list[str] = field(default_factory=list)
    rules: list[ToolRule] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ToolPolicy":
        default = d.get("default", "allow")
        if default not in {"allow", "deny"}:
            raise PolicyError("tools.default must be 'allow' or 'deny'")
        return cls(
            default=default,
            allow=[str(x) for x in d.get("allow", [])],
            deny=[str(x) for x in d.get("deny", [])],
            rules=[ToolRule.from_dict(r) for r in d.get("rules", [])],
        )


@dataclass
class Budgets:
    max_tool_calls_per_run: int | None = None
    max_calls_per_tool: dict[str, int] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Budgets":
        return cls(
            max_tool_calls_per_run=(
                int(d["max_tool_calls_per_run"]) if d.get("max_tool_calls_per_run") is not None else None
            ),
            max_calls_per_tool={str(k): int(v) for k, v in (d.get("max_calls_per_tool") or {}).items()},
        )


@dataclass
class ScanPolicy:
    """Injection scanning config for INPUT and TOOL_RESULT stages."""

    injection_detection: bool = True
    mode: str = "deny"  # deny | flag
    extra_patterns: list[re.Pattern] = field(default_factory=list)

    @classmethod
    def from_dict(cls, section: str, d: dict[str, Any]) -> "ScanPolicy":
        mode = d.get("mode", "deny")
        if mode not in _SCAN_MODES:
            raise PolicyError(f"{section}.mode must be one of {sorted(_SCAN_MODES)}")
        return cls(
            injection_detection=bool(d.get("injection_detection", True)),
            mode=mode,
            extra_patterns=[_compile(p, f"{section}.extra_patterns") for p in d.get("extra_patterns", [])],
        )


@dataclass
class OutputPolicy:
    pii_redaction: bool = True
    deny_match: list[re.Pattern] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "OutputPolicy":
        return cls(
            pii_redaction=bool(d.get("pii_redaction", True)),
            deny_match=[_compile(p, "output.deny_match") for p in d.get("deny_match", [])],
        )


@dataclass
class AuditPolicy:
    path: str | None = None

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "AuditPolicy":
        return cls(path=str(d["path"]) if d.get("path") else None)


@dataclass
class Policy:
    fail_mode: str = "closed"  # closed | open
    tools: ToolPolicy = field(default_factory=ToolPolicy)
    budgets: Budgets = field(default_factory=Budgets)
    input: ScanPolicy = field(default_factory=ScanPolicy)
    tool_result: ScanPolicy = field(default_factory=lambda: ScanPolicy(mode="flag"))
    output: OutputPolicy = field(default_factory=OutputPolicy)
    audit: AuditPolicy = field(default_factory=AuditPolicy)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Policy":
        if not isinstance(d, dict):
            raise PolicyError("policy root must be a mapping")
        fail_mode = d.get("fail_mode", "closed")
        if fail_mode not in _FAIL_MODES:
            raise PolicyError(f"fail_mode must be one of {sorted(_FAIL_MODES)}")
        return cls(
            fail_mode=fail_mode,
            tools=ToolPolicy.from_dict(d.get("tools") or {}),
            budgets=Budgets.from_dict(d.get("budgets") or {}),
            input=ScanPolicy.from_dict("input", d.get("input") or {}),
            tool_result=ScanPolicy.from_dict("tool_result", {"mode": "flag", **(d.get("tool_result") or {})}),
            output=OutputPolicy.from_dict(d.get("output") or {}),
            audit=AuditPolicy.from_dict(d.get("audit") or {}),
        )


def load_policy(path: str | Path) -> Policy:
    """Load a policy from a ``.yaml``/``.yml`` or ``.json`` file."""
    p = Path(path)
    raw = p.read_text(encoding="utf-8")
    if p.suffix.lower() in {".yaml", ".yml"}:
        try:
            import yaml
        except ImportError as e:  # pragma: no cover
            raise PolicyError("YAML policies need pyyaml: pip install 'agent-guardrails[yaml]'") from e
        data = yaml.safe_load(raw)
    elif p.suffix.lower() == ".json":
        data = json.loads(raw)
    else:
        raise PolicyError(f"unsupported policy format: {p.suffix} (use .yaml/.yml/.json)")
    return Policy.from_dict(data or {})
