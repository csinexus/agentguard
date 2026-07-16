"""Shared data model for AgentGuard.

Mirrors the TypeScript interfaces in the v1 spec: ToolDeclaration,
RiskFlag, ServerSnapshot. These are plain dataclasses with to_dict/from_dict
so they round-trip cleanly through JSON for baseline storage and CI output.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


class Capability(str, Enum):
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    EXECUTE = "execute"
    NETWORK_EGRESS = "network_egress"
    FINANCIAL = "financial"
    AUTH = "auth"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_ORDER.index(self)


_SEVERITY_ORDER = [Severity.INFO, Severity.LOW, Severity.HIGH, Severity.CRITICAL]


@dataclass
class RiskFlag:
    rule_id: str
    severity: Severity
    message: str
    location: str  # "description" | "schema" | "name"

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "message": self.message,
            "location": self.location,
        }

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "RiskFlag":
        return RiskFlag(
            rule_id=d["rule_id"],
            severity=Severity(d["severity"]),
            message=d["message"],
            location=d["location"],
        )


@dataclass
class ToolDeclaration:
    name: str
    description: str
    input_schema: dict[str, Any] = field(default_factory=dict)
    inferred_capabilities: list[Capability] = field(default_factory=list)
    capability_reasons: dict[str, list[str]] = field(default_factory=dict)
    risk_flags: list[RiskFlag] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": self.input_schema,
            "inferred_capabilities": [c.value for c in self.inferred_capabilities],
            "capability_reasons": self.capability_reasons,
            "risk_flags": [f.to_dict() for f in self.risk_flags],
        }

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "ToolDeclaration":
        return ToolDeclaration(
            name=d["name"],
            description=d.get("description", ""),
            input_schema=d.get("input_schema", {}) or {},
            inferred_capabilities=[Capability(c) for c in d.get("inferred_capabilities", [])],
            capability_reasons=d.get("capability_reasons", {}),
            risk_flags=[RiskFlag.from_dict(f) for f in d.get("risk_flags", [])],
        )


def _content_hash(tools: list[ToolDeclaration]) -> str:
    raw = json.dumps(
        [{"name": t.name, "description": t.description, "input_schema": t.input_schema} for t in tools],
        sort_keys=True,
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


@dataclass
class ServerSnapshot:
    server_name: str
    transport: str  # "stdio" | "sse" | "http" | "static"
    scanned_at: str
    tools: list[ToolDeclaration] = field(default_factory=list)
    content_hash: str = ""

    def __post_init__(self) -> None:
        if not self.content_hash:
            self.content_hash = _content_hash(self.tools)

    def to_dict(self) -> dict[str, Any]:
        return {
            "server_name": self.server_name,
            "transport": self.transport,
            "scanned_at": self.scanned_at,
            "tools": [t.to_dict() for t in self.tools],
            "content_hash": self.content_hash,
        }

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "ServerSnapshot":
        return ServerSnapshot(
            server_name=d["server_name"],
            transport=d["transport"],
            scanned_at=d["scanned_at"],
            tools=[ToolDeclaration.from_dict(t) for t in d.get("tools", [])],
            content_hash=d.get("content_hash", ""),
        )
