"""Heuristic capability tagging (spec section 3).

This is deliberately a heuristic, not ground truth: it pattern-matches verbs
in a tool's name/description and property names in its input schema. Every
inferred capability is paired with a human-readable reason so a user can see
*why* the tag was applied and override it in .agentguard/config.yaml when the
heuristic is wrong.
"""
from __future__ import annotations

import re
from typing import Any

from core.models import Capability, ToolDeclaration

# Capability -> verbs that suggest it, matched as whole words against the
# tool's name + description (case-insensitive).
_VERB_HINTS: dict[Capability, list[str]] = {
    Capability.READ: ["read", "get", "fetch", "list", "query", "search", "describe", "view", "show", "lookup"],
    Capability.WRITE: ["write", "create", "update", "set", "modify", "edit", "insert", "append", "save", "upload"],
    Capability.DELETE: ["delete", "remove", "drop", "wipe", "purge", "truncate", "destroy"],
    Capability.EXECUTE: ["execute", "run", "invoke", "call", "spawn", "exec", "eval"],
    Capability.NETWORK_EGRESS: ["fetch", "request", "download", "send", "post", "webhook", "http", "browse", "navigate"],
    Capability.FINANCIAL: ["pay", "transfer", "charge", "invoice", "purchase", "refund", "withdraw", "deposit", "checkout"],
    Capability.AUTH: ["login", "authenticate", "token", "credential", "oauth", "password", "session"],
}

# Capability -> input schema property names that suggest it.
_SCHEMA_PROPERTY_HINTS: dict[Capability, list[str]] = {
    Capability.NETWORK_EGRESS: ["url", "endpoint", "webhook", "uri", "host"],
    Capability.FINANCIAL: ["amount", "price", "currency", "account_number", "card_number", "iban"],
    Capability.EXECUTE: ["command", "cmd", "script", "shell", "code"],
    Capability.WRITE: ["content", "body", "data", "value", "payload", "new_value", "file_content", "text"],
    Capability.DELETE: ["confirm_delete", "force"],
    Capability.AUTH: ["password", "token", "api_key", "secret", "credential"],
}

_READONLY_NAME_HINTS = ["get", "list", "read", "fetch", "query", "search", "describe", "view", "show", "lookup"]
_WRITE_SHAPED_SCHEMA_PROPS = {"content", "body", "data", "value", "new_value", "payload", "file_content", "text", "update"}


def _word_match(word: str, text: str) -> bool:
    # Tool names are typically snake_case ("get_user"), where \b doesn't see a
    # boundary at underscores since \w includes them. Use an explicit
    # alnum-only lookaround instead so "get" matches inside "get_user".
    pattern = rf"(?<![A-Za-z0-9]){re.escape(word)}(?![A-Za-z0-9])"
    return re.search(pattern, text, re.IGNORECASE) is not None


def _schema_property_names(schema: dict[str, Any]) -> list[str]:
    props = schema.get("properties") if isinstance(schema, dict) else None
    if not isinstance(props, dict):
        return []
    return list(props.keys())


def infer_capabilities(tool: ToolDeclaration) -> tuple[list[Capability], dict[str, list[str]]]:
    """Return (capabilities, reasons) where reasons maps capability.value -> [explanations]."""
    text = f"{tool.name} {tool.description}"
    prop_names = _schema_property_names(tool.input_schema)

    found: set[Capability] = set()
    reasons: dict[str, list[str]] = {}

    def add_reason(cap: Capability, reason: str) -> None:
        found.add(cap)
        reasons.setdefault(cap.value, []).append(reason)

    for cap, verbs in _VERB_HINTS.items():
        for verb in verbs:
            if _word_match(verb, text):
                add_reason(cap, f"verb '{verb}' found in name/description")

    for cap, props in _SCHEMA_PROPERTY_HINTS.items():
        for prop in props:
            if prop in prop_names:
                add_reason(cap, f"schema property '{prop}' suggests {cap.value}")

    return sorted(found, key=lambda c: c.value), reasons


def name_implies_readonly(tool: ToolDeclaration) -> bool:
    name = tool.name.lower()
    return any(_word_match(hint, name) for hint in _READONLY_NAME_HINTS)


def schema_has_write_params(tool: ToolDeclaration) -> bool:
    props = set(_schema_property_names(tool.input_schema))
    return bool(props & _WRITE_SHAPED_SCHEMA_PROPS)


def apply_overrides(tool: ToolDeclaration, overrides: dict[str, list[str]]) -> None:
    """Apply a project's .agentguard.yaml capability_overrides in place, if present for this tool."""
    if tool.name in overrides:
        tool.inferred_capabilities = [Capability(c) for c in overrides[tool.name]]
        tool.capability_reasons = {"*": ["overridden by .agentguard config"]}


def tag_tool(tool: ToolDeclaration, overrides: dict[str, list[str]] | None = None) -> None:
    """Populate tool.inferred_capabilities / capability_reasons in place."""
    caps, reasons = infer_capabilities(tool)
    tool.inferred_capabilities = caps
    tool.capability_reasons = reasons
    if overrides:
        apply_overrides(tool, overrides)
