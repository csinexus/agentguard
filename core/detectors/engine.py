"""Rule-based detector engine (spec section 2).

Rules are declarative YAML so a rule pack can be extended without touching
core code. Each rule is a pure function of (ToolDeclaration) -> RiskFlag[];
there is no shared state between rules, which is what lets custom rule packs
be dropped in via `agentguard rules add` without core changes.
"""
from __future__ import annotations

import ast
import importlib.resources
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import yaml

from core.models import RiskFlag, Severity, ToolDeclaration
from core.detectors import builtin

# input_schema comes straight from whatever MCP server is being scanned.
# json.dumps() recurses per nesting level, so a maliciously deep schema
# (thousands of levels) raises RecursionError -- which, left unguarded,
# would make schema-based rules (e.g. the credential detector) silently
# skip that tool instead of ever evaluating it. Truncating past a generous
# depth keeps evaluation robust without meaningfully affecting any
# realistic MCP tool schema.
_MAX_SCHEMA_DEPTH = 50


def _bounded_for_json(obj: Any, depth: int = 0) -> Any:
    if depth >= _MAX_SCHEMA_DEPTH:
        return "...(truncated: exceeds max schema depth)"
    if isinstance(obj, dict):
        return {k: _bounded_for_json(v, depth + 1) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_bounded_for_json(v, depth + 1) for v in obj]
    return obj


def _keyword_regex(keyword: str) -> str:
    # \w* after the keyword catches simple inflections ("confirm" ->
    # "confirms"/"confirmed"/"confirmation") without allowing a match to
    # start mid-word ("reconfirm" still won't match "confirm" -- the
    # leading \b still requires a real boundary right before the keyword).
    return rf"\b{re.escape(keyword)}\w*"


@dataclass
class Rule:
    id: str
    name: str
    severity: Severity
    applies_to: str  # "description" | "schema" | "name"
    message: str
    source: str  # path/label the rule was loaded from, for `rules list`
    pattern: str | None = None
    keywords_any: list[str] = field(default_factory=list)
    requires_absence_of: list[str] = field(default_factory=list)
    condition: str | None = None

    def _target_text(self, tool: ToolDeclaration) -> str:
        if self.applies_to == "description":
            return tool.description or ""
        if self.applies_to == "name":
            return tool.name or ""
        if self.applies_to == "schema":
            return json.dumps(_bounded_for_json(tool.input_schema or {}))
        raise ValueError(f"rule {self.id}: unknown applies_to '{self.applies_to}'")

    def evaluate(self, tool: ToolDeclaration) -> list[RiskFlag]:
        if self.condition:
            return self._evaluate_condition(tool)
        text = self._target_text(tool)
        if self.pattern:
            return self._evaluate_pattern(text)
        if self.keywords_any:
            return self._evaluate_keywords(text)
        return []

    def _flag(self) -> RiskFlag:
        return RiskFlag(rule_id=self.id, severity=self.severity, message=self.message, location=self.applies_to)

    def _evaluate_pattern(self, text: str) -> list[RiskFlag]:
        if re.search(self.pattern, text):
            return [self._flag()]
        return []

    def _evaluate_keywords(self, text: str) -> list[RiskFlag]:
        lowered = text.lower()
        hit = any(re.search(_keyword_regex(k), lowered) for k in self.keywords_any)
        if not hit:
            return []
        if self.requires_absence_of:
            absent_ok = not any(re.search(_keyword_regex(k), lowered) for k in self.requires_absence_of)
            if not absent_ok:
                return []
        return [self._flag()]

    def _evaluate_condition(self, tool: ToolDeclaration) -> list[RiskFlag]:
        predicates = builtin.predicates_for(tool)
        if _eval_bool_expr(self.condition, predicates):
            return [self._flag()]
        return []


# --- safe boolean-condition evaluator -------------------------------------
# Rules author conditions like "name_implies_readonly AND schema_has_write_params".
# We parse them with ast and only allow BoolOp/UnaryOp(not)/Name nodes resolved
# against a fixed predicate dict -- no arbitrary code execution.

_BOOLOP_ALIASES = {"AND": "and", "OR": "or", "NOT": "not"}


def _eval_bool_expr(expr: str, predicates: dict[str, bool]) -> bool:
    normalized = expr
    for alias, py in _BOOLOP_ALIASES.items():
        normalized = re.sub(rf"\b{alias}\b", py, normalized)
    tree = ast.parse(normalized, mode="eval")
    return bool(_eval_node(tree.body, predicates))


def _eval_node(node: ast.AST, predicates: dict[str, bool]) -> bool:
    if isinstance(node, ast.BoolOp):
        values = [_eval_node(v, predicates) for v in node.values]
        if isinstance(node.op, ast.And):
            return all(values)
        if isinstance(node.op, ast.Or):
            return any(values)
        raise ValueError(f"unsupported bool op: {node.op}")
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return not _eval_node(node.operand, predicates)
    if isinstance(node, ast.Name):
        if node.id not in predicates:
            raise ValueError(f"unknown predicate '{node.id}' in condition")
        return predicates[node.id]
    raise ValueError(f"unsupported expression node: {ast.dump(node)}")


# --- rule loading -----------------------------------------------------------

def _rules_from_yaml_text(text: str, source: str) -> list[Rule]:
    try:
        data = yaml.safe_load(text) or []
    except yaml.YAMLError as exc:
        raise ValueError(f"{source}: invalid YAML: {exc}") from exc
    if not isinstance(data, list):
        raise ValueError(f"{source}: rule file must be a YAML list of rules")
    rules = []
    for entry in data:
        if not isinstance(entry, dict):
            raise ValueError(f"{source}: each rule must be a YAML mapping, got {entry!r}")
        try:
            rule = Rule(
                id=entry["id"],
                name=entry["name"],
                severity=Severity(entry["severity"]),
                applies_to=entry["applies_to"],
                message=entry["message"],
                source=source,
                pattern=entry.get("pattern"),
                keywords_any=entry.get("keywords_any", []) or [],
                requires_absence_of=entry.get("requires_absence_of", []) or [],
                condition=entry.get("condition"),
            )
        except KeyError as exc:
            raise ValueError(f"{source}: rule is missing required field {exc}") from exc
        # Fail fast on a broken pattern at load time (e.g. `agentguard rules
        # add`/`rules list`) instead of only discovering it mid-scan the
        # first time a tool description happens to reach this rule.
        if rule.pattern is not None:
            try:
                re.compile(rule.pattern)
            except re.error as exc:
                raise ValueError(f"{source}: rule {rule.id} has an invalid regex pattern: {exc}") from exc
        rules.append(rule)
    return rules


def load_rules_from_file(path: Path) -> list[Rule]:
    return _rules_from_yaml_text(path.read_text(encoding="utf-8"), str(path))


def load_default_rules() -> list[Rule]:
    # Loaded via importlib.resources (not a __file__-relative path) so this
    # works identically from a real installed wheel and from an editable
    # install -- a plain filesystem path relative to this module would
    # resolve to nothing once `rules/` is packaged separately from `core/`.
    text = importlib.resources.files("rules").joinpath("default.yaml").read_text(encoding="utf-8")
    return _rules_from_yaml_text(text, "rules/default.yaml (built-in)")


def load_custom_rules(custom_dir: Path) -> list[Rule]:
    if not custom_dir.exists():
        return []
    rules: list[Rule] = []
    for path in sorted(custom_dir.glob("*.yaml")):
        rules.extend(load_rules_from_file(path))
    return rules


class RuleEngine:
    def __init__(self, rules: list[Rule]):
        self.rules = rules

    @classmethod
    def with_defaults(cls, custom_dir: Path | None = None) -> "RuleEngine":
        rules = load_default_rules()
        if custom_dir is not None:
            rules.extend(load_custom_rules(custom_dir))
        return cls(rules)

    def run(self, tool: ToolDeclaration) -> list[RiskFlag]:
        flags: list[RiskFlag] = []
        for rule in self.rules:
            try:
                flags.extend(rule.evaluate(tool))
            except Exception:
                # Load-time validation (_rules_from_yaml_text) catches most
                # malformed rules already; this is a last-resort net so a
                # single misbehaving rule -- built-in or custom -- can never
                # take down the rest of the scan.
                continue
        return flags
