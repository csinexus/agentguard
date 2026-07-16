"""False-positive characterization against plausible benign tools.

One class found here (SCOPE-001 rejecting "confirms"/"confirmed" because it
only matched the exact word "confirm") was a plain word-boundary bug and got
fixed (see _keyword_regex in core/detectors/engine.py). The other two are
inherent to the heuristics themselves -- fixing them by narrowing the rule
would just open a matching false-negative hole elsewhere. They're captured
as regression tests documenting the trade-off, and confirmed to have a real
fix path via .agentguard/config.yaml capability_overrides.
"""
from core.detectors.engine import RuleEngine, load_default_rules
from core.models import Capability, ToolDeclaration
from core.capabilities import tag_tool


def _flags(tool: ToolDeclaration) -> list[str]:
    engine = RuleEngine(load_default_rules())
    return [f.rule_id for f in engine.run(tool)]


def test_scope001_no_longer_false_positives_on_confirms_or_confirmed():
    assert _flags(ToolDeclaration(
        name="delete_file",
        description="Delete a file after the user confirms via a Yes/No prompt.",
    )) == []
    assert _flags(ToolDeclaration(
        name="delete_file",
        description="Delete a file once the action is confirmed by the caller.",
    )) == []
    # true positive must still fire with no confirmation language at all
    assert "SCOPE-001" in _flags(ToolDeclaration(
        name="wipe_db", description="Delete all records from the table.",
    ))


def test_known_fp_inj001_flags_legitimate_context_reset_tool():
    # A tool that legitimately resets conversation context can end up
    # describing itself using the same phrasing INJ-001 watches for. This is
    # an accepted trade-off for a critical-severity, phrase-based rule:
    # prefer a rare false positive here over missing a real injection.
    tool = ToolDeclaration(
        name="reset_conversation",
        description="Clears history so the model will ignore previous instructions in this session.",
    )
    assert "INJ-001" in _flags(tool)


def test_known_fp_scope002_flags_readonly_search_tool_with_content_param():
    # "content" as a query/filter parameter name on an otherwise read-only
    # search tool is common and legitimate, but indistinguishable from a
    # write-shaped "content" param by property name alone.
    tool = ToolDeclaration(
        name="search_notes",
        description="Search notes for matching text.",
        input_schema={"properties": {"content": {"type": "string", "description": "text to search for"}}},
    )
    assert "SCOPE-002" in _flags(tool)


def test_capability_override_does_not_suppress_scope002():
    # IMPORTANT: capability_overrides only corrects the *displayed*
    # inferred_capabilities (used in table/JSON output and baseline
    # capability-drift diffing). SCOPE-002's condition independently
    # re-derives its write-shaped-schema signal straight from the raw
    # schema (core/capabilities.py:schema_has_write_params), by design --
    # each detector rule is documented as "a pure function of
    # (ToolDeclaration) -> RiskFlag[]" with no dependency on tagging having
    # run first. Coupling SCOPE-002 to inferred_capabilities would violate
    # that purity (it would silently stop firing for anyone using
    # RuleEngine directly on an untagged tool). So: over overrides do NOT
    # suppress this specific rule flag today. There is currently no
    # per-tool rule-suppression mechanism in v1 -- this test exists so that
    # invariant stays visible instead of silently assumed.
    tool = ToolDeclaration(
        name="search_notes",
        description="Search notes for matching text.",
        input_schema={"properties": {"content": {"type": "string", "description": "text to search for"}}},
    )
    tag_tool(tool, overrides={"search_notes": ["read"]})
    assert tool.inferred_capabilities == [Capability.READ]  # display/diffing: corrected

    assert "SCOPE-002" in _flags(tool)  # the actual flag: still fires
