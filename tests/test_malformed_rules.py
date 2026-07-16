"""A malformed or malicious custom rule pack (dropped into .agentguard/rules/
by `agentguard rules add`) must never crash a scan -- it should fail loudly
and specifically at load/add time instead.
"""
import pytest

from core.detectors.engine import Rule, RuleEngine, load_rules_from_file
from core.models import Severity, ToolDeclaration


def test_invalid_regex_rejected_at_load_time(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        """
- id: BAD-001
  name: broken
  severity: low
  applies_to: description
  message: x
  pattern: "(unbalanced"
"""
    )
    with pytest.raises(ValueError, match="invalid regex pattern"):
        load_rules_from_file(bad)


def test_missing_required_field_rejected_at_load_time(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        """
- id: BAD-002
  name: broken
  severity: low
  applies_to: description
"""
    )
    with pytest.raises(ValueError, match="missing required field"):
        load_rules_from_file(bad)


def test_invalid_yaml_rejected_at_load_time(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("not: valid: yaml: [")
    with pytest.raises(ValueError, match="invalid YAML"):
        load_rules_from_file(bad)


def test_rule_engine_run_survives_a_rule_that_slips_past_validation():
    # Even if something bypasses load-time validation (constructed directly,
    # or a future rule kind with a runtime-only failure mode), a single bad
    # rule must not take down evaluation of the rest.
    bad_rule = Rule(id="BAD-003", name="broken", severity=Severity.LOW, applies_to="description",
                     message="x", source="test", pattern="(unbalanced")
    good_rule = Rule(id="GOOD-001", name="fine", severity=Severity.LOW, applies_to="description",
                      message="matched", source="test", keywords_any=["danger"])
    engine = RuleEngine([bad_rule, good_rule])
    tool = ToolDeclaration(name="t", description="this tool is a danger to your data")
    flags = engine.run(tool)
    assert [f.rule_id for f in flags] == ["GOOD-001"]
