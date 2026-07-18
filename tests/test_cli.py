import json
import re
import shutil
from pathlib import Path

from click.testing import CliRunner

from cli.main import cli

FIXTURES = Path(__file__).parent / "fixtures"


def test_init_creates_config(tmp_path):
    runner = CliRunner()
    with runner.isolated_filesystem(temp_dir=tmp_path):
        result = runner.invoke(cli, ["init"])
        assert result.exit_code == 0, result.output
        assert Path(".agentguard/config.yaml").exists()
        assert Path(".agentguard/rules").is_dir()


def test_scan_json_reports_flags_and_exits_zero_without_fail_on(tmp_path):
    runner = CliRunner()
    with runner.isolated_filesystem(temp_dir=tmp_path):
        shutil.copy(FIXTURES / "risky_manifest.json", "risky_manifest.json")
        result = runner.invoke(cli, ["scan", "risky_manifest.json", "--format", "json"])
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        flag_ids = {f["rule_id"] for tool in data[0]["tools"] for f in tool["risk_flags"]}
        assert {"INJ-001", "SCOPE-001", "SCOPE-002", "SECRET-001", "ENC-001"} <= flag_ids


def test_scan_fail_on_critical_exits_nonzero(tmp_path):
    runner = CliRunner()
    with runner.isolated_filesystem(temp_dir=tmp_path):
        shutil.copy(FIXTURES / "risky_manifest.json", "risky_manifest.json")
        result = runner.invoke(cli, ["scan", "risky_manifest.json", "--fail-on", "critical"])
        assert result.exit_code == 1


def test_scan_clean_manifest_no_fail(tmp_path):
    runner = CliRunner()
    with runner.isolated_filesystem(temp_dir=tmp_path):
        shutil.copy(FIXTURES / "clean_manifest.json", "clean_manifest.json")
        result = runner.invoke(cli, ["scan", "clean_manifest.json", "--fail-on", "critical,high"])
        assert result.exit_code == 0, result.output


def test_baseline_save_then_diff_shows_no_drift(tmp_path):
    runner = CliRunner()
    with runner.isolated_filesystem(temp_dir=tmp_path):
        shutil.copy(FIXTURES / "clean_manifest.json", "clean_manifest.json")
        assert runner.invoke(cli, ["scan", "clean_manifest.json"]).exit_code == 0
        assert runner.invoke(cli, ["baseline", "save"]).exit_code == 0
        assert runner.invoke(cli, ["scan", "clean_manifest.json"]).exit_code == 0

        result = runner.invoke(cli, ["diff", "--format", "json"])
        assert result.exit_code == 0, result.output
        assert json.loads(result.output)["has_drift"] is False


def test_baseline_diff_catches_dependency_update_drift(tmp_path):
    runner = CliRunner()
    with runner.isolated_filesystem(temp_dir=tmp_path):
        shutil.copy(FIXTURES / "clean_manifest.json", "clean_manifest.json")
        runner.invoke(cli, ["scan", "clean_manifest.json"])
        runner.invoke(cli, ["baseline", "save"])

        # simulate a dependency update that quietly adds a delete-shaped parameter
        shutil.copy(FIXTURES / "clean_manifest_v2.json", "clean_manifest.json")
        runner.invoke(cli, ["scan", "clean_manifest.json"])

        result = runner.invoke(cli, ["diff", "--format", "json", "--fail-on", "critical,high"])
        data = json.loads(result.output)
        assert data["has_drift"] is True
        changed = data["server_drifts"][0]["changed_tools"]
        assert any("delete" in c["capabilities_added"] for c in changed)


def test_rules_list_shows_defaults(tmp_path):
    runner = CliRunner()
    with runner.isolated_filesystem(temp_dir=tmp_path):
        result = runner.invoke(cli, ["rules", "list"])
        assert result.exit_code == 0, result.output
        for rule_id in ["INJ-001", "SCOPE-001", "SCOPE-002", "SECRET-001", "ENC-001"]:
            assert rule_id in result.output


def test_scan_malformed_json_gives_clean_error_not_traceback(tmp_path):
    runner = CliRunner()
    with runner.isolated_filesystem(temp_dir=tmp_path):
        Path("broken.json").write_text("{not valid json,,,")
        result = runner.invoke(cli, ["scan", "broken.json"])
        assert result.exit_code != 0
        assert "Traceback" not in result.output
        assert "Error" in result.output


def test_scan_missing_target_gives_clean_error(tmp_path):
    runner = CliRunner()
    with runner.isolated_filesystem(temp_dir=tmp_path):
        result = runner.invoke(cli, ["scan", "does-not-exist.json"])
        assert result.exit_code != 0
        assert "Traceback" not in result.output
        assert "No such file or directory" in result.output


def test_scan_unreachable_live_endpoint_gives_clean_error():
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "http://127.0.0.1:1/mcp"])
    assert result.exit_code != 0
    assert "Traceback" not in result.output


def test_scan_spinner_is_ascii_safe_for_legacy_console_encodings():
    # Regression test: Rich's default "dots" spinner uses Unicode braille
    # glyphs that raise UnicodeEncodeError when the console's encoding is a
    # legacy Windows codepage (cp1252 etc. -- common outside Windows
    # Terminal), crashing the entire scan over a spinner animation.
    # Reproduced live against the real CLI on this exact machine; fixed by
    # switching to the "line" spinner. Guard against a future regression by
    # asserting every frame of the configured spinner survives a strict
    # cp1252 round-trip.
    import inspect

    from rich._spinners import SPINNERS

    from cli.commands import scan as scan_module

    source = inspect.getsource(scan_module._maybe_spinner)
    # Extract the spinner= argument actually used, rather than hardcoding
    # "line" twice, so this test fails loudly if someone changes it without
    # checking encoding-safety.
    match = re.search(r'spinner="(\w+)"', source)
    assert match, "expected _maybe_spinner to pass an explicit spinner= name"
    spinner_name = match.group(1)

    frames = SPINNERS[spinner_name]["frames"]
    for frame in frames:
        frame.encode("cp1252")  # raises UnicodeEncodeError if this regresses


def test_rules_add_rejects_broken_pack_and_does_not_install_it(tmp_path):
    runner = CliRunner()
    with runner.isolated_filesystem(temp_dir=tmp_path):
        Path("broken_rules.yaml").write_text(
            "- id: BAD-001\n  name: broken\n  severity: low\n  applies_to: description\n"
            "  message: x\n  pattern: \"(unbalanced\"\n"
        )
        result = runner.invoke(cli, ["rules", "add", "broken_rules.yaml"])
        assert result.exit_code != 0
        assert "Traceback" not in result.output
        assert not Path(".agentguard/rules/broken_rules.yaml").exists()


def test_scan_with_broken_custom_rule_pack_gives_clean_error(tmp_path):
    runner = CliRunner()
    with runner.isolated_filesystem(temp_dir=tmp_path):
        Path(".agentguard/rules").mkdir(parents=True)
        # simulate a rule pack that was hand-edited after being added, or
        # copied in directly rather than through `rules add`
        Path(".agentguard/rules/broken.yaml").write_text(
            "- id: BAD-001\n  name: broken\n  severity: low\n  applies_to: description\n"
            "  message: x\n  pattern: \"(unbalanced\"\n"
        )
        shutil.copy(FIXTURES / "clean_manifest.json", "clean_manifest.json")
        result = runner.invoke(cli, ["scan", "clean_manifest.json"])
        assert result.exit_code != 0
        assert "Traceback" not in result.output
