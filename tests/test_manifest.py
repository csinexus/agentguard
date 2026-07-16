import sys
import json
from pathlib import Path

import pytest

from core import introspect, manifest

FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_clean_static_manifest():
    snapshots = manifest.parse_manifest_path(FIXTURES / "clean_manifest.json")
    assert len(snapshots) == 1
    snap = snapshots[0]
    assert snap.transport == "static"
    assert {t.name for t in snap.tools} == {"list_files", "search_notes", "read_config"}


def test_parse_risky_static_manifest_tags_capabilities():
    snapshots = manifest.parse_manifest_path(FIXTURES / "risky_manifest.json")
    tools = {t.name: t for t in snapshots[0].tools}
    from core.models import Capability

    assert Capability.DELETE in tools["delete_records"].inferred_capabilities


def test_directory_scan_globs_json_files(tmp_path):
    (tmp_path / "a.json").write_text(json.dumps({"tools": [{"name": "x", "description": "read x"}]}))
    (tmp_path / "b.json").write_text(json.dumps({"tools": [{"name": "y", "description": "read y"}]}))
    snapshots = manifest.parse_manifest_path(tmp_path)
    assert {s.server_name for s in snapshots} == {"a", "b"}


def test_mcp_servers_config_spawns_stdio_and_introspects(tmp_path):
    server_script = FIXTURES / "dummy_stdio_server.py"
    config = {
        "mcpServers": {
            "dummy": {
                "command": sys.executable,
                "args": [str(server_script)],
            }
        }
    }
    config_path = tmp_path / "claude_desktop_config.json"
    config_path.write_text(json.dumps(config))

    snapshots = manifest.parse_manifest_path(config_path)
    assert len(snapshots) == 1
    snap = snapshots[0]
    assert snap.server_name == "dummy"
    assert snap.transport == "stdio"
    names = {t.name for t in snap.tools}
    assert names == {"echo", "delete_everything"}


def test_malformed_json_raises_clear_error(tmp_path):
    bad = tmp_path / "broken.json"
    bad.write_text("{not valid json,,,")
    with pytest.raises(json.JSONDecodeError):
        manifest.parse_manifest_path(bad)


def test_unrecognized_manifest_shape_raises_value_error(tmp_path):
    weird = tmp_path / "weird.json"
    weird.write_text(json.dumps({"totally": "unrelated", "shape": True}))
    with pytest.raises(ValueError, match="unrecognized manifest format"):
        manifest.parse_manifest_path(weird)


def test_nonexistent_stdio_command_raises_introspection_error(tmp_path):
    config = {"mcpServers": {"ghost": {"command": "definitely-not-a-real-binary-xyz", "args": []}}}
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(config))

    with pytest.raises(introspect.IntrospectionError):
        manifest.parse_manifest_path(config_path)


def test_unreachable_live_endpoint_raises_introspection_error():
    # Port 1 is a reserved, essentially-never-listening port -- connection
    # should fail fast rather than hang for the full timeout.
    with pytest.raises(introspect.IntrospectionError):
        introspect.introspect_live_sync("http://127.0.0.1:1/mcp")


def test_oversized_name_and_description_are_truncated_at_ingestion():
    raw = {"name": "n" * 10_000, "description": "d" * 5_000_000}
    tool = manifest.tool_from_raw(raw)
    assert len(tool.name) <= manifest._MAX_NAME_LENGTH + 50
    assert len(tool.description) <= manifest._MAX_DESCRIPTION_LENGTH + 50


def test_normal_length_name_and_description_are_unaffected():
    raw = {"name": "get_thing", "description": "Get a thing."}
    tool = manifest.tool_from_raw(raw)
    assert tool.name == "get_thing"
    assert tool.description == "Get a thing."
