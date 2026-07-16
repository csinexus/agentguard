import shutil
from pathlib import Path

from core import baseline, manifest
from core.detectors.engine import RuleEngine, load_default_rules

FIXTURES = Path(__file__).parent / "fixtures"


def _scan(name: str, tmp_path: Path | None = None, as_name: str | None = None):
    """Parse a fixture manifest. If tmp_path is given, the fixture is copied
    under `as_name` (default: same name) first, so two different fixture
    revisions can be scanned as the *same* server_name (which is derived from
    the filename stem) to simulate a re-scan of one server over time.
    """
    if tmp_path is not None:
        dest = tmp_path / (as_name or name)
        shutil.copy(FIXTURES / name, dest)
        target = dest
    else:
        target = FIXTURES / name

    snapshots = manifest.parse_manifest_path(target)
    engine = RuleEngine(load_default_rules())
    for snap in snapshots:
        for tool in snap.tools:
            tool.risk_flags = engine.run(tool)
    return snapshots


def test_save_and_load_baseline_roundtrip(tmp_path):
    snapshots = _scan("clean_manifest.json")
    path = tmp_path / "baseline.json"
    baseline.save_baseline(snapshots, path)
    loaded = baseline.load_baseline(path)
    assert [s.server_name for s in loaded] == [s.server_name for s in snapshots]
    assert loaded[0].content_hash == snapshots[0].content_hash


def test_diff_detects_removed_tool_and_gained_capability(tmp_path):
    before = _scan("clean_manifest.json", tmp_path, as_name="clean_manifest.json")
    after = _scan("clean_manifest_v2.json", tmp_path, as_name="clean_manifest.json")

    report = baseline.diff_snapshots(before, after)
    assert report.has_drift

    drift = report.server_drifts[0]
    assert "read_config" in drift.removed_tools

    changed_by_name = {c.name: c for c in drift.changed_tools}
    assert "delete" in changed_by_name["list_files"].capabilities_added


def test_diff_no_drift_when_unchanged():
    snaps = _scan("clean_manifest.json")
    report = baseline.diff_snapshots(snaps, snaps)
    assert not report.has_drift


def test_diff_surfaces_new_risk_flags():
    before = _scan("clean_manifest.json")
    after = _scan("risky_manifest.json")
    # different server names entirely -> treated as servers added/removed, not tool-level diff
    report = baseline.diff_snapshots(before, after)
    assert set(report.servers_added) == {"risky_manifest"}
    assert set(report.servers_removed) == {"clean_manifest"}
