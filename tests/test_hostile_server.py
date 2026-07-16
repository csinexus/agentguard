"""End-to-end stress test against a deliberately hostile MCP server:
huge descriptions, control-char/unicode names, markup-injection attempts,
and thousands of tools -- all live over real stdio introspection. Confirms
the full introspect -> tag -> detect -> render pipeline degrades gracefully
(no crash, bounded time, no terminal-injection leak) rather than trusting
that unit-level guards compose correctly in practice.
"""
import contextlib
import io
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from cli import output
from core import capabilities, introspect, manifest
from core.detectors.engine import RuleEngine, load_default_rules
from core.models import ServerSnapshot

FIXTURES = Path(__file__).parent / "fixtures"


def test_full_pipeline_survives_hostile_server():
    start = time.perf_counter()
    raw = introspect.introspect_stdio_sync(sys.executable, [str(FIXTURES / "hostile_stdio_server.py")])
    introspect_elapsed = time.perf_counter() - start

    assert len(raw) > 3000  # the filler tools + the handful of hostile ones

    tools = [manifest.tool_from_raw(t) for t in raw]
    for t in tools:
        capabilities.tag_tool(t)

    engine = RuleEngine(load_default_rules())
    tag_and_detect_start = time.perf_counter()
    for t in tools:
        t.risk_flags = engine.run(t)
    tag_and_detect_elapsed = time.perf_counter() - tag_and_detect_start

    # The huge-description tool's description must have been bounded --
    # otherwise this assertion is the canary for the truncation fix
    # regressing (see core/manifest.py:_MAX_DESCRIPTION_LENGTH).
    huge = next(t for t in tools if t.name.startswith("huge_description_tool"))
    assert len(huge.description) < 25_000

    # Detection + tagging for 3000+ tools (including the oversized one)
    # should be fast now that size is bounded at ingestion.
    assert tag_and_detect_elapsed < 5.0, f"tag+detect took {tag_and_detect_elapsed:.2f}s, expected well under 5s"

    snap = ServerSnapshot(
        server_name="hostile", transport="stdio", scanned_at=datetime.now(timezone.utc).isoformat(), tools=tools
    )

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        output.render_scan([snap], fmt="table", severity_min="info")
    rendered = buf.getvalue()

    # Terminal-injection payloads must not survive into rendered output.
    # tool.description is never rendered in table mode (only name,
    # capabilities, and risk-flag text are) -- so the description-borne
    # markup payload shouldn't appear at all, styled or literal.
    assert "\x1b" not in rendered
    assert "FAKE FINDING" not in rendered

    # The name-borne payload *is* rendered (Tool is a table column). Rich's
    # default column width truncates very long cell text with an ellipsis
    # regardless of content ("...FAKE_C…"), so check the part that survives
    # truncation: the raw "[31m" is literal text (markup wasn't interpreted
    # as a color, and the ESC byte that used to precede it is gone).
    assert "\x1b" not in rendered
    assert "control_char_name_[31m" in rendered

    print(f"hostile server stress test: introspect={introspect_elapsed:.2f}s tag+detect={tag_and_detect_elapsed:.2f}s")
