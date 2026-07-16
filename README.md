# AgentGuard

Risk scanning for MCP tool manifests. AgentGuard turns the loose,
human-readable metadata a Model Context Protocol server exposes via
`tools/list` (`name`, `description`, `input_schema` -- MCP has no formal
permission-scope model) into something you can inspect, gate CI on, and
diff over time.

## Scope

**In scope for v1** (tractable, well-specified engineering):

- Static scanning of MCP server tool manifests
- Live introspection of running MCP servers (`tools/list`)
- Rule-based detection of scope creep, destructive-action risk, and known
  injection patterns
- Baseline snapshotting + drift detection between scans
- A CLI with human-readable and JSON output (CI-friendly)

**Explicitly out of scope for v1** (research-grade, not solved by better
code):

- Live behavioral/traffic monitoring for exfiltration
- ML-based classification of novel prompt injection
- A community threat-intel database of known-bad servers

AgentGuard catches the checkable cases against declared tool metadata. It
is not a claim to catch every attack -- see `agentguard --help` for the
same boundary in-tool.

## Install

```bash
pip install -e .
```

This installs the `agentguard` console script (plus `click`, `pyyaml`,
`rich`, and the official `mcp` SDK as dependencies).

## Quickstart

```bash
agentguard init                 # creates .agentguard/ config + rules dir
agentguard scan .               # scan every *.json manifest in the current directory
agentguard baseline save        # snapshot the latest scan as the trusted baseline
agentguard diff                 # compare a later scan against that baseline
```

## What a scan target can be

`agentguard scan <path|url>` accepts:

- **A raw `tools/list` JSON dump** -- either `{"tools": [...]}` or a bare
  JSON list. Parsed directly, no process spawned.
- **An `mcpServers` config** (the `claude_desktop_config.json` shape:
  `{"mcpServers": {"name": {"command", "args", "env"}}}`). These configs
  don't embed tool schemas, so each declared server is briefly launched
  over stdio and asked for its `tools/list`.

  **Trust boundary:** this *executes* every `command`/`args` the config
  declares, on your machine, before AgentGuard analyzes anything. There's
  no sandboxing -- scanning is not a safe way to preview an untrusted
  config. Only run `agentguard scan` against `mcpServers` configs from
  sources you'd already trust enough to run directly (this is the same
  trust model as `claude_desktop_config.json` itself, or running `npx`/`uvx`
  against a package you haven't audited). A raw `tools/list` JSON dump (the
  other static input shape above) carries no such risk -- it's parsed as
  inert data, nothing is executed.
- **A directory** -- every `*.json` file inside is scanned as its own
  manifest (subject to the same trust boundary above for any that are
  `mcpServers`-shaped).
- **A live MCP endpoint URL** (`http://` / `https://`) -- connects over
  streamable-HTTP (falling back to SSE) and calls `tools/list` directly.
  Force this path explicitly with `--live <url>`. No local code execution
  is involved here -- it's a network connection, not a spawned process.

## CLI reference

```
agentguard init                        # creates .agentguard/ config + rules dir
agentguard scan <path|url>             # scan a config file, directory, or live MCP endpoint
agentguard scan --live <url>           # connect and call tools/list directly
agentguard baseline save               # snapshot current scan as the trusted baseline
agentguard diff [--against <file>]     # compare latest scan vs baseline, show drift
agentguard rules list                  # show active detector rules + sources
agentguard rules add <file.yaml>       # register a custom rule pack

# flags available on scan/diff:
  --format json|table       (default: table)
  --severity-min <level>    (only display flags at/above this severity)
  --fail-on critical,high   (exit code 1 if any flags at these severities)
```

`diff --fail-on` gates on *newly introduced* risk flags specifically (not
on every capability delta), so a CI job can allow a baseline to accrue
harmless drift while still blocking a PR that introduces a critical flag.

## Detector rules

Rules live in `rules/default.yaml` as plain data -- each is a pure function
of `(ToolDeclaration) -> RiskFlag[]`, so a custom pack (`agentguard rules
add my-rules.yaml`, loaded from `.agentguard/rules/`) can be dropped in
without touching core code. See `core/detectors/engine.py` for the exact
matching semantics of `pattern`, `keywords_any` / `requires_absence_of`,
and `condition` rules.

## Capability inference

Before detectors run, `core/capabilities.py` tags each tool with
`inferred_capabilities` (`read`, `write`, `delete`, `execute`,
`network_egress`, `financial`, `auth`) by matching verbs in the tool's
name/description and property names in its input schema. This is a
heuristic, not ground truth, and it will be wrong sometimes -- every
inference is paired with a `capability_reasons` explanation, and
`.agentguard/config.yaml`'s `capability_overrides` lets you correct the
*displayed* tag (shown in `scan`/`diff` output, and used for baseline
capability-drift comparisons).

**This does not suppress detector rule flags.** Rules are documented as pure
functions of `(ToolDeclaration) -> RiskFlag[]` with no dependency on tagging
having run first -- so e.g. `SCOPE-002` independently re-derives its
write-shaped-schema signal straight from the raw schema, and will still fire
even after you've overridden that tool's capability. If a rule flags
something you've confirmed is fine, that's a per-rule-flag suppression v1
doesn't have yet, not something `capability_overrides` covers.

## Project layout

```
agentguard/
  cli/
    main.py
    commands/ (scan.py, diff.py, baseline.py, rules.py, init.py)
  core/
    manifest.py        # parse static MCP config files into ServerSnapshot
    introspect.py       # live tools/list connector
    capabilities.py     # heuristic capability tagging
    detectors/
      engine.py         # loads rule YAML, runs rules against ToolDeclaration
      builtin.py         # named predicates for `condition` rules
    baseline.py          # snapshot storage + diffing
  rules/
    default.yaml
  tests/
    fixtures/            # sample MCP manifests, both clean and deliberately risky
```

## Development

```bash
pip install -e ".[dev]"
pytest
```
