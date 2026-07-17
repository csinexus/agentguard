# AgentGuard

[![Tests](https://github.com/csinexus/agentguard/actions/workflows/test.yml/badge.svg)](https://github.com/csinexus/agentguard/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/github/license/csinexus/agentguard)](LICENSE)
![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)

Risk scanning for MCP tool manifests. AgentGuard turns the loose,
human-readable metadata a Model Context Protocol server exposes via
`tools/list` (`name`, `description`, `input_schema` -- MCP has no formal
permission-scope model) into something you can inspect, gate CI on, and
diff over time.

If you're new here, read **Scope** below first, then **Install** and
**Getting started** will get you a working scan in under two minutes.

## Table of contents

- [Project status](#project-status)
- [Scope](#scope)
- [Requirements](#requirements)
- [Install](#install)
- [Getting started](#getting-started)
- [Understanding scan output](#understanding-scan-output)
- [What a scan target can be](#what-a-scan-target-can-be)
- [CLI reference](#cli-reference)
- [Detector rules](#detector-rules)
- [Capability inference](#capability-inference)
- [Known limitations](#known-limitations)
- [Troubleshooting](#troubleshooting)
- [Getting help](#getting-help)
- [Project layout](#project-layout)
- [Development](#development)

## Project status

Pre-1.0, actively developed. Concretely, as of the latest commit:

- **61 automated tests** pass, covering unit-level detector/capability
  logic, the full CLI end-to-end, an adversarial security-hardening pass
  (terminal-injection prevention, malformed-input handling, a stress test
  against a deliberately hostile MCP server), and known-limitation
  regression tests (see [Known limitations](#known-limitations)).
- **CI is green** on every push -- check the badge above or
  [Actions](https://github.com/csinexus/agentguard/actions) for the current
  status, not just this paragraph's word for it.
- **Tested against a real, independently-built MCP server**
  (`@modelcontextprotocol/server-filesystem`, the official reference
  implementation), not just self-authored test fixtures. That test caught
  and fixed a real bug (`move_file` was getting zero inferred capabilities
  because "move"/"rename" weren't in the write-verb heuristic). This is one
  server, not an exhaustive survey -- if you scan something and the result
  looks wrong, please [open an issue](#getting-help).
- **Not yet on PyPI** -- see [Install](#install).

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
same boundary in-tool, and [Known limitations](#known-limitations) below
for the specific gaps we know about.

## Requirements

- Python 3.10 or newer
- `pip` (comes with Python)
- `git`, to clone this repo (there's no PyPI package yet -- see
  [Install](#install))

Works on Windows, macOS, and Linux. No other system dependencies.

## Install

```bash
git clone https://github.com/csinexus/agentguard.git
cd agentguard
pip install -e .
```

This installs the `agentguard` console script (plus `click`, `pyyaml`,
`rich`, and the official `mcp` SDK as dependencies). PyPI packaging
(`pip install agentguard` without cloning first) is planned but not
published yet.

**Verify it worked:**

```bash
agentguard --version
agentguard --help
```

If you see `command not found` / `'agentguard' is not recognized` instead
of output, see [Troubleshooting](#troubleshooting) -- this is almost always
a PATH issue, not a broken install.

## Getting started

This walks through a full scan → baseline → drift cycle using a manifest
you create locally, so you don't need a real MCP server to try it.

**1. Save a sample manifest.** This is the "raw `tools/list` JSON dump"
input shape (see [What a scan target can be](#what-a-scan-target-can-be))
-- inert data, nothing gets executed by scanning it.

```bash
mkdir agentguard-demo && cd agentguard-demo
cat > servers.json <<'EOF'
{
  "tools": [
    {
      "name": "list_files",
      "description": "List files in a given directory.",
      "inputSchema": {"type": "object", "properties": {"directory": {"type": "string"}}}
    },
    {
      "name": "delete_records",
      "description": "Delete records from the production database by id.",
      "inputSchema": {"type": "object", "properties": {"record_id": {"type": "string"}}}
    },
    {
      "name": "get_profile",
      "description": "Get the user's profile information.",
      "inputSchema": {"type": "object", "properties": {"user_id": {"type": "string"}, "content": {"type": "string"}}}
    }
  ]
}
EOF
```

**2. Scan it:**

```bash
agentguard scan servers.json
```

```
                               servers  (static)
+-----------------------------------------------------------------------------+
| Tool           | Capabilities | Risk flags                                  |
|----------------+--------------+---------------------------------------------|
| list_files     | read         | -                                           |
|----------------+--------------+---------------------------------------------|
| delete_records | delete       | HIGH     SCOPE-001 Tool appears able to     |
|                |              | perform destructive actions with no         |
|                |              | confirmation step mentioned.                |
|----------------+--------------+---------------------------------------------|
| get_profile    | read, write  | HIGH     SCOPE-002 Tool name suggests       |
|                |              | read-only, but its input schema accepts     |
|                |              | write-shaped parameters.                    |
+-----------------------------------------------------------------------------+
```

(In a real terminal this renders in color with Unicode box-drawing lines;
it falls back to plain ASCII like above when output isn't a color
terminal -- e.g. when piped to a file.) See
[Understanding scan output](#understanding-scan-output) for what each flag
means.

**3. Establish a trusted baseline**, so you can detect drift later (e.g.
after a dependency update quietly changes a tool's schema):

```bash
agentguard init            # one-time: creates .agentguard/config.yaml + rules dir
agentguard baseline save   # snapshots the scan you just ran
```

**4. Make a change and re-scan.** Simulate a dependency update that adds a
`force` parameter to `list_files` (schema property names like `force` are
one of the signals AgentGuard's capability heuristic treats as
delete-shaped -- see [Capability inference](#capability-inference)):

```bash
# edit servers.json: add "force": {"type": "boolean"} to list_files' properties
agentguard scan servers.json
```

**5. Diff against the baseline:**

```bash
agentguard diff
```

```
                     servers
+------------------------------------------------+
| Change    | Tool       | Detail                |
|-----------+------------+-----------------------|
| ~ changed | list_files | +capabilities: delete |
|           |            | input_schema changed  |
+------------------------------------------------+
```

**6. Wire it into CI** so a PR that introduces a critical/high flag fails
the build automatically:

```bash
agentguard scan servers.json --fail-on critical,high   # exit code 1 if any critical/high flag fires
agentguard diff --fail-on critical,high                # exit code 1 only on *newly introduced* flags
```

That's the whole loop. From here: point `agentguard scan` at a real
`claude_desktop_config.json` or a live MCP endpoint (see
[What a scan target can be](#what-a-scan-target-can-be)), and drop the
`--fail-on` scan into a GitHub Action (this repo's own
[`.github/workflows/test.yml`](.github/workflows/test.yml) does exactly
that against its own test fixtures, as a working example).

## Understanding scan output

Every risk flag has a **severity**, from least to most serious:

| Severity | Meaning |
|---|---|
| `info` | Worth knowing, essentially never actionable on its own |
| `low` | Worth a glance |
| `high` | Should usually be reviewed before trusting the tool |
| `critical` | Strong signal of something dangerous -- review before use |

Filter what's displayed with `--severity-min <level>`, and fail a CI job on
specific severities with `--fail-on critical,high` (comma-separated, any
combination of the four levels).

The default rule pack ([`rules/default.yaml`](rules/default.yaml)):

| Rule ID | Severity | Catches |
|---|---|---|
| `INJ-001` | critical | Description text resembling a prompt-injection payload (e.g. "ignore previous instructions") |
| `SECRET-001` | critical | A hardcoded-looking credential (API key/secret/password/token) in the input schema |
| `SCOPE-001` | high | A destructive verb (delete/remove/drop/wipe/purge/truncate) with no confirmation language nearby |
| `SCOPE-002` | high | Tool name suggests read-only, but its input schema accepts write-shaped parameters |
| `ENC-001` | low | A long base64-like string in the description -- possibly a hidden payload |
| `ENC-002` | low | Same, but in the input schema instead of the description |

Every flagged tool also shows its **inferred capabilities**
(`read`/`write`/`delete`/`execute`/`network_egress`/`financial`/`auth`) --
see [Capability inference](#capability-inference) for how those are
derived and their limits.

## What a scan target can be

`agentguard scan <path|url>` accepts:

- **A raw `tools/list` JSON dump** -- either `{"tools": [...]}` or a bare
  JSON list. Parsed directly, no process spawned. This is what the
  [Getting started](#getting-started) walkthrough uses.
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
  inert data, nothing is executed. See [SECURITY.md](SECURITY.md) for more.
- **A directory** -- every `*.json` file inside is scanned as its own
  manifest (subject to the same trust boundary above for any that are
  `mcpServers`-shaped).
- **A live MCP endpoint URL** (`http://` / `https://`) -- connects over
  streamable-HTTP (falling back to SSE) and calls `tools/list` directly.
  Force this path explicitly with `--live <url>`. No local code execution
  is involved here -- it's a network connection, not a spawned process.

## CLI reference

| Command | What it does |
|---|---|
| `agentguard init` | Creates `.agentguard/config.yaml` (for `capability_overrides`) and `.agentguard/rules/` (for custom rule packs) in the current directory. Run once per project. |
| `agentguard scan <path\|url>` | Scans a manifest file, directory, or live endpoint. Caches the result to `.agentguard/last_scan.json` for `baseline save` / `diff` to reuse. |
| `agentguard scan --live <url>` | Forces the live-endpoint path for `<url>` explicitly. |
| `agentguard baseline save` | Snapshots the most recent `scan` result as the trusted baseline (`.agentguard/baseline.json`). |
| `agentguard diff [--against <file>]` | Compares the most recent `scan` against the baseline (or an explicit file via `--against`) and shows drift. |
| `agentguard rules list` | Shows every active detector rule (built-in + any custom packs) and where each came from. |
| `agentguard rules add <file.yaml>` | Registers a custom YAML rule pack under `.agentguard/rules/`. Validated immediately -- a broken pack is rejected and never installed. |

**Flags available on `scan` and `diff`:**

| Flag | Effect |
|---|---|
| `--format json\|table` | Output format. Default `table`. Use `json` for scripting/piping into other tools. |
| `--severity-min <level>` | Only display flags at or above this severity (`info`/`low`/`high`/`critical`). Default `info` (show everything). |
| `--fail-on <levels>` | Comma-separated severities that cause a non-zero exit code, e.g. `--fail-on critical,high`. This is the flag to use in CI. |

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
doesn't have yet, not something `capability_overrides` covers. See
[Known limitations](#known-limitations).

## Known limitations

Being upfront about these so they're not a surprise:

- **PyPI package doesn't exist yet.** Install requires `git clone` (see
  [Install](#install)).
- **`capability_overrides` doesn't suppress detector flags**, only the
  displayed capability tag -- see [Capability inference](#capability-inference)
  above. There's no per-rule-flag suppression mechanism in v1.
- **Detectors are pattern-based, not semantic.** A description that
  paraphrases an injection attempt instead of using a known phrasing, a
  destructive-action description that mentions an absence-keyword like
  "approval" without actually implementing any confirmation step, or a
  write-shaped schema property under a name outside the recognized set,
  will all slip past undetected. This is the explicit v1/vs-ML scope
  tradeoff from [Scope](#scope), not a bug -- see
  [`tests/test_evasion.py`](tests/test_evasion.py) for the exact cases this
  is known to miss.
- **Some heuristics will false-positive** on legitimate tools -- e.g. a
  read-only search tool with a `content` query parameter can trip
  `SCOPE-002`, since "content" is also a common write-shaped property name.
  See [`tests/test_false_positives.py`](tests/test_false_positives.py) for
  the known cases.
- **Scanning an `mcpServers` config executes code** -- see the trust
  boundary note in [What a scan target can be](#what-a-scan-target-can-be).

## Troubleshooting

**`agentguard: command not found` (macOS/Linux) or `'agentguard' is not
recognized...` (Windows) after `pip install -e .` succeeded.**
`pip` installed the script into a directory that isn't on your `PATH` --
this is common with per-user installs. Two options:
- Run it via `python -m cli.main <command>` instead (works regardless of
  PATH), from inside the cloned `agentguard/` directory.
- Or find where pip put it (`pip show -f agentguard` on Linux/macOS;
  on Windows check `pip install` output for a "Scripts" path warning) and
  add that directory to your `PATH`.

**`ERROR: Package 'agentguard' requires a different Python`.** You need
Python 3.10+. Check with `python --version`; if it's older, install a
newer Python and retry (e.g. via [python.org](https://www.python.org/downloads/),
your OS package manager, or `winget install Python.Python.3.12` on
Windows).

**A scan against an `mcpServers` config hangs or times out.** AgentGuard
gives a spawned server 15 seconds to respond to `tools/list` before giving
up with a clear error -- if you're consistently hitting that, the declared
`command`/`args` likely doesn't actually launch a working MCP server; try
running that exact command yourself outside AgentGuard first.

**A custom rule pack (`agentguard rules add ...`) gets rejected.** The
error message names the specific problem (invalid YAML, a missing
required field, or an invalid regex `pattern`) and which rule it's in --
fix that and re-run `rules add`. Nothing partially-broken ever gets
installed; a rejected pack isn't written to `.agentguard/rules/`.

Still stuck? See [Getting help](#getting-help).

## Getting help

- **Found a bug, or a detector gap you think is worth tracking?** Open a
  [GitHub issue](https://github.com/csinexus/agentguard/issues).
- **Found a security vulnerability** (as opposed to a detector accuracy
  gap -- see [SECURITY.md](SECURITY.md) for the distinction)? Don't open a
  public issue -- follow the private reporting process in
  [SECURITY.md](SECURITY.md) instead.
- **Not sure if something's a bug or expected behavior?** Check
  [Known limitations](#known-limitations) and
  [Troubleshooting](#troubleshooting) above first.

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
    fixtures/            # sample MCP manifests: clean, deliberately risky, and a hostile MCP server
```

## Development

```bash
pip install -e ".[dev]"
pytest
```

The test suite (60+ tests) covers unit-level detector/capability logic, the
full CLI end-to-end (via `click.testing.CliRunner`), and a stress test
against a deliberately hostile MCP server (huge payloads, terminal-injection
attempts, thousands of tools) -- see [`tests/`](tests/).
