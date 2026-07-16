# Security Policy

AgentGuard is a security-adjacent tool: it scans MCP tool manifests for risk
signals. Bugs in it fall into two buckets, and we'd like to hear about both.

## Trust model -- read this before scanning an untrusted config

`agentguard scan <config>` will **execute** every `command`/`args` an
`mcpServers`-shaped config declares, unsandboxed, on your machine, in order
to call `tools/list` on it -- before AgentGuard analyzes anything. This is
intentional (it's how MCP server introspection works, the same way `claude
desktop` itself launching that config would), not a vulnerability. Only scan
`mcpServers` configs from sources you'd already trust enough to run
directly. A raw `tools/list` JSON dump is parsed as inert data with no
execution involved, and `--live <url>` only opens a network connection --
neither of those carries this risk.

## Reporting a vulnerability in AgentGuard itself

If you find a way to make AgentGuard do something dangerous *beyond* the
documented trust model above -- e.g. a raw `tools/list` JSON dump (which is
supposed to be inert data) triggering code execution, path traversal when
writing `.agentguard/` state, a malicious rule pack escaping the YAML rule
DSL to execute arbitrary code, or a detector bypass that lets an obviously
malicious tool declaration through silently -- please report it privately
rather than opening a public issue.

**Contact:** schielchandler6@gmail.com

Please include:
- A minimal reproduction (a manifest file, rule pack, or command sequence)
- What you expected vs. what happened
- Impact, as you see it

We'll acknowledge reports within a few days and aim to ship a fix before any
public disclosure. If you don't hear back within a week, it's fine to follow
up or escalate publicly.

## Scope note

AgentGuard's detectors are heuristics over declared tool metadata (spec
`README.md`, "Scope" section). A detector *missing* a novel prompt-injection
pattern or a creative capability-mismatch is an accuracy limitation, not
itself a vulnerability -- please file those as regular GitHub issues with the
`detector-gap` label instead of a private report, unless the underlying
manifest also does something like the code-execution / path-traversal cases
above.
