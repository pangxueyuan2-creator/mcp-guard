<p align="center">
  <strong>MCP Guard</strong><br>
  Local-first security auditor for MCP servers &amp; AI agent skills
</p>

<p align="center">
  <a href="https://github.com/pangxueyuan2-creator/mcp-guard/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/pangxueyuan2-creator/mcp-guard/actions/workflows/ci.yml/badge.svg"></a>
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/license-Apache--2.0-blue"></a>
  <img alt="Python" src="https://img.shields.io/badge/python-3.11+-3776AB">
  <img alt="Dependencies" src="https://img.shields.io/badge/runtime_deps-0-2ea44f">
  <img alt="Status" src="https://img.shields.io/badge/status-public_alpha-orange">
</p>

**AI agents and MCP servers are powerful. They are also a new attack surface.**

MCP Guard is a small, offline, zero-runtime-dependency auditor for inspecting MCP configs and agent-oriented project files before you trust or run them.

No cloud. No telemetry. No model scoring its own safety.

## 60-second demo

```bash
git clone https://github.com/pangxueyuan2-creator/mcp-guard.git
cd mcp-guard
python -m pip install -e .
mcp-guard scan examples/risky-mcp-server.json
```

The intentionally risky example should produce a FAIL report with concrete findings.

## What it checks today

| Category | Current behavior |
|---|---|
| Dangerous tool declarations | Flags built-in dangerous tool names such as `exec`, `shell`, `bash`, `powershell`, and `run_command` |
| Secret patterns | Detects several common token/private-key patterns in supported text files |
| JSON MCP-style declarations | Inspects `tools`, `capabilities`, `functions`, and `allowed_tools` lists |
| Recursive local scans | Scans supported JSON, TOML, YAML, Markdown, Python, JavaScript, and TypeScript files |
| Custom local policy | `--policy` can replace the forbidden-tool list and secret regex patterns with values from TOML |

MCP Guard is intentionally conservative about what it claims. Scope analysis, package-source analysis, full MCP schema validation, and richer supply-chain checks are roadmap items rather than finished features.

## Quick start

```bash
# Install the local checkout
python -m pip install -e .

# Structural scan
mcp-guard scan path/to/mcp-config.json

# With a custom policy
mcp-guard scan path/to/skill --policy .mcp-guard.toml

# Generate a starter policy
mcp-guard init

# Machine-readable output
mcp-guard scan path/to/skill --json
```

## Custom policy

Generate a starter policy with:

```bash
mcp-guard init
```

Then edit `.mcp-guard.toml`. For example:

```toml
[policy]
forbidden_tools = ["exec", "shell", "delete_everything"]

[secrets]
patterns = [
  "sk-[a-zA-Z0-9]{20,}",
  "CUSTOM-SECRET-[0-9]+",
]
```

When `--policy` is provided, the configured `forbidden_tools` and `secrets.patterns` replace the corresponding built-in lists. Invalid or missing policy files are reported as failing findings instead of being silently ignored.

## Development

The test suite uses only the Python standard library:

```bash
python -m pip install -e .
python -m unittest discover -s tests -v
```

CI runs the tests on Python 3.11, 3.12, and 3.13 and also smoke-tests the CLI against the risky example.

## Why this exists

The explosion of MCP servers and agent skills is exciting and dangerous at the same time. Most people install first and ask questions later. MCP Guard flips that order: inspect → decide → install.

It is deliberately small, readable and local-first so the auditor itself can be inspected without dragging in a dependency forest.

## Roadmap

- [x] Core scanner + CLI skeleton
- [x] Custom local policy loading
- [x] Unit tests + CI matrix
- [ ] Full MCP protocol/schema validation
- [ ] Agent skill package (Claude / Cursor / Codex style) support
- [ ] Scope and outbound-network analysis
- [ ] Package/supply-chain source checks
- [ ] SARIF output for CI
- [ ] Plugin system for custom rules
- [ ] Signed evidence reports

## Status

Public alpha. Single maintainer. No production claims yet.

Contributions and security reports are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

Apache-2.0.
