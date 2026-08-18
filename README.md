<p align="center">
  <strong>MCP Guard</strong><br>
  Local-first security auditor for MCP servers &amp; AI agent skills
</p>

<p align="center">
  <a href="https://github.com/pangxueyuan2-creator/mcp-guard/actions"><img alt="CI" src="https://img.shields.io/badge/CI-pending-yellow"></a>
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/license-Apache--2.0-blue"></a>
  <img alt="Python" src="https://img.shields.io/badge/python-3.11+-3776AB">
  <img alt="Dependencies" src="https://img.shields.io/badge/runtime_deps-0-2ea44f">
  <img alt="Status" src="https://img.shields.io/badge/status-public_alpha-orange">
</p>

**AI agents and MCP servers are powerful. They are also a new attack surface.**

MCP Guard is a fast, offline, zero-dependency auditor that inspects MCP server configs, tool definitions and agent skill packages **before** you install or run them.

It answers the questions developers actually care about:

- Does this MCP server request dangerous tools or permissions?
- Are there hardcoded secrets or suspicious environment variables?
- Is the skill package trying to reach outside its declared scope?
- Can I trust this supply-chain artifact?

No cloud. No telemetry. No model scoring its own safety.

## 60-second demo

```bash
# Clone and run (no install required)
git clone https://github.com/pangxueyuan2-creator/mcp-guard.git
cd mcp-guard
python -m mcp_guard scan examples/risky-mcp-server.json
```

You will see a clear PASS / FAIL report with concrete findings.

## What it checks today

| Category              | What it looks for                                      |
|-----------------------|--------------------------------------------------------|
| Tool permissions      | `exec`, `shell`, `file_write`, `network`, unrestricted |
| Secrets               | API keys, tokens, private keys in configs or env       |
| Scope violations      | Paths outside declared roots, unexpected URLs          |
| Supply chain signals  | Unpinned versions, suspicious package sources          |
| Policy compliance     | Against a simple local policy file                     |

## Quick start

```bash
# Structural scan only
python -m mcp_guard scan path/to/mcp-config.json

# With a custom policy
python -m mcp_guard scan path/to/skill --policy .mcp-guard.toml

# Generate a starter policy
python -m mcp_guard init
```

## Why this exists

The current explosion of MCP servers and agent skills is exciting and dangerous at the same time. Most people install first and ask questions later. MCP Guard flips that order: inspect → decide → install.

It is deliberately small, readable and local-first so you can actually trust the auditor itself.

## Roadmap (high level)

- [x] Core scanner + CLI skeleton
- [ ] Full MCP protocol schema validation
- [ ] Agent skill package (Claude / Cursor / Codex style) support
- [ ] SARIF output for CI
- [ ] Plugin system for custom rules
- [ ] Signed evidence reports

## Status

Public alpha. Single maintainer. No production claims yet.

Contributions and security reports are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md) (coming in next commit).

Apache-2.0.
