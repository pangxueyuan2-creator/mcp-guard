<p align="center">
  <strong>MCP Guard</strong><br>
  Local-first, policy-aware security auditor for MCP servers &amp; AI agent skills
</p>

<p align="center">
  <a href="https://github.com/pangxueyuan2-creator/mcp-guard/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/pangxueyuan2-creator/mcp-guard/actions/workflows/ci.yml/badge.svg"></a>
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/license-Apache--2.0-blue"></a>
  <img alt="Python" src="https://img.shields.io/badge/python-3.11%2B-3776AB">
  <img alt="Dependencies" src="https://img.shields.io/badge/runtime_deps-0-2ea44f">
  <img alt="Version" src="https://img.shields.io/badge/version-0.2.0-orange">
</p>

**Inspect first. Decide second. Install third.**

MCP Guard is a small, offline and zero-runtime-dependency security scanner for MCP server configurations and agent-oriented manifests. It is designed to catch high-confidence risks before an untrusted server, package or skill is allowed into an AI workflow.

No cloud calls. No telemetry. No LLM judging its own safety.

## What v0.2 detects

| Signal | Example | Severity |
|---|---|---:|
| Dangerous tool declarations | `shell`, `exec`, `run_command`, `powershell` | error |
| General-purpose shell launchers | `command = "bash"`, `cmd.exe`, `pwsh` | error |
| Credential-shaped secrets | OpenAI/GitHub/Slack/AWS keys, private-key headers | error |
| Inline sensitive environment values | `API_KEY = "literal-value"` | warning |
| Plaintext remote endpoints | `http://example.com/mcp` | warning |
| Unpinned runtime packages | `npx -y @scope/server` | warning |
| Scan coverage gaps | files above the configured size limit | warning |
| Invalid MCP-like JSON | malformed config that blocks semantic checks | warning |

The scanner deliberately favors **high-confidence, actionable findings** over broad keyword matching. Merely mentioning words such as `shell` in ordinary source code does not automatically fail a scan.

## Quick start

```bash
git clone https://github.com/pangxueyuan2-creator/mcp-guard.git
cd mcp-guard
python -m pip install -e .

mcp-guard scan examples/risky-mcp-server.json
```

Example workflow:

```text
FAIL  examples/risky-mcp-server.json
  2 error(s), 1 warning(s), 0 info finding(s)

  [ERROR] shell-command
         MCP server launches through a general-purpose shell: bash
         ...
```

## Policy-as-code

Generate a starter policy:

```bash
mcp-guard init
```

Then scan with it:

```bash
mcp-guard scan path/to/project --policy .mcp-guard.toml
```

A policy can control:

```toml
[policy]
forbidden_tools = ["exec", "shell", "run_command", "bash", "powershell"]
ignored_dirs = [".git", ".venv", "node_modules", "dist", "build"]
extensions = [".json", ".toml", ".yaml", ".yml", ".md", ".py", ".js", ".ts"]
max_file_size_bytes = 2097152

[secrets]
patterns = [
  "sk-[A-Za-z0-9_-]{20,}",
  "gh[pousr]_[A-Za-z0-9]{30,}",
]
```

Custom secret patterns are compiled locally. Invalid regular expressions fail the policy load instead of silently disabling a rule.

## CI-friendly output

Human output is the default:

```bash
mcp-guard scan .
```

Structured JSON with a summary:

```bash
mcp-guard scan . --format json
```

SARIF 2.1.0 for security tooling and code-scanning pipelines:

```bash
mcp-guard scan . --format sarif > mcp-guard.sarif
```

Control the exit threshold explicitly:

```bash
# Fail only on errors (default)
mcp-guard scan . --fail-on error

# Fail on warnings or errors
mcp-guard scan . --fail-on warning

# Report findings but never fail the command
mcp-guard scan . --fail-on never
```

Exit codes are intentionally automation-friendly:

- `0` — scan completed and the configured threshold was not reached
- `1` — findings reached the configured failure threshold
- `2` — usage, path or policy error prevented a valid scan

The legacy `--strict` flag remains an alias for `--fail-on warning`, and `--json` remains accepted for compatibility.

## Scanner design

MCP Guard v0.2 keeps the runtime dependency-free by using the Python standard library only. Recursive scans prune common dependency/build directories and symlinked directories, enforce a configurable per-file size limit, and parse JSON/TOML structurally when possible.

Security findings are structured internally with:

- severity
- stable rule id
- human-readable message
- file/location
- line number when available
- remediation hint

Secret findings never echo the matched credential value in their message.

## Development

```bash
python -m pip install -e .
python -m compileall -q src tests
python -m unittest discover -s tests -v
```

GitHub Actions runs the same stdlib-only regression suite on Python 3.11, 3.12 and 3.13.

## Roadmap

- [x] Policy-aware scanning engine
- [x] Structured findings with line numbers and remediation hints
- [x] JSON and SARIF output
- [x] CI regression matrix
- [ ] Full MCP protocol/schema validation
- [ ] Deeper Claude/Cursor/Codex skill-package semantics
- [ ] Signed evidence reports
- [ ] Extensible rule/plugin API without weakening the trusted core

## Security model

MCP Guard is a **static preflight auditor**, not a sandbox and not a proof that an MCP server is safe. A clean scan means the configured static rules did not find a known signal; it does not guarantee benign runtime behavior.

For vulnerability reports, see [SECURITY.md](SECURITY.md). For contributions, see [CONTRIBUTING.md](CONTRIBUTING.md).

Apache-2.0.
