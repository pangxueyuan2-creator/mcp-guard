<p align="center">
  <strong>MCP Guard</strong><br>
  Local-first security auditor for MCP servers &amp; AI agent skills
</p>

<p align="center">
  <a href="https://github.com/pangxueyuan2-creator/mcp-guard/actions"><img alt="CI" src="https://github.com/pangxueyuan2-creator/mcp-guard/actions/workflows/ci.yml/badge.svg"></a>
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/license-Apache--2.0-blue"></a>
  <img alt="Python" src="https://img.shields.io/badge/python-3.11%2B-3776AB">
  <img alt="Dependencies" src="https://img.shields.io/badge/runtime_deps-0-2ea44f">
  <img alt="Version" src="https://img.shields.io/badge/version-0.2.0-orange">
</p>

**AI agents and MCP servers are powerful. They are also a new attack surface.**

MCP Guard is a fast, offline, zero-runtime-dependency auditor that inspects MCP server configs, tool definitions, agent skills and adjacent project files **before** you install or run them.

It is designed to answer practical questions:

- Does this package declare dangerous tools such as shell or command execution?
- Does it contain hardcoded tokens, private keys or suspicious credential fields?
- Does it reference network hosts outside a local allow-list?
- Does it invoke package installers without pinning a version?
- Does it reference absolute filesystem paths that may escape a workspace?
- Can the findings be consumed by CI or code-scanning tooling?

No cloud. No telemetry. No model grading its own safety. The scanner never executes the target.

## Quick start

```bash
git clone https://github.com/pangxueyuan2-creator/mcp-guard.git
cd mcp-guard
python -m pip install -e .

mcp-guard scan examples/risky-mcp-server.json
```

Or run from source without installing:

```bash
PYTHONPATH=src python -m mcp_guard scan examples/risky-mcp-server.json
```

Windows PowerShell:

```powershell
$env:PYTHONPATH = "src"
python -m mcp_guard scan examples/risky-mcp-server.json
```

## What v0.2 checks

| Category | Examples |
|---|---|
| Dangerous tools | `exec`, `shell`, `run_command`, `bash`, `powershell`, `subprocess` |
| Secrets | OpenAI-style keys, GitHub tokens, Slack tokens, AWS access key IDs, private keys |
| Sensitive config | Literal values in fields such as `api_key`, `access_token`, `password`, `private_key` |
| Network scope | URLs outside an optional `allowed_hosts` policy |
| Supply chain | Unpinned `npx`, `npm install`, `pip install`, and `uvx` package specs |
| Filesystem scope | Absolute Linux/Windows paths that may escape a workspace |
| Traversal safety | Symlinks skipped; common dependency/build directories pruned |
| Resource bounds | Configurable maximum file size |

MCP Guard deliberately reports heuristics rather than claiming that every finding is exploitable. Treat findings as review signals.

## Output formats

Human-readable output is the default:

```bash
mcp-guard scan path/to/skill
```

JSON for automation:

```bash
mcp-guard scan path/to/skill --format json
```

SARIF 2.1.0 for CI/code-scanning integrations:

```bash
mcp-guard scan path/to/skill --format sarif --output mcp-guard.sarif
```

The older `--json` flag remains accepted as a compatibility alias for `--format json`.

## Local policy

Generate a starter policy:

```bash
mcp-guard init
```

Then scan with it:

```bash
mcp-guard scan path/to/skill --policy .mcp-guard.toml
```

Example:

```toml
[policy]
# A finding above this severity fails the process.
# warning => errors fail, warnings are allowed.
max_severity = "warning"
max_file_bytes = 2000000
forbidden_tools = ["exec", "shell", "run_command", "bash", "powershell"]
allowed_tools = []

[scope]
# When non-empty, exact hosts and their subdomains are allowed.
allowed_hosts = ["api.example.com", "github.com"]
exclude_dirs = ["vendor"]
extensions = ["json", "toml", "yaml", "yml", "md", "py", "js", "ts"]

[secrets]
# Added on top of built-in secret patterns.
patterns = ["MYCOMPANY_[A-Z0-9]{32}"]
```

Use `--strict` when warnings should also fail the command:

```bash
mcp-guard scan path/to/skill --strict
```

Exit codes:

- `0`: scan completed and findings stayed within the allowed severity
- `1`: findings exceeded the allowed severity
- `2`: usage, missing path, or invalid policy error

## CI

The repository CI runs the package and unit tests on Python 3.11, 3.12 and 3.13. A minimal project workflow can simply run:

```bash
python -m pip install mcp-guard
mcp-guard scan . --strict
```

For SARIF-producing pipelines:

```bash
mcp-guard scan . --format sarif --output mcp-guard.sarif
```

## Design principles

1. **Local first** — source stays on your machine or CI runner.
2. **No target execution** — scanning is static and does not import or run the inspected package.
3. **Zero runtime dependencies** — Python's standard library is enough.
4. **Readable rules** — the security engine is intentionally compact enough to audit.
5. **Useful automation** — stable JSON plus SARIF makes results easy to integrate.
6. **Policy over hardcoding** — teams can tune tool, scope and secret rules locally.

## Current limitations

MCP Guard is still an alpha security tool. It does **not** currently provide:

- full MCP protocol/schema validation
- semantic data-flow analysis
- sandbox execution
- package reputation/network lookups
- cryptographic verification of downloaded artifacts
- proof that a package is safe

A clean scan means that the implemented rules did not find a problem; it is not a security guarantee.

## Roadmap

- [x] Core static scanner and CLI
- [x] TOML policy loading
- [x] JSON output
- [x] SARIF 2.1.0 output
- [x] CI test matrix
- [x] Secret, network-scope, path and supply-chain heuristics
- [ ] Full MCP protocol schema validation
- [ ] Claude / Cursor / Codex skill-format adapters
- [ ] Extensible custom rule/plugin API
- [ ] Signed evidence reports
- [ ] Optional provenance / package-integrity checks

## Development

```bash
python -m pip install -e .
python -m unittest discover -s tests -v
python -m compileall -q src
```

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md). For vulnerabilities, see [SECURITY.md](SECURITY.md).

Apache-2.0.
