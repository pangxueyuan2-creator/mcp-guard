# Contributing to MCP Guard

Thank you for considering a contribution.

## Principles

- Keep the core **zero-dependency** and readable.
- Prefer small, focused changes with tests.
- Security findings should be precise and actionable.
- Do not add network calls or telemetry to the default path.

## Development

```bash
python -m mcp_guard scan examples/risky-mcp-server.json
```

## Pull requests

1. Open an issue first for non-trivial changes.
2. Keep the PR focused.
3. Include a short description of the risk model you are addressing.

## Security reports

Please do not open public issues for vulnerabilities. Contact the maintainer privately.
