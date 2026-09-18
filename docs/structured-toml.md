# Structured TOML scanning

MCP Guard parses valid `.toml` files with Python's standard-library `tomllib` in addition to its existing text heuristics. The parsed object is walked with the same structured checks used for JSON configs.

This matters for MCP and agent configuration because a literal credential can be syntactically ordinary TOML and not resemble a provider-specific token. For example, `api_key = "development-secret"` is now reported as `sensitive-value` even when the value does not match a built-in secret regular expression. Nested tables and arrays of tables are traversed, and placeholder values such as `${API_KEY}` remain allowed.

Structured TOML also lets declared `tools`, `capabilities`, `functions`, and `allowed_tools` arrays participate in the existing forbidden-tool policy. MCP Guard still performs its normal text scans for secrets, URLs, install commands, and absolute paths.

Invalid TOML is not executed and does not abort the scan. MCP Guard falls back to the existing text-only heuristics for that file. This feature is static analysis: it does not evaluate interpolation, load referenced files, import code, or resolve runtime configuration.
