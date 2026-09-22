# Structured MCP launch checks

MCP Guard inspects `command` and `args` in parsed JSON and TOML configurations.
It recognizes server maps at the root keys `mcpServers`, `mcp_servers`, and
`servers`, and at `mcp.servers`. This includes `.mcp.json`-style files, TOML
`[mcp_servers.<name>]` tables, standalone `mcp.json` server maps, and the
`mcp.servers` object in settings files. JSON comments and trailing commas are not
supported by the standard-library JSON parser.
Because `servers` is also common in unrelated configurations, entries in that
root map are inspected only when they contain `command` or `args`.

For example, an exact npm package version can be declared as:

```json
{
  "mcpServers": {
    "demo": {
      "command": "npx",
      "args": ["--yes", "demo-mcp-server@1.2.3"]
    }
  }
}
```

The equivalent Python runner form is:

```toml
[mcp_servers.demo]
command = "uvx"
args = ["--from", "demo-mcp-server==1.2.3", "demo-mcp-server"]
```

## What is checked

- Direct `npx`, `uvx`, `npm install`/`npm i`, and `pip`/`pip3 install` commands.
- `python -m pip` and `py -3.x -m pip` forms, including common interpreter flags.
- Executable paths and Windows `.exe`/`.cmd` suffixes, without executing them.
- All positional packages in an install command, repeated `npx --package`/`-p`
  options, and `uvx --from`/`--with` packages.
- Common installer switches and value options, including attached values and
  `--` option terminators.

The scanner keeps every argument as a separate value. For `npx` and `uvx`, the
first positional argument ends installer-option parsing. Arguments after the
server's executable or package belong to that server; they are not interpreted
as installer package options. `--from` or `--package` names the package separately
from the executable that follows it.

Exact npm semantic versions and Python `==`/`===` versions are accepted by this
rule. Floating versions, placeholders, and HTTP(S) artifact URLs receive
`unpinned-package` warnings. A pip Git URL with a full commit after `@`, or an npm
Git URL with a full commit after `#`, is accepted. PEP 508 named HTTP(S)/Git
references are inspected as one argument. Local paths are outside version-pin
checking. These checks do not verify that a version exists, that a commit is
trusted, or that a published artifact is immutable.

## Findings and review boundaries

New launch findings identify the configuration field and argument index, such as
`config.json:$.mcpServers.demo.args[1]`. Their messages do not repeat argument
values, which may include credentials. SARIF records the file as its physical
location and the configuration field as a logical location. Decoded text fields
also use a field location rather than claiming a source-file line number.

An unknown installer option, a missing option value, malformed `command`/`args`,
or a referenced requirements/constraints file produces `unresolved-mcp-command`.
Unknown Python interpreter options before the module or script also require review.
Shell wrappers such as `cmd`, `bash`, and `env`, and direct Python/Node inline-code
launches, also require review. Their contents are not executed or followed.
These warnings fail the CLI under `--strict`; default severity behavior is
unchanged.

Other executables, script files, custom wrapper programs, non-install package
manager commands, and other configuration layouts are outside this rule.
Remote servers with a `url` and no local command do not need an installer pin.
Environment interpolation and installer configuration files are not evaluated.
The option allowlist is intentionally finite; newer or uncommon options may
require review even when a person can determine that they are safe.

The normal secret, URL, tool-name, and filesystem heuristics still scan the file.
Ordinary strings outside launch `command`/`args` fields retain textual install
command checks. Invalid JSON/TOML falls back to existing text heuristics; this
feature is not schema validation for malformed configuration files.
