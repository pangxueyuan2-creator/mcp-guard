"""Bounded, non-executing inspection of package installers in MCP argv arrays."""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class LaunchArguments:
    packages: list[tuple[int, str]] = field(default_factory=list)
    unresolved: list[int | None] = field(default_factory=list)
    ecosystem: str | None = None


# An unknown option is not guessed to be either a switch or a value option:
# doing so could accidentally consume a package as an option's value.
NPM_VALUES = {
    "--registry", "--prefix", "--cache", "--userconfig", "--workspace", "-w",
    "--tag", "--omit", "--include", "--install-strategy", "--save-prefix", "--loglevel",
}
NPM_SWITCHES = {
    "-y", "--yes", "--no", "-D", "-O", "-P", "-S", "-g", "--save-dev",
    "--save-optional", "--save-peer", "--save-prod", "--save", "--no-save",
    "--global", "--dry-run", "--ignore-scripts", "--no-audit", "--no-fund",
    "--offline", "--prefer-offline", "--prefer-online", "--legacy-peer-deps",
}
PIP_VALUES = {
    "-i", "--index-url", "--extra-index-url", "-f", "--find-links", "--trusted-host",
    "--proxy", "--cert", "--client-cert", "--timeout", "--retries", "--cache-dir",
    "--src", "-t", "--target", "--root", "--prefix", "--platform", "--python-version",
    "--implementation", "--abi", "-C", "--config-settings", "--python", "--log",
}
PIP_SWITCHES = {
    "-U", "--upgrade", "--pre", "--user", "--no-deps", "--ignore-installed",
    "--force-reinstall", "--no-build-isolation", "--isolated", "--no-cache-dir",
    "--disable-pip-version-check", "--no-input", "--no-index", "--require-hashes",
    "--dry-run", "--break-system-packages", "-q", "--quiet", "-v", "--verbose",
}
UV_VALUES = {
    "-p", "--python", "--python-preference", "--index-url", "--extra-index-url",
    "--index", "--default-index", "-f", "--find-links", "--cache-dir", "--directory",
    "--project", "--config-file", "--exclude-newer", "--keyring-provider",
}
UV_SWITCHES = {
    "--isolated", "--offline", "--no-cache", "--no-deps", "--no-config",
    "--native-tls", "--managed-python", "--no-managed-python", "--no-python-downloads",
    "--no-index", "--refresh", "--reinstall", "--upgrade", "-q", "--quiet", "-v", "--verbose",
}
EXTERNAL_REQUIREMENTS = {"-r", "--requirement", "--requirements", "-c", "--constraint", "--with-requirements"}
HELP_FLAGS = {"-h", "--help", "-V", "--version"}


def _option(token: str, value_options: set[str]) -> tuple[str, str | None]:
    name, equal, value = token.partition("=")
    if equal:
        return name, value
    # Short value options may be attached: -pfoo, -rrequirements.txt, -iURL.
    if len(token) > 2 and token[:2] in value_options:
        return token[:2], token[2:]
    return token, None


def _node_inline_argument(args: list[str]) -> int | None:
    index = 0
    while index < len(args):
        token = args[index]
        if token in {"-", "--"} or not token.startswith("-"):
            return None  # Remaining arguments belong to the script.
        if token in {"--eval", "--print"} or token.startswith(("--eval=", "--print=", "-e", "-p")):
            return index
        if token in {"--input-type", "--require", "-r", "--import", "--loader", "--conditions", "-C"}:
            index += 2
        else:
            index += 1
    return None


def package_arguments(command: str, args: list[str]) -> LaunchArguments:
    """Extract package tokens without joining, splitting, or executing argv.

    Indexes always refer to the original args array. Unsupported executables and
    non-install subcommands are outside this package-pinning rule's scope.
    """
    result = LaunchArguments()
    executable = command.replace("\\", "/").rsplit("/", 1)[-1].lower()
    executable = re.sub(r"\.(?:exe|cmd)$", "", executable)
    offset = 0
    if executable in {"sh", "bash", "dash", "zsh", "fish", "cmd", "powershell", "pwsh", "env"}:
        result.unresolved.append(None)
        return result
    if executable in {"node", "nodejs"}:
        inline_index = _node_inline_argument(args)
        if inline_index is not None:
            result.unresolved.append(inline_index)
        return result
    if re.fullmatch(r"python(?:3(?:\.\d+)?)?|py", executable):
        while offset < len(args):
            token = args[offset]
            if token in {"-I", "-E", "-s", "-S", "-u", "-B", "-P", "-q", "-O", "-OO"} or (
                executable == "py" and re.fullmatch(r"-3(?:\.\d+)?(?:t)?", token)
            ):
                offset += 1
            elif token in {"-W", "-X"} and offset + 1 < len(args):
                offset += 2
            elif token.startswith(("-W", "-X")) and len(token) > 2:
                offset += 1
            else:
                break
        if offset < len(args) and args[offset].startswith("-c"):
            result.unresolved.append(offset)
            return result
        if args[offset:offset + 2] != ["-m", "pip"]:
            if offset < len(args) and args[offset].startswith("-") and args[offset] not in HELP_FLAGS | {"-m", "--"}:
                result.unresolved.append(offset)
            return result
        offset += 2
        executable = "pip"
    if executable not in {"npx", "uvx", "npm", "pip", "pip3"}:
        return result
    if args[offset:] and args[offset] in HELP_FLAGS:
        return result

    runner = executable in {"npx", "uvx"}
    npm = executable in {"npm", "npx"}
    result.ecosystem = "npm" if npm else "python"
    values = NPM_VALUES if npm else UV_VALUES if executable == "uvx" else PIP_VALUES
    switches = NPM_SWITCHES if npm else UV_SWITCHES if executable == "uvx" else PIP_SWITCHES
    package_flags = {"-p", "--package"} if executable == "npx" else {"--from", "--with", "--with-editable"} if executable == "uvx" else {"-e", "--editable"} if not npm else set()
    value_options = values | package_flags | EXTERNAL_REQUIREMENTS
    installed_command = runner
    explicit_source = False
    positional_only = False
    index = offset
    while index < len(args):
        token = args[index]
        if not positional_only and token == "--":
            positional_only = True
            index += 1
            continue
        if not positional_only and token.startswith("-"):
            name, attached = _option(token, value_options)
            if name in HELP_FLAGS:
                return result
            if name in switches and attached is None:
                index += 1
                continue
            if name not in value_options:
                result.unresolved.append(index)
                return result
            value_index = index
            if attached is None:
                if index + 1 >= len(args) or args[index + 1].startswith("-"):
                    result.unresolved.append(index)
                    return result
                index += 1
                value_index = index
                attached = args[index]
            if not attached.strip():
                result.unresolved.append(value_index)
                return result
            if name in EXTERNAL_REQUIREMENTS:
                result.unresolved.append(value_index)
            elif name in package_flags:
                result.packages.append((value_index, attached))
                if name in {"-p", "--package", "--from"}:
                    explicit_source = True
            index += 1
            continue

        if not installed_command:
            if token not in ({"install", "i"} if npm else {"install"}):
                return result
            installed_command = True
        else:
            if not token.strip():
                result.unresolved.append(index)
            elif not (runner and explicit_source):
                result.packages.append((index, token))
            if runner:
                # All following tokens belong to the server/binary itself.
                return result
        index += 1

    if installed_command and not result.packages and not result.unresolved:
        result.unresolved.append(None)
    return result
