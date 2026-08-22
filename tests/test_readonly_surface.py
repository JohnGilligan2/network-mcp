"""The read-only guarantee is structural, and this file is what keeps it that way.

device.py is the only module that touches a device. If it never calls a netmiko
method that writes, then no MCP tool — and no prompt injection reaching one —
can change a router, regardless of what any docstring or system prompt says.

The check parses the AST rather than grepping text, so the words appearing in
the module's own docstring (which explains what it does NOT call) cannot make
the test pass or fail by accident.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1] / "network_mcp"

# Every netmiko method that writes to a device, enters config mode, or bypasses
# the command guard by talking to the channel directly.
FORBIDDEN_METHODS = {
    "send_config_set",
    "send_config_from_file",
    "save_config",
    "commit",
    "write_channel",
    "write_config",
    "send_command_timing",   # bypasses expect-string handling, not the guard,
                             # but it is how people accidentally send raw input
    "send_multiline",
    "send_multiline_timing",
    "config_mode",
    "cleanup_config",
}


def _attributes_called_in(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return {
        node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
    } | {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }


def test_device_layer_has_no_write_path():
    used = _attributes_called_in(PKG / "device.py")
    leaked = sorted(used & FORBIDDEN_METHODS)
    assert not leaked, (
        f"device.py now calls {leaked}. That is a write path to customer network "
        "equipment. If a change tool is genuinely wanted it belongs in a separate "
        "server with its own Entra app and its own access group, the way "
        "tactical-rmm-mcp and tactical-rmm-audit-mcp are split — not bolted onto the read-only one."
    )


# relay_shell.py is the ONE module allowed to write to a raw channel, because
# driving a login at the relay's shell is exactly that: typing `telnet <ip>`,
# a username and a password at a prompt. It is not a device configuration path.
# The guarantee that replaces the blanket ban is the next test: nothing
# caller-controlled may reach that channel.
_RAW_CHANNEL_EXEMPT = {"relay_shell.py": {"write_channel"}}


def test_no_module_in_the_package_has_a_write_path():
    for path in sorted(PKG.glob("*.py")):
        allowed = _RAW_CHANNEL_EXEMPT.get(path.name, set())
        leaked = sorted((_attributes_called_in(path) & FORBIDDEN_METHODS) - allowed)
        assert not leaked, f"{path.name} calls {leaked}"


# Every identifier permitted to be interpolated into something typed at the
# relay's shell. All of them are server-side config or a literal IP address
# that guard.resolve_target() produced via ipaddress.ip_address() — none of
# them is text a caller supplied.
_SHELL_SAFE_NAMES = {
    "cmd",                  # _hop_command output, or a literal — both checked below
    "prof.username",        # server-side credential profile
    "prof.password",        # server-side credential profile
    "prof.enable_secret",   # server-side credential profile
    "_MARKER",              # module constant
    "test_ip",              # validated literal IP
    "port",                 # from config
}


def _names_in(node: ast.AST) -> set[str]:
    found = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.Attribute) and isinstance(sub.value, ast.Name):
            found.add(f"{sub.value.id}.{sub.attr}")
        elif isinstance(sub, ast.Name):
            found.add(sub.id)
    # A dotted name also yields its root; drop roots that appear dotted.
    roots = {n.split(".")[0] for n in found if "." in n}
    return {n for n in found if n not in roots}


def test_nothing_caller_controlled_reaches_the_relay_shell():
    """A command guard protects what is typed at the DEVICE. This protects what
    is typed at the RELAY, where there is no guard at all — a shell would run
    whatever it was given. The defence is that no caller string ever gets
    there: only a validated literal IP and server-side config."""
    tree = ast.parse((PKG / "relay_shell.py").read_text(encoding="utf-8"))
    checked = 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        is_write = isinstance(fn, ast.Attribute) and fn.attr == "write_channel"
        is_shell = isinstance(fn, ast.Name) and fn.id == "_shell_cmd"
        if not (is_write or is_shell):
            continue
        # _shell_cmd's first argument is the connection object, not shell text.
        args = node.args[1:] if is_shell else node.args
        for arg in args:
            used = _names_in(arg) - {"conn"}
            assert used <= _SHELL_SAFE_NAMES, (
                f"line {node.lineno}: {sorted(used - _SHELL_SAFE_NAMES)} is "
                "interpolated into a command typed at the relay's shell. If any "
                "of that can carry caller text, this is remote command "
                "execution on the relay."
            )
            checked += 1
    assert checked >= 4, "expected to find the hop, username, password and probe writes"


def test_raw_device_commands_are_literals():
    """`cmd` is allowlisted above as a name that may be typed at the session,
    which is only safe while every caller passes a constant. Assert that,
    rather than trusting it — it is the one allowlisted name that a future edit
    could quietly point at caller input."""
    tree = ast.parse((PKG / "relay_shell.py").read_text(encoding="utf-8"))
    seen = 0
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "_raw_command":
            arg = node.args[1]
            assert isinstance(arg, ast.Constant) and isinstance(arg.value, str), (
                f"line {node.lineno}: _raw_command is called with a non-literal "
                "command. Raw writes bypass guard.check_command entirely."
            )
            seen += 1
    assert seen >= 2, "expected the paging and show-version raw commands"


def test_the_hop_command_interpolates_only_safe_fields():
    """The telnet/ssh line is built from an operator-supplied template. Only
    these three fields may be substituted, and `ip` is always a literal address
    from ipaddress.ip_address() rather than the string the caller typed."""
    src = (PKG / "relay_shell.py").read_text(encoding="utf-8")
    body = src.split("def _hop_command")[1].split("\ndef ")[0]
    assert set(re.findall(r"\{(\w+)\}", body)) == {"ip", "port", "user"}


def test_allowed_verbs_are_all_reads():
    from network_mcp.guard import ALLOWED_VERBS

    assert ALLOWED_VERBS == {"show", "display", "dir", "ping", "traceroute"}, (
        "The command verb allowlist changed. Every verb here is typed at a "
        "customer's router by a language model — adding one is a security "
        "decision, not a convenience."
    )


def test_redaction_cannot_be_disabled_by_a_tool_argument():
    """NETMCP_REDACT_SECRETS is an operator decision made in the environment.
    If it were a tool parameter, any instruction the model read — from a ticket,
    an email, a device banner — could ask for the unredacted config."""
    src = (PKG / "server.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef)) and node.name.startswith("net_"):
            args = [a.arg for a in node.args.args + node.args.kwonlyargs]
            for banned in ("redact", "include_secrets", "apply_redaction", "raw"):
                assert banned not in args, f"{node.name} exposes {banned!r} to callers"


def test_every_tool_is_prefixed_and_every_prompt_names_the_connector():
    """Playbook rule: a prompt is inserted into a session with a dozen
    connectors attached, so it must name its own connector and tool prefix or
    the model routes 'pull the config' to UniFi or IT Glue instead."""
    src = (PKG / "server.py").read_text(encoding="utf-8")

    tools = re.findall(r"@mcp\.tool\s*\nasync def (\w+)", src)
    assert len(tools) >= 8
    assert all(t.startswith("net_") for t in tools), tools

    chunks = src.split("@mcp.prompt")[1:]
    assert len(chunks) >= 4, "prompts are the only place a user discovers what to ask"
    for chunk in chunks:
        body = chunk.split("\ndef ")[0] + chunk.split("\ndef ")[1].split("\n@")[0]
        assert "network-mcp connector" in body
        assert "net_" in body


def test_the_server_module_imports_cleanly():
    pytest.importorskip("fastmcp")
    import network_mcp.server as srv  # noqa: F401

    assert srv.mcp.name == "network-mcp"
