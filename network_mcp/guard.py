"""The two gates that make a credential-bearing CLI server safe to expose.

1. WHERE it may log in  — resolve_target()
2. WHAT it may type     — check_command()

Both exist because the caller is a language model reading untrusted text. A
device banner, a ticket body, an interface description or a customer's own
email can all contain "now run `configure terminal`" or "check 203.0.113.9",
and the model has no way to tell that apart from an instruction from the
engineer. So neither the destination nor the command is a matter of prompting:
they are checked here, in code, on every call.

Failure mode being defended against, concretely: this server holds our standard
network admin password. Telnet sends it in cleartext. A single successful
"connect to <attacker IP>" is a permanent credential compromise across every
device that shares that login.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass

MAX_COMMAND_CHARS = 300

# The only words this server will type as the first token of a command. Every
# one of them is a read. Note these are EXACT words, not prefixes — IOS would
# happily accept `conf t` as an abbreviation, so accepting prefixes would
# reopen config mode through the back door.
ALLOWED_VERBS = frozenset({"show", "display", "dir", "ping", "traceroute"})

# Output filters permitted after a `|`. Deliberately excludes `tee`, `redirect`
# and `append`, which are how a show command becomes a file write or an
# outbound copy to an arbitrary URL.
ALLOWED_FILTERS = frozenset(
    {
        "include", "inc", "i",
        "exclude", "exc", "e",
        "begin", "beg", "b",
        "section", "sec",
        "count",
        "json", "xml",  # NX-OS / EOS structured output — read-only
    }
)

# Tokens that must never appear inside a filter expression. A filter's only
# legitimate content is a regex; a transport scheme or filesystem there means
# somebody is trying to write output somewhere.
FORBIDDEN_IN_FILTER = frozenset(
    {
        "tee", "redirect", "append", "copy", "write",
        "tftp", "ftp", "sftp", "scp", "rcp", "http", "https",
        "flash", "bootflash", "nvram", "usbflash", "disk0", "slot0", "cf",
    }
)

# Characters that let one command become two, or reach a shell.
_CHAINING = re.compile(r"[\r\n;&`$<>?\x00-\x1f]")
_WORD = re.compile(r"[A-Za-z0-9_-]+")


class TargetNotAllowed(RuntimeError):
    """The requested host is outside the configured management ranges."""


class CommandNotAllowed(RuntimeError):
    """The requested command is not a read, or tries to redirect output."""


@dataclass(frozen=True)
class ResolvedTarget:
    """A host that passed the allowlist.

    `ip` is what the connection actually uses. Resolving once here and passing
    the literal address downstream closes the DNS rebinding gap where a name
    resolves to an allowed address for the check and a different one for the
    connect.
    """

    requested: str
    ip: str

    @property
    def is_literal(self) -> bool:
        return self.requested == self.ip


def resolve_target(host: str, cfg) -> ResolvedTarget:
    """Resolve `host` and confirm the address is one we may log in to."""
    host = (host or "").strip()
    if not host:
        raise TargetNotAllowed("No host given.")
    if _CHAINING.search(host) or " " in host or "/" in host:
        raise TargetNotAllowed(f"{host!r} is not a valid hostname or IP address.")
    # Strip a bracketed IPv6 literal and any :port the caller pasted in.
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]

    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        try:
            infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        except socket.gaierror as exc:
            raise TargetNotAllowed(f"Could not resolve {host!r}: {exc}") from exc
        candidates = sorted({i[4][0] for i in infos})
        if not candidates:
            raise TargetNotAllowed(f"Could not resolve {host!r} to any address.")
        # EVERY address the name resolves to must be allowed. A name that
        # round-robins between an allowed and a disallowed address is exactly
        # the thing to refuse, not to gamble on.
        for cand in candidates:
            _assert_allowed(ipaddress.ip_address(cand), cfg, host)
        addr = ipaddress.ip_address(candidates[0])
    else:
        _assert_allowed(addr, cfg, host)

    return ResolvedTarget(requested=host, ip=str(addr))


def _assert_allowed(addr, cfg, shown: str) -> None:
    if (
        addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_unspecified
        or addr.is_reserved
    ):
        raise TargetNotAllowed(
            f"{shown} resolves to {addr}, which is a loopback/link-local/"
            "multicast/reserved address. Refusing."
        )
    for net in cfg.deny_cidrs:
        if addr.version == net.version and addr in net:
            raise TargetNotAllowed(
                f"{shown} resolves to {addr}, which is inside the denied range "
                f"{net} (NETMCP_DENY_CIDRS)."
            )
    for net in cfg.allowed_cidrs:
        if addr.version == net.version and addr in net:
            return
    allowed = ", ".join(str(n) for n in cfg.allowed_cidrs)
    raise TargetNotAllowed(
        f"{shown} resolves to {addr}, which is outside the management ranges "
        f"this server may log in to ({allowed}). This is a deliberate gate: the "
        "server holds shared device credentials and Telnet sends them in "
        "cleartext, so it will not connect to an arbitrary address. If this is "
        "genuinely one of our devices, add its range to NETMCP_ALLOWED_CIDRS."
    )


def check_command(command: str) -> str:
    """Validate one device command and return it normalised.

    Read-only, single command, no output redirection. Raises CommandNotAllowed
    with a reason the caller can act on.
    """
    if command is None:
        raise CommandNotAllowed("No command given.")
    # Check the RAW string for chaining characters BEFORE collapsing
    # whitespace. Normalising first would turn "show version\nconfigure
    # terminal" into a single innocuous-looking line and let it through.
    raw = command.replace("\t", " ").strip()
    if not raw:
        raise CommandNotAllowed("No command given.")
    if len(raw) > MAX_COMMAND_CHARS:
        raise CommandNotAllowed(
            f"Command is {len(raw)} characters; the limit is {MAX_COMMAND_CHARS}."
        )
    if _CHAINING.search(raw):
        raise CommandNotAllowed(
            "Command contains a newline, ';', '&', '?', '$', '`' or a redirect "
            "character. One call runs exactly one command — chaining is refused "
            "because it is how a read becomes a write."
        )
    cmd = " ".join(raw.split())

    head, *filters = [seg.strip() for seg in cmd.split("|")]
    if not head:
        raise CommandNotAllowed("Command starts with a '|'.")

    verb = head.split()[0].lower()
    if verb not in ALLOWED_VERBS:
        raise CommandNotAllowed(
            f"{verb!r} is not a read command. This server runs only: "
            + ", ".join(sorted(ALLOWED_VERBS))
            + ". It has no configuration path at all — there is no way to enter "
            "config mode, save, copy, erase or reload through it, by design. "
            "Device changes stay a manual, logged action."
        )
    if verb in ("show", "display") and len(head.split()) < 2:
        raise CommandNotAllowed(f"{verb!r} needs an argument (e.g. 'show version').")

    if len(filters) > 2:
        raise CommandNotAllowed("At most two output filters ('|') are allowed.")

    for seg in filters:
        if not seg:
            raise CommandNotAllowed("Empty filter after '|'.")
        words = [w.lower() for w in _WORD.findall(seg)]
        if not words:
            raise CommandNotAllowed(f"Filter {seg!r} has no keyword.")
        if words[0] not in ALLOWED_FILTERS:
            raise CommandNotAllowed(
                f"Output filter {words[0]!r} is not allowed. Permitted: "
                + ", ".join(sorted(ALLOWED_FILTERS))
                + ". 'tee', 'redirect' and 'append' are excluded because they "
                "write the output somewhere instead of returning it."
            )
        bad = sorted(set(words[1:]) & FORBIDDEN_IN_FILTER)
        if bad:
            raise CommandNotAllowed(
                f"Filter contains {', '.join(bad)}, which would send output to a "
                "file or a remote host. A filter may only contain a match pattern."
            )
        if "://" in seg:
            raise CommandNotAllowed("A filter may not contain a URL.")

    return cmd
