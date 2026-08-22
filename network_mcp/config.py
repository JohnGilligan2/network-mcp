"""Configuration for the network-mcp server.

Everything comes from environment variables (a .env at the repo root is loaded
by run_server.py). The auth/server halves are the house shape from the MCP
playbook, unchanged, so this promotes to the remote fastmcp+Entra stack without
edits.

The NETMCP_* half is where this server differs from every other one we run:
it holds LOGIN CREDENTIALS FOR CUSTOMER EQUIPMENT and initiates outbound
sessions to whatever address it is handed. Two settings are therefore load
bearing rather than cosmetic:

  NETMCP_ALLOWED_CIDRS — the only addresses this server will ever log in to.
  NETMCP_DENY_CIDRS    — carve-outs inside those, checked first.

Without them a prompt-injected session ("connect to 203.0.113.9 and show
version") would hand our standard admin password to an attacker-controlled
listener — over Telnet, in cleartext. The allowlist defaults to RFC1918 only.
"""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field

# Private space only. Public management IPs must be added deliberately, one
# CIDR at a time — "it stopped working after we readdressed" is a much better
# failure than "it logged in to something on the internet".
DEFAULT_ALLOWED_CIDRS = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    return int(raw) if raw else default


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name, "").strip()
    return float(raw) if raw else default


def _env_nets(name: str, default: tuple[str, ...]) -> tuple[ipaddress._BaseNetwork, ...]:
    """Parse a comma/space separated CIDR list. A malformed entry is fatal —
    a network guard that silently drops an unparseable rule is not a guard."""
    raw = os.environ.get(name)
    items = default if raw is None else tuple(
        s for s in raw.replace(",", " ").split() if s
    )
    nets = []
    for item in items:
        try:
            nets.append(ipaddress.ip_network(item, strict=False))
        except ValueError as exc:
            raise RuntimeError(
                f"{name} contains an invalid CIDR {item!r}: {exc}. Refusing to "
                "start — an unparseable entry in the target allowlist would "
                "silently widen or narrow what this server can log in to."
            ) from exc
    return tuple(nets)


@dataclass(frozen=True)
class Config:
    # --- who we are allowed to talk to -----------------------------------
    allowed_cidrs: tuple = field(default_factory=lambda: ())
    deny_cidrs: tuple = field(default_factory=lambda: ())

    # --- transport --------------------------------------------------------
    allow_telnet: bool = True
    allow_ssh: bool = True
    ssh_port: int = 22
    telnet_port: int = 23
    # telnet_first | auto | ssh | telnet.
    # telnet_first (Telnet, then SSH) is the default because that matches the
    # estate: ADTRANs ship Telnet-enabled and the older Ciscos have no SSH at
    # all, so trying SSH first spends a connect timeout per device to learn
    # something we already know. SSH stays as the fallback.
    default_transport: str = "telnet_first"

    # --- SSH jump host / relay -------------------------------------------
    # The docker host cannot route to customer management networks; the relay
    # can. When jump_host is set, EVERY device session is tunnelled through it.
    # This address is a configured value, not a caller-supplied one, so it is
    # deliberately NOT subject to allowed_cidrs — that is what makes it safe
    # for it to be a public address while device targets must be private.
    #
    # MODE. "shell" is the default and needs NOTHING changed on the relay: we
    # log in to an ordinary shell and type `telnet <ip>`, exactly as an engineer
    # would. "forward" is technically cleaner (direct-tcpip channels) but
    # requires enabling TCP forwarding in sshd on a public-facing box and a
    # `systemctl reload ssh`, which is a bigger ask than the benefit.
    jump_mode: str = "shell"
    # Overridable in case the relay wants a wrapper script. {ip} {port} {user}
    # are substituted; {ip} is always a validated literal address.
    relay_telnet_cmd: str = ""
    relay_ssh_cmd: str = ""

    jump_host: str = ""
    jump_port: int = 22
    jump_username: str = ""
    jump_password: str = ""
    jump_key_file: str = ""
    jump_key_passphrase: str = ""
    jump_host_key_sha256: str = ""
    jump_timeout: float = 20.0

    conn_timeout: float = 15.0
    read_timeout: float = 60.0
    # Netmiko's fast_cli tightens every delay; old ADTRANs and slow WAN links
    # drop characters under it. Off by default, and this is the knob to raise
    # when a device returns truncated output.
    global_delay_factor: float = 1.0

    # --- output handling --------------------------------------------------
    redact_secrets: bool = True
    max_output_chars: int = 200_000
    max_concurrent_devices: int = 8

    # Optional on-disk archive. Files written here are UNREDACTED by default —
    # a redacted config cannot be restored, so it is not a backup. The MCP
    # RESPONSE is redacted regardless; these two are separate decisions.
    backup_dir: str = ""
    backup_redacted: bool = False

    @property
    def targets_unrestricted(self) -> bool:
        """True when the allowlist has been opened to everything.

        Exposed as a property rather than left implicit in a CIDR value so the
        state is greppable, reportable in net_capabilities, and warned about at
        startup. A `0.0.0.0/0` buried in a Portainer stack variable is the kind
        of thing that reads as a typo six months later; this makes it a stated
        posture instead.
        """
        return any(int(n.prefixlen) == 0 for n in self.allowed_cidrs)


@dataclass(frozen=True)
class AuthConfig:
    """Microsoft Entra ID, resource-server mode.

    This server VALIDATES audience-bound v2 JWTs; it never issues them. The
    client secret belongs in Claude's connector Advanced settings, NOT here.
    """

    enabled: bool
    tenant_id: str = ""
    client_id: str = ""
    # MUST be the exact /mcp URL, not api://<client-id> — else AADSTS9010010.
    identifier_uri: str = ""
    scope_name: str = "access_as_user"
    required_scopes: tuple[str, ...] = ()
    base_url: str = ""
    # Advertise offline_access so Claude obtains a REFRESH token and the
    # connector does not silently die when the ~60-90 min token expires.
    advertise_offline_access: bool = True


@dataclass(frozen=True)
class ServerConfig:
    host: str = "0.0.0.0"
    port: int = 8000
    path: str = "/mcp"
    transport: str = "stdio"  # "stdio" for local Claude Code, "http" when deployed


def load_auth_config() -> AuthConfig:
    enabled = _env_bool("MCP_AUTH_ENABLED", False)
    if not enabled:
        return AuthConfig(enabled=False)

    tenant_id = os.environ.get("ENTRA_TENANT_ID", "")
    client_id = os.environ.get("ENTRA_CLIENT_ID", "")
    identifier_uri = os.environ.get("ENTRA_IDENTIFIER_URI", "")
    base_url = os.environ.get("MCP_BASE_URL", "")
    missing = [
        n
        for n, v in (
            ("ENTRA_TENANT_ID", tenant_id),
            ("ENTRA_CLIENT_ID", client_id),
            ("ENTRA_IDENTIFIER_URI", identifier_uri),
            ("MCP_BASE_URL", base_url),
        )
        if not v
    ]
    if missing:
        raise RuntimeError(
            "MCP_AUTH_ENABLED=true but these are unset: "
            + ", ".join(missing)
            + ". Refusing to start half-configured — an auth misconfiguration "
            "that starts is worse than one that does not."
        )
    raw_scopes = os.environ.get("ENTRA_REQUIRED_SCOPES", "").strip()
    return AuthConfig(
        enabled=True,
        tenant_id=tenant_id,
        client_id=client_id,
        identifier_uri=identifier_uri,
        scope_name=os.environ.get("ENTRA_SCOPE_NAME", "access_as_user"),
        required_scopes=tuple(s for s in raw_scopes.replace(",", " ").split() if s),
        base_url=base_url,
        advertise_offline_access=_env_bool("ENTRA_ADVERTISE_OFFLINE_ACCESS", True),
    )


def load_server_config() -> ServerConfig:
    return ServerConfig(
        host=os.environ.get("MCP_BIND_HOST", "0.0.0.0"),
        port=_env_int("MCP_PORT", 8000),
        path=os.environ.get("MCP_PATH", "/mcp"),
        transport=os.environ.get("MCP_TRANSPORT", "stdio").strip().lower(),
    )


def load_config() -> Config:
    transport = os.environ.get("NETMCP_DEFAULT_TRANSPORT", "telnet_first").strip().lower()
    if transport not in ("auto", "telnet_first", "ssh", "telnet"):
        raise RuntimeError(
            f"NETMCP_DEFAULT_TRANSPORT={transport!r} is not one of "
            "telnet_first|auto|ssh|telnet."
        )

    allowed = _env_nets("NETMCP_ALLOWED_CIDRS", DEFAULT_ALLOWED_CIDRS)
    if not allowed:
        raise RuntimeError(
            "NETMCP_ALLOWED_CIDRS is set but empty. That would allow logging in "
            "to nothing, which is almost certainly a typo — unset it to take the "
            "RFC1918 default, or list the management ranges explicitly."
        )

    from .credentials import read_secret_env

    jump_host = os.environ.get("NETMCP_JUMP_HOST", "").strip()
    jump_user = os.environ.get("NETMCP_JUMP_USERNAME", "").strip()
    jump_pw = read_secret_env("NETMCP_JUMP_PASSWORD")
    jump_key = os.environ.get("NETMCP_JUMP_KEY_FILE", "").strip()
    if jump_host and not jump_user:
        raise RuntimeError(
            "NETMCP_JUMP_HOST is set but NETMCP_JUMP_USERNAME is not. Refusing "
            "to start: a half-configured relay means every device call fails "
            "with a confusing auth error instead of a clear one."
        )
    if jump_host and not (jump_pw or jump_key):
        raise RuntimeError(
            "NETMCP_JUMP_HOST is set but neither NETMCP_JUMP_PASSWORD(_B64) nor "
            "NETMCP_JUMP_KEY_FILE is. The relay needs a credential."
        )

    jump_mode = os.environ.get("NETMCP_JUMP_MODE", "shell").strip().lower()
    if jump_mode not in ("shell", "forward"):
        raise RuntimeError(
            f"NETMCP_JUMP_MODE={jump_mode!r} is not 'shell' or 'forward'."
        )

    return Config(
        allowed_cidrs=allowed,
        deny_cidrs=_env_nets("NETMCP_DENY_CIDRS", ()),
        jump_mode=jump_mode,
        relay_telnet_cmd=os.environ.get("NETMCP_RELAY_TELNET_CMD", "").strip(),
        relay_ssh_cmd=os.environ.get("NETMCP_RELAY_SSH_CMD", "").strip(),
        jump_host=jump_host,
        jump_port=_env_int("NETMCP_JUMP_PORT", 22),
        jump_username=jump_user,
        jump_password=jump_pw,
        jump_key_file=jump_key,
        jump_key_passphrase=read_secret_env("NETMCP_JUMP_KEY_PASSPHRASE"),
        jump_host_key_sha256=os.environ.get("NETMCP_JUMP_HOST_KEY_SHA256", "").strip(),
        jump_timeout=_env_float("NETMCP_JUMP_TIMEOUT", 20.0),
        allow_telnet=_env_bool("NETMCP_ALLOW_TELNET", True),
        allow_ssh=_env_bool("NETMCP_ALLOW_SSH", True),
        ssh_port=_env_int("NETMCP_SSH_PORT", 22),
        telnet_port=_env_int("NETMCP_TELNET_PORT", 23),
        default_transport=transport,
        conn_timeout=_env_float("NETMCP_CONN_TIMEOUT", 15.0),
        read_timeout=_env_float("NETMCP_READ_TIMEOUT", 60.0),
        global_delay_factor=_env_float("NETMCP_GLOBAL_DELAY_FACTOR", 1.0),
        redact_secrets=_env_bool("NETMCP_REDACT_SECRETS", True),
        max_output_chars=_env_int("NETMCP_MAX_OUTPUT_CHARS", 200_000),
        max_concurrent_devices=_env_int("NETMCP_MAX_CONCURRENT_DEVICES", 8),
        backup_dir=os.environ.get("NETMCP_BACKUP_DIR", "").strip(),
        backup_redacted=_env_bool("NETMCP_BACKUP_REDACTED", False),
    )
