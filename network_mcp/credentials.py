"""House device credentials, held server-side and never returned to the client.

The whole point of this server is that an engineer (or Claude on their behalf)
supplies an IP address and nothing else. The username/password never travel
through the model, never appear in a transcript, and are not selectable by
value — only by PROFILE NAME.

Profiles are tried in order until one authenticates, which is what makes "we
have a standard login, except on the boxes we inherited" work without the
caller knowing which is which.

  NETMCP_CRED_PROFILES=default,legacy,adtran
  NETMCP_CRED_DEFAULT_USERNAME=...
  NETMCP_CRED_DEFAULT_PASSWORD=...          (or _PASSWORD_B64)
  NETMCP_CRED_DEFAULT_ENABLE_SECRET=...     (or _ENABLE_SECRET_B64)

**Use the _B64 variants in Portainer.** Portainer substitutes a stack variable
into docker-compose.yml and Compose then runs its OWN expansion on the result,
so any `$` inside a password is read as an undefined variable and silently
deleted. The symptom is a password that "just doesn't work" with no error
anywhere — it cost hours once already (see the playbook's compose-`$` incident).
Base64 never emits a `$`, so the _B64 form is immune.
"""

from __future__ import annotations

import base64
import binascii
import logging
import os
from dataclasses import dataclass

log = logging.getLogger("network_mcp.credentials")


class CredentialError(RuntimeError):
    pass


@dataclass(frozen=True)
class CredentialProfile:
    """One username/password/enable set. Never log or serialise this directly —
    use .redacted() for anything that could reach a transcript."""

    name: str
    username: str
    password: str
    enable_secret: str = ""

    def redacted(self) -> dict[str, str]:
        return {
            "profile": self.name,
            "username": self.username,
            "password": "<held server-side>",
            "enable_secret": "<held server-side>" if self.enable_secret else "(none)",
        }

    # Defensive: a stray f-string or traceback must not print the password.
    def __repr__(self) -> str:  # pragma: no cover - trivial
        return f"CredentialProfile(name={self.name!r}, username={self.username!r}, password=***)"

    __str__ = __repr__


def read_secret_env(var: str) -> str:
    """Read VAR, preferring VAR_B64 when present.

    Public because config.py loads the jump-host password the same way and the
    B64 rule (see the module docstring) has to be applied identically to every
    secret that travels through a Portainer stack variable.
    """
    b64 = os.environ.get(f"{var}_B64", "").strip()
    if b64:
        try:
            return base64.b64decode(b64, validate=True).decode("utf-8").rstrip("\r\n")
        except (binascii.Error, UnicodeDecodeError) as exc:
            raise CredentialError(
                f"{var}_B64 is not valid base64-encoded UTF-8: {exc}"
            ) from exc
    return os.environ.get(var, "")


_read = read_secret_env


def load_profiles() -> tuple[CredentialProfile, ...]:
    """Build the ordered profile list from the environment.

    Raises rather than returning an empty tuple: a credential-bearing server
    that starts with no credentials looks healthy and fails every call with a
    confusing auth error.
    """
    names = [
        n.strip()
        for n in os.environ.get("NETMCP_CRED_PROFILES", "").replace(",", " ").split()
        if n.strip()
    ]

    # Convenience for the single-credential case (and for local .env testing):
    # NETMCP_USERNAME / NETMCP_PASSWORD alone synthesise a "default" profile.
    if not names:
        user = _read("NETMCP_USERNAME")
        pw = _read("NETMCP_PASSWORD")
        if user and pw:
            return (
                CredentialProfile(
                    name="default",
                    username=user,
                    password=pw,
                    enable_secret=_read("NETMCP_ENABLE_SECRET"),
                ),
            )
        raise CredentialError(
            "No device credentials configured. Set NETMCP_CRED_PROFILES plus the "
            "per-profile variables, or NETMCP_USERNAME/NETMCP_PASSWORD for a "
            "single set. See .env.example."
        )

    profiles: list[CredentialProfile] = []
    seen: set[str] = set()
    for name in names:
        key = name.upper().replace("-", "_")
        if key in seen:
            raise CredentialError(f"Duplicate credential profile {name!r}.")
        seen.add(key)
        prefix = f"NETMCP_CRED_{key}"
        username = _read(f"{prefix}_USERNAME")
        password = _read(f"{prefix}_PASSWORD")
        if not username or not password:
            raise CredentialError(
                f"Credential profile {name!r} is listed in NETMCP_CRED_PROFILES but "
                f"{prefix}_USERNAME and/or {prefix}_PASSWORD is unset. Refusing to "
                "start with a half-defined profile — it would silently be skipped "
                "and look like a device auth failure."
            )
        if "$" in password or "$" in username:
            log.warning(
                "Credential profile %s contains a '$'. If this value ever travels "
                "through a Portainer stack variable, Compose will expand it away "
                "and the login will fail silently. Use %s_PASSWORD_B64 instead.",
                name,
                prefix,
            )
        profiles.append(
            CredentialProfile(
                name=name,
                username=username,
                password=password,
                enable_secret=_read(f"{prefix}_ENABLE_SECRET"),
            )
        )
    return tuple(profiles)


def select(profiles: tuple[CredentialProfile, ...], wanted: str | None) -> tuple[CredentialProfile, ...]:
    """Return the profiles to try: all of them in order, or just the named one."""
    if not wanted:
        return profiles
    for p in profiles:
        if p.name.lower() == wanted.strip().lower():
            return (p,)
    raise CredentialError(
        f"Unknown credential profile {wanted!r}. Available: "
        + ", ".join(p.name for p in profiles)
    )


def secret_values(profiles: tuple[CredentialProfile, ...]) -> tuple[str, ...]:
    """Every secret string this server knows, for scrubbing error text.

    Netmiko and paramiko exceptions are not supposed to contain the password,
    but "not supposed to" is not a guarantee, and an MCP error message lands in
    a transcript permanently.
    """
    out: list[str] = []
    for p in profiles:
        out.extend(v for v in (p.password, p.enable_secret) if v)
    return tuple(sorted(set(out), key=len, reverse=True))
