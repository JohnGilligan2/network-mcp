"""The device session layer. Netmiko over SSH or Telnet, read-only.

READ-ONLY IS STRUCTURAL, NOT A POLICY. This module calls exactly five netmiko
methods: ConnectHandler, .enable(), .find_prompt(), .send_command() and
.disconnect(). It never calls send_config_set, send_config_from_file,
save_config, commit, write_channel or send_command_timing, so there is no code
path from an MCP tool to a configuration change — a prompt injection cannot
reach one because one does not exist. tests/test_readonly_surface.py asserts
that by scanning this file, so the guarantee survives a future edit.

Two things worth knowing about the connection strategy:

* Credentials are tried IN ORDER and the failure is distinguished. An auth
  rejection moves to the next profile; an unreachable host does not (retrying
  four passwords against a dead address just multiplies the wait, and against
  a live-but-firewalled one it looks like a brute-force attempt).
* Transport falls back SSH -> Telnet, and every Telnet result carries a warning
  in the response, because the credentials crossed the network in cleartext and
  the person reading the output should know that.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

from . import jump, relay_shell, vendors
from .config import Config
from .credentials import CredentialProfile, secret_values
from .guard import ResolvedTarget, check_command, resolve_target
from .jump import JumpError
from .redact import redact, scrub_known_secrets

log = logging.getLogger("network_mcp.device")


class DeviceError(RuntimeError):
    """A device could not be reached, authenticated, or read."""


class AuthFailed(DeviceError):
    """Every configured credential profile was rejected."""


class Unreachable(DeviceError):
    """No transport could open a session to the address."""


@dataclass
class DeviceResult:
    host: str
    ip: str
    transport: str = ""
    via_relay: str = ""
    vendor: str = "generic"
    vendor_label: str = ""
    credential_profile: str = ""
    outputs: dict[str, str] = field(default_factory=dict)
    version_output: str = ""
    warnings: list[str] = field(default_factory=list)
    secrets_redacted: int = 0
    elapsed_s: float = 0.0
    ok: bool = True
    error: str = ""

    def as_dict(self) -> dict[str, Any]:
        d = {
            "host": self.host,
            "ip": self.ip,
            "ok": self.ok,
            "transport": self.transport,
            "via_relay": self.via_relay or "(direct — no jump host configured)",
            "vendor": self.vendor,
            "platform": self.vendor_label,
            "credential_profile": self.credential_profile,
            "elapsed_s": round(self.elapsed_s, 1),
        }
        if self.error:
            d["error"] = self.error
        if self.warnings:
            d["warnings"] = self.warnings
        if self.secrets_redacted:
            d["secrets_redacted"] = self.secrets_redacted
        if self.outputs:
            d["outputs"] = self.outputs
        return d


def _netmiko_driver(name: str, fallback: str) -> tuple[str, Optional[str]]:
    """Return a device_type netmiko actually registers, plus a warning if we
    had to substitute. Netmiko's driver list changes between releases and a
    missing telnet variant should degrade, not crash the call."""
    from netmiko.ssh_dispatcher import CLASS_MAPPER  # imported late: heavy

    if name in CLASS_MAPPER:
        return name, None
    return fallback, (
        f"netmiko has no driver {name!r} in this version; fell back to "
        f"{fallback!r}. Output should still be correct — raise "
        "NETMCP_GLOBAL_DELAY_FACTOR if it looks truncated."
    )


TRANSPORT_ORDERS = {
    "auto": ["ssh", "telnet"],
    # The house default. Almost everything we manage is an ADTRAN or an older
    # Cisco where Telnet is what is actually enabled, so trying SSH first spends
    # a connect timeout per device to learn what we already know. SSH stays as
    # the fallback so a device that has been hardened still works.
    "telnet_first": ["telnet", "ssh"],
    "ssh": ["ssh"],
    "telnet": ["telnet"],
}


def _transports_for(requested: Optional[str], cfg: Config) -> list[str]:
    want = (requested or cfg.default_transport or "telnet_first").strip().lower()
    if want not in TRANSPORT_ORDERS:
        raise DeviceError(
            f"transport must be one of {', '.join(TRANSPORT_ORDERS)}, not {want!r}"
        )

    order = TRANSPORT_ORDERS[want]
    allowed = [
        t
        for t in order
        if (t == "ssh" and cfg.allow_ssh) or (t == "telnet" and cfg.allow_telnet)
    ]
    if not allowed:
        raise DeviceError(
            f"Transport {want!r} is disabled on this server "
            f"(allow_ssh={cfg.allow_ssh}, allow_telnet={cfg.allow_telnet})."
        )
    return allowed


class _Dialer:
    """Builds ConnectHandler kwargs, tunnelling through the relay if configured.

    Every call to kwargs() produces a FRESH tunnel, because a paramiko channel
    and a one-shot loopback forwarder are both consumed by a single connection
    — and this session reconnects once, after vendor detection.
    """

    def __init__(self, target: ResolvedTarget, transport: str, cfg: Config):
        self._target = target
        self._transport = transport
        self._cfg = cfg
        self._jump = jump.get(cfg)
        self._to_close: list = []

    @property
    def relay(self) -> str:
        if self._jump is None:
            return ""
        return f"{self._cfg.jump_username}@{self._cfg.jump_host}:{self._cfg.jump_port}"

    def kwargs(self, driver: str, prof: CredentialProfile) -> dict:
        base = _connect_kwargs(self._target.ip, driver, self._transport, prof, self._cfg)
        if self._jump is None:
            return base

        if self._transport == "telnet":
            # netmiko's telnet driver opens its own socket and its only proxy
            # support is SOCKS, so give it a loopback port that tunnels out.
            cm = self._jump.loopback_forward(self._target.ip, self._cfg.telnet_port)
            local_port = cm.__enter__()
            self._to_close.append(cm.__exit__)
            base["host"] = "127.0.0.1"
            base["port"] = local_port
        else:
            chan = self._jump.channel(self._target.ip, self._cfg.ssh_port)
            self._to_close.append(lambda *_: chan.close())
            base["sock"] = chan
        return base

    def close(self) -> None:
        while self._to_close:
            closer = self._to_close.pop()
            try:
                closer(None, None, None)
            except Exception:  # noqa: BLE001
                pass


def _connect_kwargs(ip: str, driver: str, transport: str, prof: CredentialProfile, cfg: Config) -> dict:
    return {
        "device_type": driver,
        "host": ip,
        "port": cfg.telnet_port if transport == "telnet" else cfg.ssh_port,
        "username": prof.username,
        "password": prof.password,
        "secret": prof.enable_secret or prof.password,
        "conn_timeout": cfg.conn_timeout,
        "auth_timeout": cfg.conn_timeout,
        "banner_timeout": cfg.conn_timeout,
        # fast_cli tightens every inter-command delay; old ADTRANs and slow WAN
        # links drop characters under it, which shows up as truncated configs.
        "fast_cli": False,
        "global_delay_factor": cfg.global_delay_factor,
    }


def _run_session_sync(
    target: ResolvedTarget,
    transport: str,
    prof: CredentialProfile,
    commands: list[str],
    cfg: Config,
    vendor_key: Optional[str],
    want_version: bool,
) -> DeviceResult:
    """One blocking netmiko session. Runs in a worker thread."""
    from netmiko import ConnectHandler
    from netmiko.exceptions import (
        NetmikoAuthenticationException,
        NetmikoTimeoutException,
    )

    started = time.monotonic()
    result = DeviceResult(host=target.requested, ip=target.ip, transport=transport)
    if transport == "telnet":
        result.warnings.append(
            "Connected over Telnet: the login credentials crossed the network in "
            "cleartext. Fine inside a management VLAN, not over anything shared. "
            "Enabling SSH on this device removes the exposure."
        )

    spec = vendors.get(vendor_key) if vendor_key else vendors.VENDORS[vendors.PROBE_VENDOR]
    driver, warn = _netmiko_driver(spec.driver(transport), f"cisco_ios{'_telnet' if transport == 'telnet' else ''}")
    if warn:
        result.warnings.append(warn)

    # Two ways to cross the relay. "shell" is the default because it needs
    # nothing changed on the relay: log in to an ordinary shell and type
    # `telnet <ip>`, exactly as an engineer would.
    use_shell = bool(cfg.jump_host) and cfg.jump_mode == "shell"
    dialer = None if use_shell else _Dialer(target, transport, cfg)
    if use_shell:
        result.via_relay = f"{cfg.jump_username}@{cfg.jump_host}:{cfg.jump_port} (shell hop)"
    elif dialer is not None:
        result.via_relay = dialer.relay

    conn = None
    try:
        version_text = ""

        if use_shell:
            # The hop logs in, enables, disables paging and reads `show version`
            # with raw channel I/O, so the platform is known BEFORE any driver
            # touches the session. Redispatching first would run one vendor's
            # session prep against another vendor's CLI.
            from netmiko import redispatch

            hop = relay_shell.hop(target, transport, prof, cfg)
            conn = hop.conn
            result.warnings.extend(hop.notes)
            version_text = hop.version_output

            detected = vendor_key or vendors.detect(version_text)
            spec = vendors.get(detected)
            driver, warn2 = _netmiko_driver(
                spec.driver(transport),
                f"cisco_ios{'_telnet' if transport == 'telnet' else ''}",
            )
            if warn2:
                result.warnings.append(warn2)
            if detected == "generic":
                result.warnings.append(
                    "Could not identify the platform from `show version`; used "
                    "generic IOS-style commands. Pass vendor= explicitly if the "
                    "output looks wrong."
                )
            redispatch(conn, device_type=driver)
        else:
            conn = ConnectHandler(**dialer.kwargs(driver, prof))
            try:
                conn.enable()
            except Exception as exc:  # noqa: BLE001 - enable is best effort
                result.warnings.append(
                    "Could not enter enable mode "
                    f"({type(exc).__name__}). Commands ran at the current "
                    "privilege level; a running-config read may be partial."
                )

            if vendor_key is None or want_version:
                version_text = conn.send_command(
                    spec.version_cmd, read_timeout=cfg.read_timeout
                )

            if vendor_key is None:
                detected = vendors.detect(version_text)
                spec = vendors.get(detected)
                new_driver, warn2 = _netmiko_driver(
                    spec.driver(transport),
                    f"cisco_ios{'_telnet' if transport == 'telnet' else ''}",
                )
                if warn2:
                    result.warnings.append(warn2)
                if detected == "generic":
                    result.warnings.append(
                        "Could not identify the platform from `show version`; "
                        "used generic IOS-style commands. Pass vendor= "
                        "explicitly if the output looks wrong."
                    )
                if new_driver != driver:
                    conn.disconnect()
                    conn = ConnectHandler(**dialer.kwargs(new_driver, prof))
                    try:
                        conn.enable()
                    except Exception:  # noqa: BLE001
                        pass
                    driver = new_driver

        result.vendor = spec.key
        result.vendor_label = spec.label
        result.version_output = version_text
        result.credential_profile = prof.name

        for raw in commands:
            cmd = check_command(raw)  # defence in depth; server checks too
            out = conn.send_command(cmd, read_timeout=cfg.read_timeout)
            result.outputs[cmd] = out if isinstance(out, str) else str(out)

        result.elapsed_s = time.monotonic() - started
        return result

    except NetmikoAuthenticationException as exc:
        raise AuthFailed(str(exc)) from exc
    except NetmikoTimeoutException as exc:
        raise Unreachable(str(exc)) from exc
    except JumpError as exc:
        # The relay is down, or it cannot reach the device. Either way it is a
        # path problem, not a password problem — do not try the other logins.
        raise Unreachable(str(exc)) from exc
    except relay_shell.RelayShellError as exc:
        # The hop already worked out WHICH kind of failure this was by reading
        # what the device actually said, so honour that: a rejected password
        # should try the next profile, an unreachable device should not.
        detail = str(exc)
        if exc.transcript:
            detail += f"\n--- relay transcript ---\n{exc.transcript}"
        if exc.kind == "auth":
            raise AuthFailed(detail) from exc
        if exc.kind == "unreachable":
            raise Unreachable(detail) from exc
        raise DeviceError(detail) from exc
    except (OSError, EOFError) as exc:
        # Connection refused / reset / no route — a transport problem, not an
        # auth problem, so the caller should try the next transport not the
        # next password.
        raise Unreachable(f"{type(exc).__name__}: {exc}") from exc
    except Exception as exc:  # noqa: BLE001
        raise DeviceError(f"{type(exc).__name__}: {exc}") from exc
    finally:
        if conn is not None:
            try:
                conn.disconnect()
            except Exception:  # noqa: BLE001
                pass
        if dialer is not None:
            dialer.close()


def _blocking_run(
    target: ResolvedTarget,
    commands: list[str],
    cfg: Config,
    profiles: tuple[CredentialProfile, ...],
    vendor_key: Optional[str],
    transport: Optional[str],
    want_version: bool,
) -> DeviceResult:
    secrets = secret_values(profiles)
    attempts: list[str] = []

    for tr in _transports_for(transport, cfg):
        auth_rejected = 0
        for prof in profiles:
            try:
                res = _run_session_sync(
                    target, tr, prof, commands, cfg, vendor_key, want_version
                )
                if auth_rejected:
                    res.warnings.append(
                        f"{auth_rejected} credential profile(s) were rejected before "
                        f"{prof.name!r} worked. Worth reconciling this device with "
                        "the standard login."
                    )
                return res
            except AuthFailed as exc:
                auth_rejected += 1
                attempts.append(
                    f"{tr}/{prof.name}: authentication rejected "
                    f"({scrub_known_secrets(str(exc), secrets)[:160]})"
                )
                continue
            except Unreachable as exc:
                # Do not burn the remaining passwords against an address that
                # is not answering — move to the next transport instead.
                attempts.append(
                    f"{tr}: not reachable ({scrub_known_secrets(str(exc), secrets)[:160]})"
                )
                break
            except DeviceError as exc:
                attempts.append(f"{tr}/{prof.name}: {scrub_known_secrets(str(exc), secrets)[:200]}")
                break

    detail = "; ".join(attempts) or "no connection attempted"
    raise DeviceError(f"Could not read {target.requested} ({target.ip}). Tried: {detail}")


async def run_on_device(
    host: str,
    commands: Iterable[str],
    cfg: Config,
    profiles: tuple[CredentialProfile, ...],
    *,
    vendor: Optional[str] = None,
    transport: Optional[str] = None,
    credential_profile: Optional[str] = None,
    want_version: bool = False,
    apply_redaction: Optional[bool] = None,
) -> DeviceResult:
    """Open one session, run the given read commands, return the output.

    `commands` may be literal command strings or the sentinels understood by
    resolve_placeholders() in server.py; by the time they arrive here they are
    literal and every one is re-validated by guard.check_command.
    """
    from .credentials import select

    target = resolve_target(host, cfg)
    profs = select(profiles, credential_profile)
    cmds = [check_command(c) for c in commands]
    vendor_key = vendors.get(vendor).key if vendor else None

    result = await asyncio.to_thread(
        _blocking_run, target, cmds, cfg, profs, vendor_key, transport, want_version
    )

    secrets = secret_values(profiles)
    do_redact = cfg.redact_secrets if apply_redaction is None else apply_redaction
    total = 0
    cleaned: dict[str, str] = {}
    for cmd, text in result.outputs.items():
        text = scrub_known_secrets(text, secrets)
        if do_redact:
            r = redact(text)
            text, n = r.text, r.count
            total += n
        if len(text) > cfg.max_output_chars:
            text = (
                text[: cfg.max_output_chars]
                + f"\n\n... TRUNCATED at {cfg.max_output_chars} characters "
                "(NETMCP_MAX_OUTPUT_CHARS). Re-run with an output filter, e.g. "
                "`| section interface`, to get the part you need."
            )
            result.warnings.append(f"Output of {cmd!r} was truncated.")
        cleaned[cmd] = text
    result.outputs = cleaned
    result.secrets_redacted = total
    if not do_redact:
        result.warnings.append(
            "Secret redaction was DISABLED for this call: the output below may "
            "contain enable secrets, local user hashes, SNMP communities and "
            "pre-shared keys, and it is now in this transcript permanently."
        )
    result.version_output = scrub_known_secrets(result.version_output, secrets)
    return result


async def run_on_many(
    hosts: list[str],
    commands: Iterable[str],
    cfg: Config,
    profiles: tuple[CredentialProfile, ...],
    **kwargs,
) -> list[DeviceResult]:
    """Same as run_on_device across several hosts, bounded concurrency.

    One device failing never fails the batch — that is the whole point of a
    site-wide pull, where two of thirty boxes are always down for a reason
    somebody already knows about.
    """
    cmds = list(commands)
    sem = asyncio.Semaphore(max(1, cfg.max_concurrent_devices))

    async def _one(h: str) -> DeviceResult:
        async with sem:
            try:
                return await run_on_device(h, cmds, cfg, profiles, **kwargs)
            except Exception as exc:  # noqa: BLE001
                return DeviceResult(
                    host=h,
                    ip="",
                    ok=False,
                    error=scrub_known_secrets(str(exc), secret_values(profiles)),
                )

    return list(await asyncio.gather(*(_one(h) for h in hosts)))
