"""Reach devices the way a human does: SSH to the relay, then telnet onward.

    ssh relayuser@203.0.113.24        <- ordinary login, ordinary shell
    telnet 192.0.2.90            <- typed at that shell
    Username: / Password:          <- device login
    show running-config

This is the DEFAULT relay mode, and it is the one that needs **nothing changed
on the relay**: no sshd_config edit, no `systemctl reload ssh`, no TCP
forwarding enabled, no per-device `PermitOpen`. Create a user, and it works.
The alternative (`NETMCP_JUMP_MODE=forward`, in jump.py) is faster and cleaner
but requires port forwarding on a public-facing box, which is a bigger ask than
this is worth.

The mechanism is netmiko's terminal-server pattern: connect with the
`terminal_server` driver, which makes no assumptions and sends no platform
commands; drive the hop by hand; then `redispatch()` the live session onto the
real platform driver, which takes over paging, prompts and enable from there.
Vendor re-detection is also just another redispatch — no second connection.

The fragile part is screen-scraping a login, so two things are deliberate:

* Every failure carries a SCRUBBED TRANSCRIPT of what the relay and the device
  actually said. Guessing at "authentication failed" from an exception type
  wastes a round trip per attempt on real hardware.
* Login prompts are answered at most twice. A device that keeps re-prompting is
  a rejected credential, not something to sit in a loop over.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field

log = logging.getLogger("network_mcp.relay_shell")

# Old ADTRANs and 12.x IOS boxes negotiate algorithms that OpenSSH 9 dropped
# from its defaults. The `+` forms append to the defaults rather than replacing
# them, so modern gear is unaffected. Without these, `ssh` from the relay fails
# with "Unable to negotiate" on exactly the equipment this tool exists for.
LEGACY_SSH_OPTS = (
    "-o StrictHostKeyChecking=no",
    "-o UserKnownHostsFile=/dev/null",
    "-o LogLevel=ERROR",
    "-o ConnectTimeout=15",
    "-o PubkeyAuthentication=no",
    "-o KexAlgorithms=+diffie-hellman-group1-sha1,diffie-hellman-group14-sha1",
    "-o HostKeyAlgorithms=+ssh-rsa,ssh-dss",
    "-o Ciphers=+aes128-cbc,3des-cbc",
    "-o MACs=+hmac-sha1",
)

_USERNAME_PROMPT = re.compile(r"(?i)(user\s?name|login)\s*:\s*$")
_PASSWORD_PROMPT = re.compile(r"(?i)pass(word|code)\s*:\s*$")
_DEVICE_PROMPT = re.compile(r"[\r\n][^\r\n]{0,64}[>#]\s*$")
# A prompt at the very end of the buffer. Note the space in ADTRAN's
# "Branch-Router #" — the terminator is not always flush against the
# hostname, so \s* is load bearing rather than tidiness.
_PROMPT_TAIL = re.compile(r"[>#]\s*$")
_ENABLE_PROMPT = re.compile(r"#\s*$")
# ADTRAN clears the screen before its login banner.
_ANSI = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]|\x1b\][^\x07]*\x07|[\x00-\x08\x0b-\x0c\x0e-\x1f]")

# Checked before the prompt patterns, so a failure message that happens to be
# followed by a shell prompt is reported as the failure it is.
_UNREACHABLE = re.compile(
    r"(?i)("
    r"unable to connect|connection refused|no route to host|network is unreachable|"
    r"connection timed out|connection closed by (foreign host|remote host)|"
    r"host is unreachable|name or service not known|could not resolve|"
    r"unable to negotiate|no matching (key exchange|host key|cipher)|"
    r"host key verification failed|command not found|permission denied \(publickey\)"
    r")"
)
_AUTH_FAILED = re.compile(
    r"(?i)("
    r"%\s*(authentication failed|login invalid|bad (password|secret)s?|access denied)|"
    r"login incorrect|authentication failed|access denied|permission denied, please try again|"
    r"too many authentication failures|% error in authentication"
    r")"
)


class RelayShellError(RuntimeError):
    """The hop from the relay to the device failed."""

    def __init__(self, message: str, transcript: str = "", kind: str = "error"):
        super().__init__(message)
        self.transcript = transcript
        self.kind = kind  # "unreachable" | "auth" | "error"


@dataclass
class HopResult:
    conn: object
    # `show version` read RAW, before any platform driver touches the session.
    # This is what lets the caller pick the right driver first time — see the
    # note in hop() about why that ordering matters.
    version_output: str = ""
    prompt: str = ""
    in_enable: bool = False
    transcript: str = ""
    notes: list[str] = field(default_factory=list)


def _read_until(conn, timeout: float, stop_when) -> str:
    """Accumulate channel output until stop_when(buffer) is truthy, or timeout.

    Returns the whole buffer either way; the caller decides whether a timeout
    is fatal, because a device that prints a banner and then sits at a prompt
    with no newline is normal, not an error.
    """
    buf = ""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        chunk = conn.read_channel()
        if chunk:
            buf += chunk
            if stop_when(buf):
                return buf
        else:
            time.sleep(0.2)
    return buf


def _tail(text: str, n: int = 400) -> str:
    return text[-n:] if len(text) > n else text


def hop(target, transport: str, prof, cfg) -> HopResult:
    """SSH to the relay, hop to the device, log in, enable, read `show version`.

    Everything here is done by RAW channel reads and writes, and the session is
    handed back still on the neutral `terminal_server` driver. That ordering is
    deliberate and was learned the hard way: redispatching to a platform driver
    before knowing the platform means netmiko runs that platform's session prep
    against the wrong device. Against a real ADTRAN Total Access 924e, the Cisco
    driver's `terminal width 511` desynchronised the channel and every
    subsequent command failed with "Pattern not detected". The caller redispatches
    once, to the right driver, using the version output returned here.
    """
    from netmiko import ConnectHandler

    notes: list[str] = []

    relay_kwargs = {
        "device_type": "terminal_server",
        "host": cfg.jump_host,
        "port": cfg.jump_port,
        "username": cfg.jump_username,
        "conn_timeout": cfg.jump_timeout,
        "auth_timeout": cfg.jump_timeout,
        "banner_timeout": cfg.jump_timeout,
        "fast_cli": False,
        "global_delay_factor": cfg.global_delay_factor,
    }
    if cfg.jump_key_file:
        relay_kwargs["use_keys"] = True
        relay_kwargs["key_file"] = cfg.jump_key_file
        if cfg.jump_key_passphrase:
            relay_kwargs["passphrase"] = cfg.jump_key_passphrase
    if cfg.jump_password:
        relay_kwargs["password"] = cfg.jump_password

    try:
        conn = ConnectHandler(**relay_kwargs)
    except Exception as exc:  # noqa: BLE001
        raise RelayShellError(
            f"Could not log in to the relay {cfg.jump_username}@{cfg.jump_host}:"
            f"{cfg.jump_port} ({type(exc).__name__}: {exc}). Nothing was attempted "
            "against the device.",
            kind="unreachable",
        ) from exc

    transcript = ""
    try:
        # Learn the relay's own shell prompt so it is never mistaken for the
        # device's. A root shell ends in '#', which is also a Cisco enable
        # prompt — without this, "we arrived" fires before we have gone
        # anywhere.
        relay_prompt = ""
        try:
            relay_prompt = conn.find_prompt().strip()
        except Exception:  # noqa: BLE001
            notes.append("Could not read the relay shell prompt; continuing.")

        cmd = _hop_command(target.ip, transport, prof, cfg)
        log.info("relay hop: %s", cmd.replace(prof.password, "***") if prof.password else cmd)
        conn.write_channel(cmd + "\n")

        transcript = _login(conn, prof, cfg, relay_prompt, transport)
        prompt = _last_prompt(transcript)

        # enable, then stop paging, then read the banner — all raw, because we
        # still do not know what this device is.
        enable_out, in_enable = _enable(conn, prof, cfg)
        transcript += enable_out
        if not in_enable:
            notes.append(
                "Could not confirm enable mode. A running-config read may be "
                "refused or partial at this privilege level."
            )

        transcript += _raw_command(conn, "terminal length 0", cfg, timeout=15)
        version_raw = _raw_command(conn, "show version", cfg, timeout=45)
        transcript += version_raw

        return HopResult(
            conn=conn,
            version_output=_clean(version_raw, "show version"),
            prompt=_last_prompt(transcript) or prompt,
            in_enable=in_enable,
            transcript=transcript,
            notes=notes,
        )

    except RelayShellError:
        _close(conn)
        raise
    except Exception as exc:  # noqa: BLE001
        _close(conn)
        raise RelayShellError(
            f"{type(exc).__name__}: {exc}", transcript=_tail(transcript, 1500)
        ) from exc


def _hop_command(ip: str, transport: str, prof, cfg) -> str:
    """The line typed at the relay's shell.

    `ip` is always a literal address that guard.resolve_target() produced from
    ipaddress.ip_address(), never caller text, so it cannot carry shell
    metacharacters into this command.
    """
    if transport == "telnet":
        template = cfg.relay_telnet_cmd or "telnet {ip} {port}"
        return template.format(ip=ip, port=cfg.telnet_port, user=prof.username)
    template = cfg.relay_ssh_cmd or ("ssh " + " ".join(LEGACY_SSH_OPTS) + " -p {port} {user}@{ip}")
    return template.format(ip=ip, port=cfg.ssh_port, user=prof.username)


def _login(conn, prof, cfg, relay_prompt: str, transport: str) -> str:
    """Answer the device's login prompts. Returns the transcript."""
    transcript = ""
    sent_user = 0
    sent_pass = 0
    deadline = time.monotonic() + max(cfg.conn_timeout * 3, 45)

    def _at_device_prompt(buf: str) -> bool:
        m = _DEVICE_PROMPT.search(buf)
        if not m:
            return False
        line = m.group(0).strip()
        # Still at the relay: the hop command failed and we never left.
        return not (relay_prompt and line.endswith(relay_prompt[-12:]))

    while time.monotonic() < deadline:
        chunk = _read_until(
            conn,
            timeout=6,
            stop_when=lambda b: (
                _UNREACHABLE.search(b)
                or _AUTH_FAILED.search(b)
                or _USERNAME_PROMPT.search(b)
                or _PASSWORD_PROMPT.search(b)
                or _at_device_prompt(b)
            ),
        )
        transcript += chunk
        recent = _tail(transcript, 600)

        if _UNREACHABLE.search(recent):
            raise RelayShellError(
                f"The relay could not open a {transport} session to the device: "
                + _first_match(_UNREACHABLE, recent),
                transcript=_tail(transcript, 1500),
                kind="unreachable",
            )
        if _AUTH_FAILED.search(recent):
            raise RelayShellError(
                f"The device rejected credential profile {prof.name!r}: "
                + _first_match(_AUTH_FAILED, recent),
                transcript=_tail(transcript, 1500),
                kind="auth",
            )
        if _USERNAME_PROMPT.search(recent):
            if sent_user >= 2:
                raise RelayShellError(
                    f"The device kept asking for a username after profile "
                    f"{prof.name!r} was supplied twice — treating that as a "
                    "rejected credential.",
                    transcript=_tail(transcript, 1500),
                    kind="auth",
                )
            conn.write_channel(prof.username + "\n")
            sent_user += 1
            transcript += "\n<username sent>\n"
            continue
        if _PASSWORD_PROMPT.search(recent):
            if sent_pass >= 2:
                raise RelayShellError(
                    f"The device kept asking for a password after profile "
                    f"{prof.name!r} was supplied twice — treating that as a "
                    "rejected credential.",
                    transcript=_tail(transcript, 1500),
                    kind="auth",
                )
            conn.write_channel(prof.password + "\n")
            sent_pass += 1
            transcript += "\n<password sent>\n"
            continue
        if _at_device_prompt(transcript):
            return transcript

    raise RelayShellError(
        "Timed out waiting for a device prompt after the hop. The transcript "
        "below is what the relay and device actually sent — if it ends mid-"
        "banner the device is slow, and raising NETMCP_GLOBAL_DELAY_FACTOR or "
        "NETMCP_CONN_TIMEOUT will fix it.",
        transcript=_tail(transcript, 1500),
        kind="error",
    )


def _read_until_prompt(conn, timeout: float) -> str:
    """Read until the device is quiet AND sitting at a prompt.

    Checking for a prompt only once the channel has gone silent matters: a
    config line ending in '#' arriving mid-stream would otherwise look like the
    end of the output. After a match it waits once more to confirm nothing
    further is coming.
    """
    buf = ""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        chunk = conn.read_channel()
        if chunk:
            buf += chunk
            continue
        if _PROMPT_TAIL.search(_ANSI.sub("", buf)):
            time.sleep(0.4)
            more = conn.read_channel()
            if more:
                buf += more
                continue
            return buf
        time.sleep(0.2)
    return buf


def _raw_command(conn, cmd: str, cfg, timeout: float = 30.0) -> str:
    conn.write_channel(cmd + "\n")
    return _read_until_prompt(conn, timeout * max(1.0, cfg.global_delay_factor))


def _enable(conn, prof, cfg) -> tuple[str, bool]:
    """Raw `enable`. Returns (transcript, whether we reached a '#' prompt)."""
    conn.write_channel("enable\n")
    buf = _read_until(
        conn,
        timeout=12,
        stop_when=lambda b: _PASSWORD_PROMPT.search(_ANSI.sub("", b).rstrip())
        or _ENABLE_PROMPT.search(_ANSI.sub("", b)),
    )
    if _PASSWORD_PROMPT.search(_ANSI.sub("", buf).rstrip()):
        conn.write_channel((prof.enable_secret or prof.password) + "\n")
        buf += "\n<enable secret sent>\n"
        buf += _read_until_prompt(conn, 15)
    return buf, bool(_ENABLE_PROMPT.search(_ANSI.sub("", buf)))


def _last_prompt(transcript: str) -> str:
    lines = [l for l in _ANSI.sub("", transcript).splitlines() if l.strip()]
    return lines[-1].strip() if lines else ""


def _clean(raw: str, cmd: str) -> str:
    """Strip ANSI, the echoed command, and the trailing prompt line."""
    text = _ANSI.sub("", raw).replace("\r\n", "\n").replace("\r", "\n")
    lines = text.split("\n")
    if lines and lines[0].strip() == cmd:
        lines = lines[1:]
    while lines and _PROMPT_TAIL.search(lines[-1]):
        lines.pop()
    return "\n".join(lines).strip("\n")


def _first_match(pattern: re.Pattern, text: str) -> str:
    m = pattern.search(text)
    if not m:
        return "(no detail)"
    start = max(0, m.start() - 60)
    return repr(text[start : m.end() + 60].strip())


def _close(conn) -> None:
    try:
        conn.disconnect()
    except Exception:  # noqa: BLE001
        pass


_MARKER = "__NETMCP_DONE__"


def _shell_cmd(conn, cmd: str, timeout: float = 15.0) -> str:
    """Run one command at the relay's shell and return its output.

    Terminated by a marker rather than by prompt matching, because the relay's
    prompt is whatever that account's dotfiles decide and prompt regexes are
    the usual reason this kind of code is flaky. The marker appears twice: once
    in the echoed command line, once in the real output.
    """
    conn.write_channel(f"{cmd}; echo {_MARKER}\n")
    buf = _read_until(conn, timeout, lambda b: b.count(_MARKER) >= 2)
    lines = buf.splitlines()
    out = []
    started = False
    for line in lines:
        if _MARKER in line and not started:
            started = True  # skip the echoed command line
            continue
        if _MARKER in line:
            break
        if started:
            out.append(line)
    return "\n".join(out).strip()


def probe_relay(cfg, test_ip: str = "") -> dict:
    """Check the relay itself: can we log in, and does it have what we need.

    Separates 'the relay is broken' from 'that one router is down', which are
    indistinguishable from a device error otherwise.
    """
    from netmiko import ConnectHandler

    kwargs = {
        "device_type": "terminal_server",
        "host": cfg.jump_host,
        "port": cfg.jump_port,
        "username": cfg.jump_username,
        "conn_timeout": cfg.jump_timeout,
        "auth_timeout": cfg.jump_timeout,
        "banner_timeout": cfg.jump_timeout,
        "fast_cli": False,
    }
    if cfg.jump_key_file:
        kwargs["use_keys"] = True
        kwargs["key_file"] = cfg.jump_key_file
        if cfg.jump_key_passphrase:
            kwargs["passphrase"] = cfg.jump_key_passphrase
    if cfg.jump_password:
        kwargs["password"] = cfg.jump_password

    conn = ConnectHandler(**kwargs)
    try:
        out: dict = {
            "relay_configured": True,
            "mode": "shell (no relay config required)",
            "relay": f"{cfg.jump_username}@{cfg.jump_host}:{cfg.jump_port}",
            "reachable": True,
            "auth_method": "ssh key" if cfg.jump_key_file else "password",
        }
        try:
            out["shell_prompt"] = conn.find_prompt().strip()
        except Exception:  # noqa: BLE001
            out["shell_prompt"] = "(could not read)"

        out["whoami"] = _shell_cmd(conn, "id -un 2>/dev/null || whoami")
        telnet_path = _shell_cmd(conn, "command -v telnet || echo MISSING")
        ssh_path = _shell_cmd(conn, "command -v ssh || echo MISSING")
        out["telnet_binary"] = telnet_path
        out["ssh_binary"] = ssh_path
        if "MISSING" in telnet_path:
            out["blocker"] = (
                "The relay has no `telnet` client, so Telnet-only devices "
                "cannot be reached. Install it (apt install telnet) or set "
                "NETMCP_ALLOW_TELNET=false and rely on SSH."
            )

        if test_ip:
            checks = {}
            for label, port in (("ssh", cfg.ssh_port), ("telnet", cfg.telnet_port)):
                res = _shell_cmd(
                    conn,
                    f"timeout 5 bash -c '</dev/tcp/{test_ip}/{port}' 2>/dev/null "
                    f"&& echo OPEN || echo BLOCKED",
                    timeout=15,
                )
                checks[label] = "open" if "OPEN" in res else "blocked or filtered"
            out["reachability_from_relay"] = {"target": test_ip, "ports": checks}
        return out
    finally:
        _close(conn)
