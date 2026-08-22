"""SSH jump host — reach devices that the container itself cannot route to.

The docker host has no path to customer management networks. The relay does.
So every device session is tunnelled: one SSH connection to the relay, then a
`direct-tcpip` channel from the relay out to the device.

    [container] --ssh--> [relay 203.0.113.x] --direct-tcpip--> [device 192.0.2.x:22|23]

Two shapes, because netmiko handles them differently:

* **SSH devices** get the paramiko channel handed straight to netmiko as
  `sock=`. No extra machinery.
* **Telnet devices** need a real socket, because netmiko's telnet driver opens
  its own connection and its only proxy support is SOCKS (see
  netmiko/telnet_proxy.py). So we run a one-shot loopback forwarder: listen on
  127.0.0.1:<ephemeral>, accept exactly one connection, and pump bytes between
  it and the channel. netmiko telnets to the loopback port and is none the wiser.

The relay SSH connection is SHARED and lock-protected — paramiko multiplexes
channels over one transport, so a 30-device site backup costs one SSH handshake
to the relay rather than thirty.

WHAT THIS CHANGES ABOUT THE THREAT MODEL. Before the relay, the target
allowlist was belt and braces: the container could not route to much anyway.
Now it is the only thing bounding reach, because the relay can see whatever the
relay can see. NETMCP_ALLOWED_CIDRS is doing real work from here on.

The relay address itself is NOT subject to that allowlist — it is a configured
value, not a caller-supplied one, which is exactly why it is safe for it to be
a public address while device targets are not.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import select
import socket
import threading
from contextlib import contextmanager
from typing import Optional

log = logging.getLogger("network_mcp.jump")


class JumpError(RuntimeError):
    """The relay could not be reached, authenticated, or asked to forward."""


class JumpHost:
    """One shared SSH connection to the relay, opening a channel per device."""

    def __init__(self, cfg):
        self._cfg = cfg
        self._client = None
        self._lock = threading.Lock()

    # -- connection ---------------------------------------------------------

    def _connect(self):
        import paramiko

        cfg = self._cfg
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(_HostKeyPolicy(cfg.jump_host_key_sha256))

        kwargs = {
            "hostname": cfg.jump_host,
            "port": cfg.jump_port,
            "username": cfg.jump_username,
            "timeout": cfg.jump_timeout,
            "banner_timeout": cfg.jump_timeout,
            "auth_timeout": cfg.jump_timeout,
            # The relay is reached by address, and its own config decides what
            # the container may forward to. Agent/host keys from the container
            # image are never wanted here.
            "allow_agent": False,
            "look_for_keys": False,
        }
        if cfg.jump_key_file:
            kwargs["key_filename"] = cfg.jump_key_file
            if cfg.jump_key_passphrase:
                kwargs["passphrase"] = cfg.jump_key_passphrase
        if cfg.jump_password:
            kwargs["password"] = cfg.jump_password

        try:
            client.connect(**kwargs)
        except Exception as exc:  # noqa: BLE001
            raise JumpError(
                f"Could not open the SSH relay {cfg.jump_username}@{cfg.jump_host}:"
                f"{cfg.jump_port} ({type(exc).__name__}: {exc}). Nothing was "
                "attempted against the device — every device session goes "
                "through this relay."
            ) from exc
        return client

    def _transport(self):
        """The live transport, reconnecting if the relay dropped us."""
        import paramiko  # noqa: F401  (import cost paid once, here)

        with self._lock:
            if self._client is not None:
                tr = self._client.get_transport()
                if tr is not None and tr.is_active():
                    return tr
                try:
                    self._client.close()
                except Exception:  # noqa: BLE001
                    pass
                self._client = None
                log.info("Relay connection was dead; reconnecting.")
            self._client = self._connect()
            tr = self._client.get_transport()
            if tr is None:
                raise JumpError("Relay connected but produced no transport.")
            tr.set_keepalive(30)
            return tr

    def close(self) -> None:
        with self._lock:
            if self._client is not None:
                try:
                    self._client.close()
                finally:
                    self._client = None

    # -- reaching a device --------------------------------------------------

    def channel(self, dest_ip: str, dest_port: int):
        """A direct-tcpip channel from the relay to the device."""
        tr = self._transport()
        try:
            return tr.open_channel(
                "direct-tcpip",
                dest_addr=(dest_ip, int(dest_port)),
                src_addr=("127.0.0.1", 0),
                timeout=self._cfg.jump_timeout,
            )
        except Exception as exc:  # noqa: BLE001
            raise JumpError(
                f"The relay {self._cfg.jump_host} refused to forward to "
                f"{dest_ip}:{dest_port} ({type(exc).__name__}: {exc}). Two usual "
                "causes: the relay's sshd has AllowTcpForwarding disabled, or "
                "the relay itself cannot reach that address."
            ) from exc

    @contextmanager
    def loopback_forward(self, dest_ip: str, dest_port: int):
        """Yield a local 127.0.0.1 port that tunnels to the device.

        For Telnet, which opens its own socket and cannot be handed a channel.
        Single-use: it accepts one connection and then stops listening.
        """
        chan = self.channel(dest_ip, dest_port)
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(self._cfg.jump_timeout)
        local_port = listener.getsockname()[1]

        stop = threading.Event()
        threads: list[threading.Thread] = []

        def _serve() -> None:
            try:
                client_sock, _ = listener.accept()
            except Exception:  # noqa: BLE001 - timeout or closed during teardown
                return
            client_sock.settimeout(None)
            for src, dst in ((client_sock, chan), (chan, client_sock)):
                t = threading.Thread(
                    target=_pump, args=(src, dst, stop), daemon=True,
                    name=f"netmcp-tunnel-{local_port}",
                )
                t.start()
                threads.append(t)

        server = threading.Thread(target=_serve, daemon=True, name=f"netmcp-fwd-{local_port}")
        server.start()
        try:
            yield local_port
        finally:
            stop.set()
            for closer in (listener.close, chan.close):
                try:
                    closer()
                except Exception:  # noqa: BLE001
                    pass


def _pump(src, dst, stop: threading.Event) -> None:
    """Shovel bytes one way until either end closes. Both a socket and a
    paramiko Channel support recv/sendall/fileno, so this works for both."""
    try:
        while not stop.is_set():
            ready, _, _ = select.select([src], [], [], 0.5)
            if not ready:
                continue
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except Exception:  # noqa: BLE001 - teardown races are normal here
        pass
    finally:
        stop.set()


class _HostKeyPolicy:
    """Pin the relay's host key by SHA256 fingerprint when one is configured.

    The relay is on a public address, so trust-on-first-use means a MITM at
    first connect owns the device credentials for every subsequent session.
    Set NETMCP_JUMP_HOST_KEY_SHA256 (the value `ssh-keyscan` + `ssh-keygen -lf`
    prints, without the 'SHA256:' prefix) and this becomes a real check.
    """

    def __init__(self, expected: str):
        self._expected = (expected or "").strip().removeprefix("SHA256:")

    def missing_host_key(self, client, hostname, key) -> None:
        fp = base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")
        if not self._expected:
            log.warning(
                "Relay %s host key accepted UNVERIFIED (SHA256:%s). Pin it with "
                "NETMCP_JUMP_HOST_KEY_SHA256 — this relay is on a public address "
                "and an unverified key means a MITM gets the device credentials.",
                hostname, fp,
            )
            return
        if fp != self._expected:
            raise JumpError(
                f"Relay {hostname} presented host key SHA256:{fp}, but "
                f"NETMCP_JUMP_HOST_KEY_SHA256 expects SHA256:{self._expected}. "
                "Refusing to send device credentials. Either the relay's key was "
                "rotated (update the pin) or this is not the relay."
            )


_INSTANCE: Optional[JumpHost] = None
_INSTANCE_LOCK = threading.Lock()


def get(cfg) -> Optional[JumpHost]:
    """The shared relay, or None when no jump host is configured."""
    global _INSTANCE
    if not cfg.jump_host:
        return None
    with _INSTANCE_LOCK:
        if _INSTANCE is None:
            _INSTANCE = JumpHost(cfg)
        return _INSTANCE
