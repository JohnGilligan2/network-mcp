"""The relay: config validation and host-key pinning.

The tunnel itself needs a real SSH server to test, so what is asserted here is
everything that can go wrong WITHOUT one — which is most of it. A half-set
relay config must fail at startup rather than turning into a confusing device
auth error, and a host key that does not match the pin must stop the session
before the device credentials are sent.
"""

from __future__ import annotations

import base64
import hashlib

import pytest

from network_mcp import jump
from network_mcp.config import Config, load_config


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for var in (
        "NETMCP_JUMP_HOST", "NETMCP_JUMP_USERNAME", "NETMCP_JUMP_PASSWORD",
        "NETMCP_JUMP_PASSWORD_B64", "NETMCP_JUMP_KEY_FILE", "NETMCP_ALLOWED_CIDRS",
        "NETMCP_DENY_CIDRS",
    ):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("NETMCP_ALLOWED_CIDRS", "172.16.0.0/12")
    # jump.get() memoises a single shared relay; reset it between tests.
    jump._INSTANCE = None


def test_no_relay_configured_means_direct_connections():
    cfg = load_config()
    assert cfg.jump_host == ""
    assert jump.get(cfg) is None


def test_relay_without_a_username_refuses_to_start(monkeypatch):
    monkeypatch.setenv("NETMCP_JUMP_HOST", "203.0.113.24")
    with pytest.raises(RuntimeError, match="NETMCP_JUMP_USERNAME"):
        load_config()


def test_relay_without_a_credential_refuses_to_start(monkeypatch):
    monkeypatch.setenv("NETMCP_JUMP_HOST", "203.0.113.24")
    monkeypatch.setenv("NETMCP_JUMP_USERNAME", "relayuser")
    with pytest.raises(RuntimeError, match="needs a credential"):
        load_config()


def test_relay_password_can_come_from_base64(monkeypatch):
    """Portainer + Compose delete a `$` inside a stack variable. Any relay
    password containing one must travel as base64 or it silently breaks."""
    monkeypatch.setenv("NETMCP_JUMP_HOST", "203.0.113.24")
    monkeypatch.setenv("NETMCP_JUMP_USERNAME", "relayuser")
    monkeypatch.setenv(
        "NETMCP_JUMP_PASSWORD_B64", base64.b64encode(b"has$dollar#hash").decode()
    )
    cfg = load_config()
    assert cfg.jump_password == "has$dollar#hash"
    assert jump.get(cfg) is not None


def test_relay_is_not_subject_to_the_device_allowlist(monkeypatch):
    """Deliberate: the relay is a configured value, not a caller-supplied one.
    A public relay address with private-only device targets is the intended
    shape, and this test exists so nobody 'fixes' it later."""
    monkeypatch.setenv("NETMCP_JUMP_HOST", "203.0.113.24")  # public
    monkeypatch.setenv("NETMCP_JUMP_USERNAME", "relayuser")
    monkeypatch.setenv("NETMCP_JUMP_PASSWORD", "x")
    cfg = load_config()
    assert cfg.jump_host == "203.0.113.24"
    assert all(n.is_private for n in cfg.allowed_cidrs)


# --- host key pinning ------------------------------------------------------


class _FakeKey:
    def __init__(self, material: bytes):
        self._material = material

    def asbytes(self) -> bytes:
        return self._material

    def get_name(self) -> str:
        return "ssh-ed25519"


def _fingerprint(material: bytes) -> str:
    return base64.b64encode(hashlib.sha256(material).digest()).decode().rstrip("=")


def test_unpinned_host_key_is_accepted_but_warned(caplog):
    policy = jump._HostKeyPolicy("")
    policy.missing_host_key(None, "203.0.113.24", _FakeKey(b"real-key"))
    assert "UNVERIFIED" in caplog.text


def test_matching_pin_is_accepted():
    key = _FakeKey(b"real-key")
    policy = jump._HostKeyPolicy(_fingerprint(b"real-key"))
    policy.missing_host_key(None, "203.0.113.24", key)  # must not raise


def test_the_sha256_prefix_is_tolerated_in_the_pin():
    policy = jump._HostKeyPolicy("SHA256:" + _fingerprint(b"real-key"))
    policy.missing_host_key(None, "203.0.113.24", _FakeKey(b"real-key"))


def test_mismatched_host_key_stops_the_session():
    """A relay on a public address whose key changed is either a rotation or a
    machine-in-the-middle. Either way the device password does not get sent."""
    policy = jump._HostKeyPolicy(_fingerprint(b"the-real-relay"))
    with pytest.raises(jump.JumpError, match="Refusing to send device credentials"):
        policy.missing_host_key(None, "203.0.113.24", _FakeKey(b"an-impostor"))
