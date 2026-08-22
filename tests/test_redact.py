"""No secret from a device config may reach the output.

An MCP result lands in a chat transcript permanently — it gets copied into
tickets, summarised, and synced wherever the user's client syncs. A pre-shared
key that leaks here is leaked for good, and nobody thinks to rotate it. So this
file works the way the UniFi server's redaction test does: define the secret
values up front, run a realistic config through, and assert that not one of
them survives anywhere in the output.
"""

from __future__ import annotations

import pytest

from network_mcp.redact import PLACEHOLDER, redact, scrub_known_secrets

# Every one of these is a distinctive string that must not appear in output.
SECRETS = [
    "$1$mERr$H8sMxxxxxxxxxxxxxxxxx0",
    "0822455D0A16544541",
    "PublicRoCommunity99",
    "WriteMeCommunity77",
    "RadiusSharedKey123",
    "TacacsSharedKey456",
    "MyVpnPreSharedKey789",
    "AdtranPskSecret321",
    "WifiPassphrase654",
    "OspfDigestKey987",
    "BgpNeighborPass135",
    "SnmpV3AuthPass246",
    "SnmpV3PrivPass357",
    "KeyChainSecret468",
    "AdtranUserPass579",
]

CONFIG = """
!
hostname BR-RTR-01
!
enable secret 5 $1$mERr$H8sMxxxxxxxxxxxxxxxxx0
enable password 7 0822455D0A16544541
!
username netadmin privilege 15 secret 5 $1$mERr$H8sMxxxxxxxxxxxxxxxxx0
username backup password 7 0822455D0A16544541
!
snmp-server community PublicRoCommunity99 RO
snmp-server community WriteMeCommunity77 RW
snmp-server user monitor MONGRP v3 auth sha SnmpV3AuthPass246 priv aes 128 SnmpV3PrivPass357
!
radius-server host 10.20.1.5 key RadiusSharedKey123
tacacs-server key TacacsSharedKey456
!
crypto isakmp key MyVpnPreSharedKey789 address 198.51.100.4
crypto keyring BRANCH
 pre-shared-key address 198.51.100.5 key MyVpnPreSharedKey789
!
key chain EIGRP-AUTH
 key 1
  key-string KeyChainSecret468
!
interface GigabitEthernet0/0
 description WAN to carrier
 ip address 10.20.30.1 255.255.255.0
 ip ospf message-digest-key 1 md5 OspfDigestKey987
!
router bgp 65001
 neighbor 10.20.9.1 password BgpNeighborPass135
!
line vty 0 4
 password 7 0822455D0A16544541
 transport input ssh
!
"""

ADTRAN_CONFIG = """
!
hostname "BR-ADTRAN-01"
!
enable password md5 encrypted $1$mERr$H8sMxxxxxxxxxxxxxxxxx0
username "admin" password "AdtranUserPass579"
!
snmp-server community PublicRoCommunity99 RO
!
ip crypto ike policy 100
 peer 198.51.100.7
 initiate main
 preshared-key AdtranPskSecret321
!
interface wifi 1
 ssid "BranchWiFi"
 security mode wpa2-psk
 wpa psk WifiPassphrase654
!
"""


# Line SHAPES taken from a real ADTRAN Total Access 924e (AOS R10.9.5.E) pulled
# on 2026-08-17 — secret values replaced with markers here, obviously. Two of
# these were not in the synthetic fixtures above and are the reason this block
# exists: AOS quotes its usernames, and a voice gateway carries one SIP
# registration secret PER DID, which on that box was 30-odd of the 47 secrets
# in the file. A redaction rule that misses this shape leaks the SIP trunk.
REAL_ADTRAN = """
!
service password-encryption
!
enable password md5 encrypted REALENABLEHASH
username "svcuser" password "REALUSERPASS"
auto-config authname adtran encrypted password REALAUTOCFGPASS
snmp-server community REALCOMMUNITY RO
!
voice trunk T01 type sip
  register 3232015058 auth-name "3232015058" password REALSIPPASS1
  register 3232015059 auth-name "3232015059" password REALSIPPASS2
!
voice user 2001
  password REALVOICEPASS
  sip-authentication password REALSIPAUTHPASS
!
"""

REAL_ADTRAN_SECRETS = [
    "REALENABLEHASH", "REALUSERPASS", "REALAUTOCFGPASS", "REALCOMMUNITY",
    "REALSIPPASS1", "REALSIPPASS2", "REALVOICEPASS", "REALSIPAUTHPASS",
]


@pytest.mark.parametrize("secret", REAL_ADTRAN_SECRETS)
def test_no_secret_survives_a_real_adtran_config(secret):
    assert secret not in redact(REAL_ADTRAN).text


def test_real_adtran_keeps_the_diagnostic_parts():
    """The DID and the auth-name are how you tell which trunk registration is
    failing. Redacting them would make the config useless for the VoIP work
    this tool mostly exists to support."""
    out = redact(REAL_ADTRAN).text
    assert 'register 3232015058 auth-name "3232015058" password <redacted>' in out
    assert "service password-encryption" in out  # a toggle, not a secret
    assert "voice trunk T01 type sip" in out


@pytest.mark.parametrize("secret", SECRETS)
def test_no_secret_survives_a_cisco_config(secret):
    out = redact(CONFIG).text
    assert secret not in out, f"{secret!r} leaked through redaction"


@pytest.mark.parametrize("secret", SECRETS)
def test_no_secret_survives_an_adtran_config(secret):
    out = redact(ADTRAN_CONFIG).text
    assert secret not in out, f"{secret!r} leaked through redaction"


def test_the_left_hand_side_is_kept_so_config_review_still_works():
    """Redaction must not destroy the shape of the config — a reviewer needs to
    see THAT an enable secret and an SNMP community exist."""
    out = redact(CONFIG).text
    for marker in [
        "enable secret",
        "username netadmin privilege 15 secret",
        "snmp-server community",
        "crypto isakmp key",
        "neighbor 10.20.9.1 password",
    ]:
        assert marker in out


def test_non_secret_configuration_is_untouched():
    out = redact(CONFIG).text
    for keep in [
        "hostname BR-RTR-01",
        "ip address 10.20.30.1 255.255.255.0",
        "description WAN to carrier",
        "transport input ssh",
        "router bgp 65001",
    ]:
        assert keep in out


def test_isakmp_peer_address_is_preserved():
    """The peer is diagnostic information, the key is not. Losing the peer
    would make the redacted config useless for troubleshooting a VPN."""
    assert "address 198.51.100.4" in redact(CONFIG).text


def test_counts_what_it_removed():
    assert redact(CONFIG).count > 10
    assert redact("hostname FOO\n").count == 0


def test_redaction_is_idempotent():
    once = redact(CONFIG).text
    twice = redact(once).text
    assert once == twice


def test_private_key_blocks_are_replaced():
    pem = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEAxxxxSECRETKEYMATERIALxxxx\n"
        "-----END RSA PRIVATE KEY-----"
    )
    out = redact(f"crypto pki\n{pem}\n").text
    assert "SECRETKEYMATERIAL" not in out
    assert PLACEHOLDER in out


def test_our_own_login_is_scrubbed_from_any_text():
    """Netmiko is not supposed to echo the password into an exception, and a
    device is not supposed to echo it at the prompt. Both are 'supposed to'."""
    text = "Authentication to 10.20.30.1 failed for netadmin/Sup3rSecret!"
    out = scrub_known_secrets(text, ("Sup3rSecret!",))
    assert "Sup3rSecret!" not in out
    assert PLACEHOLDER in out

