"""Strip credential material out of device output before it leaves the server.

Why this is not optional. A running-config is a credential store: enable
secrets, local user hashes, SNMP communities, RADIUS/TACACS keys, IPSec
pre-shared keys, WiFi passphrases, BGP and OSPF authentication. An MCP result
lands in a chat transcript and stays there — it is copied, summarised, quoted
into a ticket, and synced to whatever the user's client syncs to. A leaked PSK
is leaked permanently, and nobody thinks to go and rotate it.

This is the same lesson the UniFi server learned the hard way (one settings
read returned 25 live secrets including a console's plaintext SSH password).

Design: keep the LEFT-HAND SIDE of every secret-bearing line and replace the
value. `enable secret <redacted>` still tells you an enable secret is set, which
is what config review and drift comparison actually need; the hash itself is
not needed for either.

The archive on disk (NETMCP_BACKUP_DIR) is written UNREDACTED by default,
because a redacted config cannot be restored and is therefore not a backup.
That is a separate switch from this one, deliberately.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

PLACEHOLDER = "<redacted>"

# Words that mark the start of secret material on a config line. Anything from
# the word to end-of-line is replaced.
#   community(?!-)  — so `ip community-list 10 permit ...` is left alone
#   pre-?shared-key — covers Cisco `pre-shared-key` and ADTRAN `preshared-key`
_SECRET_WORD = (
    r"(?:password|passwd|secret|psksecret|psk|passphrase|shared-secret|"
    r"pre-?shared-key|community(?!-)|auth-key|authentication-key)"
)

# (label, compiled pattern). Every pattern names a `keep` group (echoed back),
# a `rest` group (replaced) and optionally a `tail` group (echoed after the
# placeholder, for lines where useful information follows the secret).
RULES: list[tuple[str, re.Pattern]] = [
    (
        "secret-word",
        re.compile(rf"(?im)^(?P<keep>.*?\b{_SECRET_WORD}\b)(?P<rest>[ \t]+\S.*)$"),
    ),
    (
        # `key-string <hash>` and `key-string 7 <hash>` in key chains.
        "key-string",
        re.compile(r"(?im)^(?P<keep>\s*key-string\b)(?P<rest>[ \t]+\S.*)$"),
    ),
    (
        # ` key 7 0822455D0A16` inside radius-server / key-chain blocks.
        # `key chain FOO` and `key config-key ...` are names, not secrets.
        "key-value",
        re.compile(
            r"(?im)^(?P<keep>[ \t]*key(?:[ \t]+\d+)?)(?![ \t]+(?:chain|config-key)\b)"
            r"(?P<rest>[ \t]+\S+)[ \t]*$"
        ),
    ),
    (
        # Keep the peer selector: `crypto isakmp key <secret> address 1.2.3.4`
        "isakmp-key",
        re.compile(
            r"(?im)^(?P<keep>\s*crypto\s+isakmp\s+key)(?P<rest>[ \t]+(?:\d+[ \t]+)?"
            r'(?:"[^"]*"|\S+))(?P<tail>[ \t]+(?:address|hostname)\b.*)?$'
        ),
    ),
    (
        "radius-tacacs-key",
        re.compile(
            r"(?im)^(?P<keep>\s*(?:radius|tacacs)(?:-server)?"
            r"(?:[ \t]+host[ \t]+\S+)?[ \t]+key)(?P<rest>[ \t]+\S.*)$"
        ),
    ),
    (
        # `snmp-server user NAME GROUP v3 auth sha <auth> priv aes 128 <priv>`
        "snmpv3-user",
        re.compile(
            r"(?im)^(?P<keep>\s*snmp-server\s+user\s+\S+\s+\S+)(?P<rest>[ \t]+\S.*)$"
        ),
    ),
    (
        # OSPF/EIGRP/NTP digest keys: `message-digest-key 1 md5 <key>`
        "digest-key",
        re.compile(
            r"(?im)^(?P<keep>.*?\b(?:message-digest-key[ \t]+\d+|authentication-key)?"
            r"[ \t]*(?:md5|sha1|sha256|hmac-sha-\d+))(?P<rest>[ \t]+\S+)[ \t]*$"
        ),
    ),
    (
        "ntp-key",
        re.compile(
            r"(?im)^(?P<keep>\s*ntp\s+authentication-key\s+\d+\s+\S+)(?P<rest>[ \t]+\S.*)$"
        ),
    ),
    (
        # HSRP/VRRP plain authentication string.
        "standby-auth",
        re.compile(
            r"(?im)^(?P<keep>\s*(?:standby|vrrp)[ \t]+\d+[ \t]+authentication\b)"
            r"(?P<rest>[ \t]+\S.*)$"
        ),
    ),
]

# PEM private keys can appear inline (ADTRAN, IOS `crypto key export`). The
# body is replaced wholesale rather than line by line.
_PEM = re.compile(
    r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"
    r".*?-----END (?:RSA |DSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----",
    re.DOTALL,
)


@dataclass(frozen=True)
class RedactionResult:
    text: str
    count: int

    @property
    def summary(self) -> str:
        if not self.count:
            return "no secret material found"
        return f"{self.count} secret value(s) replaced with {PLACEHOLDER}"


def redact(text: str) -> RedactionResult:
    """Replace credential material in device output. Idempotent."""
    if not text:
        return RedactionResult(text=text or "", count=0)

    count = 0

    def _sub(m: re.Match) -> str:
        nonlocal count
        rest = m.group("rest")
        if rest.strip() == PLACEHOLDER:  # already redacted — keep idempotent
            return m.group(0)
        count += 1
        tail = ""
        if "tail" in m.groupdict() and m.group("tail"):
            tail = m.group("tail")
        return f"{m.group('keep')} {PLACEHOLDER}{tail}"

    out = text
    for _label, pattern in RULES:
        out = pattern.sub(_sub, out)

    def _pem_sub(_m: re.Match) -> str:
        nonlocal count
        count += 1
        return f"-----BEGIN PRIVATE KEY-----\n{PLACEHOLDER}\n-----END PRIVATE KEY-----"

    out = _PEM.sub(_pem_sub, out)
    return RedactionResult(text=out, count=count)


def scrub_known_secrets(text: str, secrets: tuple[str, ...]) -> str:
    """Remove this server's OWN credentials from a string.

    Applied to every error message and every device response. Netmiko and
    paramiko are not supposed to echo the password into an exception, and a
    device is not supposed to echo it back at the prompt — but "not supposed
    to" is not a guarantee, and this text goes into a permanent transcript.
    """
    if not text:
        return text
    for s in secrets:
        if s and len(s) >= 4 and s in text:
            text = text.replace(s, PLACEHOLDER)
    return text
