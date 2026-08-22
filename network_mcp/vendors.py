"""Per-platform command names, netmiko drivers, and detection signatures.

Detection works by connecting with the most forgiving IOS-style driver, running
`show version`, and matching the banner. Cisco IOS and ADTRAN AOS share enough
CLI surface (`terminal length 0`, `show running-config`, `enable`) that one
probe connection reaches both; if the detected platform needs a different
netmiko driver, device.py reconnects with the right one before doing real work.

Adding a platform is a row in VENDORS plus a signature. Nothing else here is
platform-specific.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class VendorSpec:
    key: str
    label: str
    netmiko_ssh: str
    netmiko_telnet: str
    version_cmd: str = "show version"
    running_cmd: str = "show running-config"
    startup_cmd: str = "show startup-config"
    interfaces_cmd: str = "show ip interface brief"
    inventory_cmd: str = ""
    # Matched against `show version` output to identify the platform.
    signature: re.Pattern = field(default=re.compile(r"(?!)"))

    def driver(self, transport: str) -> str:
        return self.netmiko_telnet if transport == "telnet" else self.netmiko_ssh


VENDORS: dict[str, VendorSpec] = {
    "cisco_ios": VendorSpec(
        key="cisco_ios",
        label="Cisco IOS / IOS-XE",
        netmiko_ssh="cisco_ios",
        netmiko_telnet="cisco_ios_telnet",
        inventory_cmd="show inventory",
        signature=re.compile(r"(?i)\bcisco\s+ios\b|\bios[- ]xe\b|\bcisco\s+internetwork"),
    ),
    "adtran": VendorSpec(
        key="adtran",
        label="ADTRAN AOS (NetVanta / Total Access)",
        netmiko_ssh="adtran_os",
        netmiko_telnet="adtran_os_telnet",
        # AOS accepts `show ip interface brief`; `show interfaces` is far
        # noisier and paginates differently across AOS releases.
        interfaces_cmd="show ip interface brief",
        inventory_cmd="show system",
        signature=re.compile(r"(?i)\badtran\b|\bnetvanta\b|\btotal\s+access\b|\bAOS\b"),
    ),
    "cisco_nxos": VendorSpec(
        key="cisco_nxos",
        label="Cisco NX-OS",
        netmiko_ssh="cisco_nxos",
        netmiko_telnet="cisco_nxos_telnet",
        interfaces_cmd="show ip interface brief",
        inventory_cmd="show inventory",
        signature=re.compile(r"(?i)\bnx-?os\b|\bnexus\b"),
    ),
    "cisco_xr": VendorSpec(
        key="cisco_xr",
        label="Cisco IOS-XR",
        netmiko_ssh="cisco_xr",
        netmiko_telnet="cisco_xr_telnet",
        startup_cmd="",  # XR has no startup-config in the IOS sense
        interfaces_cmd="show ipv4 interface brief",
        inventory_cmd="show inventory",
        signature=re.compile(r"(?i)\bios\s*xr\b"),
    ),
    "cisco_asa": VendorSpec(
        key="cisco_asa",
        label="Cisco ASA",
        netmiko_ssh="cisco_asa",
        netmiko_telnet="cisco_asa_telnet",
        interfaces_cmd="show interface ip brief",
        inventory_cmd="show inventory",
        signature=re.compile(r"(?i)\badaptive\s+security\s+appliance\b|\bASA\d"),
    ),
    "arista_eos": VendorSpec(
        key="arista_eos",
        label="Arista EOS",
        netmiko_ssh="arista_eos",
        netmiko_telnet="arista_eos_telnet",
        startup_cmd="show startup-config",
        inventory_cmd="show inventory",
        signature=re.compile(r"(?i)\barista\b"),
    ),
    "juniper_junos": VendorSpec(
        key="juniper_junos",
        label="Juniper Junos",
        netmiko_ssh="juniper_junos",
        netmiko_telnet="juniper_junos_telnet",
        running_cmd="show configuration | display set",
        startup_cmd="",
        interfaces_cmd="show interfaces terse",
        signature=re.compile(r"(?i)\bjunos\b|\bjuniper\b"),
    ),
    "hp_procurve": VendorSpec(
        key="hp_procurve",
        label="HP/Aruba ProCurve",
        netmiko_ssh="hp_procurve",
        netmiko_telnet="hp_procurve_telnet",
        interfaces_cmd="show ip",
        signature=re.compile(r"(?i)\bprocurve\b|\baruba\b|\bhp\s+j\d"),
    ),
    "generic": VendorSpec(
        key="generic",
        label="Generic IOS-like CLI",
        netmiko_ssh="cisco_ios",
        netmiko_telnet="cisco_ios_telnet",
        signature=re.compile(r"(?!)"),
    ),
}

# The driver used for the identification connection. Chosen because its paging
# and prompt handling work on both Cisco IOS and ADTRAN AOS, which is 95%+ of
# what we manage.
PROBE_VENDOR = "cisco_ios"

# Signature match order. ADTRAN is checked before the Cisco entries because an
# ADTRAN banner sometimes name-checks Cisco compatibility, and NX-OS/XR before
# plain IOS because their banners also contain the word "Cisco".
DETECT_ORDER = ("adtran", "cisco_nxos", "cisco_xr", "cisco_asa", "arista_eos",
                "juniper_junos", "hp_procurve", "cisco_ios")


def detect(version_output: str) -> str:
    """Return a vendor key from `show version` output, or 'generic'."""
    text = version_output or ""
    for key in DETECT_ORDER:
        if VENDORS[key].signature.search(text):
            return key
    return "generic"


def get(key: str | None) -> VendorSpec:
    if not key:
        return VENDORS["generic"]
    k = key.strip().lower().replace("-", "_")
    aliases = {
        "cisco": "cisco_ios",
        "ios": "cisco_ios",
        "iosxe": "cisco_ios",
        "ios_xe": "cisco_ios",
        "nxos": "cisco_nxos",
        "iosxr": "cisco_xr",
        "asa": "cisco_asa",
        "adtran_os": "adtran",
        "netvanta": "adtran",
        "aos": "adtran",
        "eos": "arista_eos",
        "arista": "arista_eos",
        "junos": "juniper_junos",
        "juniper": "juniper_junos",
        "procurve": "hp_procurve",
        "aruba": "hp_procurve",
    }
    k = aliases.get(k, k)
    if k not in VENDORS:
        raise ValueError(
            f"Unknown vendor {key!r}. Known: " + ", ".join(sorted(VENDORS))
        )
    return VENDORS[k]


# --- light fact parsing -----------------------------------------------------
# Deliberately shallow. Anything richer belongs in the model reading the raw
# output, not in a regex here that silently rots when a platform changes format.

_FACT_PATTERNS: dict[str, list[tuple[str, re.Pattern]]] = {
    "cisco_ios": [
        ("version", re.compile(r"(?im)^.*?Version\s+([^,\s]+)")),
        ("uptime", re.compile(r"(?im)^\s*(\S+)\s+uptime\s+is\s+(.+)$")),
        ("model", re.compile(r"(?im)^\s*(?:cisco\s+)?(\S+)\s+\(.*?\)\s+processor")),
        ("serial", re.compile(r"(?im)Processor\s+board\s+ID\s+(\S+)")),
    ],
    "adtran": [
        ("version", re.compile(r"(?im)^\s*ADTRAN,?\s+Inc\..*?\n?.*?version\s*:?\s*(\S+)")),
        ("uptime", re.compile(r"(?im)uptime\s+is\s+(.+)$")),
        ("model", re.compile(r"(?im)^\s*(?:Platform:?\s*)?(NetVanta\s+\S+|Total\s+Access\s+\S+)")),
        ("serial", re.compile(r"(?im)serial\s+number\s*:?\s*(\S+)")),
    ],
}


def parse_facts(vendor_key: str, version_output: str) -> dict[str, str]:
    """Best-effort model/version/serial/uptime. Missing keys are simply absent —
    the raw output is always returned alongside so nothing is lost."""
    out: dict[str, str] = {}
    text = version_output or ""

    m = re.search(r"(?im)^\s*(\S+)\s+uptime\s+is\s+", text)
    if m:
        out["hostname"] = m.group(1)

    for name, pat in _FACT_PATTERNS.get(vendor_key, []):
        hit = pat.search(text)
        if hit:
            out[name] = hit.group(hit.lastindex or 1).strip()
    return out
