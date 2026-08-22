"""network-mcp — read-only CLI access to network devices over SSH/Telnet.

Pulls running configs, startup configs and show-command output from Cisco
IOS/IOS-XE/NX-OS, ADTRAN AOS (NetVanta / Total Access) and a few neighbours,
using house credentials held server-side. Every tool is read-only by
construction: see device.py (no write path) and guard.py (command allowlist).
"""

__version__ = "1.0.0"
