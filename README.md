# network-mcp

Read-only CLI access to managed network devices, over SSH or Telnet, exposed as
an MCP connector. Give it an IP address; it logs in with the house credentials,
works out whether it is a Cisco or an ADTRAN, pulls the config, strips the
secrets out, and hands it back.

Built on the house MCP pattern (fastmcp resource-server + Entra OAuth, behind
NPM on Portainer) — see `~/.claude/context/mcp-server-playbook.md`.

```
"pull the config from 10.20.30.1"   ->  net_running_config
"is 10.20.30.1 up, and what is it?" ->  net_probe_device
"unsaved changes on 10.20.30.1?"    ->  net_config_diff
"back up these six routers"         ->  net_backup_configs
```

## Status

**Working end to end against real hardware, 2026-08-17.** Pulled the running
config from an ADTRAN Total Access 924e (AOS R10.9.5.E) at 192.0.2.90 via the
relay: platform auto-detected, 454 lines, 47 secrets redacted, 4.8 seconds, no
credential leakage. The `relayuser` relay account exists.

**Not deployed** — no Entra app, no Portainer stack, no NPM host, no GitHub
repo. See [PORTAINER_DEPLOY.md](PORTAINER_DEPLOY.md).

## How it reaches devices

Neither this workstation nor the docker host can route to customer management
networks. A relay can — so the server does exactly what an engineer does:

```
ssh relayuser@203.0.113.24     ->  telnet 192.0.2.90  ->  show running-config
```

**Nothing is configured on the relay.** No `sshd_config` edit, no reload, no
TCP forwarding, no per-device rules. Create a user, and a new device IP works
immediately. Mechanically this is netmiko's terminal-server pattern: connect
with the `terminal_server` driver, drive the hop by hand, then `redispatch()`
the live session onto the Cisco or ADTRAN driver
(`network_mcp/relay_shell.py`). Vendor re-detection is another redispatch on
the same session — no second login.

A tunnelled mode (`NETMCP_JUMP_MODE=forward`, `network_mcp/jump.py`) is also
implemented and is technically cleaner, but it needs port forwarding enabled on
a public-facing box. Shell mode is the default for that reason.

`net_relay_status` checks the relay on its own — login, `telnet` client
present, and whether the relay can actually open a path to a given device.
That's what separates "the relay is down" from "that router is down", which are
otherwise identical from a device error.

**This raises the stakes on `NETMCP_ALLOWED_CIDRS.`** The relay is a shell; it
reaches whatever it can reach. The MCP server's allowlist is the only thing
bounding which addresses get logged into.

## What it can reach

Cisco IOS / IOS-XE, NX-OS, IOS-XR, ASA; ADTRAN AOS (NetVanta, Total Access);
Arista EOS; Juniper Junos; HP/Aruba ProCurve. The platform is detected from
`show version`, so callers never have to say what a box is.

## Tools

| Tool | What it does |
|---|---|
| `net_capabilities` | What this connector is for — the front door |
| `net_probe_device` | Reachable? over what? which login? what platform? **No config returned** |
| `net_running_config` | The running config, redacted. `section=` filter for big ones |
| `net_startup_config` | The saved config |
| `net_show` | Any single show-style command |
| `net_facts` | Model, serial, software version, uptime |
| `net_interfaces` | Interface / IP / status summary |
| `net_backup_configs` | Many devices at once; status + hash per device, text on request |
| `net_config_diff` | Running vs startup (unsaved changes), or device A vs device B |

Five prompts ship as the discovery surface in claude.ai
(`+` → Connectors → **Add from network-mcp**): Pull Device Config, Site Config
Backup, Unsaved Changes Check, Device Triage, Compare Two Devices.

## The three things that make this safe

This server is different from the others we run: it holds a shared admin
credential for customer network equipment, and it is driven by a language model
that reads untrusted text (tickets, emails, device banners, interface
descriptions). "Now check 203.0.113.9" or "run `configure terminal`" can appear
in any of those. So none of this is left to prompting.

**1. It is read-only by construction, not by policy** — `device.py` calls five
netmiko methods and none of them write. There is no `send_config_set`, no
config mode, no save/copy/erase/reload anywhere in the package.
`tests/test_readonly_surface.py` parses the AST and fails if one appears. A
change tool, if ever wanted, belongs in a separate server with its own Entra app
and access group — the way `tactical-rmm-mcp` and `tactical-rmm-audit-mcp` are split.

**2. `guard.py` decides what it may log in to** — it resolves the target first,
requires every address a name resolves to be permitted, and connects to the
address it checked (no DNS-rebinding gap).

**The allowlist is currently OPEN** (`NETMCP_ALLOWED_CIDRS=0.0.0.0/0,::/0`) —
John's call, 2026-08-17, because managed devices sit on private and public
addresses across many customers and a hand-maintained list would be wrong more
often than right during build-out. Loopback, link-local (incl. the
`169.254.169.254` metadata address), multicast and reserved space are still
refused.

Know what that trades away: the credentials are shared across the estate and
Telnet sends them in cleartext, so an address arriving from a ticket, an email,
an interface description or a device banner is acted on exactly like one an
engineer typed. `net_capabilities` says so out loud and the server logs a
warning at startup, so the posture is visible rather than buried in a value.
Narrowing later: our own public blocks + RFC1918, or — better — allow only
addresses documented as configurations in IT Glue, which is tighter than any
CIDR list and makes documentation load-bearing.

**3. Configs come back redacted** — `redact.py` replaces enable secrets, local
user hashes, SNMP communities, RADIUS/TACACS keys, IPSec PSKs, WiFi
passphrases, BGP/OSPF authentication and inline private keys, keeping the
left-hand side so config review and drift comparison still work. There is **no
tool parameter** that turns this off; only the `NETMCP_REDACT_SECRETS`
environment variable, changed deliberately by a person. An MCP result lands in
a transcript permanently.

Plus: command allowlist (`show`, `display`, `dir`, `ping`, `traceroute` only —
no chaining, no `| tee`/`redirect`/`append`), credentials selectable only by
profile *name* and never returned, every Telnet session flagged in its own
result as cleartext, and a per-call audit line carrying the Entra identity of
the human who asked.

## Local development

```bash
python -m venv .venv && .venv/Scripts/pip install -r requirements.txt pytest
```
```bash
cp .env.example .env
```

Fill in `NETMCP_ALLOWED_CIDRS` and one credential profile, then run the tests:

```bash
<your-workspace>/network-mcp/.venv/Scripts/python.exe -m pytest tests -q
```

Run it over stdio in Claude Code (`MCP_TRANSPORT=stdio`, the default):

```bash
<your-workspace>/network-mcp/.venv/Scripts/python.exe <your-workspace>/network-mcp/run_server.py
```

`MCP_AUTH_ENABLED=false` is for local stdio and MCP Inspector only. Never expose
it — this server holds device credentials.

## Layout

```
network_mcp/
  server.py        MCP tools and prompts
  device.py        netmiko sessions — the only module that touches a device
  guard.py         where it may log in, and what it may type
  redact.py        what is removed before output leaves the process
  credentials.py   profiles, held server-side, never returned
  vendors.py       per-platform commands, drivers, detection signatures
  archive.py       optional on-disk config archive
  config.py        environment -> settings
tests/             the security spec: guard, redaction, read-only surface
scripts/           setup_entra_app.ps1
docs/              ENTRA_SETUP_CHECKLIST.md
```

## Known limits

- **`show archive` and `show boot` are refused** as a side effect of the filter
  rules. `show bootvar` works. Nobody has needed the other two yet.
- **Vendor detection needs a reachable `show version`.** A device with a login
  banner that swallows the first command, or an unusual platform, falls back to
  generic IOS-style commands and says so in `warnings`.
- **Telnet is slow and fragile** on old hardware. Raise
  `NETMCP_GLOBAL_DELAY_FACTOR` to 2 or 4 if output comes back truncated.
- **The on-disk archive is unredacted by default** (a redacted config cannot be
  restored, so it is not a backup). The volume is a credential store — back it
  up and treat it as one.
- **Structured parsing is deliberately shallow.** `net_facts` regexes a few
  fields and always returns the raw output alongside; anything richer is better
  done by the model reading the text than by a regex here that rots silently.
