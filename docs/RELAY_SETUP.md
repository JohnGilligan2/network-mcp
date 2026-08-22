# Relay setup — the `relayuser` account on 203.0.113.24

## What the server actually does

Exactly what an engineer does:

```
ssh relayuser@203.0.113.24        <- ordinary login, ordinary shell
telnet 192.0.2.90            <- typed at that shell
Username: / Password:          <- device login
terminal length 0
show running-config
```

It then reads the output back, redacts the secrets, and returns it. There is no
port forwarding, no tunnel, and **nothing to change on the relay** — no
`sshd_config` edit, no `systemctl reload ssh`, no `PermitOpen`. Create a user
and it works. A new device IP needs no change anywhere on the relay, ever.

Under the hood this is netmiko's terminal-server pattern: connect with the
`terminal_server` driver (which sends no platform commands and assumes
nothing), drive the hop by hand, then `redispatch()` the live session onto the
Cisco or ADTRAN driver, which takes over paging, prompts and enable from there.
Implemented in `network_mcp/relay_shell.py`.

## Setup — two commands

```bash
sudo useradd --create-home --shell /bin/bash --comment 'network-mcp service account' relayuser
```

```bash
sudo passwd relayuser
```

Interactive, so the password stays out of shell history.

**The password is not in this repo.** It lives in the Portainer stack variable
`NETMCP_JUMP_PASSWORD_B64` and in the gitignored local `.env`. Choose an
**alphanumeric** one: a `$` is expanded away by Compose inside a Portainer stack
variable, and a `#` is read as a comment by dotenv. Both traps have cost real
hours on other stacks.

```bash
python -c "import secrets,string; print(''.join(secrets.choice(string.ascii_letters+string.digits) for _ in range(24)))"
```

That is the whole required setup. Everything below is optional or a check.

## Confirm the relay has a telnet client

```bash
command -v telnet || sudo apt-get install -y telnet
```

Most of the ADTRANs are Telnet-only, so a missing client is a hard blocker.
`net_relay_status` reports this explicitly rather than letting it surface as a
confusing per-device failure.

## Optional: SSH key instead of a password

No sshd change needed — this is the stock `~/.ssh/authorized_keys` path.

```bash
sudo -u relayuser install -d -m 700 /home/relayuser/.ssh
```

```bash
sudo -u relayuser tee /home/relayuser/.ssh/authorized_keys >/dev/null <<'EOF'
<paste the contents of your own .pub file here>
EOF
```

```bash
sudo chmod 600 /home/relayuser/.ssh/authorized_keys
```

Then in the MCP server's `.env`, comment `NETMCP_JUMP_PASSWORD` and uncomment
`NETMCP_JUMP_KEY_FILE`. Keep the private half on the operator workstation, outside the repo.

## Checks to hand back

Relay can reach the device — `net_relay_status` runs exactly this itself, but
it is worth seeing by hand once:

```bash
for p in 22 23; do timeout 5 bash -c "</dev/tcp/192.0.2.90/$p" 2>/dev/null && echo "$p OPEN" || echo "$p BLOCKED"; done
```

## The trade-off, stated plainly

This account **has a real shell**. That is the cost of not touching sshd: a
tunnel-only account (no shell, no home, `PermitOpen`-scoped) is a smaller grant,
but it requires `AllowTcpForwarding` and a config reload on a public-facing box.
That mode is still implemented — `NETMCP_JUMP_MODE=forward`, see
`network_mcp/jump.py` — if the relay is ever rebuilt and it becomes easy.

What limits the damage in shell mode, without touching sshd:

- **No sudo, no supplementary groups.** `useradd` gives neither by default;
  don't add any. The account is an ordinary unprivileged user.
- **The device credentials are the valuable thing, not the relay shell.** They
  are already scoped by `NETMCP_ALLOWED_CIDRS` in the MCP server, which is the
  layer that decides which addresses may be logged into at all.
- **Rotate the relay password when someone leaves**, the same as any shared
  service account. One place: the Portainer stack variable.

A restricted shell (`--shell /bin/rbash` plus a private `PATH` holding only
`telnet` and `ssh`) also needs no sshd change and is worth doing if you want it.
Be clear-eyed that `rbash` is friction rather than a security boundary — it is
escapable in several well-known ways — so it is not a substitute for the points
above.

## Concurrency note

Each device session is one SSH session to the relay, and
`NETMCP_MAX_CONCURRENT_DEVICES` (default 8) bounds how many run at once. A
site-wide `net_backup_configs` therefore opens up to 8 concurrent logins as
`relayuser`. If the relay's `MaxSessions` / `MaxStartups` are tightened, lower that
number to match.
