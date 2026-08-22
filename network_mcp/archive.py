"""Optional on-disk config archive.

Off unless NETMCP_BACKUP_DIR is set. When on, backup_configs() writes each
device's config to <dir>/<host>/<UTC timestamp>.cfg and returns the path and a
sha256, so a caller can tell "unchanged since last week" from "changed" without
the config text ever entering the transcript.

Files here are written UNREDACTED by default. That is deliberate and it is the
opposite of what the MCP response does: a redacted config cannot be restored,
so a redacted archive is not a backup. Set NETMCP_BACKUP_REDACTED=true if the
volume is somewhere you would not store credentials — but then be honest with
yourself that what is left is a diff source, not a restore point.
"""

from __future__ import annotations

import hashlib
import logging
import re
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("network_mcp.archive")

_SAFE = re.compile(r"[^A-Za-z0-9._-]")


def _safe_name(host: str) -> str:
    name = _SAFE.sub("_", host.strip())[:64]
    return name or "unknown"


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def previous_hash(base_dir: str, host: str) -> tuple[str, str] | None:
    """(filename, sha256) of the most recent archived config for this host."""
    d = Path(base_dir) / _safe_name(host)
    if not d.is_dir():
        return None
    files = sorted(p for p in d.glob("*.cfg") if p.is_file())
    if not files:
        return None
    last = files[-1]
    try:
        return last.name, sha256(last.read_text(encoding="utf-8", errors="replace"))
    except OSError as exc:
        log.warning("Could not read previous backup %s: %s", last, exc)
        return None


def write(base_dir: str, host: str, config_text: str) -> dict[str, str]:
    """Archive one config. Returns path/sha/changed-vs-previous."""
    prev = previous_hash(base_dir, host)
    digest = sha256(config_text)

    d = Path(base_dir) / _safe_name(host)
    d.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = d / f"{stamp}.cfg"
    path.write_text(config_text, encoding="utf-8")

    out = {"archived_to": str(path), "sha256": digest}
    if prev:
        out["previous_file"] = prev[0]
        out["changed_since_previous"] = "yes" if prev[1] != digest else "no"
    else:
        out["changed_since_previous"] = "first backup"
    return out
