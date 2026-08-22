"""Entry point for network-mcp over stdio (local Claude Code).

Loads .env from the repo root so the server works no matter what working
directory Claude Code launches it from.
"""

import sys
from pathlib import Path

from dotenv import load_dotenv

_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(_ROOT))
load_dotenv(_ROOT / ".env")

from network_mcp.server import main  # noqa: E402

if __name__ == "__main__":
    main()
