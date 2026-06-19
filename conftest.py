"""Root conftest — ensure the worktree's src/ takes precedence on sys.path."""
from __future__ import annotations

import sys
from pathlib import Path

# Insert this worktree's src/ at the front so imports resolve here, not the
# main checkout's installed package.
_SRC = str(Path(__file__).parent / "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)
