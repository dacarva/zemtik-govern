"""Entry point for `python -m zemtik_govern.cli`.

Dispatches subcommands::

    python -m zemtik_govern.cli init langchain [--tools-module M] [--output F]
"""
from __future__ import annotations

import sys


def main() -> int:
    args = sys.argv[1:]
    if len(args) >= 2 and args[0] == "init" and args[1] == "langchain":
        from zemtik_govern.cli.init_langchain import main as _init_langchain_main

        return _init_langchain_main(args[2:])

    print(f"Unknown command: {' '.join(args)}", file=sys.stderr)
    print(
        "Usage: python -m zemtik_govern.cli init langchain [--tools-module M] [--output F]",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
