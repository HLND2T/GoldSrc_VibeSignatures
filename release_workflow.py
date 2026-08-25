#!/usr/bin/env python3
"""CLI entry point for the GoldSrc release build/stage/promote lifecycle."""

from release_workflow_lib.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
