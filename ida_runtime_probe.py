#!/usr/bin/env python3
"""Resolve the IDA kernel version from the interpreter paired with idalib-mcp."""

from __future__ import annotations

import argparse
import importlib
import os
import sys
from collections.abc import Callable
from pathlib import Path


class IdaRuntimeProbeError(RuntimeError):
    pass


def _resolved_executable(value: str | Path, label: str) -> Path:
    try:
        executable = Path(value).resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise IdaRuntimeProbeError(f"{label} executable is unavailable: {value}") from exc
    if not executable.is_file():
        raise IdaRuntimeProbeError(f"{label} executable is not a file: {executable}")
    return executable


def _path_key(path: Path) -> str:
    return os.path.normcase(os.path.normpath(str(path)))


def validate_same_installation(
    python_executable: str | Path,
    idalib_mcp_executable: str | Path,
) -> tuple[Path, Path]:
    """Require idalib-mcp beside Python or in that Python's Scripts directory."""

    python = _resolved_executable(python_executable, "Python")
    idalib_mcp = _resolved_executable(idalib_mcp_executable, "idalib-mcp")
    python_directory = python.parent
    allowed_mcp_directories = {
        _path_key(python_directory),
        _path_key(python_directory / "Scripts"),
    }
    if _path_key(idalib_mcp.parent) not in allowed_mcp_directories:
        raise IdaRuntimeProbeError(
            f"Python and idalib-mcp resolve to different installations: python={python} idalib-mcp={idalib_mcp}"
        )
    return python, idalib_mcp


def query_ida_kernel_version(*, importer: Callable[[str], object] = importlib.import_module) -> str:
    """Initialize idalib and return the installed IDA kernel version."""

    try:
        importer("idapro")
        idaapi = importer("idaapi")
        version = str(idaapi.get_kernel_version()).strip()
    except (AttributeError, ImportError, OSError, RuntimeError) as exc:
        raise IdaRuntimeProbeError(f"failed to query the IDA kernel version: {exc}") from exc
    if not version:
        raise IdaRuntimeProbeError("IDA kernel version probe returned an empty value")
    return version


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--idalib-mcp", required=True, help="Resolved idalib-mcp executable paired with this Python")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        validate_same_installation(sys.executable, args.idalib_mcp)
        version = query_ida_kernel_version()
    except IdaRuntimeProbeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    print(version)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
