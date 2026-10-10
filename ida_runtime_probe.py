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
    """Keep venv identity and require a paired entry point or explicit POSIX shebang."""

    python = _resolved_executable(python_executable, "Python")
    idalib_mcp = _resolved_executable(idalib_mcp_executable, "idalib-mcp")
    # Resolving the leaf of a POSIX venv Python loses the venv identity: many
    # distinct environments link to the same system executable.
    python_directory = Path(python_executable).absolute().parent.resolve()
    allowed_mcp_directories = {
        _path_key(python_directory),
        _path_key(python_directory / "Scripts"),
    }
    paired = _path_key(idalib_mcp.parent) in allowed_mcp_directories
    if os.name == "posix":
        try:
            with idalib_mcp.open("rb") as handle:
                shebang = handle.readline(4096).decode("utf-8").strip()
            if shebang.startswith("#!"):
                interpreter = Path(shebang[2:]) if shebang.startswith("#!/") else None
                paired = (
                    interpreter is not None
                    and _path_key(interpreter.parent.resolve()) == _path_key(python_directory)
                    and interpreter.resolve(strict=True) == python
                )
        except (OSError, UnicodeError, RuntimeError):
            paired = False
    if not paired:
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
