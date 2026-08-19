"""DepotDownloader command helpers."""

from __future__ import annotations

import subprocess
from pathlib import PurePosixPath


def append_auth_args(command: list[str], username=None, password=None, remember_password=False) -> None:
    if username:
        command.extend(["-username", str(username)])
    if password:
        command.extend(["-password", str(password)])
    if remember_password:
        command.append("-remember-password")


def run_command(command: list[str]) -> None:
    subprocess.run(command, check=True)


def safe_relative_path(value: object, field: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise ValueError(f"{field} must be a non-empty relative POSIX path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError(f"{field} is unsafe: {value!r}")
    return path.as_posix()


def module_depot_path(module: dict, platform: str, context: str) -> str | None:
    depot_field = f"{context}.depot_{platform}"
    depot_value = module.get(f"depot_{platform}")
    return None if depot_value is None else safe_relative_path(depot_value, depot_field)
