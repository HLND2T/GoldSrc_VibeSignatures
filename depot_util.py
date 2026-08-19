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


def resolve_module_depot_path(module: dict, platform: str, basepath: str, context: str) -> str | None:
    base = PurePosixPath(safe_relative_path(basepath, "basepath"))
    depot_field = f"{context}.depot_{platform}"
    legacy_field = f"{context}.path_{platform}"
    depot_value = module.get(f"depot_{platform}")
    legacy_value = module.get(f"path_{platform}")
    depot_path = None if depot_value is None else safe_relative_path(depot_value, depot_field)
    legacy_path = None
    if legacy_value is not None:
        source = PurePosixPath(safe_relative_path(legacy_value, legacy_field))
        try:
            relative = source.relative_to(base)
        except ValueError as exc:
            raise ValueError(f"{legacy_field} must be within basepath {base.as_posix()!r}") from exc
        if not relative.parts:
            raise ValueError(f"{legacy_field} must name a file below basepath {base.as_posix()!r}")
        legacy_path = relative.as_posix()
    if depot_path is not None and legacy_path is not None and depot_path != legacy_path:
        raise ValueError(f"{depot_field} and {legacy_field} must identify the same depot file")
    return depot_path or legacy_path
