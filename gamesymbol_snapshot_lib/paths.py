from __future__ import annotations

import os
from pathlib import Path, PurePosixPath, PureWindowsPath

from gamesymbol_snapshot_lib.errors import SnapshotConfigError, SnapshotSchemaError


def validate_snapshot_key(key: object) -> str:
    if not isinstance(key, str) or not key or "\\" in key or PureWindowsPath(key).is_absolute():
        raise SnapshotSchemaError("Snapshot file path must be a non-empty relative POSIX path")
    path = PurePosixPath(key)
    if (
        path.is_absolute()
        or len(path.parts) != 2
        or "//" in key
        or any(part in {"", ".", ".."} for part in path.parts)
        or not key.endswith(".yaml")
    ):
        raise SnapshotSchemaError(f"Unsafe or non-flat snapshot file path: {key!r}")
    return path.as_posix()


def canonical_key(game_root: Path, artifact_path: str | Path) -> str:
    root = game_root.resolve()
    candidate = Path(artifact_path).resolve()
    try:
        relative = candidate.relative_to(root)
    except ValueError as exc:
        raise SnapshotConfigError(f"Artifact path escapes game root: {artifact_path}") from exc
    try:
        return validate_snapshot_key(relative.as_posix())
    except SnapshotSchemaError as exc:
        raise SnapshotConfigError(str(exc)) from exc


def path_from_key(game_root: Path, key: str) -> Path:
    safe = validate_snapshot_key(key)
    root = game_root.resolve()
    candidate = (root / PurePosixPath(safe)).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise SnapshotSchemaError(f"Snapshot path escapes target root: {key}") from exc
    return candidate


def is_reparse_point(path: Path) -> bool:
    if path.is_symlink():
        return True
    try:
        attributes = path.stat(follow_symlinks=False).st_file_attributes
    except (AttributeError, FileNotFoundError, OSError):
        return False
    return bool(attributes & 0x400)


def ensure_real_tree(bindir: Path, game_root: Path) -> None:
    for path in (bindir, game_root):
        if path.exists() and is_reparse_point(path):
            raise SnapshotConfigError(f"Snapshot target must not be a link/reparse point: {path}")
    try:
        game_root.resolve().relative_to(bindir.resolve())
    except ValueError as exc:
        raise SnapshotConfigError(f"Game root is outside bin directory: {game_root}") from exc


def iter_yaml_paths(game_root: Path):
    if not game_root.exists():
        return
    for current, directories, files in os.walk(game_root, followlinks=False):
        current_path = Path(current)
        for directory in directories:
            if is_reparse_point(current_path / directory):
                raise SnapshotConfigError(f"Refusing to traverse linked directory: {current_path / directory}")
        for filename in files:
            path = current_path / filename
            if path.suffix.lower() == ".yaml":
                if is_reparse_point(path):
                    raise SnapshotConfigError(f"Refusing to read linked YAML: {path}")
                yield path
