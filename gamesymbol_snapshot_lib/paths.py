from __future__ import annotations

import os
import re
from pathlib import Path, PurePosixPath, PureWindowsPath

from analysis_config import validated_tag
from gamesymbol_snapshot_lib.errors import SnapshotConfigError, SnapshotSchemaError

SNAPSHOT_FILENAME_RE = re.compile(r"^(?P<tag>[a-z0-9]+(?:-[a-z0-9]+)*-[0-9]+)\.yaml$")
METADATA_FILENAME_RE = re.compile(r"^(?P<tag>[a-z0-9]+(?:-[a-z0-9]+)*-[0-9]+)\.metadata\.yaml$")


def snapshot_tag_from_filename(filename: str) -> str | None:
    match = SNAPSHOT_FILENAME_RE.fullmatch(filename)
    return None if match is None else validated_tag(match.group("tag"))


def metadata_tag_from_filename(filename: str) -> str | None:
    match = METADATA_FILENAME_RE.fullmatch(filename)
    return None if match is None else validated_tag(match.group("tag"))


def metadata_filename(tag: str) -> str:
    return f"{validated_tag(tag)}.metadata.yaml"


def metadata_path_for_snapshot(snapshot_path: str | Path) -> Path:
    path = Path(snapshot_path)
    tag = snapshot_tag_from_filename(path.name)
    if tag is None:
        raise SnapshotSchemaError(f"Invalid snapshot filename: {path.name!r}")
    return path.with_name(metadata_filename(tag))


def iter_snapshot_paths(directory: str | Path) -> tuple[Path, ...]:
    root = Path(directory)
    if not root.is_dir():
        return ()
    return tuple(
        path
        for path in sorted(root.iterdir(), key=lambda item: item.name)
        if path.is_file() and snapshot_tag_from_filename(path.name)
    )


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
