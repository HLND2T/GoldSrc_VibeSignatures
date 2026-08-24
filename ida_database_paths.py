from __future__ import annotations

import os
import stat
from pathlib import Path

IDA_DATABASE_SUFFIXES = (".i64", ".idb")
IDA_DATABASE_SIDE_SUFFIXES = (".id1", ".id2", ".nam", ".til")


class IdaDatabasePathError(ValueError):
    pass


def primary_database_paths(binary_path: str | os.PathLike[str]) -> tuple[Path, ...]:
    binary = Path(binary_path)
    return tuple(Path(f"{binary}{suffix}") for suffix in IDA_DATABASE_SUFFIXES)


def database_side_paths(binary_path: str | os.PathLike[str]) -> tuple[Path, ...]:
    binary = Path(binary_path)
    bases = (binary, *primary_database_paths(binary))
    return tuple(Path(f"{base}{suffix}") for base in bases for suffix in IDA_DATABASE_SIDE_SUFFIXES)


def database_paths(binary_path: str | os.PathLike[str]) -> tuple[Path, ...]:
    return tuple(dict.fromkeys((*primary_database_paths(binary_path), *database_side_paths(binary_path))))


def database_lock_paths(binary_path: str | os.PathLike[str]) -> tuple[Path, ...]:
    binary = Path(binary_path)
    return (Path(f"{binary}.id0"), *(Path(f"{path}.id0") for path in primary_database_paths(binary)))


def existing_database_lock(binary_path: str | os.PathLike[str]) -> Path | None:
    return next((path for path in database_lock_paths(binary_path) if path.is_file()), None)


def existing_database_files(binary_path: str | os.PathLike[str], *, require_primary: bool = False) -> tuple[Path, ...]:
    files = tuple(path for path in database_paths(binary_path) if path.is_file())
    primary = tuple(path for path in primary_database_paths(binary_path) if path.is_file())
    if len(primary) > 1:
        raise IdaDatabasePathError(f"Multiple primary IDA databases exist for {binary_path}")
    if require_primary and len(primary) != 1:
        raise IdaDatabasePathError(f"Exactly one primary IDA database is required for {binary_path}")
    return files


def database_file_role(binary_path: str | os.PathLike[str], database_path: str | os.PathLike[str]) -> str:
    candidate = Path(database_path)
    if candidate in primary_database_paths(binary_path):
        return "primary"
    if candidate in database_side_paths(binary_path):
        return "side"
    raise IdaDatabasePathError(f"File is not an allowed IDA database path for {binary_path}: {database_path}")


def is_reparse_point(path: str | os.PathLike[str]) -> bool:
    target = Path(path)
    info = target.lstat()
    attributes = getattr(info, "st_file_attributes", 0)
    return target.is_symlink() or bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def validate_plain_file(path: str | os.PathLike[str], *, context: str) -> Path:
    target = Path(path)
    if not target.is_file() or is_reparse_point(target):
        raise IdaDatabasePathError(f"{context} must be a regular non-reparse file: {target}")
    return target


def validate_database_file_set(binary_path: str | os.PathLike[str]) -> tuple[Path, ...]:
    lock = existing_database_lock(binary_path)
    if lock is not None:
        raise IdaDatabasePathError(f"Active IDA database lock is present: {lock}")
    files = existing_database_files(binary_path, require_primary=True)
    spellings: dict[str, str] = {}
    for path in files:
        validate_plain_file(path, context="IDA database file")
        spelling = os.path.normcase(os.path.abspath(path))
        previous = spellings.setdefault(spelling.casefold(), os.fspath(path))
        if previous != os.fspath(path):
            raise IdaDatabasePathError(f"Case-colliding IDA database files: {previous!r} and {path!s}")
    return files
