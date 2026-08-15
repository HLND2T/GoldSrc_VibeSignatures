from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path, PurePosixPath

from release_workflow_lib.errors import ReleaseWorkflowError


def canonical_json_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def normalized_relative_path(value: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise ReleaseWorkflowError(f"Path must be a non-empty relative POSIX path: {value!r}")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ReleaseWorkflowError(f"Unsafe relative path: {value!r}")
    return path.as_posix()


def _is_reparse(path: Path) -> bool:
    info = path.lstat()
    attributes = getattr(info, "st_file_attributes", 0)
    return path.is_symlink() or bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def reject_reparse_points(root: str | Path) -> None:
    root = Path(root)
    if not root.exists():
        raise ReleaseWorkflowError(f"Path does not exist: {root}")
    for path in (root, *root.rglob("*")):
        if _is_reparse(path):
            raise ReleaseWorkflowError(f"Links/reparse points are not allowed: {path}")


def file_inventory(root: str | Path) -> list[dict]:
    root = Path(root)
    reject_reparse_points(root)
    return [
        {
            "path": normalized_relative_path(path.relative_to(root).as_posix()),
            "size": path.stat().st_size,
            "sha256": sha256_file(path),
        }
        for path in sorted(item for item in root.rglob("*") if item.is_file())
    ]


def inventory_sha256(inventory: list[dict]) -> str:
    return sha256_bytes(canonical_json_bytes({"files": inventory}))


def write_canonical_json(path: str | Path, value: object) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_bytes(canonical_json_bytes(value))
    os.replace(temporary, path)


def load_json_object(path: str | Path) -> dict:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ReleaseWorkflowError(f"Unable to read JSON object {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ReleaseWorkflowError(f"JSON top level must be an object: {path}")
    return value
