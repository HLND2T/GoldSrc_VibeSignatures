from __future__ import annotations

import hashlib
import json
import os
import random
import re
import stat
import subprocess
import time
import uuid
from pathlib import Path, PurePosixPath

from release_workflow_lib.errors import ReleaseWorkflowError

SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
REGULAR_GIT_MODES = {"100644", "100755"}
WINDOWS_ERROR_ACCESS_DENIED = 5
WINDOWS_ERROR_SHARING_VIOLATION = 32
WINDOWS_REPLACE_RETRY_ERRORS = {WINDOWS_ERROR_ACCESS_DENIED, WINDOWS_ERROR_SHARING_VIOLATION}
WINDOWS_REPLACE_RETRY_DELAYS = (0.05, 0.1, 0.2, 0.4, 0.8, 1.6)
WINDOWS_REPLACE_RETRY_JITTER_RATIO = 0.25


def canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, allow_nan=False, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n"
    ).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def normalized_sha256(value: object, context: str, *, allow_prefix: bool = False) -> str:
    if allow_prefix and isinstance(value, str) and value.startswith("sha256:"):
        value = value.removeprefix("sha256:")
    if not isinstance(value, str) or not SHA256_PATTERN.fullmatch(value):
        raise ReleaseWorkflowError(f"{context} must be a lowercase raw SHA-256 digest")
    return value


def normalized_relative_path(value: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\0" in value:
        raise ReleaseWorkflowError(f"Path must be a non-empty relative POSIX path: {value!r}")
    path = PurePosixPath(value)
    if path.is_absolute() or path.as_posix() != value or any(part in {"", ".", ".."} for part in path.parts):
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


def _path_matches_payload(path: Path, payload: bytes) -> bool:
    try:
        return path.read_bytes() == payload
    except OSError:
        return False


def _replace_with_windows_retry(source: Path, target: Path, payload: bytes) -> None:
    """Replace ``target`` with ``source``, retrying transient Windows sharing violations.

    A concurrent reader can hold ``target`` open just long enough to fail the rename with
    WinError 5/32. Those are retried with bounded jittered backoff; a target that already
    carries the expected canonical bytes means another writer won the race, which is success.
    """
    attempts = 0
    while True:
        attempts += 1
        try:
            os.replace(source, target)
            return
        except OSError as exc:
            if _path_matches_payload(target, payload):
                return
            winerror = getattr(exc, "winerror", None)
            retry_index = attempts - 1
            if winerror not in WINDOWS_REPLACE_RETRY_ERRORS:
                raise
            if retry_index >= len(WINDOWS_REPLACE_RETRY_DELAYS):
                raise OSError(
                    f"atomic replace failed after {attempts} attempts with WinError {winerror}: "
                    f"{source} -> {target}: {exc}"
                ) from exc
            delay = WINDOWS_REPLACE_RETRY_DELAYS[retry_index]
            time.sleep(delay + random.uniform(0.0, delay * WINDOWS_REPLACE_RETRY_JITTER_RATIO))


def write_canonical_json(path: str | Path, value: object) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = canonical_json_bytes(value)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        temporary.write_bytes(payload)
        _replace_with_windows_retry(temporary, path, payload)
    except BaseException:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    else:
        temporary.unlink(missing_ok=True)


def load_json_object(path: str | Path) -> dict:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ReleaseWorkflowError(f"Unable to read JSON object {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ReleaseWorkflowError(f"JSON top level must be an object: {path}")
    return value


def contained_path(root: str | Path, *parts: str) -> Path:
    root = Path(os.path.abspath(root))
    target = Path(os.path.abspath(root.joinpath(*parts)))
    resolved_root = root.resolve(strict=False)
    resolved_target = target.resolve(strict=False)
    try:
        resolved_target.relative_to(resolved_root)
    except ValueError as exc:
        raise ReleaseWorkflowError(f"Path escapes root {root}: {target}") from exc
    return target


def reject_reparse_components(root: str | Path, target: str | Path) -> None:
    root = Path(os.path.abspath(root))
    target = Path(os.path.abspath(target))
    try:
        relative = target.relative_to(root)
    except ValueError as exc:
        raise ReleaseWorkflowError(f"Path escapes root {root}: {target}") from exc
    current = root
    for part in relative.parts:
        current /= part
        if current.exists() and _is_reparse(current):
            raise ReleaseWorkflowError(f"Reparse path component is not allowed: {current}")


def verify_inventory(root: str | Path, expected: list[dict]) -> str:
    actual = file_inventory(root)
    if actual != expected:
        raise ReleaseWorkflowError(f"File inventory mismatch under {root}")
    return inventory_sha256(actual)


def _git_bytes(repo_root: str | Path, arguments: list[str]) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(repo_root), *arguments],
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.decode(errors="replace").strip()
        raise ReleaseWorkflowError(detail or f"git {' '.join(arguments)} failed")
    return result.stdout


def _git_index_inventory(repo_root: str | Path, pathspecs: list[str]) -> list[dict]:
    raw_entries = _git_bytes(repo_root, ["ls-files", "--stage", "-z", "--", *pathspecs])
    inventory = []
    seen = set()
    for record in raw_entries.split(b"\0"):
        if not record:
            continue
        metadata, raw_path = record.split(b"\t", 1)
        mode, object_id, stage = metadata.decode("ascii").split()
        relative = normalized_relative_path(os.fsdecode(raw_path).replace("\\", "/"))
        if stage != "0" or mode not in REGULAR_GIT_MODES or relative in seen:
            raise ReleaseWorkflowError(f"Tracked output has an unsupported Git index entry: {relative}")
        blob = _git_bytes(repo_root, ["cat-file", "blob", object_id])
        inventory.append({"path": relative, "size": len(blob), "sha256": sha256_bytes(blob)})
        seen.add(relative)
    return sorted(inventory, key=lambda item: item["path"])


def tracked_output_inventory(repo_root: str | Path, gamevers: list[str]) -> list[dict]:
    repo_root = Path(repo_root)
    pathspecs = []
    for gamever in gamevers:
        pathspecs.extend((f"gamesymbols/{gamever}.yaml", f"gamesymbols/{gamever}.metadata.yaml", f"gamedata/{gamever}"))
    inventory = _git_index_inventory(repo_root, pathspecs)
    paths = {item["path"] for item in inventory}
    for gamever in gamevers:
        if f"gamesymbols/{gamever}.yaml" not in paths:
            raise ReleaseWorkflowError(
                f"required tracked output is missing from the Git index: gamesymbols/{gamever}.yaml"
            )
        if f"gamesymbols/{gamever}.metadata.yaml" not in paths:
            raise ReleaseWorkflowError(
                f"required tracked output is missing from the Git index: gamesymbols/{gamever}.metadata.yaml"
            )
        if not any(path.startswith(f"gamedata/{gamever}/") for path in paths):
            raise ReleaseWorkflowError(f"required tracked output is missing from the Git index: gamedata/{gamever}")
    return inventory


def allowed_output_path(path: str, gamevers: list[str], version: str) -> bool:
    path = normalized_relative_path(path)
    if path == f"release-manifests/{version}.json":
        return True
    for gamever in gamevers:
        if path in {f"gamesymbols/{gamever}.yaml", f"gamesymbols/{gamever}.metadata.yaml"}:
            return True
        if path.startswith(f"gamedata/{gamever}/"):
            return True
    return False


def validate_output_paths(paths: list[str], gamevers: list[str], version: str) -> None:
    rejected = [path for path in paths if not allowed_output_path(path, gamevers, version)]
    if rejected:
        raise ReleaseWorkflowError("generated-output PR contains disallowed paths: " + ", ".join(sorted(rejected)))
    if f"release-manifests/{version}.json" not in paths:
        raise ReleaseWorkflowError(f"generated-output PR must change release-manifests/{version}.json")
