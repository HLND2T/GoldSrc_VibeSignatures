"""Durable accepted-bin inventory helpers and the checkout materialization entry point.

``PERSISTED_WORKSPACE/bin/<gamever>`` is the accepted binary tree. Release promotion swaps it,
while the IDB cache producer and the release consumer both read it into their own checkout.
Every one of those paths goes through the same per-gamever lock so a promotion can never swap
the directory while a job is halfway through copying it out.

"Durable" means the binaries and their side files, excluding recoverable analysis state
(IDA databases, BinSync projects) which is restored from the immutable IDB cache instead.
"""

from __future__ import annotations

import shutil
from pathlib import Path, PurePosixPath

from release_workflow_lib.errors import ReleaseWorkflowError
from release_workflow_lib.hashing import (
    contained_path,
    inventory_sha256,
    normalized_relative_path,
    reject_reparse_components,
    reject_reparse_points,
    sha256_file,
)
from release_workflow_lib.locks import accepted_bin_lock_path, version_lock
from release_workflow_lib.manifests import require_gamever
from release_workflow_lib.staging import is_recoverable_analysis_path


def durable_files(root: Path) -> list[Path]:
    reject_reparse_points(root)
    return [
        path
        for path in sorted(item for item in root.rglob("*") if item.is_file())
        if not is_recoverable_analysis_path(path.relative_to(root))
    ]


def durable_inventory(root: Path) -> tuple[list[dict], str]:
    records = [
        {
            "path": normalized_relative_path(path.relative_to(root).as_posix()),
            "size": path.stat().st_size,
            "sha256": sha256_file(path),
        }
        for path in durable_files(root)
    ]
    return records, inventory_sha256(records)


def durable_skeleton(root: Path) -> list[tuple[str, int]]:
    return [
        (normalized_relative_path(path.relative_to(root).as_posix()), path.stat().st_size)
        for path in durable_files(root)
    ]


def contains_recoverable_analysis_state(root: Path) -> bool:
    return any(is_recoverable_analysis_path(path.relative_to(root)) for path in root.rglob("*"))


def materialize_accepted_bin(
    *, repo_root: str | Path, persisted_root: str | Path, gamever: str, bindir: str = "bin"
) -> dict:
    """Overlay the persisted accepted bin tree for one gamever onto the current checkout.

    This is the single materialization entry point for both the warmup producer and the
    release consumer, so the two jobs cannot drift into different include/exclude rules.
    The overlay is additive: checked-out submodule files stay unless the accepted tree
    replaces them, matching the previous per-workflow copy behaviour.
    """
    gamever = require_gamever(gamever)
    repo_root = Path(repo_root).resolve()
    persisted_root = Path(persisted_root).resolve()
    reject_reparse_components(persisted_root, persisted_root)
    bin_root = contained_path(repo_root, bindir)
    if not bin_root.is_dir():
        raise ReleaseWorkflowError(f"checkout bin directory does not exist: {bin_root}")
    source = contained_path(persisted_root, "bin", gamever)
    target = contained_path(bin_root, gamever)
    with version_lock(accepted_bin_lock_path(persisted_root, gamever)):
        if not source.is_dir():
            print(f"accepted bin materialization skipped (no persisted tree): {gamever}")
            return {"materialized": False, "gamever": gamever, "files": 0, "hash": None}
        expected, digest = durable_inventory(source)
        target.mkdir(parents=True, exist_ok=True)
        reject_reparse_components(repo_root, target)
        for record in expected:
            parts = PurePosixPath(record["path"]).parts
            destination = contained_path(target, *parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            reject_reparse_components(target, destination)
            shutil.copy2(contained_path(source, *parts), destination)
        for record in expected:
            destination = contained_path(target, *PurePosixPath(record["path"]).parts)
            if destination.stat().st_size != record["size"] or sha256_file(destination) != record["sha256"]:
                raise ReleaseWorkflowError(f"accepted bin materialization mismatch for {gamever}: {record['path']}")
    print(f"accepted bin materialized: {gamever}; files={len(expected)}; inventory_sha256={digest}")
    return {"materialized": True, "gamever": gamever, "files": len(expected), "hash": digest}
