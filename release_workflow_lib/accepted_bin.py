"""Durable accepted-bin inventory helpers and the checkout materialization entry point.

``PERSISTED_WORKSPACE/bin/<gamever>`` is a binary-only cache read by the IDB cache producer.
Every materialization goes through the same per-gamever lock so cleanup cannot race a reader.

"Durable" means binaries and side files, excluding analysis YAML and recoverable analysis
state (IDA databases, BinSync projects).
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

IDA_DATABASE_SUFFIXES = (".i64", ".idb", ".id0", ".id1", ".id2", ".nam", ".til")
RECOVERABLE_ANALYSIS_SUFFIXES = (*IDA_DATABASE_SUFFIXES, ".bsproj", ".binsync.json")


def is_recoverable_analysis_path(path: Path) -> bool:
    return any(part.lower().endswith(RECOVERABLE_ANALYSIS_SUFFIXES) for part in Path(path).parts)


def is_analysis_yaml_path(path: Path) -> bool:
    return any(part.lower().endswith((".yaml", ".yml")) for part in Path(path).parts)


def durable_files(root: Path) -> list[Path]:
    reject_reparse_points(root)
    return [
        path
        for path in sorted(item for item in root.rglob("*") if item.is_file())
        if not is_recoverable_analysis_path(path.relative_to(root))
        and not is_analysis_yaml_path(path.relative_to(root))
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
    cache consumer, so jobs cannot drift into different include/exclude rules.
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
