"""Durable accepted-bin inventory helpers and the checkout materialization entry point.

``PERSISTED_WORKSPACE/bin/<gamever>`` is a binary-only cache read by the IDB cache producer.
Every materialization goes through the same per-gamever lock so cleanup cannot race a reader.

"Durable" means binaries and side files, excluding analysis YAML and recoverable analysis
state (IDA databases, BinSync projects).
"""

from __future__ import annotations

import re
import shutil
from pathlib import Path, PurePosixPath

from idb_cache_selection import IdbCacheSelectionError, validate_persisted_workspace
from release_workflow_lib.errors import ReleaseWorkflowError
from release_workflow_lib.hashing import (
    canonical_json_bytes,
    contained_path,
    inventory_sha256,
    load_json_object,
    normalized_sha256,
    normalized_relative_path,
    reject_reparse_components,
    reject_reparse_points,
    sha256_file,
    write_canonical_json,
)
from release_workflow_lib.locks import accepted_bin_lock_path, version_lock
from release_workflow_lib.manifests import require_gamever

IDA_DATABASE_SUFFIXES = (".i64", ".idb", ".id0", ".id1", ".id2", ".nam", ".til")
RECOVERABLE_ANALYSIS_SUFFIXES = (*IDA_DATABASE_SUFFIXES, ".bsproj", ".binsync.json")
CUTOVER_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")


def is_recoverable_analysis_path(path: Path) -> bool:
    return any(part.lower().endswith(RECOVERABLE_ANALYSIS_SUFFIXES) for part in Path(path).parts)


def is_analysis_yaml_path(path: Path) -> bool:
    return Path(path).suffix.lower() in {".yaml", ".yml"}


def legacy_yaml_inventory(root: Path) -> tuple[list[dict], str]:
    reject_reparse_points(root)
    records = [
        {
            "path": normalized_relative_path(path.relative_to(root).as_posix()),
            "size": path.stat().st_size,
            "sha256": sha256_file(path),
        }
        for path in sorted(item for item in root.rglob("*") if item.is_file())
        if is_analysis_yaml_path(path.relative_to(root))
    ]
    return records, inventory_sha256(records)


def _verified_legacy_yaml_backup(
    root: Path,
    *,
    gamever: str,
    cutover_id: str,
    durable_inventory_sha256: str,
) -> tuple[list[dict], str]:
    if not root.is_dir():
        raise ReleaseWorkflowError(f"legacy YAML backup is not a directory: {root}")
    records, digest = legacy_yaml_inventory(root)
    manifest_path = root / "legacy-yaml-inventory.json"
    document = load_json_object(manifest_path)
    expected_fields = {
        "schema_version",
        "cutover_id",
        "gamever",
        "durable_inventory_sha256",
        "legacy_yaml_inventory_sha256",
        "files",
    }
    if set(document) != expected_fields or document.get("schema_version") != 1:
        raise ReleaseWorkflowError(f"legacy YAML backup manifest has an unexpected schema: {manifest_path}")
    if document.get("cutover_id") != cutover_id or document.get("gamever") != gamever:
        raise ReleaseWorkflowError(f"legacy YAML backup identity differs: {manifest_path}")
    if (
        normalized_sha256(document.get("durable_inventory_sha256"), "legacy backup durable inventory")
        != durable_inventory_sha256
    ):
        raise ReleaseWorkflowError(f"legacy YAML backup durable inventory differs: {manifest_path}")
    if (
        normalized_sha256(document.get("legacy_yaml_inventory_sha256"), "legacy backup YAML inventory") != digest
        or document.get("files") != records
    ):
        raise ReleaseWorkflowError(f"legacy YAML backup inventory differs: {root}")
    if manifest_path.read_bytes() != canonical_json_bytes(document):
        raise ReleaseWorkflowError(f"legacy YAML backup manifest is not canonical: {manifest_path}")
    return records, digest


def _require_legacy_source_subset(source: list[dict], backup: list[dict]) -> None:
    backup_by_path = {record["path"]: record for record in backup}
    for record in source:
        if backup_by_path.get(record["path"]) != record:
            raise ReleaseWorkflowError(
                f"persisted legacy YAML is new or differs from its verified backup: {record['path']}"
            )


def _remove_legacy_yaml(path: Path) -> None:
    path.unlink()


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
    try:
        persisted_root = validate_persisted_workspace(persisted_root, repo_root)
    except IdbCacheSelectionError as exc:
        raise ReleaseWorkflowError(str(exc)) from exc
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


def cleanup_legacy_accepted_yaml(
    *,
    repo_root: str | Path,
    persisted_root: str | Path,
    gamever: str,
    cutover_id: str,
    bindir: str = "bin",
) -> dict:
    """Back up and remove persisted legacy YAML after binary-only materialization succeeds."""
    gamever = require_gamever(gamever)
    if not isinstance(cutover_id, str) or not CUTOVER_ID_RE.fullmatch(cutover_id):
        raise ReleaseWorkflowError(f"invalid cutover ID: {cutover_id!r}")
    repo_root = Path(repo_root).resolve()
    try:
        persisted_root = validate_persisted_workspace(persisted_root, repo_root)
    except IdbCacheSelectionError as exc:
        raise ReleaseWorkflowError(str(exc)) from exc
    materialized = materialize_accepted_bin(
        repo_root=repo_root,
        persisted_root=persisted_root,
        gamever=gamever,
        bindir=bindir,
    )
    if not materialized["materialized"]:
        return {"cleaned": False, "gamever": gamever, "files": 0, "backup": None, "hash": None}

    source = contained_path(persisted_root, "bin", gamever)
    backup_root = contained_path(persisted_root, "accepted-bin", "legacy-yaml-backups", cutover_id, gamever)
    incoming = backup_root.with_name(f".{gamever}.incoming")
    with version_lock(accepted_bin_lock_path(persisted_root, gamever)):
        _records, durable_digest = durable_inventory(source)
        if durable_digest != materialized["hash"]:
            raise ReleaseWorkflowError("accepted-bin durable inventory changed after binary-only materialization")
        legacy, legacy_digest = legacy_yaml_inventory(source)
        reject_reparse_components(persisted_root, backup_root)
        reject_reparse_components(persisted_root, incoming)
        if incoming.exists() and backup_root.exists():
            raise ReleaseWorkflowError(f"conflicting complete and incomplete legacy YAML backups: {backup_root}")
        try:
            if incoming.exists() and not (incoming / "legacy-yaml-inventory.json").is_file():
                if not incoming.is_dir():
                    raise ReleaseWorkflowError(f"incomplete legacy YAML backup is not a directory: {incoming}")
                reject_reparse_points(incoming)
                shutil.rmtree(incoming)
            if incoming.exists():
                backup_files, backup_digest = _verified_legacy_yaml_backup(
                    incoming,
                    gamever=gamever,
                    cutover_id=cutover_id,
                    durable_inventory_sha256=durable_digest,
                )
                _require_legacy_source_subset(legacy, backup_files)
                incoming.replace(backup_root)
            elif backup_root.exists():
                backup_files, backup_digest = _verified_legacy_yaml_backup(
                    backup_root,
                    gamever=gamever,
                    cutover_id=cutover_id,
                    durable_inventory_sha256=durable_digest,
                )
                _require_legacy_source_subset(legacy, backup_files)
            elif not legacy:
                return {"cleaned": False, "gamever": gamever, "files": 0, "backup": None, "hash": legacy_digest}
            else:
                incoming.mkdir(parents=True)
                reject_reparse_components(persisted_root, incoming)
                for record in legacy:
                    parts = PurePosixPath(record["path"]).parts
                    destination = contained_path(incoming, *parts)
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(contained_path(source, *parts), destination)
                write_canonical_json(
                    incoming / "legacy-yaml-inventory.json",
                    {
                        "schema_version": 1,
                        "cutover_id": cutover_id,
                        "gamever": gamever,
                        "durable_inventory_sha256": durable_digest,
                        "legacy_yaml_inventory_sha256": legacy_digest,
                        "files": legacy,
                    },
                )
                backup_files, backup_digest = _verified_legacy_yaml_backup(
                    incoming,
                    gamever=gamever,
                    cutover_id=cutover_id,
                    durable_inventory_sha256=durable_digest,
                )
                if backup_files != legacy or backup_digest != legacy_digest:
                    raise ReleaseWorkflowError("legacy YAML backup verification failed")
                incoming.replace(backup_root)
        except OSError as exc:
            raise ReleaseWorkflowError(f"legacy YAML backup preparation failed: {exc}") from exc

        if not legacy:
            return {
                "cleaned": False,
                "gamever": gamever,
                "files": 0,
                "backup": str(backup_root),
                "hash": backup_digest,
            }
        current, current_digest = legacy_yaml_inventory(source)
        if current != legacy or current_digest != legacy_digest:
            raise ReleaseWorkflowError("legacy YAML changed while its backup was being prepared")
        try:
            for record in legacy:
                _remove_legacy_yaml(contained_path(source, *PurePosixPath(record["path"]).parts))
        except OSError as exc:
            raise ReleaseWorkflowError(f"legacy YAML cleanup was interrupted; rerun the same cutover: {exc}") from exc
        remaining, _remaining_digest = legacy_yaml_inventory(source)
        if remaining:
            raise ReleaseWorkflowError("legacy YAML cleanup did not remove the exact inventory")
    return {
        "cleaned": True,
        "gamever": gamever,
        "files": len(legacy),
        "backup": str(backup_root),
        "hash": backup_digest,
    }
