"""Selective trusted-baseline materialization for PR validation workspaces."""

from __future__ import annotations

from pathlib import Path

from gamesymbol_snapshot_lib.codec import canonical_yaml_bytes
from gamesymbol_snapshot_lib.errors import SnapshotConfigError
from gamesymbol_snapshot_lib.model import SnapshotContext, SnapshotContract
from gamesymbol_snapshot_lib.operations import _atomic_write
from gamesymbol_snapshot_lib.paths import (
    ensure_real_tree,
    is_reparse_point,
    iter_yaml_paths,
    path_from_key,
    validate_snapshot_key,
)


def _clear_analysis_yaml(game_root: Path) -> None:
    for path in list(iter_yaml_paths(game_root)):
        path.unlink()


def materialize_baseline(
    *,
    base: SnapshotContext | None,
    merge_contract: SnapshotContract,
    bindir: str | Path,
    invalidated_paths: tuple[str, ...],
    mode: str,
) -> tuple[str, ...]:
    if mode not in {"incremental", "full-rebuild"}:
        raise SnapshotConfigError(f"Unsupported materialization mode: {mode!r}")
    invalidated = {validate_snapshot_key(path) for path in invalidated_paths}
    ensure_real_tree(Path(bindir), merge_contract.game_root)
    merge_contract.game_root.mkdir(parents=True, exist_ok=True)
    if is_reparse_point(merge_contract.game_root):
        raise SnapshotConfigError(f"Snapshot target must not be a link/reparse point: {merge_contract.game_root}")
    _clear_analysis_yaml(merge_contract.game_root)
    if mode == "full-rebuild":
        return ()
    if base is None or base.contract.game_version != merge_contract.game_version:
        raise SnapshotConfigError("Incremental materialization requires a trusted base snapshot for the same tag")

    selected = sorted(set(base.document["files"]) & merge_contract.formal_paths - invalidated)
    for key in selected:
        target = path_from_key(merge_contract.game_root, key)
        target.parent.mkdir(parents=True, exist_ok=True)
        if is_reparse_point(target.parent) or target.exists() and is_reparse_point(target):
            raise SnapshotConfigError(f"Refusing to materialize through a link/reparse point: {target}")
        _atomic_write(target, canonical_yaml_bytes(base.document["files"][key]))
    return tuple(selected)
